"""Bounded, validated loading of local lab evidence files for the engineering report.

Each evidence file is read without following symlinks, capped in size, parsed as strict JSON
(duplicate keys, NaN/Infinity and over-deep nesting rejected) and checked against the schema
the producing module writes. A file that is absent is MISSING (the report shows the area as
UNTESTED/UNKNOWN); a file that cannot be trusted is INVALID with a short reason. Nothing here
raises for bad evidence: the report must say what is wrong instead of failing or omitting it.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from cryptoagility import benchmark, cbom, migration, policy, tls
from cryptoagility.models import SCHEMA_VERSION, Asset

LOADED = "LOADED"
MISSING = "MISSING"
INVALID = "INVALID"

EVIDENCE_FILES: dict[str, str] = {
    "inventory": "inventory.json",
    "policy": "policy.json",
    "migration_plan": "migration-plan.json",
    "matrix": "matrix.json",
    "benchmark": "benchmark.json",
    "capabilities": "capabilities.json",
    "cbom": "cbom.json",
}
OPTIONAL_EVIDENCE = frozenset({"cbom"})

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 500_000
MAX_ITEMS = 10_000
MAX_STRING = 8192


class EvidenceError(ValueError):
    """Evidence file rejected; the message names the problem, not the content."""


@dataclass(frozen=True)
class Evidence:
    key: str
    filename: str
    status: str
    data: dict[str, Any] | None = None
    error: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None

    @property
    def loaded(self) -> bool:
        return self.status == LOADED and self.data is not None


# --------------------------------------------------------------------------- reading


def _read_bounded(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise EvidenceError(f"cannot open file ({exc.strerror or 'error'})") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceError("not a regular file")
        if info.st_size > MAX_FILE_BYTES:
            raise EvidenceError(f"file exceeds the {MAX_FILE_BYTES} byte limit")
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise EvidenceError(f"file exceeds the {MAX_FILE_BYTES} byte limit")
    return data


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise EvidenceError("non-finite number (NaN/Infinity) in JSON")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise EvidenceError("non-finite number in JSON")
    return value


def _check_bounds(data: Any) -> None:
    stack: list[tuple[Any, int]] = [(data, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise EvidenceError(f"JSON has more than {MAX_NODES} values")
        if depth > MAX_DEPTH:
            raise EvidenceError(f"JSON nesting deeper than {MAX_DEPTH} levels")
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
        elif isinstance(value, str) and len(value) > MAX_STRING:
            raise EvidenceError(f"JSON string longer than {MAX_STRING} characters")


def parse_json(raw: bytes) -> Any:
    """Strict bounded JSON parsing; raises EvidenceError only."""
    if len(raw) > MAX_FILE_BYTES:
        raise EvidenceError(f"file exceeds the {MAX_FILE_BYTES} byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise EvidenceError("file is not valid UTF-8") from None
    try:
        data = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except EvidenceError:
        raise
    except RecursionError:
        raise EvidenceError(f"JSON nesting deeper than {MAX_DEPTH} levels") from None
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"not valid JSON (line {exc.lineno}, column {exc.colno})") from None
    except ValueError:
        raise EvidenceError("not valid JSON (number out of range)") from None
    _check_bounds(data)
    return data


# --------------------------------------------------------------------------- schema helpers


def _obj(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{where} must be an object")
    return value


def _arr(value: Any, where: str, limit: int = MAX_ITEMS) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceError(f"{where} must be a list")
    if len(value) > limit:
        raise EvidenceError(f"{where} has more than {limit} entries")
    return value


def _str(value: Any, where: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str):
        raise EvidenceError(f"{where} must be a string" + (" or null" if optional else ""))


def _int(value: Any, where: str, *, optional: bool = False, low: int = 0) -> None:
    if value is None and optional:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < low:
        raise EvidenceError(
            f"{where} must be an integer >= {low}" + (" or null" if optional else "")
        )


def _num(value: Any, where: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        raise EvidenceError(
            f"{where} must be a non-negative number" + (" or null" if optional else "")
        )


def _bool(value: Any, where: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, bool):
        raise EvidenceError(f"{where} must be a boolean" + (" or null" if optional else ""))


def _choice(value: Any, where: str, choices: tuple[str, ...], *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if value not in choices:
        raise EvidenceError(f"{where} must be one of {', '.join(choices)}")


def _strs(value: Any, where: str) -> None:
    for index, item in enumerate(_arr(value, where)):
        _str(item, f"{where}[{index}]")


def _schema(data: dict[str, Any], what: str) -> None:
    if data.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceError(f"{what} schema_version must be {SCHEMA_VERSION!r}")


def _counts(actual: list[str], declared: Any, choices: tuple[str, ...], where: str) -> None:
    declared = _obj(declared, where)
    counted = Counter(actual)
    for name, value in declared.items():
        if name not in choices:
            raise EvidenceError(f"{where} has an unknown category")
        _int(value, f"{where}.{name}")
    if any(declared.get(name, 0) != counted.get(name, 0) for name in choices):
        raise EvidenceError(f"{where} does not match the listed entries")


# --------------------------------------------------------------------------- per-file schemas

_ASSET_FIELDS = frozenset(f.name for f in fields(Asset))
_ASSET_REQUIRED = ("asset_id", "asset_type", "source")
_ASSET_TEXT = ("algorithm_family", "algorithm", "migration_status")
_ASSET_OPTIONAL_TEXT = (
    "parameter_set",
    "signature_algorithm",
    "tls_version",
    "cipher_suite",
    "negotiated_group",
    "certificate_subject",
    "issuer",
    "expiry",
    "policy_result",
)


def _asset(value: Any, where: str) -> None:
    asset = _obj(value, where)
    if set(asset) - _ASSET_FIELDS:
        raise EvidenceError(f"{where} has fields that are not part of the asset schema")
    for name in _ASSET_REQUIRED:
        _str(asset.get(name), f"{where}.{name}")
    for name in _ASSET_TEXT:
        if name in asset:
            _str(asset[name], f"{where}.{name}")
    for name in _ASSET_OPTIONAL_TEXT:
        _str(asset.get(name), f"{where}.{name}", optional=True)
    for name in ("key_size", "chain_length"):
        _int(asset.get(name), f"{where}.{name}", optional=True)
    _strs(asset.get("sans", []), f"{where}.sans")
    _obj(asset.get("evidence", {}), f"{where}.evidence")


def _discovery_errors(value: Any, where: str) -> None:
    for index, error in enumerate(_arr(value, where)):
        error = _obj(error, f"{where}[{index}]")
        for name in ("source", "code", "message"):
            _str(error.get(name), f"{where}[{index}].{name}")


def _assets(data: dict[str, Any]) -> None:
    assets = _arr(data.get("assets"), "assets")
    for index, asset in enumerate(assets):
        _asset(asset, f"assets[{index}]")
    ids = [a["asset_id"] for a in assets]
    if len(set(ids)) != len(ids):
        raise EvidenceError("assets contain duplicate asset_id values")
    _discovery_errors(data.get("errors", []), "errors")


def validate_inventory(data: Any) -> dict[str, Any]:
    data = _obj(data, "inventory")
    _schema(data, "inventory")
    _assets(data)
    return data


def validate_cbom(data: Any) -> dict[str, Any]:
    data = _obj(data, "cbom")
    if data.get("cbom_format") != cbom.CBOM_FORMAT or data.get("cbom_version") != cbom.CBOM_VERSION:
        raise EvidenceError(f"cbom must be {cbom.CBOM_FORMAT} version {cbom.CBOM_VERSION}")
    if data.get("inventory_schema_version") != SCHEMA_VERSION:
        raise EvidenceError(f"cbom inventory_schema_version must be {SCHEMA_VERSION!r}")
    _str(data.get("compliance"), "compliance")
    _assets(data)
    summary = _obj(data.get("summary"), "summary")
    _int(summary.get("asset_count"), "summary.asset_count")
    _int(summary.get("error_count"), "summary.error_count")
    if summary["asset_count"] != len(data["assets"]) or (
        summary["error_count"] != len(data.get("errors", []))
    ):
        raise EvidenceError("cbom summary counts do not match the listed assets/errors")
    return data


_EVIDENCE_STATUSES = ("complete", "missing", "unrecognized")


def validate_policy(data: Any) -> dict[str, Any]:
    data = _obj(data, "policy evaluation")
    _schema(data, "policy evaluation")
    for name in ("policy_id", "policy_digest", "evaluated_at"):
        _str(data.get(name), name)
    findings = _arr(data.get("findings"), "findings")
    for index, value in enumerate(findings):
        where = f"findings[{index}]"
        finding = _obj(value, where)
        for name in ("asset_id", "asset_type", "source", "current_algorithm"):
            _str(finding.get(name), f"{where}.{name}")
        _choice(finding.get("outcome"), f"{where}.outcome", policy.OUTCOMES)
        _choice(
            finding.get("known_outcome"), f"{where}.known_outcome", policy.OUTCOMES, optional=True
        )
        _choice(finding.get("evidence_status"), f"{where}.evidence_status", _EVIDENCE_STATUSES)
        _bool(finding.get("compliant"), f"{where}.compliant")
        _bool(finding.get("quantum_vulnerable"), f"{where}.quantum_vulnerable", optional=True)
        _str(finding.get("expiry_status"), f"{where}.expiry_status", optional=True)
        for name in (
            "quantum_vulnerable_usages",
            "rule_ids",
            "reasons",
            "migration_options",
            "recommended_tests",
        ):
            _strs(finding.get(name), f"{where}.{name}")
        if not finding["reasons"]:
            raise EvidenceError(f"{where}.reasons must explain the outcome")
        if finding["compliant"] != (finding["outcome"] not in policy.NON_COMPLIANT_OUTCOMES):
            raise EvidenceError(f"{where}.compliant contradicts its outcome")
    summary = _obj(data.get("summary"), "summary")
    _int(summary.get("total_assets"), "summary.total_assets")
    if summary["total_assets"] != len(findings):
        raise EvidenceError("summary.total_assets does not match the findings")
    _counts(
        [f["outcome"] for f in findings],
        summary.get("by_outcome"),
        policy.OUTCOMES,
        "summary.by_outcome",
    )
    for name in ("compliant", "evidence_incomplete", "quantum_vulnerable", "inventory_errors"):
        _int(summary.get(name), f"summary.{name}")
    return data


def validate_plan(data: Any) -> dict[str, Any]:
    data = _obj(data, "migration plan")
    _schema(data, "migration plan")
    for name in ("policy_id", "policy_digest", "profile", "generated_at"):
        _str(data.get(name), name)
    _choice(data.get("readiness"), "readiness", migration.READINESS)
    _strs(data.get("reasons"), "reasons")
    items = _arr(data.get("items"), "items")
    for index, value in enumerate(items):
        where = f"items[{index}]"
        item = _obj(value, where)
        for name in (
            "asset_id",
            "asset_type",
            "current_algorithm",
            "reason",
            "dependency",
            "recommended_test",
            "next_action",
        ):
            _str(item.get(name), f"{where}.{name}")
        _choice(item.get("outcome"), f"{where}.outcome", policy.OUTCOMES)
        _choice(item.get("evidence_status"), f"{where}.evidence_status", _EVIDENCE_STATUSES)
        _choice(item.get("priority"), f"{where}.priority", policy.PRIORITIES)
        _bool(item.get("ready"), f"{where}.ready")
        _str(item.get("blocker"), f"{where}.blocker", optional=True)
        _choice(
            item.get("blocker_kind"),
            f"{where}.blocker_kind",
            migration.BLOCKER_KINDS,
            optional=True,
        )
        if (item["blocker"] is None) != (item["blocker_kind"] is None):
            raise EvidenceError(f"{where} blocker and blocker_kind must be set together")
        if item["ready"] and item["blocker"] is not None:
            raise EvidenceError(f"{where} cannot be ready while blocked")
        _strs(item.get("migration_options"), f"{where}.migration_options")
    if data["readiness"] == "READY" and (not items or not all(i["ready"] for i in items)):
        raise EvidenceError("readiness READY contradicts items that are not ready")
    summary = _obj(data.get("summary"), "summary")
    for name in ("total_assets", "ready_assets", "inventory_errors"):
        _int(summary.get(name), f"summary.{name}")
    if summary["total_assets"] != len(items) or (
        summary["ready_assets"] != sum(1 for i in items if i["ready"])
    ):
        raise EvidenceError("plan summary counts do not match the items")
    _counts(
        [i["priority"] for i in items],
        summary.get("by_priority"),
        policy.PRIORITIES,
        "summary.by_priority",
    )
    lab = data.get("matrix")
    if lab is not None:
        lab = _obj(lab, "matrix")
        _arr(lab.get("rows"), "matrix.rows")
        for name in ("pq_key_establishment_rows", "pq_authentication_rows"):
            _int(lab.get(name), f"matrix.{name}")
        violations = lab.get("violations")
        if not isinstance(violations, int | list) or isinstance(violations, bool):
            raise EvidenceError("matrix.violations must be a count or list")
    footprint = _obj(data.get("footprint"), "footprint")
    _choice(footprint.get("status"), "footprint.status", ("measured", "unknown"))
    _str(footprint.get("statement"), "footprint.statement")
    _str(footprint.get("label"), "footprint.label", optional=True)
    _int(footprint.get("declared_budget_bytes"), "footprint.declared_budget_bytes", optional=True)
    _bool(
        footprint.get("within_declared_budget"), "footprint.within_declared_budget", optional=True
    )
    for index, m in enumerate(
        _arr(footprint.get("handshake_measurements"), "footprint.handshake_measurements")
    ):
        where = f"footprint.handshake_measurements[{index}]"
        m = _obj(m, where)
        _str(m.get("group_rule_id"), f"{where}.group_rule_id")
        _int(m.get("samples"), f"{where}.samples", low=1)
        for name in ("median_handshake_bytes", "min", "max"):
            _num(m.get(name), f"{where}.{name}")
    _arr(footprint.get("measured_sizes"), "footprint.measured_sizes")
    if footprint["status"] == "unknown" and footprint["handshake_measurements"]:
        raise EvidenceError("footprint status unknown contradicts its measurements")
    return data


_ROW_TEXT = (
    "negotiated_group",
    "negotiated_group_kind",
    "tls_version",
    "cipher_suite",
    "certificate_type",
    "certificate_signature_algorithm",
    "peer_signature_type",
    "failure_kind",
    "error_reason",
    "experiment",
    "server_profile",
    "server_group",
    "server_certificate_key",
    "server_credential_variant",
    "client_binary_version",
)
_ROW_INTS = (
    "certificate_der_bytes",
    "chain_der_bytes",
    "chain_length",
    "handshake_bytes_read",
    "handshake_bytes_written",
)


def validate_matrix(data: Any) -> dict[str, Any]:
    data = _obj(data, "matrix")
    _schema(data, "matrix")
    rows = _arr(data.get("rows"), "rows", limit=2000)
    for index, value in enumerate(rows):
        where = f"rows[{index}]"
        row = _obj(value, where)
        _str(row.get("client"), f"{where}.client")
        _str(row.get("server"), f"{where}.server")
        _choice(row.get("status"), f"{where}.status", tls.STATUSES)
        _bool(row.get("network_attempted", False), f"{where}.network_attempted")
        _bool(row.get("policy_pass"), f"{where}.policy_pass", optional=True)
        _strs(row.get("policy_reasons", []), f"{where}.policy_reasons")
        for name in _ROW_TEXT:
            _str(row.get(name), f"{where}.{name}", optional=True)
        for name in _ROW_INTS:
            _int(row.get(name), f"{where}.{name}", optional=True)
        _num(row.get("client_process_ms"), f"{where}.client_process_ms", optional=True)
        if row["status"] == tls.SUCCESS and not (
            row.get("negotiated_group") and row.get("tls_version")
        ):
            raise EvidenceError(f"{where} SUCCESS without a negotiated group and TLS version")
        if row["status"] == tls.UNSUPPORTED and row.get("network_attempted"):
            raise EvidenceError(f"{where} UNSUPPORTED rows must not attempt the network")
        if row.get("policy_pass") is True and not row.get("negotiated_group"):
            raise EvidenceError(f"{where} cannot pass policy without a negotiated connection")
    environment = _obj(data.get("environment", {}), "environment")
    for name in (
        "latency_semantics",
        "standardization",
        "generated_at",
        "platform",
        "legacy_client",
        "hostname",
    ):
        _str(environment.get(name), f"environment.{name}", optional=True)
    _obj(environment.get("openssl", {}), "environment.openssl")
    _obj(data.get("policy", {}), "policy")
    return data


_BENCH_KINDS = ("baseline", "signature", "kem", "tls_handshake")


def validate_benchmark(data: Any) -> dict[str, Any]:
    try:
        benchmark.validate_results(data)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise EvidenceError(f"benchmark validation failed: {exc}") from None
    method = data["methodology"]
    for name in ("timing_clock", "p95_method", "operation_scope"):
        _str(method.get(name), f"methodology.{name}", optional=True)
    _strs(method.get("caveats", []), "methodology.caveats")
    for index, entry in enumerate(data["results"]):
        where = f"results[{index}]"
        _str(entry.get("id"), f"{where}.id")
        _choice(entry.get("kind"), f"{where}.kind", _BENCH_KINDS)
        _str(entry.get("algorithm"), f"{where}.algorithm", optional=True)
        _str(entry.get("reason"), f"{where}.reason", optional=True)
        sizes = _obj(entry.get("sizes", {}), f"{where}.sizes")
        for name, size in sizes.items():
            if isinstance(size, dict):
                _int(size.get("min"), f"{where}.sizes.{name}.min")
                _int(size.get("max"), f"{where}.sizes.{name}.max")
            elif not isinstance(size, str):
                _int(size, f"{where}.sizes.{name}")
    environment = data["environment"]
    for name in ("host", "os", "python", "container"):
        _obj(environment.get(name), f"environment.{name}")
    return data


def validate_capabilities(data: Any) -> dict[str, Any]:
    data = _obj(data, "capabilities")
    _schema(data, "capabilities")
    ossl = _obj(data.get("openssl"), "openssl")
    _str(ossl.get("version"), "openssl.version")
    _str(ossl.get("version_number"), "openssl.version_number", optional=True)
    _bool(data.get("oqs_provider_loaded"), "oqs_provider_loaded")
    for index, provider in enumerate(_arr(data.get("providers"), "providers")):
        for name, value in _obj(provider, f"providers[{index}]").items():
            _str(value, f"providers[{index}].{name}")
    _strs(data.get("tls13_groups"), "tls13_groups")
    _strs(data.get("unavailable_queries", []), "unavailable_queries")
    standardized = _obj(data.get("standardized"), "standardized")
    for name in ("ml_kem", "ml_dsa", "slh_dsa"):
        _strs(standardized.get(name), f"standardized.{name}")
    classes = _obj(data.get("tls_group_classes"), "tls_group_classes")
    for name in ("classical", "hybrid", "pqc"):
        _strs(classes.get(name), f"tls_group_classes.{name}")
    for name, value in _obj(data.get("x509"), "x509").items():
        _bool(_obj(value, f"x509.{name}").get("supported"), f"x509.{name}.supported")
    for name, value in _obj(data.get("profiles"), "profiles").items():
        profile = _obj(value, f"profiles.{name}")
        _bool(profile.get("supported"), f"profiles.{name}.supported")
        for key in ("group", "group_kind", "certificate_key", "authentication"):
            _str(profile.get(key), f"profiles.{name}.{key}", optional=True)
        _strs(profile.get("missing", []), f"profiles.{name}.missing")
        if profile["supported"] and profile.get("missing"):
            raise EvidenceError(f"profiles.{name} is supported but lists missing support")
    _str(data.get("notes"), "notes", optional=True)
    return data


VALIDATORS: dict[str, Callable[[Any], dict[str, Any]]] = {
    "inventory": validate_inventory,
    "policy": validate_policy,
    "migration_plan": validate_plan,
    "matrix": validate_matrix,
    "benchmark": validate_benchmark,
    "capabilities": validate_capabilities,
    "cbom": validate_cbom,
}


# --------------------------------------------------------------------------- loading


def load_file(key: str, path: Path) -> Evidence:
    filename = EVIDENCE_FILES[key]
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return Evidence(key, filename, MISSING)
    except OSError as exc:
        return Evidence(key, filename, INVALID, error=f"cannot stat file ({exc.strerror})")
    if stat.S_ISLNK(info.st_mode):
        return Evidence(key, filename, INVALID, error="symbolic links are not followed")
    try:
        raw = _read_bounded(path)
        digest, size = hashlib.sha256(raw).hexdigest(), len(raw)
        data = VALIDATORS[key](parse_json(raw))
    except EvidenceError as exc:
        return Evidence(key, filename, INVALID, error=str(exc))
    except (TypeError, KeyError, AttributeError, IndexError):
        return Evidence(key, filename, INVALID, error="unexpected structure for this schema")
    return Evidence(key, filename, LOADED, data=data, sha256=digest, size_bytes=size)


def load_evidence(results_dir: Path) -> dict[str, Evidence]:
    """Load every known evidence file from results_dir (which must be a real directory)."""
    results_dir = Path(results_dir)
    try:
        info = os.lstat(results_dir)
    except OSError:
        raise EvidenceError("results directory does not exist") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise EvidenceError("results directory must be a directory (symlinks are not followed)")
    return {key: load_file(key, results_dir / name) for key, name in EVIDENCE_FILES.items()}
