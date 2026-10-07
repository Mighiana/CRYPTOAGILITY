"""Strict, rule-driven crypto policy loading and explainable, fail-closed evaluation.

All algorithm knowledge (names, thresholds, outcomes, reasons, migration options) lives in the
policy file. This module only validates the schema and applies the rules; it contains no
algorithm-specific conclusions of its own.

Outcomes, ordered from least to most severe:

- APPROVED: meets the policy's target state.
- ACCEPTABLE_FOR_NOW: permitted today, but long-term post-quantum migration planning is required.
- EXPERIMENTAL: laboratory integration (for example PQ TLS groups or PQ X.509); not a target state.
- MIGRATION_REQUIRED: the policy requires a migration action (including negotiation violations).
- DEPRECATED: below the policy minimum; replace.
- UNSUPPORTED: unknown, unrecognised, conflicting or missing evidence, or explicitly unsupported;
  evaluation fails closed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from cryptoagility.models import SCHEMA_VERSION, Asset, Inventory

OUTCOMES = (
    "APPROVED",
    "ACCEPTABLE_FOR_NOW",
    "EXPERIMENTAL",
    "MIGRATION_REQUIRED",
    "DEPRECATED",
    "UNSUPPORTED",
)
SEVERITY = {outcome: rank for rank, outcome in enumerate(OUTCOMES)}
NON_COMPLIANT_OUTCOMES = frozenset({"MIGRATION_REQUIRED", "DEPRECATED", "UNSUPPORTED"})
PRIORITIES = ("IMMEDIATE", "SHORT_TERM", "MEDIUM_TERM", "MONITOR", "UNKNOWN")
EVIDENCE_FIELDS = (
    "algorithm",
    "signature_algorithm",
    "expiry",
    "tls_version",
    "negotiated_group",
    "cipher_suite",
)
FAMILIES = ("classical", "post_quantum", "hybrid")
USAGES = ("signature", "key_establishment")
DIFFICULTIES = ("low", "medium", "high")
SUCCESS_STATUSES = frozenset({"SUCCESS", "PASS"})
EVIDENCE_COMPLETE, EVIDENCE_MISSING, EVIDENCE_UNRECOGNIZED = "complete", "missing", "unrecognized"

MAX_POLICY_BYTES = 256 * 1024
MAX_TEXT = 600
MAX_NAME = 128
MAX_LIST = 64
MAX_RULES = 256
MAX_OBSERVED = 256
MAX_KEY_BITS = 65536
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
# Policies must not use misleading security language (see docs/STANDARDS.md).
_BANNED_TERMS = re.compile(
    r"\b(broken|quantum[- ]proof|unbreakable|military[- ]grade|uncrackable)\b", re.IGNORECASE
)


class PolicyError(ValueError):
    """Raised for any invalid, unsafe or ambiguous policy input."""


# --------------------------------------------------------------------------- loading


class _StrictLoader(yaml.SafeLoader):
    """Safe loader that also rejects aliases (expansion bombs), merge keys and duplicate keys."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise PolicyError("YAML aliases are not permitted in policy files")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise PolicyError("YAML merge keys are not permitted in policy files")
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise PolicyError("Policy mapping keys must be strings")
            if key in seen:
                raise PolicyError(f"Duplicate policy key {_short(key)}")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def load_policy(path: Path) -> dict[str, Any]:
    """Load and strictly validate a YAML policy file; returns a validated plain dict."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise PolicyError("Policy must be a regular non-symlink file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_POLICY_BYTES + 1)
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError("Policy file exceeds 256 KiB limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError("Policy file must be UTF-8") from exc
    try:
        data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass
    except PolicyError:
        raise
    except (yaml.YAMLError, RecursionError) as exc:
        raise PolicyError("Policy file is not valid single-document safe YAML") from exc
    return validate_policy(data)


# --------------------------------------------------------------------------- validation


def _short(value: Any, limit: int = 60) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _mapping(
    value: Any, where: str, required: tuple[str, ...], optional: tuple[str, ...] = ()
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be a mapping")
    unknown = [key for key in value if key not in required and key not in optional]
    if unknown:
        raise PolicyError(f"{where} has unknown keys: {', '.join(_short(k) for k in unknown[:5])}")
    missing = [key for key in required if key not in value]
    if missing:
        raise PolicyError(f"{where} is missing keys: {', '.join(missing)}")
    return value


def _text(value: Any, where: str, max_len: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_len:
        raise PolicyError(f"{where} must be a non-empty string of at most {max_len} characters")
    if any(not ch.isprintable() and ch not in "\n" for ch in value):
        raise PolicyError(f"{where} contains control characters")
    if _BANNED_TERMS.search(value):
        raise PolicyError(f"{where} uses misleading security language")
    return value


def _text_list(
    value: Any, where: str, *, min_items: int = 1, max_len: int = MAX_TEXT
) -> list[str]:
    if not isinstance(value, list) or not min_items <= len(value) <= MAX_LIST:
        raise PolicyError(f"{where} must be a list of {min_items}-{MAX_LIST} strings")
    return [_text(item, f"{where}[{index}]", max_len) for index, item in enumerate(value)]


def _int(value: Any, where: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise PolicyError(f"{where} must be an integer between {low} and {high}")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{where} must be a boolean")
    return value


def _choice(value: Any, where: str, choices: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise PolicyError(f"{where} must be one of {', '.join(choices)}")
    return value


def _identifier(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.match(value):
        raise PolicyError(f"{where} must be a lowercase identifier")
    return value


def normalize_name(value: str) -> str:
    """Case/separator-insensitive key used to match observed names against policy names."""
    return re.sub(r"[\s_\-]", "", value.casefold())


def _decision(value: Any, where: str, *, non_compliant: bool = False) -> dict[str, Any]:
    _mapping(value, where, ("outcome", "reason", "migration_options"))
    outcome = _choice(value["outcome"], f"{where}.outcome", OUTCOMES)
    if non_compliant and outcome not in NON_COMPLIANT_OUTCOMES:
        raise PolicyError(f"{where}.outcome must be a non-compliant outcome (fails closed)")
    _text(value["reason"], f"{where}.reason")
    _text_list(value["migration_options"], f"{where}.migration_options")
    return value


class _Names:
    """Tracks normalised names in one rule table so a name never matches two rules."""

    def __init__(self, table: str) -> None:
        self.table = table
        self.seen: dict[str, str] = {}

    def add(self, names: list[str], owner: str) -> None:
        for name in names:
            key = normalize_name(name)
            if not key:
                raise PolicyError(f"{self.table}: empty name for {owner}")
            if key in self.seen and self.seen[key] != owner:
                raise PolicyError(f"{self.table}: name {_short(name)} is ambiguous")
            self.seen[key] = owner


def _rule(
    value: Any,
    where: str,
    *,
    names: _Names,
    rule_ids: set[str],
    asset_types: set[str],
    crypto: bool,
    sized: bool,
) -> None:
    required: tuple[str, ...] = ("id", "names", "migration_options")
    optional: tuple[str, ...] = ("standard", "recommended_test", "contexts", "outcome", "reason")
    if crypto:
        required += ("family", "quantum_vulnerable")
    if sized:
        required += ("usage",)
        optional += ("key_size", "parameter_sets")
    _mapping(value, where, required, optional)
    rule_id = _identifier(value["id"], f"{where}.id")
    if rule_id in rule_ids:
        raise PolicyError(f"{where}: duplicate rule id {rule_id}")
    rule_ids.add(rule_id)
    names.add(_text_list(value["names"], f"{where}.names", max_len=MAX_NAME), rule_id)
    _text_list(value["migration_options"], f"{where}.migration_options")
    for key in ("standard", "recommended_test"):
        if key in value:
            _text(value[key], f"{where}.{key}")
    if crypto:
        _choice(value["family"], f"{where}.family", FAMILIES)
        _bool(value["quantum_vulnerable"], f"{where}.quantum_vulnerable")
    if sized:
        usage = _text_list(value["usage"], f"{where}.usage")
        for item in usage:
            _choice(item, f"{where}.usage", USAGES)
    modes = [key for key in ("outcome", "key_size", "parameter_sets") if key in value]
    if len(modes) != 1:
        raise PolicyError(f"{where} must define exactly one of outcome, key_size, parameter_sets")
    if modes[0] == "outcome":
        _choice(value["outcome"], f"{where}.outcome", OUTCOMES)
        _text(value.get("reason"), f"{where}.reason")
    elif "reason" in value:
        raise PolicyError(f"{where}.reason belongs to bands or parameter sets")
    if "key_size" in value:
        _mapping(value["key_size"], f"{where}.key_size", ("bands",))
        bands = value["key_size"]["bands"]
        if not isinstance(bands, list) or not 1 <= len(bands) <= MAX_LIST:
            raise PolicyError(f"{where}.key_size.bands must be a non-empty list")
        previous = MAX_KEY_BITS + 1
        for index, band in enumerate(bands):
            band_where = f"{where}.key_size.bands[{index}]"
            _mapping(band, band_where, ("min_bits", "outcome", "reason"))
            bits = _int(band["min_bits"], f"{band_where}.min_bits", 0, MAX_KEY_BITS)
            if bits >= previous:
                raise PolicyError(f"{where}.key_size.bands must have descending min_bits")
            previous = bits
            _choice(band["outcome"], f"{band_where}.outcome", OUTCOMES)
            _text(band["reason"], f"{band_where}.reason")
        if previous != 0:
            raise PolicyError(f"{where}.key_size.bands must end with min_bits 0 (fail closed)")
    if "parameter_sets" in value:
        sets = value["parameter_sets"]
        if not isinstance(sets, list) or not 1 <= len(sets) <= MAX_LIST:
            raise PolicyError(f"{where}.parameter_sets must be a non-empty list")
        for index, entry in enumerate(sets):
            set_where = f"{where}.parameter_sets[{index}]"
            _mapping(entry, set_where, ("names", "outcome", "reason"))
            names.add(_text_list(entry["names"], f"{set_where}.names", max_len=MAX_NAME), rule_id)
            _choice(entry["outcome"], f"{set_where}.outcome", OUTCOMES)
            _text(entry["reason"], f"{set_where}.reason")
    if "contexts" in value:
        contexts = value["contexts"]
        if not isinstance(contexts, dict) or not contexts:
            raise PolicyError(f"{where}.contexts must be a non-empty mapping")
        for type_name, context in contexts.items():
            if type_name not in asset_types:
                raise PolicyError(f"{where}.contexts references unknown asset type")
            ctx_where = f"{where}.contexts.{type_name}"
            _mapping(context, ctx_where, ("outcome", "reason"))
            _choice(context["outcome"], f"{ctx_where}.outcome", OUTCOMES)
            _text(context["reason"], f"{ctx_where}.reason")


def _rule_table(
    value: Any, where: str, rule_ids: set[str], asset_types: set[str], *, crypto: bool,
    sized: bool = False,
) -> _Names:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_RULES:
        raise PolicyError(f"{where} must be a list of 1-{MAX_RULES} rules")
    names = _Names(where)
    for index, rule in enumerate(value):
        _rule(rule, f"{where}[{index}]", names=names, rule_ids=rule_ids,
              asset_types=asset_types, crypto=crypto, sized=sized)
    return names


def validate_policy(data: Any) -> dict[str, Any]:
    """Validate a policy mapping against the strict schema and return a deep copy.

    Raises PolicyError on unknown keys, wrong types, ambiguous names, misleading language or any
    configuration that would let unknown evidence or negotiation violations pass.
    """
    top = _mapping(data, "policy", (
        "schema_version", "policy_id", "title", "description", "profile", "compliant_outcomes",
        "unknown_evidence", "asset_types", "algorithms", "signature_algorithms", "tls",
        "certificates", "planning",
    ))
    if top["schema_version"] != SCHEMA_VERSION:
        raise PolicyError(f"policy.schema_version must be {SCHEMA_VERSION!r}")
    _identifier(top["policy_id"], "policy.policy_id")
    _text(top["title"], "policy.title")
    _text(top["description"], "policy.description", 2000)

    profile = _mapping(top["profile"], "policy.profile", (
        "name", "description", "long_confidentiality_years", "long_system_lifetime_years",
        "escalate_update_difficulty", "require_footprint_evidence",
    ))
    _identifier(profile["name"], "policy.profile.name")
    _text(profile["description"], "policy.profile.description", 2000)
    _int(profile["long_confidentiality_years"], "policy.profile.long_confidentiality_years", 1, 100)
    _int(profile["long_system_lifetime_years"], "policy.profile.long_system_lifetime_years", 1, 100)
    difficulties = profile["escalate_update_difficulty"]
    if not isinstance(difficulties, list) or len(difficulties) > len(DIFFICULTIES):
        raise PolicyError("policy.profile.escalate_update_difficulty must be a list")
    for item in difficulties:
        _choice(item, "policy.profile.escalate_update_difficulty", DIFFICULTIES)
    _bool(profile["require_footprint_evidence"], "policy.profile.require_footprint_evidence")

    compliant = top["compliant_outcomes"]
    if not isinstance(compliant, list) or "APPROVED" not in compliant:
        raise PolicyError("policy.compliant_outcomes must be a list including APPROVED")
    for item in compliant:
        _choice(item, "policy.compliant_outcomes", OUTCOMES)
        if item in NON_COMPLIANT_OUTCOMES:
            raise PolicyError("policy.compliant_outcomes cannot include non-compliant outcomes")

    unknown = _mapping(top["unknown_evidence"], "policy.unknown_evidence",
                       ("reason", "migration_options", "recommended_test"))
    _text(unknown["reason"], "policy.unknown_evidence.reason")
    _text_list(unknown["migration_options"], "policy.unknown_evidence.migration_options")
    _text(unknown["recommended_test"], "policy.unknown_evidence.recommended_test")

    types = top["asset_types"]
    if not isinstance(types, dict) or not 1 <= len(types) <= MAX_LIST:
        raise PolicyError("policy.asset_types must be a non-empty mapping")
    aliases = _Names("policy.asset_types")
    for type_name, spec in types.items():
        where = f"policy.asset_types.{_identifier(type_name, 'policy.asset_types key')}"
        _mapping(spec, where, ("aliases", "required_evidence", "dependency", "recommended_test"))
        aliases.add([type_name, *_text_list(spec["aliases"], f"{where}.aliases",
                                            max_len=MAX_NAME)], type_name)
        required = spec["required_evidence"]
        if not isinstance(required, list) or len(required) > len(EVIDENCE_FIELDS):
            raise PolicyError(f"{where}.required_evidence must be a list")
        for item in required:
            _choice(item, f"{where}.required_evidence", EVIDENCE_FIELDS)
        _text(spec["dependency"], f"{where}.dependency")
        _text(spec["recommended_test"], f"{where}.recommended_test")
    type_names = set(types)

    rule_ids: set[str] = set()
    _rule_table(top["algorithms"], "policy.algorithms", rule_ids, type_names,
                crypto=True, sized=True)
    _rule_table(top["signature_algorithms"], "policy.signature_algorithms", rule_ids,
                type_names, crypto=True)

    tls = _mapping(top["tls"], "policy.tls", (
        "minimum_version", "versions", "below_minimum", "groups", "required_groups",
        "negotiation_violation", "cipher_suites",
    ))
    version_names = _rule_table(tls["versions"], "policy.tls.versions", rule_ids, type_names,
                                crypto=False)
    minimum = _text(tls["minimum_version"], "policy.tls.minimum_version", MAX_NAME)
    if normalize_name(minimum) not in version_names.seen:
        raise PolicyError("policy.tls.minimum_version must name a listed version")
    _decision(tls["below_minimum"], "policy.tls.below_minimum", non_compliant=True)
    group_names = _rule_table(tls["groups"], "policy.tls.groups", rule_ids, type_names,
                              crypto=True)
    required_groups = tls["required_groups"]
    if not isinstance(required_groups, list) or len(required_groups) > MAX_LIST:
        raise PolicyError("policy.tls.required_groups must be a list")
    for item in required_groups:
        if normalize_name(_text(item, "policy.tls.required_groups", MAX_NAME)) not in (
            group_names.seen
        ):
            raise PolicyError("policy.tls.required_groups must name listed groups")
    _decision(tls["negotiation_violation"], "policy.tls.negotiation_violation",
              non_compliant=True)
    _rule_table(tls["cipher_suites"], "policy.tls.cipher_suites", rule_ids, type_names,
                crypto=False)

    certs = _mapping(top["certificates"], "policy.certificates",
                     ("renewal_window_days", "valid", "expiring", "expired"))
    _int(certs["renewal_window_days"], "policy.certificates.renewal_window_days", 0, 3650)
    _decision(certs["valid"], "policy.certificates.valid")
    _decision(certs["expiring"], "policy.certificates.expiring")
    _decision(certs["expired"], "policy.certificates.expired", non_compliant=True)

    planning = _mapping(top["planning"], "policy.planning", (
        "outcome_priority", "ready_outcomes", "next_actions", "unknown_next_action",
    ))
    priority = _mapping(planning["outcome_priority"], "policy.planning.outcome_priority", OUTCOMES)
    for outcome, value in priority.items():
        _choice(value, f"policy.planning.outcome_priority.{outcome}", PRIORITIES[:-1])
    ready = planning["ready_outcomes"]
    if not isinstance(ready, list) or not ready:
        raise PolicyError("policy.planning.ready_outcomes must be a non-empty list")
    for item in ready:
        if item not in compliant:
            raise PolicyError("policy.planning.ready_outcomes must be compliant outcomes")
    actions = _mapping(planning["next_actions"], "policy.planning.next_actions", OUTCOMES)
    for outcome, value in actions.items():
        _text(value, f"policy.planning.next_actions.{outcome}")
    _text(planning["unknown_next_action"], "policy.planning.unknown_next_action")
    return copy.deepcopy(top)


def policy_digest(policy: dict[str, Any]) -> str:
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


# --------------------------------------------------------------------------- rule index


@dataclass
class _Match:
    rule: dict[str, Any]
    parameter_set: dict[str, Any] | None = None


class _Index:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        self.asset_types: dict[str, str] = {}
        for type_name, spec in policy["asset_types"].items():
            for alias in [type_name, *spec["aliases"]]:
                self.asset_types[normalize_name(alias)] = type_name
        self.tables: dict[str, dict[str, _Match]] = {
            "algorithms": self._table(policy["algorithms"]),
            "signature_algorithms": self._table(policy["signature_algorithms"]),
            "versions": self._table(policy["tls"]["versions"]),
            "groups": self._table(policy["tls"]["groups"]),
            "cipher_suites": self._table(policy["tls"]["cipher_suites"]),
        }
        self.version_rank = {
            rule["id"]: rank for rank, rule in enumerate(policy["tls"]["versions"])
        }
        self.minimum_rank = self.version_rank[
            self.tables["versions"][normalize_name(policy["tls"]["minimum_version"])].rule["id"]
        ]
        self.required_groups = [
            self.tables["groups"][normalize_name(name)].rule["id"]
            for name in policy["tls"]["required_groups"]
        ]

    @staticmethod
    def _table(rules: list[dict[str, Any]]) -> dict[str, _Match]:
        table: dict[str, _Match] = {}
        for rule in rules:
            for name in rule["names"]:
                table[normalize_name(name)] = _Match(rule)
            for entry in rule.get("parameter_sets", []):
                for name in entry["names"]:
                    table[normalize_name(name)] = _Match(rule, entry)
        return table

    def lookup(self, table: str, name: str) -> _Match | None:
        return self.tables[table].get(normalize_name(name))


# --------------------------------------------------------------------------- evaluation

_INVALID = object()


def _observed(value: Any) -> str | object | None:
    """Return a usable observed string, None when absent, or _INVALID for unusable input."""
    if value is None:
        return None
    if not isinstance(value, str):
        return _INVALID
    stripped = value.strip()
    if not stripped or stripped.casefold() == "unknown":
        return None
    if len(stripped) > MAX_OBSERVED or not stripped.isprintable():
        return _INVALID
    return stripped


def _display(value: Any) -> str:
    text = value if isinstance(value, str) else repr(value)
    text = "".join(ch if ch.isprintable() else "?" for ch in text)
    return text if len(text) <= 80 else text[:77] + "..."


@dataclass
class _Check:
    check: str
    observed: str
    outcome: str
    reason: str
    evidence: str = EVIDENCE_COMPLETE
    rule_id: str | None = None
    migration_options: list[str] = field(default_factory=list)
    recommended_test: str | None = None
    quantum_vulnerable: bool | None = None
    usages: tuple[str, ...] = ()
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "rule_id": self.rule_id,
            "observed": self.observed,
            "outcome": self.outcome,
            "evidence": self.evidence,
            "reason": self.reason,
        }


class PolicyEngine:
    """A validated policy plus rule index; reuse it to evaluate many assets or matrix rows."""

    def __init__(self, policy: dict[str, Any], *, now: datetime | None = None) -> None:
        self.policy = validate_policy(policy)
        self.index = _Index(self.policy)
        self.now = _now(now)
        self.digest = policy_digest(self.policy)

    def classify(self, table: str, name: Any) -> dict[str, Any] | None:
        """Look up an observed name in a rule table (algorithms, signature_algorithms,
        versions, groups, cipher_suites); None when the policy does not recognise it."""
        if table not in self.index.tables:
            raise PolicyError("Unknown policy table")
        observed = _observed(name)
        if not isinstance(observed, str):
            return None
        match = self.index.lookup(table, observed)
        if match is None:
            return None
        return {
            "rule_id": match.rule["id"],
            "family": match.rule.get("family"),
            "quantum_vulnerable": match.rule.get("quantum_vulnerable"),
            "parameter_set": match.parameter_set["names"][0] if match.parameter_set else None,
        }

    def unknown(self, check: str, observed: str, why: str, evidence: str) -> _Check:
        spec = self.policy["unknown_evidence"]
        return _Check(
            check=check, observed=observed, outcome="UNSUPPORTED", evidence=evidence,
            reason=f"{check}: {why}. {spec['reason']}",
            migration_options=list(spec["migration_options"]),
            recommended_test=spec["recommended_test"],
        )

    def decision(self, check: str, observed: str, spec: dict[str, Any], detail: str,
                 rule_id: str | None = None, state: str | None = None) -> _Check:
        return _Check(
            check=check, observed=observed, outcome=spec["outcome"], rule_id=rule_id,
            reason=f"{check}: {detail}. {spec['reason']}",
            migration_options=list(spec["migration_options"]), detail=state,
        )

    def rule_check(self, check: str, observed: str, match: _Match, outcome: str,
                   reason: str, detail: str) -> _Check:
        rule = match.rule
        standard = f" Reference: {rule['standard']}." if "standard" in rule else ""
        usages = tuple(rule.get("usage", ("key_establishment",) if check == "negotiated_group"
                                     else ("signature",) if check == "signature_algorithm"
                                     else ()))
        return _Check(
            check=check, observed=observed, outcome=outcome, rule_id=rule["id"],
            reason=f"{check}: observed {detail}; rule {rule['id']}: {reason}{standard}",
            migration_options=list(rule["migration_options"]),
            recommended_test=rule.get("recommended_test"),
            quantum_vulnerable=rule.get("quantum_vulnerable"), usages=usages,
        )

    def contexts(self, check: _Check, match: _Match, type_name: str | None) -> list[_Check]:
        context = match.rule.get("contexts", {}).get(type_name or "")
        if not context:
            return [check]
        extra = _Check(
            check=f"{check.check}_context", observed=f"{check.observed} in {type_name}",
            outcome=context["outcome"], rule_id=match.rule["id"],
            reason=f"{check.check}: {type_name} context; rule {match.rule['id']}: "
                   f"{context['reason']}",
            migration_options=list(match.rule["migration_options"]),
            recommended_test=match.rule.get("recommended_test"),
            quantum_vulnerable=check.quantum_vulnerable, usages=check.usages,
        )
        return [check, extra]

    # ---- individual checks

    def algorithm(self, asset: Asset, name: str, type_name: str | None) -> list[_Check]:
        match = self.index.lookup("algorithms", name)
        if match is None:
            return [self.unknown("algorithm", name, f"algorithm {_display(name)} is not "
                                 "recognised by this policy", EVIDENCE_UNRECOGNIZED)]
        rule = match.rule
        if "outcome" in rule:
            check = self.rule_check("algorithm", name, match, rule["outcome"], rule["reason"],
                                    _display(name))
            return self.contexts(check, match, type_name)
        if "key_size" in rule:
            bits = asset.key_size
            if isinstance(bits, bool) or not isinstance(bits, int) or not 0 < bits <= MAX_KEY_BITS:
                why = f"rule {rule['id']} requires a valid key_size for {_display(name)}"
                return [self.unknown("key_size", _display(bits), why, EVIDENCE_MISSING)]
            band = next(b for b in rule["key_size"]["bands"] if bits >= b["min_bits"])
            check = self.rule_check(
                "algorithm", f"{name} {bits} bits", match, band["outcome"], band["reason"],
                f"{_display(name)} with key_size={bits} (band min_bits={band['min_bits']})",
            )
            return self.contexts(check, match, type_name)
        observed_set = _observed(asset.parameter_set)
        if observed_set is _INVALID:
            return [self.unknown("parameter_set", _display(asset.parameter_set),
                                 "parameter_set has an invalid value", EVIDENCE_UNRECOGNIZED)]
        selected = match.parameter_set
        if isinstance(observed_set, str):
            set_match = self.index.lookup("algorithms", observed_set)
            if set_match is None or set_match.rule is not rule or set_match.parameter_set is None:
                return [self.unknown(
                    "parameter_set", observed_set,
                    f"parameter set {_display(observed_set)} is not listed under rule "
                    f"{rule['id']}", EVIDENCE_UNRECOGNIZED)]
            if selected is not None and selected is not set_match.parameter_set:
                return [self.unknown(
                    "parameter_set", f"{name} / {observed_set}",
                    "algorithm and parameter_set evidence conflict", EVIDENCE_UNRECOGNIZED)]
            selected = set_match.parameter_set
        if selected is None:
            return [self.unknown("parameter_set", "absent",
                                 f"rule {rule['id']} requires a parameter set for "
                                 f"{_display(name)}", EVIDENCE_MISSING)]
        label = selected["names"][0]
        check = self.rule_check("algorithm", label, match, selected["outcome"],
                                selected["reason"], f"{_display(name)} parameter set {label}")
        return self.contexts(check, match, type_name)

    def table_check(self, check: str, table: str, name: str,
                    type_name: str | None) -> list[_Check]:
        match = self.index.lookup(table, name)
        if match is None:
            return [self.unknown(check, name, f"{check} {_display(name)} is not recognised by "
                                 "this policy", EVIDENCE_UNRECOGNIZED)]
        result = self.rule_check(check, name, match, match.rule["outcome"], match.rule["reason"],
                                 _display(name))
        return self.contexts(result, match, type_name)

    def tls_version(self, name: str, type_name: str | None) -> list[_Check]:
        checks = self.table_check("tls_version", "versions", name, type_name)
        match = self.index.lookup("versions", name)
        if match and self.index.version_rank[match.rule["id"]] < self.index.minimum_rank:
            minimum = self.policy["tls"]["minimum_version"]
            checks.append(self.decision("tls_version", name, self.policy["tls"]["below_minimum"],
                                        f"{_display(name)} is below policy minimum {minimum}",
                                        match.rule["id"]))
        return checks

    def group(self, name: str, requested: Any, type_name: str | None) -> list[_Check]:
        checks = self.table_check("negotiated_group", "groups", name, type_name)
        match = self.index.lookup("groups", name)
        violation = self.policy["tls"]["negotiation_violation"]
        required = self.index.required_groups
        if match and required and match.rule["id"] not in required:
            names = ", ".join(self.policy["tls"]["required_groups"])
            checks.append(self.decision(
                "required_group", name, violation,
                f"negotiated {_display(name)} but policy requires one of [{names}]; a "
                "successful handshake is not policy compliance", match.rule["id"]))
        requested_name = _observed(requested)
        if requested_name is _INVALID:
            checks.append(self.unknown("requested_group", _display(requested),
                                       "requested_group has an invalid value",
                                       EVIDENCE_UNRECOGNIZED))
        elif isinstance(requested_name, str):
            requested_match = self.index.lookup("groups", requested_name)
            if requested_match is None:
                checks.append(self.unknown("requested_group", requested_name,
                                           "requested group is not recognised by this policy",
                                           EVIDENCE_UNRECOGNIZED))
            elif match is not None and requested_match.rule is not match.rule:
                checks.append(self.decision(
                    "downgrade", f"{requested_name} -> {name}", violation,
                    f"requested {_display(requested_name)} but negotiated {_display(name)}; "
                    "treated as a downgrade, not silently accepted", match.rule["id"]))
        return checks

    def expiry(self, value: str) -> list[_Check]:
        try:
            expires = datetime.fromisoformat(value)
        except ValueError:
            return [self.unknown("expiry", value, "expiry is not an ISO 8601 timestamp",
                                 EVIDENCE_UNRECOGNIZED)]
        note = ""
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
            note = " (no timezone; interpreted as UTC)"
        certs = self.policy["certificates"]
        remaining = (expires - self.now).total_seconds() / 86400
        if remaining <= 0:
            return [self.decision("expiry", value, certs["expired"],
                                  f"certificate expired at {expires.isoformat()}{note}",
                                  state="expired")]
        if remaining <= certs["renewal_window_days"]:
            return [self.decision(
                "expiry", value, certs["expiring"],
                f"certificate expires at {expires.isoformat()}{note}, within the "
                f"{certs['renewal_window_days']}-day renewal window", state="expiring")]
        return [self.decision("expiry", value, certs["valid"],
                              f"certificate valid until {expires.isoformat()}{note}",
                              state="valid")]

    # ---- assets

    def asset(self, asset: Asset) -> dict[str, Any]:
        checks: list[_Check] = []
        raw_type = _observed(asset.asset_type)
        type_name = (self.index.asset_types.get(normalize_name(raw_type))
                     if isinstance(raw_type, str) else None)
        if type_name is None:
            checks.append(self.unknown("asset_type", _display(asset.asset_type),
                                       "asset type is not recognised by this policy",
                                       EVIDENCE_UNRECOGNIZED))
            required: set[str] = set()
        else:
            required = set(self.policy["asset_types"][type_name]["required_evidence"])
        values = {name: _observed(getattr(asset, name, None)) for name in EVIDENCE_FIELDS}
        for name in EVIDENCE_FIELDS:
            value = values[name]
            if value is _INVALID:
                checks.append(self.unknown(name, _display(getattr(asset, name)),
                                           f"{name} has an invalid value", EVIDENCE_UNRECOGNIZED))
            elif value is None:
                if name in required:
                    checks.append(self.unknown(name, "absent", f"{name} evidence is required "
                                               f"for {type_name} assets", EVIDENCE_MISSING))
            elif isinstance(value, str):
                checks.extend(self._field(asset, name, value, type_name))
        if not checks:
            checks.append(self.unknown("evidence", "absent", "no evaluable evidence was "
                                       "recorded for this asset", EVIDENCE_MISSING))
        return self.finding(asset, type_name, checks)

    def _field(self, asset: Asset, name: str, value: str, type_name: str | None) -> list[_Check]:
        if name == "algorithm":
            return self.algorithm(asset, value, type_name)
        if name == "signature_algorithm":
            return self.table_check(name, "signature_algorithms", value, type_name)
        if name == "expiry":
            return self.expiry(value)
        if name == "tls_version":
            return self.tls_version(value, type_name)
        if name == "negotiated_group":
            evidence = asset.evidence if isinstance(asset.evidence, dict) else {}
            return self.group(value, evidence.get("requested_group"), type_name)
        return self.table_check(name, "cipher_suites", value, type_name)

    def finding(self, asset: Asset, type_name: str | None, checks: list[_Check]) -> dict[str, Any]:
        outcome = max((c.outcome for c in checks), key=SEVERITY.__getitem__)
        evidence = _evidence_status(checks)
        known = [c for c in checks if c.evidence == EVIDENCE_COMPLETE]
        worst = [c for c in checks if c.outcome == outcome]
        options = list(dict.fromkeys(opt for c in worst for opt in c.migration_options))
        tests = list(dict.fromkeys(c.recommended_test for c in worst if c.recommended_test))
        crypto = [c for c in known if c.quantum_vulnerable is not None]
        vulnerable = [c for c in crypto if c.quantum_vulnerable]
        expiry = next((c for c in checks if c.check == "expiry"), None)
        return {
            "asset_id": _display(asset.asset_id),
            "asset_type": type_name or _display(asset.asset_type),
            "source": _display(asset.source),
            "current_algorithm": _current_algorithm(asset),
            "outcome": outcome,
            "compliant": evidence == EVIDENCE_COMPLETE
            and outcome in self.policy["compliant_outcomes"],
            "evidence_status": evidence,
            "known_outcome": max((c.outcome for c in known), key=SEVERITY.__getitem__)
            if known else None,
            "quantum_vulnerable": bool(vulnerable) if crypto else None,
            "quantum_vulnerable_usages": sorted({u for c in vulnerable for u in c.usages}),
            "expiry_status": _expiry_status(expiry),
            "rule_ids": list(dict.fromkeys(c.rule_id for c in checks if c.rule_id)),
            "checks": [c.to_dict() for c in checks],
            "reasons": [c.reason for c in worst] + [c.reason for c in checks if c not in worst],
            "migration_options": options,
            "recommended_tests": tests,
        }

    def negotiation(self, observation: dict[str, Any]) -> dict[str, Any]:
        status = observation.get("status")
        checks: list[_Check] = []
        if not isinstance(status, str) or status.strip().upper() not in SUCCESS_STATUSES:
            checks.append(self.unknown(
                "status", _display(status), "connection did not succeed, so no negotiated "
                "parameters exist to evaluate; failure is not treated as compliance",
                EVIDENCE_MISSING))
        else:
            for name, table in (("tls_version", "versions"), ("negotiated_group", "groups"),
                                ("cipher_suite", "cipher_suites")):
                value = _observed(observation.get(name))
                if value is _INVALID:
                    checks.append(self.unknown(name, _display(observation.get(name)),
                                               f"{name} has an invalid value",
                                               EVIDENCE_UNRECOGNIZED))
                elif value is None:
                    if name != "cipher_suite":
                        checks.append(self.unknown(name, "absent", f"{name} was not recorded",
                                                   EVIDENCE_MISSING))
                elif isinstance(value, str):
                    if name == "tls_version":
                        checks.extend(self.tls_version(value, None))
                    elif name == "negotiated_group":
                        checks.extend(self.group(value, observation.get("requested_group"), None))
                    else:
                        checks.extend(self.table_check(name, table, value, None))
        outcome = max((c.outcome for c in checks), key=SEVERITY.__getitem__)
        evidence = _evidence_status(checks)
        complete = evidence == EVIDENCE_COMPLETE
        group_checks = [c for c in checks if c.check == "negotiated_group" and
                        c.evidence == EVIDENCE_COMPLETE]
        group = group_checks[0] if group_checks else None
        return {
            "outcome": outcome,
            "compliant": complete and outcome in self.policy["compliant_outcomes"],
            "evidence_status": evidence,
            "group_quantum_vulnerable": group.quantum_vulnerable if group else None,
            "group_rule_id": group.rule_id if group else None,
            "checks": [c.to_dict() for c in checks],
            "reasons": [c.reason for c in checks if c.outcome == outcome]
            + [c.reason for c in checks if c.outcome != outcome],
        }


def _evidence_status(checks: list[_Check]) -> str:
    statuses = {c.evidence for c in checks}
    if EVIDENCE_MISSING in statuses:
        return EVIDENCE_MISSING
    return EVIDENCE_UNRECOGNIZED if EVIDENCE_UNRECOGNIZED in statuses else EVIDENCE_COMPLETE


def _expiry_status(check: _Check | None) -> str | None:
    if check is None:
        return None
    return check.detail if check.evidence == EVIDENCE_COMPLETE and check.detail else "unknown"


def _current_algorithm(asset: Asset) -> str:
    parts = []
    algorithm = _observed(asset.algorithm)
    parts.append(_display(algorithm) if isinstance(algorithm, str) else "unknown")
    if isinstance(asset.key_size, int) and not isinstance(asset.key_size, bool):
        parts.append(f"{asset.key_size} bits")
    parameter_set = _observed(asset.parameter_set)
    if isinstance(parameter_set, str):
        parts.append(_display(parameter_set))
    group = _observed(asset.negotiated_group)
    if isinstance(group, str):
        parts.append(f"group {_display(group)}")
    return " / ".join(parts)


def _now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if now.tzinfo is None:
        raise PolicyError("now must be timezone-aware")
    return now


def evaluate(
    inventory: Inventory, policy: dict[str, Any], *, now: datetime | None = None
) -> dict[str, Any]:
    """Evaluate every asset; returns schema_version, findings, summary (inventory unchanged)."""
    if not isinstance(inventory, Inventory):
        raise PolicyError("evaluate() requires an Inventory")
    if inventory.schema_version != SCHEMA_VERSION:
        raise PolicyError("Unsupported inventory schema version")
    evaluator = PolicyEngine(policy, now=now)
    validated = evaluator.policy
    findings = []
    for asset in inventory.assets:
        if not isinstance(asset, Asset):
            raise PolicyError("Inventory assets must be Asset instances")
        findings.append(evaluator.asset(asset))
    by_outcome = {outcome: 0 for outcome in OUTCOMES}
    for finding in findings:
        by_outcome[finding["outcome"]] += 1
    errors = inventory.errors if isinstance(inventory.errors, list) else [{"error": "invalid"}]
    return {
        "schema_version": SCHEMA_VERSION,
        "policy_id": validated["policy_id"],
        "policy_digest": evaluator.digest,
        "evaluated_at": evaluator.now.isoformat(),
        "findings": findings,
        "summary": {
            "total_assets": len(findings),
            "by_outcome": by_outcome,
            "compliant": sum(1 for f in findings if f["compliant"]),
            "evidence_incomplete": sum(1 for f in findings
                                       if f["evidence_status"] != EVIDENCE_COMPLETE),
            "quantum_vulnerable": sum(1 for f in findings if f["quantum_vulnerable"]),
            "inventory_errors": len(errors),
        },
    }


def evaluate_negotiation(observation: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one observed TLS negotiation (e.g. a matrix row) against the policy.

    Connection success is never treated as compliance: the negotiated version, group and
    cipher suite are evaluated, required groups are enforced, and a requested/negotiated group
    mismatch is a downgrade.
    """
    if not isinstance(observation, dict):
        raise PolicyError("observation must be a mapping")
    return PolicyEngine(policy).negotiation(observation)


def classify(policy: dict[str, Any], table: str, name: Any) -> dict[str, Any] | None:
    """Convenience wrapper around PolicyEngine.classify."""
    return PolicyEngine(policy).classify(table, name)
