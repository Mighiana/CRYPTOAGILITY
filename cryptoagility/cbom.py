"""Project-specific Cryptographic Bill of Materials (CBOM) export, format version 1.

This is the CryptoAgility Lab's own JSON/CSV layout. It is NOT a CycloneDX CBOM and makes no
claim of CycloneDX schema compliance. Output is deterministic for identical inventories.
Exporters defensively re-check that no PEM/private material or secret-named evidence leaks,
and CSV cells are neutralized against spreadsheet formula injection.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter
from typing import Any

from cryptoagility.models import SCHEMA_VERSION, Asset, Inventory

CBOM_FORMAT = "cryptoagility-lab-cbom"
CBOM_VERSION = "1"
COMPLIANCE_NOTICE = (
    "Project-specific CBOM v1 for the CryptoAgility Lab; not a CycloneDX document and not "
    "validated against any CycloneDX schema."
)
REDACTED = "[REDACTED]"

ASSET_COLUMNS = [
    "asset_id",
    "asset_type",
    "source",
    "algorithm_family",
    "algorithm",
    "key_size",
    "parameter_set",
    "signature_algorithm",
    "tls_version",
    "cipher_suite",
    "negotiated_group",
    "certificate_subject",
    "issuer",
    "expiry",
    "sans",
    "chain_length",
    "migration_status",
    "policy_result",
]
EVIDENCE_COLUMNS = [
    "crypto_class",
    "algorithm_standard",
    "integration_status",
    "validity",
    "signature_algorithm_family",
    "certificate_sha256",
    "public_key_sha256",
    "setting",
    "purpose",
    "location",
]
CSV_COLUMNS = ASSET_COLUMNS + [f"evidence.{name}" for name in EVIDENCE_COLUMNS]

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n", "\uff1d", "\uff0b", "\uff0d", "\uff20")
_SECRET_KEY = re.compile(
    r"(private|secret|password|passphrase|master|session_?key|psk|ticket|seed|token)", re.I
)
_ALLOWED_SECRET_NAMED = {"private_material_exported"}
_PEM_MARKER = re.compile(r"-----BEGIN [A-Z0-9 ]+-----|PRIVATE KEY")
_MAX_DEPTH = 8


def _sanitize(value: Any, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        return REDACTED
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key in sorted(value, key=str):
            name = str(key)
            if _SECRET_KEY.search(name) and name not in _ALLOWED_SECRET_NAMED:
                continue
            clean[name] = _sanitize(value[key], depth + 1)
        return clean
    if isinstance(value, list | tuple):
        return [_sanitize(item, depth + 1) for item in value]
    if isinstance(value, bytes | bytearray):
        return REDACTED
    if isinstance(value, str) and _PEM_MARKER.search(value):
        return REDACTED
    if value is None or isinstance(value, bool | int | float | str):
        return value
    return REDACTED


def _asset_record(asset: Asset) -> dict[str, Any]:
    record: dict[str, Any] = _sanitize(asset.to_dict())
    record["evidence"] = record.get("evidence") or {}
    return record


def _ordered(inventory: Inventory) -> list[Asset]:
    return sorted(inventory.assets, key=lambda a: (a.source, a.asset_type, a.asset_id))


def export_json(inventory: Inventory) -> dict[str, Any]:
    """Return the CBOM v1 document as a JSON-serializable dict."""
    if inventory.schema_version != SCHEMA_VERSION:
        raise ValueError("Unsupported inventory schema version")
    assets = [_asset_record(asset) for asset in _ordered(inventory)]
    errors = sorted(
        (_sanitize(dict(error)) for error in inventory.errors),
        key=lambda e: (str(e.get("source", "")), str(e.get("code", "")), str(e.get("message", ""))),
    )
    by_family = Counter(a["algorithm_family"] for a in assets)
    by_type = Counter(a["asset_type"] for a in assets)
    by_class = Counter(str(a["evidence"].get("crypto_class", "unknown")) for a in assets)
    return {
        "cbom_format": CBOM_FORMAT,
        "cbom_version": CBOM_VERSION,
        "inventory_schema_version": inventory.schema_version,
        "compliance": COMPLIANCE_NOTICE,
        "summary": {
            "asset_count": len(assets),
            "error_count": len(errors),
            "by_asset_type": dict(sorted(by_type.items())),
            "by_algorithm_family": dict(sorted(by_family.items())),
            "by_crypto_class": dict(sorted(by_class.items())),
        },
        "assets": assets,
        "errors": errors,
    }


def escape_csv_cell(value: Any) -> str:
    """Render one CSV cell, neutralizing values a spreadsheet could evaluate as a formula."""
    if value is None:
        return ""
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, list | tuple):
        text = ";".join(escape_csv_cell(item).lstrip("'") for item in value)
    else:
        text = str(value)
    if text.startswith(_FORMULA_PREFIXES) or text.lstrip(" ").startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def export_csv(inventory: Inventory) -> str:
    """Return one CSV row per asset (errors are only in the JSON export)."""
    document = export_json(inventory)
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)
    for record in document["assets"]:
        evidence = record["evidence"]
        row = [record.get(column) for column in ASSET_COLUMNS]
        row += [evidence.get(name) for name in EVIDENCE_COLUMNS]
        writer.writerow([escape_csv_cell(cell) for cell in row])
    return buffer.getvalue()
