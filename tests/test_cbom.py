"""Tests for the project-specific CBOM v1 JSON/CSV exporter."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cryptoagility import cbom, inventory
from cryptoagility.models import Asset, Inventory

NOW = datetime(2026, 6, 1, tzinfo=UTC)


def _asset(**overrides: Any) -> Asset:
    base: dict[str, Any] = {"asset_id": "a1", "asset_type": "certificate", "source": "x.pem",
            "algorithm_family": "RSA", "algorithm": "RSA", "key_size": 2048}
    base.update(overrides)
    return Asset(**base)


def _rows(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text)))


def test_json_is_versioned_project_specific_and_not_cyclonedx() -> None:
    inv = Inventory(
        assets=[_asset(asset_id="b", source="z"), _asset(asset_id="a", source="y",
                                                         algorithm_family="ML-DSA")],
        errors=[{"source": "q", "code": "malformed_pem", "message": "bad"}],
    )
    doc = cbom.export_json(inv)
    assert doc["cbom_format"] == "cryptoagility-lab-cbom" and doc["cbom_version"] == "1"
    assert doc["inventory_schema_version"] == "1.0"
    assert "not a CycloneDX" in doc["compliance"]
    assert "bomFormat" not in doc and "specVersion" not in doc
    assert [a["source"] for a in doc["assets"]] == ["y", "z"]
    assert doc["summary"]["by_algorithm_family"] == {"ML-DSA": 1, "RSA": 1}
    assert doc["summary"]["error_count"] == 1
    assert json.loads(json.dumps(doc)) == doc
    assert cbom.export_json(inv) == doc


def test_unsupported_schema_rejected() -> None:
    with pytest.raises(ValueError):
        cbom.export_json(Inventory(schema_version="0.9"))


def test_defensive_redaction_of_pem_and_secret_named_evidence() -> None:
    asset = _asset(
        certificate_subject="-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----",
        evidence={"private_key_pem": "MIIEvQ", "nested": {"session_key": "00ff", "ok": 1},
                  "blob": b"raw", "private_material_exported": False, "password": "hunter2"},
    )
    doc = cbom.export_json(Inventory(assets=[asset]))
    record = doc["assets"][0]
    assert record["certificate_subject"] == cbom.REDACTED
    assert record["evidence"] == {"blob": cbom.REDACTED, "nested": {"ok": 1},
                                  "private_material_exported": False}
    text = json.dumps(doc) + cbom.export_csv(Inventory(assets=[asset]))
    for leaked in ("MIIB", "MIIEvQ", "00ff", "hunter2", "BEGIN"):
        assert leaked not in text


@pytest.mark.parametrize("payload", [
    "=HYPERLINK(\"http://evil\")", "+1+2", "-2+3", "@SUM(A1)", "\t=1", "\r=1",
    "  =cmd|' /C calc'!A0", "\uff1d1+1",
])
def test_csv_formula_injection_is_neutralized(payload: str) -> None:
    inv = Inventory(assets=[_asset(source=payload, issuer=payload, sans=[payload, "ok"])])
    (row,) = _rows(cbom.export_csv(inv))
    assert row["source"] == "'" + payload
    assert row["issuer"] == "'" + payload
    assert row["sans"].startswith("'")
    assert row["sans"].endswith(";ok")


def test_csv_shape_and_benign_values() -> None:
    inv = Inventory(assets=[_asset(
        sans=["a.lab.test", "127.0.0.1"], chain_length=2,
        evidence={"crypto_class": "classical-public-key", "validity": "valid",
                  "certificate_sha256": "ab" * 32},
    )])
    text = cbom.export_csv(inv)
    header = text.splitlines()[0].split(",")
    assert header == cbom.CSV_COLUMNS
    (row,) = _rows(text)
    assert row["sans"] == "a.lab.test;127.0.0.1"
    assert row["key_size"] == "2048" and row["chain_length"] == "2"
    assert row["evidence.crypto_class"] == "classical-public-key"
    assert row["parameter_set"] == ""
    assert cbom.export_csv(inv) == text


def test_end_to_end_scan_export_contains_no_private_material(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "=evil.lab.test")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    (tmp_path / "=cmd.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM)
                                        + private_pem)
    (tmp_path / "app.yaml").write_text("tls:\n  key_exchange: X25519MLKEM768\npassword: s3cr3t\n")
    inv = inventory.scan(tmp_path, now=NOW)
    doc = cbom.export_json(inv)
    text = cbom.export_csv(inv)
    assert doc["summary"]["by_asset_type"] == {
        "application_config": 1, "certificate": 1, "private_key": 1
    }
    rows = _rows(text)
    assert {r["source"] for r in rows} == {"'=cmd.pem", "app.yaml"}
    cert_row = next(r for r in rows if r["asset_type"] == "certificate")
    assert cert_row["certificate_subject"] == "CN==evil.lab.test"
    blob = json.dumps(doc) + text
    for line in private_pem.decode().splitlines()[1:-1]:
        assert line not in blob
    assert "s3cr3t" not in blob and "PRIVATE KEY" not in blob
