"""Synthetic scenario: public-only material, expected variety, and config-token policy routing."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from cryptoagility import inventory, migration, policy, scenario

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return scenario.generate(tmp_path_factory.mktemp("sc") / "org")


@pytest.fixture(scope="module")
def evaluation(generated: Path) -> dict:
    inv = inventory.scan(generated)
    return policy.evaluate(inv, policy.load_policy(ROOT / "policies/default.yaml"))


def test_no_private_keys_written(generated: Path) -> None:
    for path in generated.rglob("*"):
        if path.is_file():
            assert b"PRIVATE KEY" not in path.read_bytes(), path
    assert len(list((generated / "certs").glob("*.pem"))) == len(scenario.CERTIFICATES)


def test_refuses_non_empty_or_symlink_output(generated: Path, tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        scenario.generate(generated)
    link = tmp_path / "link"
    link.symlink_to(tmp_path)
    with pytest.raises(ValueError):
        scenario.generate(link)


def test_scenario_variety(generated: Path) -> None:
    inv = inventory.scan(generated)
    assert not inv.errors
    certs = [a for a in inv.assets if a.asset_type == "certificate"]
    families = Counter(a.algorithm for a in certs)
    assert families["RSA"] >= 7 and families["ECDSA"] >= 3
    assert any(a.algorithm == "ML-DSA-65" or a.parameter_set == "ML-DSA-65" for a in certs)


def _finding(evaluation: dict, source: str, current: str) -> dict:
    return next(
        f
        for f in evaluation["findings"]
        if f["source"] == source and f["current_algorithm"].startswith(current)
    )


@pytest.mark.parametrize(
    "source, token, outcome, check",
    [
        ("services/03-legacy-portal.yaml", "TLSv1.1", "DEPRECATED", "tls_version"),
        ("services/03-legacy-portal.yaml", "3DES", "DEPRECATED", "cipher_suite"),
        ("services/03-legacy-portal.yaml", "rsa_pkcs1_sha1", "DEPRECATED", "configured_signature"),
        ("services/07-backup-archive.yaml", "ffdhe2048", "MIGRATION_REQUIRED", "configured_group"),
        (
            "services/05-identity-provider.yaml",
            "X25519MLKEM768",
            "EXPERIMENTAL",
            "configured_group",
        ),
        ("services/11-pqc-pilot.yaml", "pqc", "EXPERIMENTAL", "algorithm"),
        ("services/01-public-web.yaml", "classical", "ACCEPTABLE_FOR_NOW", "algorithm"),
    ],
)
def test_config_tokens_route_to_policy_tables(
    evaluation: dict, source: str, token: str, outcome: str, check: str
) -> None:
    finding = _finding(evaluation, source, token)
    assert finding["outcome"] == outcome
    assert finding["evidence_status"] == "complete"
    assert check in {c["check"] for c in finding["checks"]}


def test_unknown_cipher_string_fails_closed(evaluation: dict) -> None:
    flagged = [
        f
        for f in evaluation["findings"]
        if f["source"] == "clients/legacy-batch-client.cnf" and f["outcome"] == "UNSUPPORTED"
    ]
    assert flagged and all(f["evidence_status"] != "complete" for f in flagged)


def test_scenario_plan_is_blocked_with_reasons(generated: Path) -> None:
    inv = inventory.scan(generated)
    result = migration.plan(inv, policy.load_policy(ROOT / "policies/constrained.yaml"))
    assert result["readiness"] == "BLOCKED" and result["reasons"]
