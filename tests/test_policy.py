import copy
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from cryptoagility.models import Asset, Inventory
from cryptoagility.policy import (
    MAX_POLICY_BYTES,
    OUTCOMES,
    PolicyEngine,
    PolicyError,
    classify,
    evaluate,
    evaluate_negotiation,
    load_policy,
    policy_digest,
    validate_policy,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "policies" / "default.yaml"
CONSTRAINED = ROOT / "policies" / "constrained.yaml"
NOW = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture(scope="module")
def policy() -> dict:
    return load_policy(DEFAULT)


def key(asset_id: str, algorithm: str, **kwargs: Any) -> Asset:
    return Asset(asset_id=asset_id, asset_type="public_key", source="synthetic",
                 algorithm=algorithm, **kwargs)


def cert(asset_id: str = "cert", **kwargs: Any) -> Asset:
    fields: dict[str, Any] = {"algorithm": "RSA", "key_size": 3072,
                              "signature_algorithm": "sha256WithRSAEncryption",
                              "expiry": "2030-01-01T00:00:00+00:00"}
    fields.update(kwargs)
    return Asset(asset_id=asset_id, asset_type="certificate", source="synthetic", **fields)


def endpoint(asset_id: str = "ep", **kwargs: Any) -> Asset:
    fields: dict[str, Any] = {"tls_version": "TLSv1.3", "negotiated_group": "X25519",
                              "cipher_suite": "TLS_AES_256_GCM_SHA384"}
    fields.update(kwargs)
    return Asset(asset_id=asset_id, asset_type="tls_endpoint", source="synthetic", **fields)


def one(policy: dict, asset: Asset) -> dict:
    result = evaluate(Inventory(assets=[asset]), policy, now=NOW)
    return result["findings"][0]


def write(tmp_path: Path, text: str, name: str = "p.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def default_text() -> str:
    return DEFAULT.read_text(encoding="utf-8")


# ------------------------------------------------------------------ shipped policies

def test_shipped_policies_load_and_are_deterministic() -> None:
    for path in (DEFAULT, CONSTRAINED):
        first, second = load_policy(path), load_policy(path)
        assert first == second
        assert policy_digest(first) == policy_digest(second)
    assert load_policy(DEFAULT)["profile"]["require_footprint_evidence"] is False
    constrained = load_policy(CONSTRAINED)
    assert constrained["profile"]["require_footprint_evidence"] is True
    assert policy_digest(load_policy(DEFAULT)) != policy_digest(constrained)


def test_shipped_policies_avoid_misleading_language() -> None:
    for path in (DEFAULT, CONSTRAINED):
        text = path.read_text(encoding="utf-8").lower()
        for term in ("broken", "quantum-proof", "unbreakable", "military-grade", "railway"):
            assert term not in text


def test_constrained_profile_is_generic_and_states_no_estimate_without_measurement() -> None:
    profile = load_policy(CONSTRAINED)["profile"]
    assert profile["escalate_update_difficulty"] == ["medium", "high"]
    assert "no size, MTU or network estimate" in profile["description"]


# ------------------------------------------------------------------ algorithm rules

@pytest.mark.parametrize(("bits", "outcome"), [
    (4096, "ACCEPTABLE_FOR_NOW"), (3072, "ACCEPTABLE_FOR_NOW"),
    (3071, "MIGRATION_REQUIRED"), (2048, "MIGRATION_REQUIRED"), (1024, "DEPRECATED"),
])
def test_rsa_key_size_bands(policy: dict, bits: int, outcome: str) -> None:
    finding = one(policy, key("rsa", "RSA", key_size=bits))
    assert finding["outcome"] == outcome
    assert finding["quantum_vulnerable"] is True
    assert finding["migration_options"]
    assert f"key_size={bits}" in finding["reasons"][0]
    assert "broken" not in json.dumps(finding).lower()


def test_rsa_reason_uses_quantum_vulnerable_language(policy: dict) -> None:
    finding = one(policy, key("rsa", "rsaEncryption", key_size=2048))
    assert "Quantum-vulnerable public-key dependency identified" in finding["reasons"][0]
    assert finding["compliant"] is False
    assert "Plan a hybrid transition" in " ".join(finding["migration_options"])


@pytest.mark.parametrize("bits", [None, 0, -1, True, "3072", 10**9])
def test_rsa_without_valid_key_size_fails_closed(policy: dict, bits: object) -> None:
    finding = one(policy, key("rsa", "RSA", key_size=bits))  # type: ignore[arg-type]
    assert finding["outcome"] == "UNSUPPORTED"
    assert finding["evidence_status"] != "complete"
    assert finding["compliant"] is False


@pytest.mark.parametrize(("algorithm", "parameter_set", "outcome"), [
    ("EC", "P-256", "ACCEPTABLE_FOR_NOW"),
    ("ECDSA", "secp384r1", "ACCEPTABLE_FOR_NOW"),
    ("EC", "prime192v1", "DEPRECATED"),
    ("ML-KEM-768", None, "APPROVED"),
    ("ML-KEM", "ML-KEM-1024", "APPROVED"),
    ("ml_kem_512", None, "ACCEPTABLE_FOR_NOW"),
    ("ML-DSA-65", None, "APPROVED"),
    ("ML-DSA-44", None, "ACCEPTABLE_FOR_NOW"),
    ("SLH-DSA", "SLH-DSA-SHAKE-256f", "APPROVED"),
    ("Ed25519", None, "ACCEPTABLE_FOR_NOW"),
    ("DSA", None, "DEPRECATED"),
])
def test_parameterised_algorithm_rules(
    policy: dict, algorithm: str, parameter_set: str | None, outcome: str
) -> None:
    finding = one(policy, key("k", algorithm, parameter_set=parameter_set))
    assert finding["outcome"] == outcome
    assert finding["evidence_status"] == "complete"
    assert finding["reasons"] and finding["migration_options"]


def test_pq_reasons_cite_standard_and_are_not_vulnerable(policy: dict) -> None:
    finding = one(policy, key("k", "ML-KEM-768"))
    assert "NIST FIPS 203" in finding["reasons"][0]
    assert finding["quantum_vulnerable"] is False


@pytest.mark.parametrize(("algorithm", "parameter_set"), [
    ("EC", None),                     # curve evidence missing
    ("EC", "brainpoolP256r1"),        # curve not in policy
    ("ML-KEM", None),                 # parameter set missing
    ("ML-KEM", "ML-KEM-999"),         # non-standard parameter set
    ("ML-KEM-512", "ML-KEM-768"),     # conflicting evidence
    ("ML-KEM", "ML-DSA-65"),          # parameter set of another algorithm
    ("FrodoKEM-640", None),           # algorithm not covered by policy
    ("unknown", None),
    ("", None),
    ("RSA\x00", None),                # control characters
    ("A" * 1000, None),               # oversized
])
def test_unknown_or_conflicting_algorithm_evidence_fails_closed(
    policy: dict, algorithm: str, parameter_set: str | None
) -> None:
    finding = one(policy, key("k", algorithm, parameter_set=parameter_set))
    assert finding["outcome"] == "UNSUPPORTED"
    assert finding["compliant"] is False
    assert finding["evidence_status"] in ("missing", "unrecognized")
    assert finding["migration_options"]


def test_non_string_evidence_fails_closed(policy: dict) -> None:
    asset = key("k", 42)  # type: ignore[arg-type]
    finding = one(policy, asset)
    assert finding["outcome"] == "UNSUPPORTED"
    assert finding["evidence_status"] == "unrecognized"


def test_unknown_asset_type_fails_closed(policy: dict) -> None:
    asset = Asset(asset_id="x", asset_type="hsm_slot", source="s", algorithm="ML-KEM-768")
    finding = one(policy, asset)
    assert finding["outcome"] == "UNSUPPORTED"
    assert any("asset type is not recognised" in reason for reason in finding["reasons"])


def test_asset_without_any_evidence_fails_closed(policy: dict) -> None:
    asset = Asset(asset_id="cfg", asset_type="openssl_config", source="s")
    finding = one(policy, asset)
    assert finding["outcome"] == "UNSUPPORTED"
    assert finding["evidence_status"] == "missing"


def test_pq_certificate_profile_is_experimental_not_approved(policy: dict) -> None:
    finding = one(policy, cert(algorithm="ML-DSA-65", key_size=None,
                               signature_algorithm="ML-DSA-65"))
    assert finding["outcome"] == "EXPERIMENTAL"
    assert finding["compliant"] is True
    assert any("laboratory interoperability experiment" in r for r in finding["reasons"])


# ------------------------------------------------------------------ certificates

def test_certificate_weak_signature_is_deprecated(policy: dict) -> None:
    finding = one(policy, cert(signature_algorithm="sha1WithRSAEncryption"))
    assert finding["outcome"] == "DEPRECATED"
    assert "Re-issue the certificate with a SHA-2 based signature immediately" in (
        finding["migration_options"])


@pytest.mark.parametrize(("expiry", "outcome", "status"), [
    ("2025-06-01T00:00:00+00:00", "DEPRECATED", "expired"),
    ("2026-02-01T00:00:00+00:00", "ACCEPTABLE_FOR_NOW", "expiring"),
    ("2030-01-01T00:00:00+00:00", "ACCEPTABLE_FOR_NOW", "valid"),
    ("2030-01-01T00:00:00", "ACCEPTABLE_FOR_NOW", "valid"),
    ("not-a-date", "UNSUPPORTED", "unknown"),
    (None, "UNSUPPORTED", "unknown"),
])
def test_certificate_expiry(policy: dict, expiry: str | None, outcome: str,
                            status: str | None) -> None:
    finding = one(policy, cert(expiry=expiry))
    assert finding["outcome"] == outcome
    assert finding["expiry_status"] == status


def test_naive_expiry_is_reported_as_utc_assumption(policy: dict) -> None:
    finding = one(policy, cert(expiry="2030-01-01T00:00:00"))
    assert any("interpreted as UTC" in r for r in finding["reasons"])


def test_certificate_missing_signature_evidence_fails_closed(policy: dict) -> None:
    finding = one(policy, cert(signature_algorithm=None))
    assert finding["outcome"] == "UNSUPPORTED"
    assert finding["evidence_status"] == "missing"


# ------------------------------------------------------------------ TLS and negotiation

@pytest.mark.parametrize(("version", "outcome"), [
    ("TLSv1.3", "ACCEPTABLE_FOR_NOW"), ("TLSv1.2", "ACCEPTABLE_FOR_NOW"),
    ("TLSv1.1", "DEPRECATED"), ("SSLv3", "DEPRECATED"), ("TLSv9", "UNSUPPORTED"),
])
def test_tls_versions(policy: dict, version: str, outcome: str) -> None:
    assert one(policy, endpoint(tls_version=version))["outcome"] == outcome


def test_tls_minimum_is_policy_driven(policy: dict) -> None:
    strict = copy.deepcopy(policy)
    strict["tls"]["minimum_version"] = "TLSv1.3"
    finding = one(strict, endpoint(tls_version="TLSv1.2"))
    assert finding["outcome"] == "DEPRECATED"
    assert any("below policy minimum TLSv1.3" in r for r in finding["reasons"])


def test_hybrid_group_is_experimental_and_compliant(policy: dict) -> None:
    finding = one(policy, endpoint(negotiated_group="X25519MLKEM768"))
    assert finding["outcome"] == "EXPERIMENTAL"
    assert finding["compliant"] is True
    assert finding["quantum_vulnerable"] is False


def test_required_hybrid_group_rejects_successful_x25519_negotiation(policy: dict) -> None:
    required = copy.deepcopy(policy)
    required["tls"]["required_groups"] = ["X25519MLKEM768"]
    finding = one(required, endpoint(negotiated_group="X25519"))
    assert finding["outcome"] == "MIGRATION_REQUIRED"
    assert finding["compliant"] is False
    assert any("successful handshake is not policy compliance" in r for r in finding["reasons"])
    assert one(required, endpoint(negotiated_group="x25519mlkem768"))["compliant"] is True


def test_requested_hybrid_downgraded_to_x25519_is_detected(policy: dict) -> None:
    asset = endpoint(negotiated_group="X25519", evidence={"requested_group": "X25519MLKEM768"})
    finding = one(policy, asset)
    assert finding["outcome"] == "MIGRATION_REQUIRED"
    assert any("treated as a downgrade" in r for r in finding["reasons"])


def test_endpoint_missing_group_evidence_fails_closed(policy: dict) -> None:
    finding = one(policy, endpoint(negotiated_group=None))
    assert finding["outcome"] == "UNSUPPORTED"


def test_negotiation_success_does_not_imply_compliance(policy: dict) -> None:
    required = copy.deepcopy(policy)
    required["tls"]["required_groups"] = ["X25519MLKEM768"]
    row = {"status": "SUCCESS", "tls_version": "TLSv1.3", "negotiated_group": "X25519",
           "cipher_suite": "TLS_AES_256_GCM_SHA384", "policy_pass": True}
    result = evaluate_negotiation(row, required)
    assert result["outcome"] == "MIGRATION_REQUIRED"
    assert result["compliant"] is False
    assert result["group_quantum_vulnerable"] is True
    ok = dict(row, negotiated_group="X25519MLKEM768")
    assert evaluate_negotiation(ok, required)["compliant"] is True


def test_negotiation_downgrade_against_requested_group(policy: dict) -> None:
    row = {"status": "SUCCESS", "tls_version": "TLSv1.3", "negotiated_group": "X25519",
           "requested_group": "X25519MLKEM768"}
    result = evaluate_negotiation(row, policy)
    assert result["outcome"] == "MIGRATION_REQUIRED"
    assert result["compliant"] is False


@pytest.mark.parametrize("row", [
    {"status": "FAILED", "negotiated_group": "X25519MLKEM768", "tls_version": "TLSv1.3"},
    {"status": None},
    {"status": "SUCCESS", "tls_version": "TLSv1.3"},
    {"status": "SUCCESS", "tls_version": "TLSv1.3", "negotiated_group": ["X25519"]},
    {"status": "SUCCESS", "tls_version": "TLSv1.3", "negotiated_group": "X25519",
     "requested_group": "NotAGroup"},
])
def test_failed_or_incomplete_negotiation_never_passes(policy: dict, row: dict) -> None:
    result = evaluate_negotiation(row, policy)
    assert result["outcome"] == "UNSUPPORTED"
    assert result["compliant"] is False


def test_evaluate_negotiation_rejects_non_mapping(policy: dict) -> None:
    with pytest.raises(PolicyError):
        evaluate_negotiation(["SUCCESS"], policy)  # type: ignore[arg-type]


# ------------------------------------------------------------------ rule-driven behaviour

def test_thresholds_come_from_policy_not_code(policy: dict) -> None:
    stricter = copy.deepcopy(policy)
    rsa = next(rule for rule in stricter["algorithms"] if rule["id"] == "rsa")
    rsa["key_size"]["bands"][0]["min_bits"] = 4096
    assert one(stricter, key("r", "RSA", key_size=3072))["outcome"] == "MIGRATION_REQUIRED"
    assert one(policy, key("r", "RSA", key_size=3072))["outcome"] == "ACCEPTABLE_FOR_NOW"


def test_new_algorithm_needs_only_a_policy_rule(policy: dict) -> None:
    extended = copy.deepcopy(policy)
    extended["algorithms"].append({
        "id": "example-kem", "names": ["ExampleKEM"], "family": "post_quantum",
        "quantum_vulnerable": False, "usage": ["key_establishment"],
        "outcome": "EXPERIMENTAL", "reason": "Synthetic test rule.",
        "migration_options": ["Synthetic option"],
    })
    assert one(policy, key("k", "ExampleKEM"))["outcome"] == "UNSUPPORTED"
    finding = one(extended, key("k", "ExampleKEM"))
    assert finding["outcome"] == "EXPERIMENTAL"
    assert finding["rule_ids"] == ["example-kem"]


def test_classify_reports_rule_metadata(policy: dict) -> None:
    hybrid = classify(policy, "groups", "X25519MLKEM768")
    mldsa = classify(policy, "algorithms", "ML-DSA-87")
    assert hybrid is not None and hybrid["family"] == "hybrid"
    assert mldsa is not None and mldsa["parameter_set"] == "ML-DSA-87"
    assert classify(policy, "groups", "NotAGroup") is None
    assert classify(policy, "groups", 7) is None
    with pytest.raises(PolicyError):
        classify(policy, "nonexistent", "X25519")


def test_evaluation_is_deterministic_and_does_not_mutate_inputs(policy: dict) -> None:
    inventory = Inventory(assets=[key("a", "RSA", key_size=2048), cert(), endpoint()],
                          errors=[{"path": "x", "error": "unreadable"}])
    before_inv, before_policy = copy.deepcopy(inventory), copy.deepcopy(policy)
    first = evaluate(inventory, policy, now=NOW)
    second = evaluate(inventory, policy, now=NOW)
    assert first == second
    assert inventory == before_inv and policy == before_policy
    json.dumps(first)
    assert first["summary"]["inventory_errors"] == 1
    assert first["summary"]["total_assets"] == 3
    assert set(first["summary"]["by_outcome"]) == set(OUTCOMES)
    assert first["evaluated_at"] == NOW.isoformat()


def test_evaluate_rejects_bad_inputs(policy: dict) -> None:
    with pytest.raises(PolicyError):
        evaluate({"assets": []}, policy)  # type: ignore[arg-type]
    with pytest.raises(PolicyError):
        evaluate(Inventory(schema_version="0.1"), policy)
    with pytest.raises(PolicyError):
        evaluate(Inventory(assets=["not an asset"]), policy)  # type: ignore[list-item]
    with pytest.raises(PolicyError):
        evaluate(Inventory(), policy, now=datetime(2026, 1, 1))
    with pytest.raises(PolicyError):
        PolicyEngine({"not": "a policy"})


def test_untrusted_asset_id_is_sanitised(policy: dict) -> None:
    finding = one(policy, key("evil\x1b[31m\n", "ML-KEM-768"))
    assert "\x1b" not in finding["asset_id"] and "\n" not in finding["asset_id"]


# ------------------------------------------------------------------ malicious / invalid YAML

@pytest.mark.parametrize("text", [
    "a: &x [1, 2]\nb: *x\n",                                       # alias
    "base: &b {k: 1}\nother:\n  <<: *b\n",                       # merge key
    "a: 1\na: 2\n",                                                # duplicate key
    "a: !!python/object/apply:os.system ['echo pwned']\n",        # code execution tag
    "a: !!binary aGVsbG8=\n",                                      # non-safe tag
    "- just\n- a list\n",                                          # wrong top-level type
    "",                                                            # empty document
    "a: [unterminated\n",                                          # syntax error
    "a: 1\n---\nb: 2\n",                                           # multiple documents
])
def test_malicious_or_malformed_yaml_is_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(PolicyError):
        load_policy(write(tmp_path, text))


def test_billion_laughs_is_rejected_without_expansion(tmp_path: Path) -> None:
    lines = ['a0: &a0 ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]']
    for i in range(1, 9):
        lines.append(f"a{i}: &a{i} [" + ",".join([f"*a{i - 1}"] * 9) + "]")
    with pytest.raises(PolicyError):
        load_policy(write(tmp_path, "\n".join(lines) + "\n"))


def test_oversized_non_utf8_symlink_and_missing_files_are_rejected(tmp_path: Path) -> None:
    big = write(tmp_path, "a: '" + "x" * (MAX_POLICY_BYTES + 1) + "'\n", "big.yaml")
    with pytest.raises(PolicyError):
        load_policy(big)
    binary = tmp_path / "bin.yaml"
    binary.write_bytes(b"\xff\xfe\x00policy")
    with pytest.raises(PolicyError):
        load_policy(binary)
    link = tmp_path / "link.yaml"
    os.symlink(DEFAULT, link)
    with pytest.raises(PolicyError):
        load_policy(link)
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "missing.yaml")
    with pytest.raises(PolicyError):
        load_policy(tmp_path)


def mutate(policy: dict, path: tuple, value: object) -> dict:
    data = copy.deepcopy(policy)
    target = data
    for part in path[:-1]:
        target = target[part]
    if value is KeyError:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return data


@pytest.mark.parametrize(("path", "value"), [
    (("schema_version",), "2.0"),
    (("schema_version",), 1.0),
    (("unexpected",), "key"),
    (("planning",), KeyError),
    (("policy_id",), "Bad ID!"),
    (("compliant_outcomes",), ["APPROVED", "UNSUPPORTED"]),
    (("compliant_outcomes",), ["ACCEPTABLE_FOR_NOW"]),
    (("unknown_evidence", "migration_options"), []),
    (("tls", "below_minimum", "outcome"), "APPROVED"),
    (("tls", "negotiation_violation", "outcome"), "EXPERIMENTAL"),
    (("tls", "required_groups"), ["NotAGroup"]),
    (("tls", "minimum_version"), "TLSv9"),
    (("certificates", "expired", "outcome"), "ACCEPTABLE_FOR_NOW"),
    (("certificates", "renewal_window_days"), True),
    (("certificates", "renewal_window_days"), -1),
    (("planning", "ready_outcomes"), ["MIGRATION_REQUIRED"]),
    (("planning", "outcome_priority", "APPROVED"), "UNKNOWN"),
    (("planning", "outcome_priority", "APPROVED"), "SOMEDAY"),
    (("profile", "escalate_update_difficulty"), ["impossible"]),
    (("profile", "long_system_lifetime_years"), 0),
    (("asset_types", "certificate", "required_evidence"), ["private_key_bytes"]),
    (("algorithms",), []),
    (("algorithms", 0, "key_size", "bands", 2, "min_bits"), 1),
    (("algorithms", 0, "key_size", "bands", 0, "min_bits"), "3072"),
    (("algorithms", 0, "family"), "magic"),
    (("algorithms", 0, "quantum_vulnerable"), "yes"),
    (("algorithms", 0, "outcome"), "APPROVED"),
    (("algorithms", 0, "reason"), "RSA is broken."),
    (("algorithms", 1, "id"), "rsa"),
    (("algorithms", 1, "names"), ["RSA"]),
    (("algorithms", 0, "migration_options"), ["x" * 5000]),
    (("algorithms", 0, "contexts"), {"mainframe": {"outcome": "APPROVED", "reason": "r"}}),
    (("tls", "groups", 0, "reason"), "This group is quantum-proof."),
    (("description",), "Unbreakable military-grade crypto."),
])
def test_schema_violations_are_rejected(policy: dict, path: tuple, value: object) -> None:
    with pytest.raises(PolicyError):
        validate_policy(mutate(policy, path, value))


def test_validate_policy_returns_independent_copy(policy: dict) -> None:
    validated = validate_policy(policy)
    validated["algorithms"][0]["names"].append("Injected")
    assert "Injected" not in policy["algorithms"][0]["names"]


def test_yaml_roundtrip_of_mutated_policy_is_rejected_from_file(tmp_path: Path,
                                                                 policy: dict) -> None:
    bad = mutate(policy, ("tls", "below_minimum", "outcome"), "APPROVED")
    with pytest.raises(PolicyError):
        load_policy(write(tmp_path, yaml.safe_dump(bad)))
    assert load_policy(write(tmp_path, default_text(), "ok.yaml")) == policy
