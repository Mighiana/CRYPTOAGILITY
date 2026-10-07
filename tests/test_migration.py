import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from cryptoagility.migration import (
    ESTIMATE_LABEL,
    READINESS,
    MigrationError,
    plan,
    render_markdown,
    validate_constraints,
)
from cryptoagility.models import SCHEMA_VERSION, Asset, Inventory
from cryptoagility.policy import PRIORITIES, PolicyError, load_policy

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture(scope="module")
def policy() -> dict:
    return load_policy(ROOT / "policies" / "default.yaml")


@pytest.fixture(scope="module")
def constrained() -> dict:
    return load_policy(ROOT / "policies" / "constrained.yaml")


@pytest.fixture
def required_hybrid(policy: dict) -> dict:
    data = copy.deepcopy(policy)
    data["tls"]["required_groups"] = ["X25519MLKEM768"]
    return data


def key(asset_id: str, algorithm: str, **kwargs: Any) -> Asset:
    return Asset(
        asset_id=asset_id,
        asset_type="public_key",
        source="synthetic",
        algorithm=algorithm,
        **kwargs,
    )


def endpoint(asset_id: str = "ep", group: str = "X25519", **kwargs: Any) -> Asset:
    return Asset(
        asset_id=asset_id,
        asset_type="tls_endpoint",
        source="synthetic",
        tls_version="TLSv1.3",
        negotiated_group=group,
        cipher_suite="TLS_AES_256_GCM_SHA384",
        **kwargs,
    )


def row(group: str, status: str = "SUCCESS", **kwargs: Any) -> dict:
    data = {
        "client": "openssl-3.5.9",
        "server": "openssl-3.5.9",
        "status": status,
        "tls_version": "TLSv1.3",
        "negotiated_group": group,
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "certificate_type": "RSA",
        "policy_pass": True,
        "error_reason": None,
    }
    data.update(kwargs)
    return data


def matrix(*rows: dict) -> dict:
    return {"schema_version": SCHEMA_VERSION, "environment": {}, "rows": list(rows)}


def inv(*assets: Asset, errors: list | None = None) -> Inventory:
    return Inventory(assets=list(assets), errors=errors or [])


def item(result: dict, asset_id: str) -> dict:
    return next(i for i in result["items"] if i["asset_id"] == asset_id)


def walk_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in walk_keys(v)}
    if isinstance(value, list):
        return {k for v in value for k in walk_keys(v)}
    return set()


REQUIRED_ITEM_FIELDS = {
    "asset_id",
    "priority",
    "reason",
    "dependency",
    "recommended_test",
    "blocker",
    "next_action",
}


# ------------------------------------------------------------------ readiness states


def test_ready_requires_complete_evidence_and_ready_outcomes(policy: dict) -> None:
    result = plan(inv(key("kem", "ML-KEM-768"), key("sig", "ML-DSA-65")), policy, now=NOW)
    assert result["readiness"] == "READY"
    assert all(i["priority"] == "MONITOR" and i["blocker"] is None for i in result["items"])
    assert result["summary"]["ready_assets"] == 2


def test_partially_ready_explains_pending_migration(policy: dict) -> None:
    result = plan(inv(key("kem", "ML-KEM-768"), key("rsa", "RSA", key_size=3072)), policy, now=NOW)
    assert result["readiness"] == "PARTIALLY_READY"
    rsa = item(result, "rsa")
    assert rsa["priority"] == "MEDIUM_TERM"
    assert "outcome ACCEPTABLE_FOR_NOW maps to MEDIUM_TERM" in rsa["reason"]
    assert "No lab matrix supplied" in rsa["dependency"]
    assert rsa["recommended_test"].startswith("Run the loopback matrix")
    assert rsa["blocker"] is None
    assert any("1 of 2 asset(s) meet a policy ready outcome" in r for r in result["reasons"])


@pytest.mark.parametrize(
    "unknown_asset",
    [
        Asset(asset_id="mystery", asset_type="hsm_slot", source="s", algorithm="ML-KEM-768"),
        key("mystery", "FrodoKEM-640"),
        key("mystery", "RSA"),  # missing key size
        endpoint("mystery", group=None),  # type: ignore[arg-type]
    ],
)
def test_unknown_assets_or_missing_evidence_prevent_ready(
    policy: dict, unknown_asset: Asset
) -> None:
    result = plan(inv(key("kem", "ML-KEM-768"), unknown_asset), policy, now=NOW)
    assert result["readiness"] == "UNKNOWN"
    mystery = item(result, "mystery")
    assert mystery["priority"] == "UNKNOWN"
    assert mystery["blocker_kind"] == "evidence"
    assert mystery["blocker"].startswith("Evidence gap:")
    assert mystery["next_action"] == policy["planning"]["unknown_next_action"]


def test_discovery_errors_and_empty_inventory_are_unknown(policy: dict) -> None:
    errored = plan(
        inv(key("kem", "ML-KEM-768"), errors=[{"path": "x", "error": "denied"}]), policy, now=NOW
    )
    assert errored["readiness"] == "UNKNOWN"
    assert any("discovery error" in r for r in errored["reasons"])
    empty = plan(inv(), policy, now=NOW)
    assert empty["readiness"] == "UNKNOWN"
    assert empty["items"] == []


def test_deprecated_dependency_blocks_with_immediate_priority(policy: dict) -> None:
    weak = Asset(
        asset_id="legacy-cert",
        asset_type="certificate",
        source="s",
        algorithm="RSA",
        key_size=3072,
        signature_algorithm="sha1WithRSAEncryption",
        expiry="2030-01-01T00:00:00+00:00",
    )
    result = plan(inv(weak, key("kem", "ML-KEM-768")), policy, now=NOW)
    assert result["readiness"] == "BLOCKED"
    legacy = item(result, "legacy-cert")
    assert legacy["priority"] == "IMMEDIATE"
    assert legacy["blocker_kind"] == "policy"
    assert result["items"][0]["asset_id"] == "legacy-cert"


def test_required_hybrid_with_x25519_endpoint_blocks(required_hybrid: dict) -> None:
    result = plan(inv(endpoint("ep", "X25519")), required_hybrid, now=NOW)
    assert result["readiness"] == "BLOCKED"
    ep = item(result, "ep")
    assert ep["outcome"] == "MIGRATION_REQUIRED"
    assert ep["priority"] == "SHORT_TERM"
    assert "not policy compliance" in ep["blocker"]


# ------------------------------------------------------------------ lab matrix evidence


def test_matrix_hybrid_fallback_to_x25519_blocks_even_if_row_claims_pass(policy: dict) -> None:
    lab = matrix(
        row("X25519", requested_group="X25519MLKEM768", profile="hybrid", policy_pass=True)
    )
    result = plan(inv(endpoint("ep", "X25519")), policy, lab, now=NOW)
    assert result["readiness"] == "BLOCKED"
    evaluated = result["matrix"]["rows"][0]
    assert evaluated["status"] == "SUCCESS"
    assert evaluated["reported_policy_pass"] is True
    assert evaluated["compliant"] is False and evaluated["violation"] is True
    assert any("a successful handshake is not policy compliance" in r for r in result["reasons"])
    assert item(result, "ep")["blocker_kind"] == "lab"


def test_matrix_profile_expected_group_alias_is_enforced(required_hybrid: dict) -> None:
    lab = matrix(row("X25519", expected_group="X25519MLKEM768", profile="hybrid"))
    result = plan(inv(key("kem", "ML-KEM-768")), required_hybrid, lab, now=NOW)
    assert result["readiness"] == "BLOCKED"
    assert result["matrix"]["violations"] == 1


def test_compliant_hybrid_matrix_row_is_cited_as_dependency_evidence(policy: dict) -> None:
    lab = matrix(
        row("X25519MLKEM768", requested_group="X25519MLKEM768", profile="hybrid"),
        row("X25519", profile="classical"),
    )
    result = plan(inv(endpoint("ep", "X25519")), policy, lab, now=NOW)
    assert result["readiness"] == "PARTIALLY_READY"
    ep = item(result, "ep")
    assert "Lab evidence: 1 policy-compliant matrix row(s)" in ep["dependency"]
    assert ep["blocker"] is None
    assert result["matrix"]["pq_key_establishment_rows"] == 1


def test_failed_matrix_rows_are_not_evidence_of_support(policy: dict) -> None:
    lab = matrix(row("X25519MLKEM768", status="FAILED", error_reason="no shared group"))
    result = plan(inv(endpoint("ep", "X25519")), policy, lab, now=NOW)
    ep = item(result, "ep")
    assert "no policy-compliant row demonstrating" in ep["dependency"]
    assert result["matrix"]["rows"][0]["outcome"] == "UNSUPPORTED"
    assert result["matrix"]["violations"] == 0
    assert result["readiness"] == "PARTIALLY_READY"


def test_pq_certificate_rows_count_as_authentication_evidence(policy: dict) -> None:
    lab = matrix(row("MLKEM768", certificate_type="ML-DSA-65", profile="pqc"))
    result = plan(inv(key("rsa", "RSA", key_size=3072)), policy, lab, now=NOW)
    assert result["matrix"]["pq_authentication_rows"] == 1
    assert "demonstrate post-quantum authentication" in item(result, "rsa")["dependency"]


@pytest.mark.parametrize(
    "bad",
    [
        [],
        {"rows": []},
        {"schema_version": "0.9", "rows": []},
        {"schema_version": SCHEMA_VERSION, "rows": "not-a-list"},
        {"schema_version": SCHEMA_VERSION, "rows": ["row"]},
        {"schema_version": SCHEMA_VERSION, "rows": [{}] * 2001},
        {"schema_version": SCHEMA_VERSION, "rows": [row("X25519", handshake_bytes=-5)]},
        {"schema_version": SCHEMA_VERSION, "rows": [row("X25519", handshake_bytes=True)]},
    ],
)
def test_malformed_matrix_is_rejected(policy: dict, bad: Any) -> None:
    with pytest.raises(MigrationError):
        plan(inv(key("kem", "ML-KEM-768")), policy, bad, now=NOW)


# ------------------------------------------------------------------ constraints and profiles


def test_long_confidentiality_escalates_with_explanation(policy: dict) -> None:
    result = plan(
        inv(endpoint("ep", "X25519"), key("sig", "Ed25519")),
        policy,
        constraints={"data_confidentiality_years": 25},
        now=NOW,
    )
    ep, sig = item(result, "ep"), item(result, "sig")
    assert ep["priority"] == "SHORT_TERM"
    assert "harvest-now-decrypt-later" in ep["reason"]
    assert sig["priority"] == "MEDIUM_TERM"  # signature-only: confidentiality does not apply


def test_per_asset_constraints_override_defaults(policy: dict) -> None:
    result = plan(
        inv(key("a", "RSA", key_size=3072), key("b", "RSA", key_size=3072)),
        policy,
        constraints={"assets": {"b": {"system_lifetime_years": 30}}},
        now=NOW,
    )
    assert item(result, "a")["priority"] == "MEDIUM_TERM"
    assert item(result, "b")["priority"] == "SHORT_TERM"


def test_escalation_never_reaches_immediate_and_skips_ready_assets(constrained: dict) -> None:
    constraints = {
        "data_confidentiality_years": 50,
        "system_lifetime_years": 50,
        "update_difficulty": "high",
        "measured_sizes": [
            {
                "label": "ML-KEM-768 ciphertext",
                "bytes": 1088,
                "source": "benchmark run (test fixture)",
            }
        ],
    }
    result = plan(
        inv(key("rsa", "RSA", key_size=3072), key("kem", "ML-KEM-768")),
        constrained,
        constraints=constraints,
        now=NOW,
    )
    rsa = item(result, "rsa")
    assert rsa["priority"] == "SHORT_TERM"
    assert "escalation capped at SHORT_TERM" in rsa["reason"]
    assert "update difficulty 'high'" in rsa["reason"]
    assert item(result, "kem")["priority"] == "MONITOR"


def test_default_profile_ignores_update_difficulty(policy: dict) -> None:
    result = plan(
        inv(key("rsa", "RSA", key_size=3072)),
        policy,
        constraints={"update_difficulty": "high"},
        now=NOW,
    )
    assert item(result, "rsa")["priority"] == "MEDIUM_TERM"


def test_constrained_profile_without_measurements_reports_unknown_footprint(
    constrained: dict,
) -> None:
    result = plan(
        inv(key("rsa", "RSA", key_size=3072)),
        constrained,
        constraints={"bandwidth_budget_bytes": 4096},
        now=NOW,
    )
    assert result["readiness"] == "UNKNOWN"
    assert result["footprint"]["status"] == "unknown"
    assert result["footprint"]["label"] is None
    assert result["footprint"]["within_declared_budget"] is None
    assert result["footprint"]["handshake_measurements"] == []
    rsa = item(result, "rsa")
    assert rsa["blocker_kind"] == "footprint"
    assert "requires measured byte counts" in rsa["blocker"]
    text = json.dumps(result).lower()
    assert "mtu" not in text.replace("no size, mtu or network estimate", "")


def test_constrained_footprint_uses_measured_matrix_bytes(constrained: dict) -> None:
    lab = matrix(
        row("X25519MLKEM768", handshake_bytes=3000),
        row("X25519MLKEM768", handshake_bytes=3200),
        row("X25519MLKEM768", handshake_bytes=3100),
        row("X25519MLKEM768", status="FAILED", handshake_bytes=99999),
    )
    result = plan(
        inv(endpoint("ep", "X25519")),
        constrained,
        lab,
        constraints={"bandwidth_budget_bytes": 3150},
        now=NOW,
    )
    footprint = result["footprint"]
    assert footprint["status"] == "measured"
    assert footprint["label"] == ESTIMATE_LABEL
    assert footprint["handshake_measurements"] == [
        {
            "group_rule_id": "grp-hybrid-x25519-mlkem768",
            "samples": 3,
            "median_handshake_bytes": 3100,
            "min": 3000,
            "max": 3200,
            "source": "matrix rows (local loopback lab)",
        }
    ]
    assert footprint["within_declared_budget"] is False
    assert "exceeds the declared budget of 3150 bytes" in footprint["statement"]
    assert item(result, "ep")["blocker"] is None
    assert result["readiness"] == "PARTIALLY_READY"


@pytest.mark.parametrize(
    "bad",
    [
        "high",
        {"update_difficulty": "impossible"},
        {"system_lifetime_years": -1},
        {"system_lifetime_years": True},
        {"data_confidentiality_years": "10"},
        {"bandwidth_budget_bytes": 1 << 40},
        {"mtu": 1500},
        {"assets": {"a": {"unknown": 1}}},
        {"assets": ["a"]},
        {"measured_sizes": [{"label": "x", "bytes": 10}]},
        {"measured_sizes": [{"label": "x", "bytes": -1, "source": "s"}]},
        {"measured_sizes": [{"label": "\x1b[2J", "bytes": 1, "source": "s"}]},
    ],
)
def test_invalid_constraints_are_rejected(bad: Any) -> None:
    with pytest.raises(MigrationError):
        validate_constraints(bad)


def test_planner_rejects_invalid_policy() -> None:
    with pytest.raises(PolicyError):
        plan(inv(), {"schema_version": "1.0"}, now=NOW)


# ------------------------------------------------------------------ contract properties


def test_plan_contract_determinism_no_score_and_no_input_mutation(policy: dict) -> None:
    inventory = inv(
        endpoint("ep", "X25519"),
        key("rsa", "RSA", key_size=2048),
        key("kem", "ML-KEM-768"),
        key("odd", "FrodoKEM-640"),
    )
    lab = matrix(row("X25519MLKEM768", handshake_bytes=3000))
    constraints = {"system_lifetime_years": 20}
    snapshot = copy.deepcopy((inventory, policy, lab, constraints))
    first = plan(inventory, policy, lab, constraints, now=NOW)
    second = plan(inventory, policy, lab, constraints, now=NOW)
    assert first == second
    assert (inventory, policy, lab, constraints) == snapshot
    json.dumps(first)
    assert first["schema_version"] == SCHEMA_VERSION
    assert first["readiness"] in READINESS
    assert "score" not in " ".join(walk_keys(first)).lower()
    for entry in first["items"]:
        assert REQUIRED_ITEM_FIELDS <= set(entry)
        assert entry["priority"] in PRIORITIES
        assert entry["reason"].startswith(f"Priority {entry['priority']}:")
    ranks = [PRIORITIES.index(i["priority"]) for i in first["items"]]
    assert ranks == sorted(ranks)
    assert "broken" not in json.dumps(first).lower()


# ------------------------------------------------------------------ markdown rendering


def test_markdown_renders_plan_and_escapes_untrusted_text(policy: dict) -> None:
    evil = key("<script>alert(1)</script>|[x](http://evil.example)", "RSA", key_size=2048)
    result = plan(inv(evil, key("kem", "ML-KEM-768")), policy, now=NOW)
    text = render_markdown(result)
    assert text.startswith("# Migration plan\n")
    assert "Readiness: **BLOCKED**" in text
    assert "<script>" not in text
    assert "](http" not in text
    assert "\\<script\\>" in text and "\\|" in text
    assert "No numerical score" in text
    for field in ("priority", "dependency", "recommended_test", "blocker", "next_action"):
        assert f"| {field} |" in text
    assert render_markdown(result) == text


def test_markdown_includes_footprint_estimate_label(constrained: dict) -> None:
    lab = matrix(row("X25519MLKEM768", handshake_bytes=3000))
    text = render_markdown(plan(inv(endpoint()), constrained, lab, now=NOW))
    assert "ESTIMATE: derived only from byte counts measured in the local lab" in text
    assert "median 3000 bytes over 1 sample(s)" in text


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        {"schema_version": SCHEMA_VERSION},
        {"schema_version": SCHEMA_VERSION, "readiness": "GREAT", "items": []},
    ],
)
def test_markdown_rejects_non_plans(bad: Any) -> None:
    with pytest.raises(MigrationError):
        render_markdown(bad)
