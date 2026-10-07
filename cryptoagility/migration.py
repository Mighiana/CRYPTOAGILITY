"""Explainable, policy-driven migration planning.

The planner consumes an inventory and a validated policy, plus optional lab evidence (a TLS
interoperability matrix) and declared constraints. It never modifies targets, never produces a
numerical score, and never treats a successful negotiation as policy compliance: every matrix
row is re-evaluated against the policy.

Readiness, from best to worst:

- READY: every asset has complete evidence and meets a policy ready outcome, and no lab evidence
  contradicts the policy.
- PARTIALLY_READY: evidence is complete and nothing blocks migration, but some assets still
  require migration work.
- UNKNOWN: unknown assets, missing evidence or discovery errors prevent a readiness decision.
- BLOCKED: a dependency is below the policy minimum, or lab evidence shows a negotiation that
  succeeded but violated policy (for example a required hybrid group falling back to X25519).
"""

from __future__ import annotations

import re
from datetime import datetime
from statistics import median
from typing import Any

from cryptoagility.models import SCHEMA_VERSION, Inventory
from cryptoagility.policy import (
    DIFFICULTIES,
    EVIDENCE_COMPLETE,
    PRIORITIES,
    SUCCESS_STATUSES,
    PolicyEngine,
    PolicyError,
    evaluate,
)

READINESS = ("READY", "PARTIALLY_READY", "UNKNOWN", "BLOCKED")
BLOCKER_KINDS = ("evidence", "policy", "lab", "footprint")
MAX_MATRIX_ROWS = 2000
MAX_ROW_TEXT = 256
MAX_YEARS = 200
MAX_BYTES = 1 << 32
ESTIMATE_LABEL = (
    "ESTIMATE: derived only from byte counts measured in the local lab; not network, MTU, "
    "latency or field evidence."
)
_CONSTRAINT_KEYS = (
    "data_confidentiality_years",
    "system_lifetime_years",
    "update_difficulty",
    "bandwidth_budget_bytes",
)
_PRIORITY_RANK = {priority: rank for rank, priority in enumerate(PRIORITIES)}
_ESCALATION_CAP = "SHORT_TERM"


class MigrationError(PolicyError):
    """Raised for malformed planner inputs (matrix, constraints or plan)."""


# --------------------------------------------------------------------------- input validation


def _bounded_int(value: Any, where: str, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= high:
        raise MigrationError(f"{where} must be an integer between 0 and {high}")
    return value


def _short_text(value: Any, where: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > MAX_ROW_TEXT
        or not value.isprintable()
    ):
        raise MigrationError(f"{where} must be a short printable string")
    return value.strip()


def _constraint_block(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MigrationError(f"{where} must be a mapping")
    unknown = sorted(str(key)[:40] for key in value if key not in _CONSTRAINT_KEYS)
    if unknown:
        raise MigrationError(f"{where}: unknown keys {unknown}")
    block: dict[str, Any] = {}
    for key in ("data_confidentiality_years", "system_lifetime_years"):
        if key in value:
            block[key] = _bounded_int(value[key], f"{where}.{key}", MAX_YEARS)
    if "update_difficulty" in value:
        if value["update_difficulty"] not in DIFFICULTIES:
            raise MigrationError(f"{where}.update_difficulty must be one of {DIFFICULTIES}")
        block["update_difficulty"] = value["update_difficulty"]
    if "bandwidth_budget_bytes" in value:
        block["bandwidth_budget_bytes"] = _bounded_int(
            value["bandwidth_budget_bytes"], f"{where}.bandwidth_budget_bytes", MAX_BYTES
        )
    return block


def validate_constraints(constraints: Any) -> dict[str, Any]:
    """Validate declared constraints. All keys are optional; unknown keys are rejected.

    Shape: {data_confidentiality_years, system_lifetime_years, update_difficulty,
    bandwidth_budget_bytes, assets: {asset_id: {same keys}}, measured_sizes: [{label, bytes,
    source}]}. Declared values are operator statements, not measurements; measured_sizes must
    come from a real measurement (for example benchmark output) and name its source.
    """
    if constraints is None:
        return {"defaults": {}, "assets": {}, "measured_sizes": []}
    if not isinstance(constraints, dict):
        raise MigrationError("constraints must be a mapping")
    extra = {key: constraints[key] for key in ("assets", "measured_sizes") if key in constraints}
    defaults = _constraint_block(
        {k: v for k, v in constraints.items() if k not in extra}, "constraints"
    )
    assets: dict[str, dict[str, Any]] = {}
    raw_assets = extra.get("assets", {})
    if not isinstance(raw_assets, dict) or len(raw_assets) > MAX_MATRIX_ROWS:
        raise MigrationError("constraints.assets must be a mapping of asset_id to constraints")
    for asset_id, block in raw_assets.items():
        if not isinstance(asset_id, str) or not 0 < len(asset_id) <= MAX_ROW_TEXT:
            raise MigrationError("constraints.assets keys must be asset ids")
        assets[asset_id] = _constraint_block(block, "constraints.assets[...]")
    sizes = []
    raw_sizes = extra.get("measured_sizes", [])
    if not isinstance(raw_sizes, list) or len(raw_sizes) > MAX_MATRIX_ROWS:
        raise MigrationError("constraints.measured_sizes must be a list")
    for entry in raw_sizes:
        if not isinstance(entry, dict) or set(entry) != {"label", "bytes", "source"}:
            raise MigrationError("measured_sizes entries need exactly label, bytes, source")
        sizes.append(
            {
                "label": _short_text(entry["label"], "measured_sizes.label"),
                "bytes": _bounded_int(entry["bytes"], "measured_sizes.bytes", MAX_BYTES),
                "source": _short_text(entry["source"], "measured_sizes.source"),
            }
        )
    return {"defaults": defaults, "assets": assets, "measured_sizes": sizes}


def _validate_matrix(matrix: Any) -> list[dict[str, Any]]:
    if not isinstance(matrix, dict):
        raise MigrationError("matrix must be a mapping")
    if matrix.get("schema_version") != SCHEMA_VERSION:
        raise MigrationError("Unsupported matrix schema version")
    rows = matrix.get("rows")
    if not isinstance(rows, list) or len(rows) > MAX_MATRIX_ROWS:
        raise MigrationError(f"matrix.rows must be a list of at most {MAX_MATRIX_ROWS} rows")
    for row in rows:
        if not isinstance(row, dict):
            raise MigrationError("matrix rows must be mappings")
    return rows


# --------------------------------------------------------------------------- lab evidence


def _row_label(row: dict[str, Any], index: int) -> str:
    parts = []
    for key in ("profile", "client", "server"):
        value = row.get(key)
        if isinstance(value, str) and value.isprintable() and value.strip():
            parts.append(value.strip()[:60])
    return f"row {index}" + (f" ({' / '.join(parts)})" if parts else "")


def _matrix_evidence(engine: PolicyEngine, rows: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = []
    for index, row in enumerate(rows):
        observation = dict(row)
        if observation.get("requested_group") is None and "expected_group" in row:
            observation["requested_group"] = row["expected_group"]
        result = engine.negotiation(observation)
        status = row.get("status")
        succeeded = isinstance(status, str) and status.strip().upper() in SUCCESS_STATUSES
        cert = engine.classify("algorithms", row.get("certificate_type"))
        handshake = row.get("handshake_bytes")
        if handshake is not None:
            handshake = _bounded_int(handshake, f"matrix.rows[{index}].handshake_bytes", MAX_BYTES)
        elif row.get("handshake_bytes_read") is not None:
            handshake = sum(
                _bounded_int(row.get(key), f"matrix.rows[{index}].{key}", MAX_BYTES)
                for key in ("handshake_bytes_read", "handshake_bytes_written")
            )
        reported = row.get("policy_pass")
        evaluated.append(
            {
                "row": _row_label(row, index),
                "status": "SUCCESS" if succeeded else "FAILED",
                "outcome": result["outcome"],
                "compliant": result["compliant"],
                "violation": succeeded
                and not result["compliant"]
                and result["evidence_status"] == EVIDENCE_COMPLETE,
                "group_rule_id": result["group_rule_id"],
                "group_quantum_vulnerable": result["group_quantum_vulnerable"],
                "certificate_rule_id": cert["rule_id"] if cert else None,
                "certificate_quantum_vulnerable": cert["quantum_vulnerable"] if cert else None,
                "handshake_bytes": handshake if succeeded else None,
                "reported_policy_pass": reported if isinstance(reported, bool) else None,
                "reason": result["reasons"][0],
            }
        )
    return {
        "rows": evaluated,
        "violations": [r for r in evaluated if r["violation"]],
        "pq_key_establishment": [
            r for r in evaluated if r["compliant"] and r["group_quantum_vulnerable"] is False
        ],
        "pq_authentication": [
            r for r in evaluated if r["compliant"] and r["certificate_quantum_vulnerable"] is False
        ],
    }


def _footprint(lab: dict[str, Any] | None, constraints: dict[str, Any]) -> dict[str, Any]:
    by_group: dict[str, list[int]] = {}
    candidate_groups: set[str] = set()
    if lab:
        for row in lab["rows"]:
            if row["compliant"] and row["handshake_bytes"] is not None and row["group_rule_id"]:
                by_group.setdefault(row["group_rule_id"], []).append(row["handshake_bytes"])
                if row["group_quantum_vulnerable"] is False:
                    candidate_groups.add(row["group_rule_id"])
    measurements = [
        {
            "group_rule_id": group,
            "samples": len(values),
            "median_handshake_bytes": median(values),
            "min": min(values),
            "max": max(values),
            "source": "matrix rows (local loopback lab)",
        }
        for group, values in sorted(by_group.items())
    ]
    sizes = constraints["measured_sizes"]
    budget = constraints["defaults"].get("bandwidth_budget_bytes")
    status = "measured" if measurements or sizes else "unknown"
    candidate_measured = bool(candidate_groups or sizes)
    within = None
    if budget is not None and measurements:
        within = all(m["max"] <= budget for m in measurements)
    if status == "unknown":
        statement = (
            "Footprint unknown: no measured byte counts were supplied, so no size or "
            "bandwidth estimate is made."
        )
    elif budget is None:
        statement = (
            f"{ESTIMATE_LABEL} No bandwidth budget was declared, so no budget comparison is made."
        )
    elif within is None:
        statement = (
            f"{ESTIMATE_LABEL} No measured handshake bytes, so the declared budget "
            "cannot be compared."
        )
    else:
        statement = (
            f"{ESTIMATE_LABEL} Largest measured handshake "
            f"{'fits within' if within else 'exceeds'} the declared budget of "
            f"{budget} bytes."
        )
    if status == "measured" and not candidate_measured:
        statement += (
            " Only quantum-vulnerable handshakes were measured, so the footprint of a hybrid "
            "or post-quantum candidate profile is unknown."
        )
    return {
        "status": status,
        "candidate_measured": candidate_measured,
        "label": ESTIMATE_LABEL if status == "measured" else None,
        "statement": statement,
        "handshake_measurements": measurements,
        "measured_sizes": sizes,
        "declared_budget_bytes": budget,
        "within_declared_budget": within,
    }


# --------------------------------------------------------------------------- planning


def _escalations(
    finding: dict[str, Any], constraints: dict[str, Any], profile: dict[str, Any]
) -> list[str]:
    if finding["quantum_vulnerable"] is not True:
        return []
    usages = finding["quantum_vulnerable_usages"]
    factors = []
    confidentiality = constraints.get("data_confidentiality_years")
    if (
        confidentiality is not None
        and "key_establishment" in usages
        and confidentiality >= profile["long_confidentiality_years"]
    ):
        factors.append(
            f"declared data confidentiality of {confidentiality} years meets the profile "
            f"threshold of {profile['long_confidentiality_years']} years "
            "(harvest-now-decrypt-later exposure for quantum-vulnerable key establishment)"
        )
    lifetime = constraints.get("system_lifetime_years")
    if lifetime is not None and lifetime >= profile["long_system_lifetime_years"]:
        factors.append(
            f"declared system lifetime of {lifetime} years meets the profile threshold of "
            f"{profile['long_system_lifetime_years']} years"
        )
    difficulty = constraints.get("update_difficulty")
    if difficulty is not None and difficulty in profile["escalate_update_difficulty"]:
        factors.append(
            f"declared update difficulty '{difficulty}' means replacement takes "
            "longer to roll out under this profile"
        )
    return factors


def _escalate(priority: str, steps: int) -> str:
    rank = _PRIORITY_RANK[priority]
    cap = _PRIORITY_RANK[_ESCALATION_CAP]
    if rank <= cap or steps == 0:
        return priority
    return PRIORITIES[max(cap, rank - steps)]


def _lab_dependency(
    usages: list[str], lab: dict[str, Any] | None, dependency: list[str], tests: list[str]
) -> str | None:
    needs = (
        ("key_establishment", "pq_key_establishment", "quantum-resistant key establishment"),
        ("signature", "pq_authentication", "post-quantum authentication"),
    )
    for usage, key, label in needs:
        if usage not in usages:
            continue
        if lab is None:
            dependency.append(f"No lab matrix supplied: {label} target is untested")
            tests.insert(0, f"Run the loopback matrix with a policy-compliant {label} profile")
            continue
        rows = lab[key]
        if rows:
            dependency.append(
                f"Lab evidence: {len(rows)} policy-compliant matrix row(s) "
                f"demonstrate {label}, first {rows[0]['row']}"
            )
        else:
            dependency.append(f"Lab matrix has no policy-compliant row demonstrating {label}")
            tests.insert(
                0,
                f"Re-run the loopback matrix with a policy-compliant {label} "
                "profile and investigate failures",
            )
    if lab and lab["violations"]:
        first = lab["violations"][0]
        return (
            f"Lab: {first['row']} negotiated successfully but failed policy "
            f"({first['outcome']}): {first['reason']}"
        )
    return None


def _item(
    finding: dict[str, Any],
    policy: dict[str, Any],
    constraints: dict[str, Any],
    lab: dict[str, Any] | None,
    footprint: dict[str, Any],
) -> dict[str, Any]:
    planning = policy["planning"]
    profile = policy["profile"]
    outcome = finding["outcome"]
    type_spec = policy["asset_types"].get(finding["asset_type"])
    complete = finding["evidence_status"] == EVIDENCE_COMPLETE
    ready = complete and outcome in planning["ready_outcomes"]
    dependency = [
        type_spec["dependency"]
        if type_spec
        else "Unknown: asset type is not recognised, so dependencies cannot be determined"
    ]
    tests = list(finding["recommended_tests"])
    if type_spec:
        tests.append(type_spec["recommended_test"])
    blocker: str | None = None
    kind: str | None = None

    if not complete:
        priority = "UNKNOWN"
        basis = (
            f"evidence is {finding['evidence_status']}; the policy fails closed and no "
            "migration priority can be assigned until evidence is complete"
        )
        blocker, kind = "Evidence gap: " + finding["reasons"][0], "evidence"
        tests.insert(0, policy["unknown_evidence"]["recommended_test"])
        next_action = planning["unknown_next_action"]
    else:
        base = planning["outcome_priority"][outcome]
        factors = [] if ready else _escalations(finding, constraints, profile)
        priority = _escalate(base, len(factors))
        basis = f"outcome {outcome} maps to {base} under policy {policy['policy_id']}"
        if priority != base:
            basis += (
                f"; escalated to {priority} (escalation capped at {_ESCALATION_CAP}) "
                "because " + "; ".join(factors)
            )
        elif factors:
            basis += (
                "; constraint factors noted but already at or above the escalation cap: "
                + "; ".join(factors)
            )
        next_action = planning["next_actions"][outcome]
        if outcome not in policy["compliant_outcomes"]:
            blocker, kind = f"Policy: {outcome}. {finding['reasons'][0]}", "policy"
        if not ready and finding["quantum_vulnerable"]:
            lab_blocker = _lab_dependency(
                finding["quantum_vulnerable_usages"], lab, dependency, tests
            )
            if blocker is None and lab_blocker is not None:
                blocker, kind = lab_blocker, "lab"
            if (
                blocker is None
                and profile["require_footprint_evidence"]
                and not footprint["candidate_measured"]
            ):
                blocker = (
                    f"Footprint evidence absent: profile {profile['name']} requires "
                    "measured byte counts for a hybrid or post-quantum candidate before a "
                    "target profile is selected"
                )
                kind = "footprint"
                tests.insert(
                    0,
                    "Run the local benchmark and loopback matrix to measure key, "
                    "signature and handshake bytes for the candidate profiles",
                )
    return {
        "asset_id": finding["asset_id"],
        "asset_type": finding["asset_type"],
        "current_algorithm": finding["current_algorithm"],
        "outcome": outcome,
        "evidence_status": finding["evidence_status"],
        "ready": ready,
        "priority": priority,
        "reason": f"Priority {priority}: {basis}. Evidence: {finding['reasons'][0]}",
        "dependency": "; ".join(dependency),
        "recommended_test": tests[0] if tests else policy["unknown_evidence"]["recommended_test"],
        "blocker": blocker,
        "blocker_kind": kind,
        "next_action": next_action,
        "migration_options": finding["migration_options"],
    }


def _readiness(
    items: list[dict[str, Any]], inventory: Inventory, lab: dict[str, Any] | None
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    errors = inventory.errors if isinstance(inventory.errors, list) else [{}]
    hard = [i for i in items if i["blocker_kind"] in ("policy", "lab")]
    unknown = [i for i in items if i["blocker_kind"] in ("evidence", "footprint")]
    pending = [i for i in items if not i["ready"]]
    violations = lab["violations"] if lab else []
    sources = {
        getattr(a, "asset_id", None): str(getattr(a, "source", "")) for a in inventory.assets
    }

    def names(group: list[dict[str, Any]]) -> str:
        return ", ".join(
            f"{sources.get(i['asset_id']) or i['asset_id']} ({i['current_algorithm']})"
            for i in group[:10]
        )

    if violations:
        reasons.append(
            f"{len(violations)} matrix row(s) negotiated successfully but failed "
            "policy; a successful handshake is not policy compliance."
        )
    if hard:
        reasons.append(f"{len(hard)} asset(s) blocked by policy or lab evidence: " + names(hard))
    if unknown:
        reasons.append(
            f"{len(unknown)} asset(s) have missing, unrecognised or footprint "
            "evidence gaps: " + names(unknown)
        )
    if errors:
        reasons.append(
            f"{len(errors)} discovery error(s) recorded; inventory coverage is incomplete."
        )
    if not items:
        reasons.append("Inventory contains no assets; readiness cannot be determined.")
    if hard or violations:
        return "BLOCKED", reasons
    if unknown or errors or not items:
        return "UNKNOWN", reasons
    if pending:
        reasons.append(
            f"{len(items) - len(pending)} of {len(items)} asset(s) meet a policy "
            f"ready outcome; {len(pending)} still require migration work."
        )
        return "PARTIALLY_READY", reasons
    reasons.append(
        f"All {len(items)} asset(s) have complete evidence and meet a policy ready outcome."
    )
    return "READY", reasons


def plan(
    inventory: Inventory,
    policy: dict[str, Any],
    matrix: dict[str, Any] | None = None,
    constraints: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build an explainable migration plan; inputs are never modified."""
    engine = PolicyEngine(policy, now=now)
    validated = engine.policy
    checked = validate_constraints(constraints)
    evaluation = evaluate(inventory, validated, now=engine.now)
    lab = _matrix_evidence(engine, _validate_matrix(matrix)) if matrix is not None else None
    footprint = _footprint(lab, checked)
    items = []
    for finding in evaluation["findings"]:
        merged = dict(checked["defaults"])
        merged.update(checked["assets"].get(finding["asset_id"], {}))
        items.append(_item(finding, validated, merged, lab, footprint))
    items.sort(key=lambda i: (_PRIORITY_RANK[i["priority"]], i["asset_id"]))
    readiness, reasons = _readiness(items, inventory, lab)
    if not footprint["candidate_measured"] and validated["profile"]["require_footprint_evidence"]:
        reasons.append(footprint["statement"])
    by_priority = {priority: 0 for priority in PRIORITIES}
    for item in items:
        by_priority[item["priority"]] += 1
    return {
        "schema_version": SCHEMA_VERSION,
        "policy_id": validated["policy_id"],
        "policy_digest": engine.digest,
        "profile": validated["profile"]["name"],
        "generated_at": engine.now.isoformat(),
        "readiness": readiness,
        "reasons": reasons,
        "summary": {
            "total_assets": len(items),
            "ready_assets": sum(1 for i in items if i["ready"]),
            "by_priority": by_priority,
            "by_outcome": evaluation["summary"]["by_outcome"],
            "inventory_errors": evaluation["summary"]["inventory_errors"],
        },
        "items": items,
        "matrix": None
        if lab is None
        else {
            "rows": lab["rows"],
            "violations": len(lab["violations"]),
            "pq_key_establishment_rows": len(lab["pq_key_establishment"]),
            "pq_authentication_rows": len(lab["pq_authentication"]),
        },
        "constraints": checked,
        "footprint": footprint,
    }


# --------------------------------------------------------------------------- markdown

_MD_SPECIAL = re.compile(r"([\\\x60*_{}\[\]()<>#+!|~])")


def _md(value: Any) -> str:
    text = value if isinstance(value, str) else "" if value is None else str(value)
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    return _MD_SPECIAL.sub(r"\\\1", text.replace("&", "&amp;"))


def render_markdown(plan_result: dict[str, Any]) -> str:
    """Render a plan as Markdown; all untrusted text is escaped (no raw HTML or links)."""
    if (
        not isinstance(plan_result, dict)
        or plan_result.get("schema_version") != SCHEMA_VERSION
        or plan_result.get("readiness") not in READINESS
        or not isinstance(plan_result.get("items"), list)
    ):
        raise MigrationError("render_markdown() requires a plan produced by plan()")
    lines = [
        "# Migration plan",
        "",
        f"- Readiness: **{_md(plan_result['readiness'])}**",
        f"- Policy: {_md(plan_result.get('policy_id'))} "
        f"(profile {_md(plan_result.get('profile'))})",
        f"- Generated: {_md(plan_result.get('generated_at'))}",
        "- No numerical score is produced; priorities are explained per item.",
        "",
        "## Reasons",
        "",
    ]
    lines += [f"- {_md(reason)}" for reason in plan_result.get("reasons", [])] or ["- None"]
    footprint = plan_result.get("footprint") or {}
    lines += ["", "## Footprint", "", _md(footprint.get("statement", "Footprint unknown."))]
    for m in footprint.get("handshake_measurements", []):
        lines.append(
            f"- {_md(m['group_rule_id'])}: median {_md(m['median_handshake_bytes'])} "
            f"bytes over {_md(m['samples'])} sample(s) ({_md(m['source'])})"
        )
    for size in footprint.get("measured_sizes", []):
        lines.append(f"- {_md(size['label'])}: {_md(size['bytes'])} bytes ({_md(size['source'])})")
    lines += ["", "## Items", ""]
    if not plan_result["items"]:
        lines.append("No assets in inventory.")
    for item in plan_result["items"]:
        lines += [f"### {_md(item['asset_id'])}", "", "| Field | Value |", "|---|---|"]
        for key in (
            "priority",
            "outcome",
            "current_algorithm",
            "evidence_status",
            "reason",
            "dependency",
            "recommended_test",
            "blocker",
            "next_action",
        ):
            lines.append(f"| {key} | {_md(item.get(key)) or '-'} |")
        options = item.get("migration_options") or []
        if options:
            lines += ["", "Migration options:", ""]
            lines += [f"- {_md(option)}" for option in options]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
