"""End-to-end lab pipeline over the synthetic fictional-organization scenario.

scenario -> inventory + CBOM -> policy -> capabilities -> interoperability matrix ->
benchmarks -> migration plan -> offline HTML report. Every file in RESULTS is produced by this
run from local measurements; nothing is copied from a previous run.
"""

from __future__ import annotations

import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptoagility import benchmark, cbom, inventory, migration, policy, reporting, scenario, tls
from cryptoagility.cli import read_yaml, write_json, write_text

DEFAULT_CONSTRAINTS = scenario.ROOT / "scenario" / "constraints.yaml"


def _stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def run(
    results: Path,
    *,
    policy_path: Path,
    constraints_path: Path | None = None,
    iterations: int = 20,
    warmups: int = 3,
    include_benchmark: bool = True,
    log: Callable[[str], None] = _stderr,
) -> dict[str, Any]:
    results = Path(results)
    if results.is_symlink() or (results.exists() and not results.is_dir()):
        raise ValueError("results must be a directory, not a symlink or file")
    results.mkdir(parents=True, exist_ok=True)
    for stale in reporting.EVIDENCE_FILES.values():
        (results / stale).unlink(missing_ok=True)
    pol = policy.load_policy(policy_path)
    constraints = read_yaml(constraints_path or DEFAULT_CONSTRAINTS)
    started = time.monotonic()

    def step(name: str) -> None:
        log(f"[{time.monotonic() - started:6.1f}s] {name}")

    with tempfile.TemporaryDirectory(prefix="cryptoagility-lab-") as tmp:
        step("generating synthetic scenario (public certificates only)")
        source = scenario.generate(Path(tmp) / "fictional-org")
        step("discovering crypto assets")
        inv = inventory.scan(source)
    write_json(results / "inventory.json", inv.to_dict())
    write_json(results / "cbom.json", cbom.export_json(inv))
    write_text(results / "cbom.csv", cbom.export_csv(inv))

    step("evaluating policy")
    evaluation = policy.evaluate(inv, pol)
    write_json(results / "policy.json", evaluation)

    step("probing OpenSSL capabilities")
    caps = tls.capabilities()
    write_json(results / "capabilities.json", caps)

    step("running loopback interoperability matrix")
    with tempfile.TemporaryDirectory(prefix="cryptoagility-matrix-") as work:
        matrix = tls.run_matrix(Path(work), caps=caps)
    write_json(results / "matrix.json", matrix)

    if include_benchmark:
        step(f"benchmarking ({iterations} iterations, {warmups} warmups)")
        with tempfile.TemporaryDirectory(prefix="cryptoagility-bench-") as work:
            bench = benchmark.run_benchmarks(Path(work), iterations, warmups, caps=caps)
        write_json(results / "benchmark.json", bench)

    step("planning migration")
    plan = migration.plan(inv, pol, matrix, constraints)
    write_json(results / "migration-plan.json", plan)
    write_text(results / "migration-plan.md", migration.render_markdown(plan))

    step("rendering offline report")
    report = reporting.render_report(results, results / "report.html")
    step("done")
    statuses: dict[str, int] = {}
    for row in matrix["rows"]:
        statuses[row["status"]] = statuses.get(row["status"], 0) + 1
    return {
        "results": str(results),
        "report": str(report),
        "assets": len(inv.assets),
        "inventory_errors": len(inv.errors),
        "policy_outcomes": evaluation["summary"]["by_outcome"],
        "matrix_statuses": statuses,
        "readiness": plan["readiness"],
        "benchmark": include_benchmark,
    }
