"""End-to-end lab pipeline over the synthetic fictional-organization scenario.

scenario -> inventory + CBOM -> policy -> capabilities -> interoperability matrix ->
benchmarks -> migration plan -> offline HTML report. Every file in RESULTS is produced by this
run from local measurements; nothing is copied from a previous run.
"""

from __future__ import annotations

import fcntl
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptoagility import benchmark, cbom, inventory, migration, policy, reporting, scenario, tls
from cryptoagility.cli import read_yaml, write_json, write_text

DEFAULT_CONSTRAINTS = scenario.ROOT / "scenario" / "constraints.yaml"
REPORT_NAME = "report.html"
EXTRA_OUTPUTS = ("cbom.csv", "migration-plan.md", REPORT_NAME)
PUBLISH_LOCK = ".lab-publish.lock"


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
    pol = policy.load_policy(policy_path)
    constraints = read_yaml(constraints_path or DEFAULT_CONSTRAINTS)
    results.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".lab-staging-", dir=results))
    try:
        summary = _run(staging, pol, constraints, iterations, warmups, include_benchmark, log)
        _publish(staging, results, log)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    summary["results"] = str(results)
    summary["report"] = str(results / REPORT_NAME)
    return summary


@contextmanager
def _exclusive(results: Path) -> Iterator[None]:
    fd = os.open(results / PUBLISH_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _publish(staging: Path, results: Path, log: Callable[[str], None] = _stderr) -> None:
    """Swap in a complete new result set, restoring the previous one if any step fails.

    Each file moves with an atomic rename, but the set as a whole is not switched atomically,
    so a concurrent reader can briefly see a mix; a failed swap never leaves one behind.
    Concurrent lab runs on one results directory publish one at a time under a file lock.
    """
    with _exclusive(results):
        _swap(staging, results, log)


def _swap(staging: Path, results: Path, log: Callable[[str], None]) -> None:
    produced = sorted(p.name for p in staging.iterdir())
    managed = sorted({*reporting.EVIDENCE_FILES.values(), *EXTRA_OUTPUTS, *produced})
    backup = Path(tempfile.mkdtemp(prefix=".lab-previous-", dir=results))
    moved: list[str] = []
    placed: list[str] = []
    try:
        for name in managed:
            if (results / name).is_symlink() or (results / name).exists():
                os.replace(results / name, backup / name)
                moved.append(name)
        for name in produced:
            os.replace(staging / name, results / name)
            placed.append(name)
    except BaseException:
        for name in placed:
            _remove(results / name)
        for name in moved:
            os.replace(backup / name, results / name)
        backup.rmdir()
        raise
    shutil.rmtree(backup, ignore_errors=True)
    if backup.exists():
        log(f"warning: new results are published but the old copy in {backup} was not removed")


def _remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def _run(
    results: Path,
    pol: dict[str, Any],
    constraints: Any,
    iterations: int,
    warmups: int,
    include_benchmark: bool,
    log: Callable[[str], None],
) -> dict[str, Any]:
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
    report = reporting.render_report(results, results / REPORT_NAME)
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
