"""cryptoagility command line: inventory, policy, TLS lab, benchmarks, planning and reports.

Exit codes: 0 success; 1 gate failed (--fail-on-noncompliant, --fail-on-blocked, failed
handshake); 2 invalid input; 3 requested crypto profile unsupported locally (never downgraded).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import yaml

from cryptoagility import __version__, benchmark, cbom, inventory, migration, openssl, policy, tls
from cryptoagility.models import Inventory

EXIT_GATE, EXIT_INPUT, EXIT_UNSUPPORTED = 1, 2, 3
DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "policies" / "default.yaml"
MAX_INPUT_BYTES = 16 * 1024 * 1024


class CLIError(Exception):
    """User-facing input error (exit code 2)."""


# --------------------------------------------------------------------------- I/O helpers


def _regular_file(path: Path) -> Path:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise CLIError(f"{path}: not a regular file")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise CLIError(f"{path}: larger than {MAX_INPUT_BYTES} bytes")
    return path


def read_json(path: Path) -> Any:
    try:
        return json.loads(_regular_file(path).read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CLIError(f"{path}: not valid JSON ({exc.__class__.__name__})") from exc


def read_yaml(path: Path | None) -> Any:
    if path is None:
        return None
    try:
        data = yaml.safe_load(_regular_file(path).read_text(encoding="utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise CLIError(f"{path}: not valid YAML/JSON") from exc
    return data if data is not None else {}


def read_inventory(path: Path) -> Inventory:
    data = read_json(path)
    if not isinstance(data, dict):
        raise CLIError(f"{path}: not a CryptoAgility inventory")
    if data.get("cbom_format") == cbom.CBOM_FORMAT:
        raise CLIError(f"{path}: this is a CBOM export; pass inventory.json instead")
    try:
        return Inventory.from_dict(data)
    except (KeyError, TypeError, ValueError) as exc:
        raise CLIError(f"{path}: not a CryptoAgility inventory ({exc})") from exc


def write_text(path: Path, text: str) -> Path:
    """Atomic write that refuses to replace a symlink."""
    path = Path(path)
    if path.is_symlink():
        raise CLIError(f"{path}: refusing to overwrite a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path


def write_json(path: Path, data: Any) -> Path:
    return write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def emit(data: Any, output: Path | None, as_json: bool, text: Callable[[], str]) -> None:
    if output is not None:
        write_json(output, data)
        print(f"wrote {output}", file=sys.stderr)
    if as_json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        sys.stdout.write(text())


def _table(header: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    cells = [["-" if c is None else str(c) for c in row] for row in rows]
    widths = [max([len(h), *(len(r[i]) for r in cells)]) for i, h in enumerate(header)]
    lines = [
        "  ".join(h.ljust(w) for h, w in zip(header, widths, strict=True)),
        "  ".join("-" * w for w in widths),
    ]
    lines += ["  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)).rstrip() for r in cells]
    return "\n".join(lines) + "\n"


def _counts(title: str, counts: dict[str, int]) -> str:
    return f"{title}: " + ", ".join(f"{k}={v}" for k, v in counts.items() if v) + "\n"


# --------------------------------------------------------------------------- renderers


def render_inventory(inv: Inventory) -> str:
    rows = [
        (a.asset_type, a.algorithm_family, a.algorithm, a.key_size or a.parameter_set, a.source)
        for a in inv.assets
    ]
    text = _table(("type", "family", "algorithm", "size/params", "source"), rows)
    text += f"\n{len(inv.assets)} assets, {len(inv.errors)} discovery errors\n"
    for err in inv.errors:
        text += f"  error {err.get('source')}: {err.get('code')} - {err.get('message')}\n"
    return text


def render_policy(result: dict[str, Any]) -> str:
    flagged = [f for f in result["findings"] if not f["compliant"]]
    rows = [
        (f["outcome"], f["current_algorithm"], f["source"], f["reasons"][0][:90]) for f in flagged
    ]
    text = _table(("outcome", "algorithm", "source", "reason"), rows) if rows else ""
    summary = result["summary"]
    text += "\n" + _counts("outcomes", summary["by_outcome"])
    text += (
        f"{summary['compliant']}/{summary['total_assets']} compliant, "
        f"{summary['quantum_vulnerable']} quantum-vulnerable, "
        f"{summary['evidence_incomplete']} with incomplete evidence\n"
    )
    return text


def render_matrix(result: dict[str, Any]) -> str:
    verdict = {True: "pass", False: "FAIL", None: "-"}
    rows = [
        (
            r["server"],
            r["client"],
            r["status"],
            r["negotiated_group"],
            r["certificate_type"],
            r["handshake_bytes_read"],
            verdict[r["policy_pass"]],
            r["error_reason"],
        )
        for r in result["rows"]
    ]
    text = _table(
        ("server", "client", "status", "group", "cert", "bytes read", "policy", "reason"), rows
    )
    version = result["environment"].get("openssl", {}).get("version")
    text += (
        f"\n{version}; TLS policy {result['policy'].get('name')}. A successful "
        "handshake and a policy pass are judged separately.\n"
    )
    return text


def render_plan(result: dict[str, Any], sources: dict[str, str]) -> str:
    rows = [
        (
            i["priority"],
            i["outcome"],
            i["current_algorithm"],
            sources.get(i["asset_id"], i["asset_id"]),
            i["next_action"][:70],
        )
        for i in result["items"]
        if not i["ready"]
    ]
    text = _table(("priority", "outcome", "algorithm", "source", "next action"), rows)
    text += f"\nreadiness: {result['readiness']}\n"
    text += "".join(f"  - {reason}\n" for reason in result["reasons"])
    text += _counts("priorities", result["summary"]["by_priority"])
    return text


def render_capabilities(caps: dict[str, Any]) -> str:
    lines = [
        f"OpenSSL: {caps.get('openssl', {}).get('version')}",
        "providers: " + ", ".join(str(p.get("name", "?")) for p in caps.get("providers", [])),
        "TLS 1.3 groups: " + ", ".join(caps.get("tls13_groups", [])),
    ]
    for name, info in caps.get("profiles", {}).items():
        state = "supported" if info.get("supported") else "UNSUPPORTED"
        missing = "; ".join(info.get("missing", []))
        lines.append(f"profile {name}: {state}" + (f" ({missing})" if missing else ""))
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- commands


def cmd_inventory(args: argparse.Namespace) -> int:
    inv = inventory.scan(args.path)
    if args.cbom_dir:
        write_json(args.cbom_dir / "cbom.json", cbom.export_json(inv))
        write_text(args.cbom_dir / "cbom.csv", cbom.export_csv(inv))
        print(f"wrote {args.cbom_dir / 'cbom.json'} and cbom.csv", file=sys.stderr)
    emit(inv.to_dict(), args.output, args.json, lambda: render_inventory(inv))
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    inv = inventory.inspect_endpoint(
        args.host,
        args.port,
        cafile=args.cafile,
        server_name=args.server_name,
        allow_remote=args.allow_remote,
        timeout=args.timeout,
    )
    emit(inv.to_dict(), args.output, args.json, lambda: render_inventory(inv))
    return EXIT_GATE if inv.errors and not inv.assets else 0


def cmd_cbom(args: argparse.Namespace) -> int:
    inv = read_inventory(args.inventory)
    text = (
        cbom.export_csv(inv)
        if args.format == "csv"
        else json.dumps(cbom.export_json(inv), indent=2, sort_keys=True) + "\n"
    )
    if args.output:
        write_text(args.output, text)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    result = policy.evaluate(read_inventory(args.inventory), policy.load_policy(args.policy))
    emit(result, args.output, args.json, lambda: render_policy(result))
    noncompliant = result["summary"]["total_assets"] - result["summary"]["compliant"]
    return EXIT_GATE if args.fail_on_noncompliant and noncompliant else 0


def cmd_capabilities(args: argparse.Namespace) -> int:
    caps = tls.capabilities()
    emit(caps, args.output, args.json, lambda: render_capabilities(caps))
    return 0


def _tls_policy(path: Path | None) -> dict[str, Any] | None:
    data = read_yaml(path)
    if data is not None and not isinstance(data, dict):
        raise CLIError(f"{path}: TLS policy must be a mapping")
    return data


def cmd_test(args: argparse.Namespace) -> int:
    caps = tls.capabilities()
    tls.resolve_profile(args.profile, caps)
    client = args.client or benchmark.PROFILE_CLIENTS[args.profile]
    with tempfile.TemporaryDirectory(prefix="cryptoagility-test-") as work:
        result = tls.run_matrix(
            Path(work),
            servers=[args.profile],
            clients=[client],
            include_negative=False,
            caps=caps,
            policy=_tls_policy(args.tls_policy),
        )
    emit(result, args.output, args.json, lambda: render_matrix(result))
    return 0 if result["rows"][0]["status"] == tls.SUCCESS else EXIT_GATE


def cmd_matrix(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="cryptoagility-matrix-") as work:
        result = tls.run_matrix(
            Path(work),
            servers=args.server,
            clients=args.client,
            include_negative=not args.no_negative,
            policy=_tls_policy(args.tls_policy),
        )
    emit(result, args.output, args.json, lambda: render_matrix(result))
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    caps = tls.capabilities()
    if args.strict:
        for name in args.profile or benchmark.PROFILES:
            tls.resolve_profile(name, caps)
    with tempfile.TemporaryDirectory(prefix="cryptoagility-bench-") as work:
        result = benchmark.run_benchmarks(
            Path(work),
            args.iterations,
            args.warmups,
            args.profile,
            algorithms=args.algorithm,
            include_tls=not args.no_tls,
            caps=caps,
        )
    emit(result, args.output, args.json, lambda: benchmark.render_text(result))
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    matrix = read_json(args.matrix) if args.matrix else None
    inv = read_inventory(args.inventory)
    result = migration.plan(
        inv, policy.load_policy(args.policy), matrix, read_yaml(args.constraints)
    )
    sources = {a.asset_id: a.source for a in inv.assets}
    if args.markdown:
        write_text(args.markdown, migration.render_markdown(result))
        print(f"wrote {args.markdown}", file=sys.stderr)
    emit(result, args.output, args.json, lambda: render_plan(result, sources))
    return EXIT_GATE if args.fail_on_blocked and result["readiness"] == "BLOCKED" else 0


def cmd_report(args: argparse.Namespace) -> int:
    from cryptoagility import reporting

    path = reporting.render_report(args.results, args.output or args.results / "report.html")
    evidence = reporting.load_evidence(args.results)
    print(f"wrote {path}")
    states = [ev.status for ev in evidence.values()]
    print(
        _counts(
            "evidence files",
            {s: states.count(s) for s in (reporting.LOADED, reporting.MISSING, reporting.INVALID)},
        ),
        end="",
    )
    return 0


def cmd_lab(args: argparse.Namespace) -> int:
    from cryptoagility import lab

    summary = lab.run(
        args.results,
        policy_path=args.policy,
        constraints_path=args.constraints,
        iterations=args.iterations,
        warmups=args.warmups,
        include_benchmark=not args.no_benchmark,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


# --------------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptoagility",
        description="Local cryptographic inventory, policy, PQC/hybrid TLS lab and migration "
        "planning. Lab experiments use synthetic identities on loopback only.",
    )
    parser.add_argument("--version", action="version", version=f"cryptoagility {__version__}")
    parser.add_argument(
        "--openssl-version",
        action="store_true",
        help="print the pinned lab OpenSSL version and exit",
    )
    sub = parser.add_subparsers(dest="command", metavar="command")

    def command(
        name: str, func: Callable[[argparse.Namespace], int], text: str, json_output: bool = True
    ) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=text, description=text)
        p.set_defaults(func=func)
        if json_output:
            p.add_argument("-o", "--output", type=Path, help="write JSON evidence to this file")
            p.add_argument("--json", action="store_true", help="print JSON instead of a table")
        return p

    p = command("inventory", cmd_inventory, "Discover crypto assets under an explicit path")
    p.add_argument("path", type=Path)
    p.add_argument("--cbom-dir", type=Path, help="also write cbom.json and cbom.csv here")

    p = command("inspect", cmd_inspect, "Inspect one TLS endpoint (loopback unless allowed)")
    p.add_argument("host")
    p.add_argument("port", type=int)
    p.add_argument("--cafile", type=Path)
    p.add_argument("--server-name")
    p.add_argument(
        "--allow-remote",
        action="store_true",
        help="permit a non-loopback endpoint you are authorized to test",
    )
    p.add_argument("--timeout", type=float, default=5.0)

    p = command(
        "cbom", cmd_cbom, "Export the project-specific CBOM from inventory.json", json_output=False
    )
    p.add_argument("inventory", type=Path)
    p.add_argument("--format", choices=("json", "csv"), default="json")
    p.add_argument("-o", "--output", type=Path)

    p = command("policy", cmd_policy, "Evaluate an inventory against a YAML policy")
    p.add_argument("inventory", type=Path)
    p.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    p.add_argument("--fail-on-noncompliant", action="store_true")

    p = command("plan", cmd_plan, "Build an explainable migration plan")
    p.add_argument("inventory", type=Path)
    p.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    p.add_argument("--matrix", type=Path, help="matrix.json from 'cryptoagility matrix'")
    p.add_argument("--constraints", type=Path, help="declared constraints (YAML/JSON)")
    p.add_argument("--markdown", type=Path, help="also write a Markdown plan")
    p.add_argument("--fail-on-blocked", action="store_true")

    command("capabilities", cmd_capabilities, "Report the lab OpenSSL's real PQC support")

    p = command(
        "test",
        cmd_test,
        "One strict-profile loopback handshake; an unsupported "
        "profile is an error (exit 3), never a downgrade",
    )
    p.add_argument("--profile", choices=tuple(tls.PROFILES), required=True)
    p.add_argument(
        "--client",
        choices=tuple(tls.CLIENT_VARIANTS),
        help="client variant (default: the profile's own strict client)",
    )
    p.add_argument("--tls-policy", type=Path, help="TLS negotiation policy (YAML/JSON)")

    p = command("matrix", cmd_matrix, "Run the client x server interoperability matrix")
    p.add_argument("--server", action="append", choices=tuple(tls.SERVER_SPECS))
    p.add_argument("--client", action="append", choices=tuple(tls.CLIENT_VARIANTS))
    p.add_argument("--no-negative", action="store_true", help="skip negative-control rows")
    p.add_argument("--tls-policy", type=Path, help="TLS negotiation policy (YAML/JSON)")

    p = command("benchmark", cmd_benchmark, "Measure primitives and TLS handshakes locally")
    p.add_argument("--profile", action="append", choices=benchmark.PROFILES)
    p.add_argument("--algorithm", action="append", choices=tuple(benchmark.KNOWN_ALGORITHMS))
    p.add_argument("--iterations", type=int, default=20)
    p.add_argument("--warmups", type=int, default=3)
    p.add_argument("--no-tls", action="store_true")
    p.add_argument(
        "--strict",
        action="store_true",
        help="exit 3 if a requested profile is unsupported instead of recording it",
    )

    p = command(
        "report", cmd_report, "Render the offline HTML report from a results dir", json_output=False
    )
    p.add_argument("results", type=Path)
    p.add_argument("-o", "--output", type=Path, help="default: RESULTS/report.html")

    p = command(
        "lab", cmd_lab, "Run the full synthetic-scenario pipeline into RESULTS", json_output=False
    )
    p.add_argument("results", type=Path, nargs="?", default=Path("results"))
    p.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    p.add_argument("--constraints", type=Path)
    p.add_argument("--iterations", type=int, default=20)
    p.add_argument("--warmups", type=int, default=3)
    p.add_argument("--no-benchmark", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.openssl_version:
            print(openssl.run(["version"]).decode().strip())
            return 0
        if getattr(args, "func", None) is None:
            parser.print_help()
            return 0
        return int(args.func(args))
    except tls.UnsupportedProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_UNSUPPORTED
    except (
        CLIError,
        policy.PolicyError,
        migration.MigrationError,
        openssl.OpenSSLError,
        tls.TLSLabError,
        ValueError,
        OSError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
