"""Static HTML report: real lab evidence, safe failure paths, escaping and offline output."""

import base64
import copy
import hashlib
import html
import json
import os
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from cryptoagility import benchmark, cbom, inventory, migration, openssl, policy, reporting, tls
from cryptoagility.reporting import evidence as ev_mod
from cryptoagility.reporting import render as render_mod

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 1, 1, tzinfo=UTC)
SVG_NS = "http://www.w3.org/2000/svg"
XSS = '"><script>alert(1)</script><img src=x onerror=alert(2)>'
PEM = ("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGJ1aWx0LWluLXRlc3Qta2V5LW5vdC1yZWFs"
       "\n-----END PRIVATE KEY-----")


def _write(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _lab_evidence(workdir: Path, matrix: dict[str, Any] | None = None,
                  bench: dict[str, Any] | None = None) -> Path:
    """Produce every evidence file with the real lab modules and local OpenSSL."""
    scan = workdir / "scan"
    out = workdir / "results"
    scan.mkdir(parents=True)
    out.mkdir()
    openssl.run(["genpkey", "-algorithm", "ML-DSA-65", "-out", str(scan / "mldsa.key")])
    openssl.run(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout",
                 str(scan / "rsa.key"), "-out", str(scan / "rsa.crt"), "-subj",
                 "/CN=lab.test", "-days", "30"])
    (scan / "openssl.cnf").write_text("[system_default_sect]\nGroups = X25519MLKEM768:X25519\n")
    (scan / "bad.pem").write_text("-----BEGIN CERTIFICATE-----\nnot base64\n"
                                  "-----END CERTIFICATE-----\n")
    caps = tls.capabilities()
    inv = inventory.scan(scan, now=NOW)
    pol = policy.load_policy(ROOT / "policies" / "default.yaml")
    if matrix is None:
        # Real matrix code path with every group withheld: rows are UNSUPPORTED and no
        # network or key generation happens.
        reduced = copy.deepcopy(caps)
        reduced["tls13_groups"] = []
        matrix = tls.run_matrix(workdir / "mx", servers=["hybrid"],
                                clients=["hybrid-only", "classical-only"],
                                include_negative=False, caps=reduced)
    if bench is None:
        bench = benchmark.run_benchmarks(workdir / "bm", iterations=5, warmups=2,
                                         profiles=["pqc"],
                                         algorithms=["ML-KEM-768", "ML-DSA-65"],
                                         include_tls=False, caps=caps)
    for name, data in (("capabilities", caps), ("inventory", inv.to_dict()),
                       ("policy", policy.evaluate(inv, pol, now=NOW)), ("matrix", matrix),
                       ("migration-plan", migration.plan(inv, pol, matrix, now=NOW)),
                       ("benchmark", bench), ("cbom", cbom.export_json(inv))):
        _write(out / f"{name}.json", data)
    return out


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _lab_evidence(tmp_path_factory.mktemp("lab"))


@pytest.fixture
def results(lab: Path, tmp_path: Path) -> Path:
    copy_dir = tmp_path / "results"
    shutil.copytree(lab, copy_dir)
    return copy_dir


def _render(results_dir: Path, tmp_path: Path, name: str = "report.html") -> str:
    out = reporting.render_report(results_dir, tmp_path / name)
    assert out == tmp_path / name
    return out.read_text(encoding="utf-8")


def _body(page: str) -> str:
    start = page.index('<section class="a-section"', page.index("data-a-error"))
    return page[start:page.index("<footer")]


def _provenance(page: str, filename: str) -> str:
    match = re.search(rf"<tr data-status=\"[a-z]+\"><td><code>{re.escape(filename)}</code>"
                      r"</td><td>(.*?)</td>", page)
    assert match, filename
    return match.group(1)


def _states(fragment: str) -> list[str]:
    return re.findall(r'class="a-status" data-state="([a-z-]+)"', fragment)


def _section(page: str, ident: str) -> str:
    start = page.index(f'<section class="a-section" id="{ident}"')
    end = page.find('<section class="a-section"', start + 1)
    return page[start:end if end != -1 else page.index("<footer")]


# --------------------------------------------------------------------------- real evidence


def test_full_report_from_real_lab_evidence(results: Path, tmp_path: Path) -> None:
    page = _render(results, tmp_path)
    for name in ev_mod.EVIDENCE_FILES.values():
        assert "Loaded" in _provenance(page, name)
        digest = hashlib.sha256((results / name).read_bytes()).hexdigest()[:16]
        assert f"<code>{digest}\u2026</code>" in page
    for ident in ("summary", "inventory", "classification", "findings", "interop",
                  "performance", "footprint", "methodology", "limitations"):
        assert f'id="{ident}"' in page, ident
    plan = _read(results / "migration-plan.json")
    assert f">{plan['readiness']}</span>" in _section(page, "summary")
    for asset in _read(results / "inventory.json")["assets"]:
        assert html.escape(asset["asset_id"]) in _section(page, "inventory")
    # Discovery errors are reported, not dropped.
    assert "bad.pem" in _section(page, "inventory")
    # Real matrix rows (UNSUPPORTED locally) are never green.
    interop = _section(page, "interop")
    assert "UNSUPPORTED" in interop and "done" not in _states(interop)
    # Charts are table-driven kit charts.
    assert page.count('data-a-chart="') >= 3
    assert "CycloneDX" in page and "not production" in page


def test_numbers_come_from_evidence_not_fixtures(results: Path, tmp_path: Path) -> None:
    bench = _read(results / "benchmark.json")
    page = _render(results, tmp_path)
    perf = _section(page, "performance")
    measured = [e for e in bench["results"] if e["status"] == "SUCCESS"]
    assert measured
    for entry in measured:
        for op, result in entry["operations"].items():
            assert f"{result['statistics']['median_ms']:,.3f}" in perf, (entry["id"], op)
    pol = _read(results / "policy.json")
    bad = pol["summary"]["total_assets"] - pol["summary"]["compliant"]
    assert f"{bad:,} of {pol['summary']['total_assets']:,}" in page


def test_output_is_deterministic_and_path_independent(results: Path, tmp_path: Path) -> None:
    first = reporting.render_report(results, tmp_path / "a.html").read_bytes()
    second = reporting.render_report(results, tmp_path / "b.html").read_bytes()
    moved = tmp_path / "elsewhere" / "deeper"
    shutil.copytree(results, moved)
    third = reporting.render_report(moved, tmp_path / "c.html").read_bytes()
    assert first == second == third
    assert str(tmp_path).encode() not in first
    assert reporting.render_html(reporting.load_evidence(results)).encode() == first


def test_sample_count_caveat_and_no_fabricated_p95(results: Path, tmp_path: Path) -> None:
    bench = _read(results / "benchmark.json")
    n = bench["methodology"]["iterations"]
    assert n < benchmark.P95_MIN_SAMPLES
    page = _render(results, tmp_path)
    perf = _section(page, "performance")
    assert f"not reported (n = {n} &lt; {benchmark.P95_MIN_SAMPLES})" in perf
    assert f"n = {n} measured samples per operation" in perf
    assert f"Benchmarks used {n} samples per operation" in page
    assert "indicative" in perf
    # The p95 column never carries a number when the evidence has none.
    assert not re.search(r"p95[^<]*</th>.*?data-value=\"[0-9]", perf, re.S) or all(
        e["operations"][op]["statistics"]["p95_ms"] is None
        for e in bench["results"] if e["status"] == "SUCCESS" for op in e["operations"])


def test_page_is_offline_single_script_and_csp_pinned(results: Path, tmp_path: Path) -> None:
    page = _render(results, tmp_path)
    urls = set(re.findall(r"[a-z][a-z0-9+.-]*://[^\s\"'<>)]+", page, re.I))
    assert urls <= {SVG_NS}, urls
    assert not re.search(r"(?:src|href|action)\s*=\s*[\"']?\s*//", page, re.I)
    assert not re.search(r"@import|url\(\s*['\"]?(?!data:|#)", page, re.I)
    assert not re.search(r"\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket|EventSource)\s*\(",
                         page)
    scripts = re.findall(r"<script>(.*?)</script>", page, re.S)
    assert len(scripts) == 1 and page.lower().count("<script") == 1
    digest = base64.b64encode(hashlib.sha256(scripts[0].encode()).digest()).decode()
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page)
    assert csp and f"script-src 'sha256-{digest}'" in csp.group(1)
    for directive in ("default-src 'none'", "connect-src 'none'", "form-action 'none'"):
        assert directive in csp.group(1)
    # Report body uses only kit components, no inline event handlers.
    body = _body(page)
    assert not re.search(r"\son[a-z]+\s*=", body, re.I)
    assert 'class="a-' in body


# --------------------------------------------------------------------------- missing evidence


def test_empty_results_are_untested_or_unknown_never_green(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    page = _render(empty, tmp_path)
    body = _body(page)
    assert "done" not in _states(body)
    for name in ev_mod.EVIDENCE_FILES.values():
        assert "Missing" in _provenance(page, name)
    summary = _section(page, "summary")
    assert summary.count("UNKNOWN") >= 3 and summary.count("UNTESTED") >= 2
    assert "READY" not in re.sub(r"UNKNOWN|NOT_READY", "", summary.split("Evidence provenance")[0])
    assert "Absence of evidence is not a pass" in body


@pytest.mark.parametrize("key", sorted(ev_mod.EVIDENCE_FILES))
def test_each_missing_file_is_reported(key: str, results: Path, tmp_path: Path) -> None:
    name = ev_mod.EVIDENCE_FILES[key]
    (results / name).unlink()
    page = _render(results, tmp_path)
    chip = _provenance(page, name)
    expected = "optional" if key in ev_mod.OPTIONAL_EVIDENCE else "untested"
    assert f"Missing \u2014 {expected}" in chip and 'data-state="planned"' in chip
    if key not in ev_mod.OPTIONAL_EVIDENCE:
        assert f"{name}" in _section(page, "limitations")


def test_missing_matrix_and_benchmark_mark_areas_untested(results: Path,
                                                           tmp_path: Path) -> None:
    (results / "matrix.json").unlink()
    (results / "benchmark.json").unlink()
    page = _render(results, tmp_path)
    for ident in ("interop", "performance"):
        part = _section(page, ident)
        assert "UNTESTED" in part and "done" not in _states(part)
        assert "<table" not in part


# --------------------------------------------------------------------------- malformed input


BAD_BYTES = {
    "not-json": b"{not json",
    "duplicate-key": b'{"schema_version": "1", "schema_version": "1"}',
    "nan": b'{"schema_version": NaN}',
    "infinity": b'{"x": Infinity}',
    "not-utf8": b'{"x": "\xff\xfe"}',
    "deep": b"[" * 200 + b"]" * 200,
    "long-string": json.dumps({"x": "a" * (ev_mod.MAX_STRING + 1)}).encode(),
    "top-level-list": b"[]",
}


@pytest.mark.parametrize("key", sorted(ev_mod.EVIDENCE_FILES))
@pytest.mark.parametrize("case", sorted(BAD_BYTES))
def test_malformed_files_are_rejected_explicitly(key: str, case: str, results: Path,
                                                 tmp_path: Path) -> None:
    name = ev_mod.EVIDENCE_FILES[key]
    (results / name).write_bytes(BAD_BYTES[case])
    page = _render(results, tmp_path)
    chip = _provenance(page, name)
    assert "Invalid" in chip and 'data-state="blocked"' in chip
    assert f"{name} rejected" in page or f"{name}" in _section(page, "limitations")
    assert "Traceback" not in page
    loaded = reporting.load_evidence(results)[key]
    assert loaded.status == reporting.INVALID and loaded.data is None and loaded.error


def _mutations() -> list[tuple[str, str, Any]]:
    def schema(d: dict[str, Any]) -> None:
        d["schema_version"] = "999"

    def compliant_lie(d: dict[str, Any]) -> None:
        bad = next(f for f in d["findings"] if not f["compliant"])
        bad["compliant"] = True

    def ready_lie(d: dict[str, Any]) -> None:
        blocked = next(i for i in d["items"] if i.get("blocker"))
        blocked["ready"] = True

    def success_lie(d: dict[str, Any]) -> None:
        d["rows"][0]["status"] = tls.SUCCESS

    def bench_secret(d: dict[str, Any]) -> None:
        d["results"][0]["description"] = PEM

    def bench_p95(d: dict[str, Any]) -> None:
        entry = next(e for e in d["results"] if e["status"] == "SUCCESS")
        next(iter(entry["operations"].values()))["statistics"]["p95_ms"] = 1.0

    def cbom_format(d: dict[str, Any]) -> None:
        d["cbom_format"] = "CycloneDX"

    def extra_asset_field(d: dict[str, Any]) -> None:
        d["assets"][0]["private_key_pem"] = PEM

    def unknown_outcome(d: dict[str, Any]) -> None:
        d["findings"][0]["outcome"] = "GREEN"

    return [
        ("inventory", "schema", schema), ("inventory", "extra-field", extra_asset_field),
        ("policy", "schema", schema), ("policy", "compliant-lie", compliant_lie),
        ("policy", "unknown-outcome", unknown_outcome),
        ("migration_plan", "ready-lie", ready_lie), ("matrix", "success-lie", success_lie),
        ("benchmark", "secret", bench_secret), ("benchmark", "fabricated-p95", bench_p95),
        ("cbom", "format", cbom_format), ("capabilities", "schema", schema),
    ]


@pytest.mark.parametrize("key,label,mutate", _mutations(), ids=[m[1] + "-" + m[0]
                                                                for m in _mutations()])
def test_schema_mismatch_and_contradictions_are_errors(key: str, label: str, mutate: Any,
                                                       results: Path, tmp_path: Path) -> None:
    path = results / ev_mod.EVIDENCE_FILES[key]
    data = _read(path)
    mutate(data)
    _write(path, data)
    page = _render(results, tmp_path)
    assert "Invalid" in _provenance(page, ev_mod.EVIDENCE_FILES[key])
    assert "BEGIN PRIVATE KEY" not in page and "GREEN" not in page
    assert reporting.load_evidence(results)[key].status == reporting.INVALID


def test_oversized_and_symlinked_evidence_are_refused(results: Path, tmp_path: Path) -> None:
    with (results / "inventory.json").open("wb") as handle:
        handle.truncate(ev_mod.MAX_FILE_BYTES + 1)
    elsewhere = tmp_path / "policy-real.json"
    shutil.move(results / "policy.json", elsewhere)
    os.symlink(elsewhere, results / "policy.json")
    loaded = reporting.load_evidence(results)
    assert loaded["inventory"].status == reporting.INVALID
    assert "limit" in (loaded["inventory"].error or "")
    assert loaded["policy"].status == reporting.INVALID
    assert "symbolic" in (loaded["policy"].error or "")
    page = _render(results, tmp_path)
    assert "Invalid" in _provenance(page, "policy.json")


def test_bad_directories_and_outputs_raise_report_error(results: Path, tmp_path: Path) -> None:
    with pytest.raises(reporting.ReportError, match="does not exist"):
        reporting.render_report(tmp_path / "nope", tmp_path / "r.html")
    link = tmp_path / "linked"
    os.symlink(results, link)
    with pytest.raises(reporting.ReportError, match="symlinks"):
        reporting.render_report(link, tmp_path / "r.html")
    with pytest.raises(reporting.ReportError, match=r"\.html"):
        reporting.render_report(results, tmp_path / "r.json")
    with pytest.raises(reporting.ReportError, match="output directory"):
        reporting.render_report(results, tmp_path / "missing" / "r.html")
    target = tmp_path / "target.html"
    target.write_text("keep")
    os.symlink(target, tmp_path / "out.html")
    with pytest.raises(reporting.ReportError, match="symlinks"):
        reporting.render_report(results, tmp_path / "out.html")
    assert target.read_text() == "keep"
    assert not list(tmp_path.glob(".report-*"))


def test_render_html_requires_exact_evidence_keys(results: Path) -> None:
    loaded = reporting.load_evidence(results)
    loaded.pop("cbom")
    with pytest.raises(reporting.ReportError):
        reporting.render_html(loaded)


@pytest.mark.parametrize("raw", [b"[" * (ev_mod.MAX_DEPTH + 2) + b"]" * (ev_mod.MAX_DEPTH + 2),
                                 b'{"a": 1, "a": 2}', b"[NaN]", b"[-Infinity]",
                                 json.dumps(list(range(ev_mod.MAX_NODES + 1))).encode()])
def test_parse_json_is_strict_and_bounded(raw: bytes) -> None:
    with pytest.raises(reporting.EvidenceError):
        ev_mod.parse_json(raw)


# --------------------------------------------------------------------------- escaping / secrets


def _inject(results: Path, payload: str) -> None:
    inv = _read(results / "inventory.json")
    inv["assets"][0]["certificate_subject"] = payload
    inv["assets"][0]["source"] = payload
    inv["errors"].append({"source": payload, "code": payload, "message": payload})
    _write(results / "inventory.json", inv)
    pol = _read(results / "policy.json")
    pol["findings"][0]["reasons"].append(payload)
    _write(results / "policy.json", pol)
    mx = _read(results / "matrix.json")
    mx["rows"][0]["error_reason"] = payload
    mx["environment"]["latency_semantics"] = payload
    _write(results / "matrix.json", mx)


def test_markup_in_evidence_is_escaped(results: Path, tmp_path: Path) -> None:
    _inject(results, XSS)
    loaded = reporting.load_evidence(results)
    assert {k: e.status for k, e in loaded.items() if k in ("inventory", "policy", "matrix")} == {
        "inventory": reporting.LOADED, "policy": reporting.LOADED, "matrix": reporting.LOADED}
    page = _render(results, tmp_path)
    body = _body(page)
    assert "<script" not in body.lower() and "<img" not in body.lower()
    assert not re.search(r"<[^>]*\sonerror\s*=", body, re.I)
    assert html.escape(XSS, quote=True) in body
    assert page.lower().count("<script") == 1


@pytest.mark.parametrize("secret", [
    PEM,
    "RSA PRIVATE KEY material",
    "CLIENT_RANDOM 0011 2233",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET abcd",
    "Master-Key: 0A1B2C",
    "PSK identity hint",
    base64.b64encode(bytes(range(256)) * 2).decode(),
])
def test_secret_like_strings_are_redacted(secret: str, results: Path, tmp_path: Path) -> None:
    _inject(results, f"prefix {secret} suffix")
    page = _render(results, tmp_path)
    for marker in ("BEGIN PRIVATE", "PRIVATE KEY", "CLIENT_RANDOM", "TRAFFIC_SECRET",
                   "Master-Key", "PSK identity", secret[:60]):
        assert marker not in page, marker
    assert render_mod.REDACTED in page
    assert "looked like key material" in page


def test_control_and_bidi_characters_are_stripped(results: Path, tmp_path: Path) -> None:
    payload = "lab\x00\x1b[31m\u202eevil\u2066name\u200b\x7f"
    _inject(results, payload)
    page = _render(results, tmp_path)
    for ch in ("\x00", "\x1b", "\u202e", "\u2066", "\u200b", "\x7f"):
        assert ch not in page
    assert "lab [31m evil name" in page


def test_long_values_are_truncated(results: Path, tmp_path: Path) -> None:
    _inject(results, "x" * 5000)
    page = _render(results, tmp_path)
    assert "x" * 1000 not in page and "\u2026" in page


def test_rejection_reasons_are_escaped_and_sanitized(results: Path, tmp_path: Path) -> None:
    bench = _read(results / "benchmark.json")
    bench["results"][0]["id"] = XSS
    bench["results"].append(copy.deepcopy(bench["results"][0]))
    _write(results / "benchmark.json", bench)
    page = _render(results, tmp_path)
    assert "Invalid" in _provenance(page, "benchmark.json")
    assert "<script" not in _body(page).lower()


# --------------------------------------------------------------------------- packaged shell


def test_packaged_shell_is_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    shell = render_mod.load_shell()
    assert shell.count(render_mod.BODY_MARKER) == 1

    class Fake:
        def __init__(self, text: str) -> None:
            self.text = text

        def joinpath(self, _name: str) -> "Fake":
            return self

        def read_text(self, encoding: str = "utf-8") -> str:
            return self.text

    tampered = {
        "script": shell.replace("<script>", "<script>window.x=1;", 1),
        "remote": shell.replace("</head>", '<link rel="stylesheet" href="https://cdn.test/a.css">'
                                "</head>", 1),
        "marker": shell.replace(render_mod.BODY_MARKER, ""),
    }
    for name, text in tampered.items():
        monkeypatch.setattr(render_mod.resources, "files", lambda _pkg, t=text: Fake(t))
        with pytest.raises(reporting.ReportError):
            render_mod.load_shell()
        assert name


def test_shell_ships_with_the_package() -> None:
    path = Path(reporting.__file__).with_name("shell.html")
    text = path.read_text(encoding="utf-8")
    assert "a-section" in text and render_mod.BODY_MARKER in text
    assert not re.search(r"https?://(?!www\.w3\.org/2000/svg)", text)


# --------------------------------------------------------------------------- real TLS evidence


@pytest.mark.integration
def test_real_loopback_matrix_and_tls_benchmark_render(tmp_path_factory: pytest.TempPathFactory,
                                                       tmp_path: Path) -> None:
    work = tmp_path_factory.mktemp("tls-lab")
    matrix = tls.run_matrix(work / "mx", servers=["hybrid", "classical"],
                            clients=["hybrid-only"], include_negative=True)
    bench = benchmark.run_benchmarks(work / "bm", iterations=5, warmups=2,
                                     profiles=["hybrid"], algorithms=["ML-KEM-768"],
                                     include_tls=True)
    results = _lab_evidence(work / "lab", matrix=matrix, bench=bench)
    page = _render(results, tmp_path)
    interop = _section(page, "interop")
    statuses = {r["status"] for r in matrix["rows"]}
    assert tls.SUCCESS in statuses
    for status in statuses:
        assert f">{status}</span>" in interop
    negatives = [r for r in matrix["rows"] if r.get("experiment") == "negative"]
    assert negatives and "negative control (failure expected)" in interop
    perf = _section(page, "performance")
    tls_entries = [e for e in bench["results"] if e["kind"] == "tls_handshake"
                   and e["status"] == "SUCCESS"]
    assert tls_entries
    for entry in tls_entries:
        median = entry["operations"]["handshake"]["statistics"]["median_ms"]
        assert f"{median:,.3f}" in perf
    footprint = _section(page, "footprint")
    assert "UNKNOWN" in footprint and "TCP/IP" in footprint
    for name in ("BEGIN", "PRIVATE KEY", "CLIENT_RANDOM", "TRAFFIC_SECRET"):
        assert name not in page
