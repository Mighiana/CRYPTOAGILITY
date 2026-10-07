"""Tests for cryptoagility.benchmark.

Unit tests cover bounds, statistics and the evidence validator against tampered results.
Integration tests (marked) run real benchmarks on the pinned OpenSSL 3.5.9 build, including
the required 20 iterations + 3 warmups run and fault-injected OpenSSL wrappers that must
turn into ERROR entries without samples. They are skipped only when that build is absent.
"""

from __future__ import annotations

import copy
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

from cryptoagility import benchmark, openssl, tls
from cryptoagility.models import SCHEMA_VERSION


def _pinned() -> str | None:
    try:
        return openssl.executable()
    except openssl.OpenSSLError:
        return None


def _pinned_version() -> str | None:
    try:
        return openssl.run(["version"]).decode()
    except openssl.OpenSSLError:
        return None


PINNED = _pinned_version()
needs_native = pytest.mark.skipif(
    PINNED is None or "OpenSSL 3.5" not in PINNED,
    reason="pinned OpenSSL 3.5.x not built; run scripts/setup-openssl.sh",
)
integration = [pytest.mark.integration, needs_native]

SYSTEM_OPENSSL = Path("/usr/bin/openssl")


def _system_version() -> str | None:
    if not SYSTEM_OPENSSL.is_file():
        return None
    out = subprocess.run([str(SYSTEM_OPENSSL), "version"], capture_output=True, check=False)
    return out.stdout.decode()


def _modes(root: Path) -> list[tuple[str, int]]:
    return sorted(
        (str(p.relative_to(root)), stat.S_IMODE(p.stat().st_mode)) for p in root.rglob("*")
    )


def _assert_clean(workdir: Path) -> None:
    for name in ("benchmark-lab", "tls-lab"):
        root = workdir / name
        if root.exists():
            assert stat.S_IMODE(root.stat().st_mode) == 0o700
            assert _modes(root) == [(".gitignore", 0o600)]
            assert (root / ".gitignore").read_text() == "*\n"


def _sample_ops(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [op for e in data["results"] for op in e["operations"].values()]


# ------------------------------------------------------------------- unit: bounds & stats


@pytest.mark.parametrize(
    "kwargs",
    [
        {"iterations": 4},
        {"iterations": 501},
        {"iterations": True},
        {"iterations": "20"},
        {"iterations": 20.0},
        {"warmups": 1},
        {"warmups": 51},
        {"warmups": False},
        {"timeout": 0.5},
        {"timeout": 301},
        {"timeout": True},
        {"timeout": "5"},
        {"profiles": "hybrid"},
        {"profiles": []},
        {"profiles": ["hybrid;rm -rf /"]},
        {"profiles": ["HYBRID"]},
        {"profiles": [None]},
        {"algorithms": ["ML-DSA-65; id"]},
        {"algorithms": "ML-DSA-65"},
        {"algorithms": ["X448"]},
        {"include_tls": "yes"},
        {"algorithms": [], "include_tls": False},
    ],
)
def test_rejects_invalid_parameters_before_any_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, Any]
) -> None:
    monkeypatch.setenv("CRYPTOAGILITY_OPENSSL", str(tmp_path / "missing-openssl"))
    workdir = tmp_path / "work"
    with pytest.raises(ValueError):
        benchmark.run_benchmarks(workdir, **kwargs)
    assert not workdir.exists()


def test_bounds_are_strict_constants() -> None:
    assert benchmark.MIN_ITERATIONS >= 5 and benchmark.MAX_ITERATIONS <= 500
    assert benchmark.MIN_WARMUPS >= 2
    assert benchmark.P95_MIN_SAMPLES == 20


def test_summarize_p95_only_with_twenty_samples() -> None:
    nineteen = list(range(1, 20))
    stats = benchmark.summarize(nineteen)
    assert stats["p95_ns"] is None and stats["p95_ms"] is None
    assert stats["median_ns"] == 10 and stats["min_ns"] == 1 and stats["max_ns"] == 19
    twenty = [v * 1000 for v in range(20, 0, -1)]
    stats = benchmark.summarize(twenty)
    assert stats["count"] == 20
    assert stats["p95_ns"] == 19000  # nearest rank: ceil(0.95 * 20) = 19th smallest
    assert stats["median_ns"] == 10500
    assert benchmark.p95_nearest_rank(list(range(1, 101))) == 95
    with pytest.raises(ValueError):
        benchmark.summarize([])


def test_measure_rejects_bogus_durations() -> None:
    plan = benchmark._Plan(2, 5, 5.0)

    def constant(value: Any) -> Any:
        return lambda _index: value

    for bad in (0, -5, True, 1.5):
        with pytest.raises(benchmark.BenchmarkError):
            plan.measure(constant(bad))
    result = plan.measure(lambda i: i + 1)
    assert result["warmup_samples_ns"] == [1, 2]
    assert result["samples_ns"] == [3, 4, 5, 6, 7]
    assert result["statistics"]["p95_ns"] is None


def test_known_algorithms_cover_standardized_parameter_sets() -> None:
    names = set(benchmark.KNOWN_ALGORITHMS)
    assert {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"} <= names
    assert {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} <= names
    assert len([n for n in names if n.startswith("SLH-DSA-")]) == 12
    for profile, algorithms in benchmark.PROFILE_ALGORITHMS.items():
        assert profile in tls.PROFILES
        assert set(algorithms) <= names
    assert "ML-KEM-768" in benchmark.PROFILE_ALGORITHMS["hybrid"]
    assert set(benchmark.PROFILE_ALGORITHMS["pqc"]) == {
        "ML-KEM-768",
        "ML-DSA-65",
        "SLH-DSA-SHA2-128s",
    }


def test_container_detection_sanitizes_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("container", "podman;rm -rf /$(id)\n")
    info = benchmark.detect_container()
    assert info["detected"] is True
    text = json.dumps(info)
    assert ";" not in text and "$" not in text and "\\n" not in text
    assert "podman" in (info["runtime"] or "")


# ------------------------------------------------------------------- integration: real runs


@pytest.fixture(scope="module")
def full_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    if PINNED is None or "OpenSSL 3.5" not in PINNED:
        pytest.skip("pinned OpenSSL 3.5.x not built")
    workdir = tmp_path_factory.mktemp("bench")
    data = benchmark.run_benchmarks(workdir, iterations=20, warmups=3)
    return workdir, data


@pytest.mark.integration
def test_full_run_twenty_iterations_three_warmups(full_run: tuple[Path, dict[str, Any]]) -> None:
    _, data = full_run
    benchmark.validate_results(data)
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["summary"] == {"SUCCESS": 9, "UNSUPPORTED": 0, "ERROR": 0}
    ids = [e["id"] for e in data["results"]]
    assert ids == [
        "baseline:openssl-version",
        "signature:RSA-3072",
        "signature:ECDSA-P-256",
        "kem:ML-KEM-768",
        "signature:ML-DSA-65",
        "signature:SLH-DSA-SHA2-128s",
        "tls:classical",
        "tls:hybrid",
        "tls:pqc",
    ]
    for op in _sample_ops(data):
        assert len(op["samples_ns"]) == 20 and len(op["warmup_samples_ns"]) == 3
        assert all(isinstance(v, int) and v > 0 for v in op["samples_ns"])
        stats = op["statistics"]
        assert stats["min_ns"] <= stats["median_ns"] <= stats["p95_ns"] <= stats["max_ns"]
    method = data["methodology"]
    assert method["iterations"] == 20 and method["warmups"] == 3
    assert method["timing_clock"] == "time.perf_counter_ns"
    assert any("not an isolated" in c for c in method["caveats"])
    assert "BIO counters" in method["handshake_bytes_definition"]


@pytest.mark.integration
def test_environment_metadata(full_run: tuple[Path, dict[str, Any]]) -> None:
    _, data = full_run
    env = data["environment"]
    assert env["openssl"]["version_number"].startswith("3.5.")
    assert env["openssl"]["config"] == "OPENSSL_CONF=/dev/null"
    assert env["openssl"]["oqs_provider_loaded"] is False
    assert any(p.get("id") == "default" for p in env["openssl"]["providers"])
    assert env["openssl"]["built_on"]
    assert env["host"]["architecture"] and env["host"]["logical_cpus"]
    assert env["host"]["cpu_model"]
    assert env["os"]["system"] and env["python"]["version"].startswith("3.")
    assert env["timestamp_utc"].endswith("Z")
    assert set(env["container"]) >= {"detected", "runtime", "indicators", "virtualization"}
    assert env["wall_time_s"] > 0


@pytest.mark.integration
def test_primitive_sizes_come_from_real_encodings(full_run: tuple[Path, dict[str, Any]]) -> None:
    _, data = full_run
    by_id = {e["id"]: e for e in data["results"]}
    kem = by_id["kem:ML-KEM-768"]
    assert kem["sizes"]["ciphertext_bytes"] == {"min": 1088, "max": 1088}  # FIPS 203
    assert kem["sizes"]["shared_secret_bytes"] == {"min": 32, "max": 32}
    assert kem["sizes"]["public_key_der_bytes"] > 1184  # raw ek + SPKI wrapping
    assert kem["checks"]["every_shared_secret_matched"] is True
    assert kem["checks"]["shared_secrets_distinct"] is True
    assert kem["checks"]["truncated_ciphertext_rejected"] is True
    assert kem["checks"]["tampered_ciphertext"] in (
        "implicit_rejection_different_secret",
        "rejected_with_error",
    )
    assert set(kem["operations"]) == {"keygen", "encapsulate", "decapsulate"}
    mldsa = by_id["signature:ML-DSA-65"]
    assert mldsa["sizes"]["signature_bytes"] == {"min": 3309, "max": 3309}  # FIPS 204
    assert mldsa["sizes"]["public_key_der_bytes"] > 1952
    slh = by_id["signature:SLH-DSA-SHA2-128s"]
    assert slh["sizes"]["signature_bytes"] == {"min": 7856, "max": 7856}  # FIPS 205
    assert by_id["signature:RSA-3072"]["sizes"]["signature_bytes"] == {"min": 384, "max": 384}
    ec = by_id["signature:ECDSA-P-256"]["sizes"]["signature_bytes"]
    assert 64 <= ec["min"] <= ec["max"] <= 72
    for name in ("RSA-3072", "ECDSA-P-256", "ML-DSA-65", "SLH-DSA-SHA2-128s"):
        entry = by_id[f"signature:{name}"]
        assert set(entry["operations"]) == {"keygen", "sign", "verify"}
        assert entry["checks"] == {
            "every_signature_verified": True,
            "tampered_signature_rejected": True,
            "modified_message_rejected": True,
        }
        assert entry["sizes"]["private_key_der_bytes"] > 0
        assert entry["provider"] == "default"
    assert by_id["signature:ML-DSA-65"]["standard"] == "FIPS 204"
    assert by_id["kem:ML-KEM-768"]["profiles"] == ["hybrid", "pqc"]
    assert by_id["signature:RSA-3072"]["family"] == "classical"


@pytest.mark.integration
def test_tls_profiles_measured_with_instrumented_bytes(
    full_run: tuple[Path, dict[str, Any]],
) -> None:
    _, data = full_run
    by_id = {e["id"]: e for e in data["results"]}
    expected = {
        "classical": ("X25519", "classical", "RSA-3072", False),
        "hybrid": ("X25519MLKEM768", "hybrid", "RSA-3072", True),
        "pqc": ("MLKEM768", "pqc", "ML-DSA-65", False),
    }
    for name, (group, kind, cert, policy_pass) in expected.items():
        entry = by_id[f"tls:{name}"]
        assert entry["status"] == "SUCCESS" and entry["network_attempted"] is True
        assert tls.same_group(entry["negotiated_group"], group)
        assert entry["negotiated_group_kind"] == kind
        assert entry["tls_version"] == "TLSv1.3"
        assert entry["certificate_type"] == cert
        assert entry["policy"]["pass"] is policy_pass
        sizes = entry["sizes"]
        assert sizes["observed_chain_der_bytes"] == sizes["served_chain_der_bytes"]
        assert sizes["served_chain_der_bytes"] > sizes["leaf_certificate_der_bytes"]
        assert sizes["handshake_bytes_read"]["min"] > sizes["served_chain_der_bytes"]
        total = sizes["handshake_bytes_total"]
        assert total["min"] == (
            sizes["handshake_bytes_read"]["min"] + sizes["handshake_bytes_written"]["min"]
        )
        assert entry["operations"]["handshake"]["timing_source"].startswith("TLS samples")
    classical, hybrid, pqc = (by_id[f"tls:{n}"]["sizes"] for n in expected)
    # The X25519MLKEM768 key share (1184-byte ML-KEM-768 encapsulation key + 32-byte X25519
    # share) is in the ClientHello; the ML-KEM ciphertext (1088 bytes) in the ServerHello.
    assert hybrid["handshake_bytes_written"]["min"] >= 1184 + 32
    assert hybrid["handshake_bytes_written"]["min"] > classical["handshake_bytes_written"]["min"]
    assert hybrid["handshake_bytes_read"]["min"] >= classical["handshake_bytes_read"]["min"] + 1088
    assert pqc["leaf_certificate_der_bytes"] > classical["leaf_certificate_der_bytes"]
    assert pqc["handshake_bytes_read"]["min"] > hybrid["handshake_bytes_read"]["min"]


@pytest.mark.integration
def test_evidence_has_no_secrets_paths_and_runtime_is_cleaned(
    full_run: tuple[Path, dict[str, Any]],
) -> None:
    workdir, data = full_run
    text = json.dumps(data)
    for marker in (
        "PRIVATE KEY",
        "BEGIN",
        "Master-Key",
        "PSK",
        ".pem",
        str(workdir),
        tempfile.gettempdir(),
        "benchmark-lab",
        "tls-lab",
    ):
        assert marker not in text
    assert json.loads(text) == data
    benchmark.validate_results(json.loads(text))
    _assert_clean(workdir)
    assert (workdir / "benchmark-lab").is_dir() and (workdir / "tls-lab").is_dir()


@pytest.mark.integration
def test_capability_inventory_detects_but_benchmarks_in_depth(
    full_run: tuple[Path, dict[str, Any]],
) -> None:
    _, data = full_run
    inv = data["capabilities"]
    assert len(inv["standardized"]["slh_dsa"]) == 12
    assert set(inv["known_algorithms_available"]) == set(benchmark.KNOWN_ALGORITHMS)
    assert inv["benchmarked_algorithms"] == [
        "RSA-3072",
        "ECDSA-P-256",
        "ML-KEM-768",
        "ML-DSA-65",
        "SLH-DSA-SHA2-128s",
    ]
    assert "ML-DSA-87" in inv["available_not_benchmarked"]
    assert "X25519MLKEM768" in inv["tls_group_classes"]["hybrid"]
    assert inv["standardization_note"] == tls.STANDARDIZATION_NOTE


@pytest.mark.integration
def test_render_text(full_run: tuple[Path, dict[str, Any]]) -> None:
    _, data = full_run
    out = benchmark.render_text(data)
    assert "this lab environment only" in out
    assert "kem:ML-KEM-768" in out and "decapsulate" in out and "tls:pqc" in out


# ------------------------------------------------------------------- tamper detection


def _tamper_cases() -> list[tuple[str, Any]]:
    def first_op(d: dict[str, Any]) -> dict[str, Any]:
        return d["results"][1]["operations"]["sign"]

    cases: list[tuple[str, Any]] = [
        ("median", lambda d: first_op(d)["statistics"].update(median_ns=1)),
        ("extra sample", lambda d: first_op(d)["samples_ns"].append(5)),
        ("dropped sample", lambda d: first_op(d)["samples_ns"].pop()),
        ("negative", lambda d: first_op(d)["samples_ns"].__setitem__(0, -1)),
        ("bool sample", lambda d: first_op(d)["samples_ns"].__setitem__(0, True)),
        ("float sample", lambda d: first_op(d)["samples_ns"].__setitem__(0, 1.5)),
        ("dropped warmup", lambda d: first_op(d)["warmup_samples_ns"].pop()),
        ("op status", lambda d: first_op(d).update(status="ERROR")),
        ("p95 removed", lambda d: first_op(d)["statistics"].update(p95_ns=None)),
        ("schema", lambda d: d.update(schema_version="0.1")),
        ("kind", lambda d: d.update(kind="other")),
        ("iterations claim", lambda d: d["methodology"].update(iterations=21)),
        ("iterations bound", lambda d: d["methodology"].update(iterations=1000)),
        ("summary", lambda d: d["summary"].update(SUCCESS=99)),
        ("bad status", lambda d: d["results"][1].update(status="PASS")),
        ("duplicate", lambda d: d["results"].append(copy.deepcopy(d["results"][1]))),
        ("private key", lambda d: d["results"][1].update(note="-----BEGIN PRIVATE KEY-----")),
        ("no openssl", lambda d: d["environment"]["openssl"].update(version=None)),
        ("no env", lambda d: d.pop("environment")),
        ("success without ops", lambda d: d["results"][1].update(operations={})),
        ("error with samples", lambda d: d["results"][1].update(status="ERROR", reason="x")),
        (
            "unsupported without reason",
            lambda d: d["results"][1].update(
                status="UNSUPPORTED", operations={}, sizes={}, reason=None
            ),
        ),
    ]
    return cases


@pytest.mark.integration
@pytest.mark.parametrize("name,mutate", _tamper_cases(), ids=[c[0] for c in _tamper_cases()])
def test_validate_rejects_tampered_evidence(
    full_run: tuple[Path, dict[str, Any]], name: str, mutate: Any
) -> None:
    _, data = full_run
    tampered = copy.deepcopy(data)
    mutate(tampered)
    with pytest.raises(ValueError):
        benchmark.validate_results(tampered)
    with pytest.raises(ValueError):
        benchmark.render_text(tampered)
    benchmark.validate_results(data)


@pytest.mark.parametrize("data", [None, [], "x", {"schema_version": SCHEMA_VERSION}])
def test_validate_rejects_non_results(data: Any) -> None:
    with pytest.raises(ValueError):
        benchmark.validate_results(data)


@pytest.mark.integration
@pytest.mark.parametrize("n", [5, 19])
def test_small_runs_omit_p95_and_reject_fabricated_p95(tmp_path: Path, n: int) -> None:
    data = benchmark.run_benchmarks(
        tmp_path, iterations=n, warmups=2, algorithms=["ECDSA-P-256"], include_tls=False
    )
    benchmark.validate_results(data)
    for op in _sample_ops(data):
        assert len(op["samples_ns"]) == n and op["statistics"]["p95_ns"] is None
    tampered = copy.deepcopy(data)
    tampered["results"][1]["operations"]["sign"]["statistics"]["p95_ns"] = 123
    with pytest.raises(ValueError):
        benchmark.validate_results(tampered)
    assert data["requested"] == {
        "profiles": ["classical", "hybrid", "pqc"],
        "algorithms": ["ECDSA-P-256"],
        "include_tls": False,
    }
    _assert_clean(tmp_path)


# ------------------------------------------------------------------- unsupported paths


def _reduced_caps() -> dict[str, Any]:
    caps = json.loads(json.dumps(tls.capabilities()))
    caps["signature_algorithms"] = [
        e
        for e in caps["signature_algorithms"]
        if not any(n.startswith("ML-DSA") for n in e["names"])
    ]
    caps["kem_algorithms"] = [
        e for e in caps["kem_algorithms"] if not any(n.startswith("ML-KEM") for n in e["names"])
    ]
    caps["tls13_groups"] = [g for g in caps["tls13_groups"] if "MLKEM" not in g.upper()]
    caps["x509"]["ML-DSA-65"] = {"supported": False}
    return caps


@pytest.mark.integration
def test_unavailable_algorithms_and_profiles_are_explicitly_unsupported(tmp_path: Path) -> None:
    workdir = tmp_path / "work"
    data = benchmark.run_benchmarks(
        workdir,
        iterations=5,
        warmups=2,
        profiles=["hybrid", "pqc"],
        algorithms=["ML-DSA-65", "ML-KEM-768"],
        caps=_reduced_caps(),
    )
    benchmark.validate_results(data)
    by_id = {e["id"]: e for e in data["results"]}
    assert data["summary"] == {"SUCCESS": 1, "UNSUPPORTED": 4, "ERROR": 0}
    for key in ("signature:ML-DSA-65", "kem:ML-KEM-768"):
        assert by_id[key]["status"] == "UNSUPPORTED"
        assert "ALGORITHM NOT AVAILABLE" in by_id[key]["reason"]
        assert by_id[key]["operations"] == {} and by_id[key]["sizes"] == {}
    for key in ("tls:hybrid", "tls:pqc"):
        assert by_id[key]["status"] == "UNSUPPORTED"
        assert by_id[key]["network_attempted"] is False
        assert "MLKEM" in by_id[key]["reason"].upper()
    assert by_id["baseline:openssl-version"]["status"] == "SUCCESS"
    assert not workdir.exists()  # nothing runnable: no keys, no runtime directories


@pytest.mark.integration
@pytest.mark.skipif(
    "OpenSSL 3.0" not in (_system_version() or ""), reason="Ubuntu system OpenSSL 3.0.x not present"
)
def test_real_legacy_openssl_marks_pqc_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CRYPTOAGILITY_OPENSSL", str(SYSTEM_OPENSSL))
    data = benchmark.run_benchmarks(
        tmp_path,
        iterations=5,
        warmups=2,
        profiles=["hybrid"],
        algorithms=["ECDSA-P-256", "ML-KEM-768", "ML-DSA-65"],
    )
    benchmark.validate_results(data)
    by_id = {e["id"]: e for e in data["results"]}
    assert data["environment"]["openssl"]["version_number"].startswith("3.0.")
    assert data["environment"]["openssl"]["source"] == "CRYPTOAGILITY_OPENSSL"
    assert by_id["signature:ECDSA-P-256"]["status"] == "SUCCESS"
    assert by_id["kem:ML-KEM-768"]["status"] == "UNSUPPORTED"
    assert by_id["signature:ML-DSA-65"]["status"] == "UNSUPPORTED"
    assert by_id["tls:hybrid"]["status"] == "UNSUPPORTED"
    assert by_id["tls:hybrid"]["network_attempted"] is False
    _assert_clean(tmp_path)


# ------------------------------------------------------------------- fault injection


def _wrapper(tmp_path: Path, body: str) -> Path:
    real = _pinned()
    assert real is not None
    script = tmp_path / "fake-openssl"
    script.write_text(f'#!/bin/sh\nREAL="{real}"\n{body}\nexec "$REAL" "$@"\n')
    script.chmod(0o700)
    return script


def _has(flag: str) -> str:
    return f'for a in "$@"; do if [ "$a" = "{flag}" ]; then HIT=1; fi; done\n'


FAULTS = {
    "verify accepts everything": (
        ["ECDSA-P-256"],
        _has("-verify")
        + 'if [ -n "$HIT" ]; then echo "Signature Verified Successfully"; exit 0; fi',
        "tampered signature accepted",
    ),
    "verify always fails": (
        ["ML-DSA-65"],
        _has("-verify") + 'if [ -n "$HIT" ]; then exit 1; fi',
        "pkeyutl failed",
    ),
    "decap returns wrong secret": (
        ["ML-KEM-768"],
        _has("-decap") + 'if [ -n "$HIT" ]; then head -c 32 /dev/urandom; exit 0; fi',
        "does not match",
    ),
    "decap crashes": (
        ["ML-KEM-768"],
        _has("-decap") + 'if [ -n "$HIT" ]; then exit 3; fi',
        "pkeyutl failed",
    ),
    "keygen emits no key": (
        ["RSA-3072"],
        'if [ "$1" = "genpkey" ]; then echo nothing; exit 0; fi',
        "did not return",
    ),
    "encap repeats secret": (
        ["ML-KEM-768"],
        _has("-encap") + 'if [ -n "$HIT" ]; then "$REAL" "$@" >/dev/null || exit 1; '
        'printf "%032d" 0; exit 0; fi',
        "repeated shared secret",
    ),
}


@pytest.mark.integration
@pytest.mark.parametrize("fault", list(FAULTS))
def test_faulty_openssl_yields_error_without_samples(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    algorithms, body, reason = FAULTS[fault]
    caps = tls.capabilities()
    monkeypatch.setenv("CRYPTOAGILITY_OPENSSL", str(_wrapper(tmp_path, body)))
    workdir = tmp_path / "work"
    data = benchmark.run_benchmarks(
        workdir, iterations=5, warmups=2, algorithms=algorithms, include_tls=False, caps=caps
    )
    benchmark.validate_results(data)
    entry = data["results"][1]
    assert entry["status"] == "ERROR", entry
    assert reason in entry["reason"]
    assert entry["operations"] == {} and entry["sizes"] == {} and entry["checks"] == {}
    assert data["summary"]["ERROR"] == 1 and data["summary"]["SUCCESS"] == 1
    assert str(workdir) not in json.dumps(data)
    _assert_clean(workdir)


@pytest.mark.integration
def test_operation_timeout_is_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    caps = tls.capabilities()
    body = _has("-sign") + 'if [ -n "$HIT" ]; then sleep 5; fi'
    monkeypatch.setenv("CRYPTOAGILITY_OPENSSL", str(_wrapper(tmp_path, body)))
    data = benchmark.run_benchmarks(
        tmp_path / "w",
        iterations=5,
        warmups=2,
        timeout=1,
        algorithms=["ECDSA-P-256"],
        include_tls=False,
        caps=caps,
    )
    entry = data["results"][1]
    assert entry["status"] == "ERROR" and "timed out" in entry["reason"]
    assert entry["operations"] == {}
    _assert_clean(tmp_path / "w")


@pytest.mark.integration
def test_failed_tls_handshakes_are_error_not_samples(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    caps = tls.capabilities()
    body = 'if [ "$1" = "s_client" ]; then echo "garbage"; exit 1; fi'
    monkeypatch.setenv("CRYPTOAGILITY_OPENSSL", str(_wrapper(tmp_path, body)))
    data = benchmark.run_benchmarks(
        tmp_path / "w", iterations=5, warmups=2, profiles=["classical"], algorithms=[], caps=caps
    )
    benchmark.validate_results(data)
    entry = {e["id"]: e for e in data["results"]}["tls:classical"]
    assert entry["status"] == "ERROR"
    assert entry["network_attempted"] is True
    assert entry["reason"].startswith("handshake 0 ")
    assert entry["operations"] == {} and entry["sizes"] == {}
    _assert_clean(tmp_path / "w")


@pytest.mark.integration
def test_missing_handshake_counters_are_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    caps = tls.capabilities()
    body = (
        'if [ "$1" = "s_client" ]; then "$REAL" "$@" | sed "/SSL handshake has read/d"; exit 0; fi'
    )
    monkeypatch.setenv("CRYPTOAGILITY_OPENSSL", str(_wrapper(tmp_path, body)))
    data = benchmark.run_benchmarks(
        tmp_path / "w", iterations=5, warmups=2, profiles=["hybrid"], algorithms=[], caps=caps
    )
    entry = {e["id"]: e for e in data["results"]}["tls:hybrid"]
    assert entry["status"] == "ERROR"
    assert "counters missing" in entry["reason"]
    assert entry["operations"] == {}


# ------------------------------------------------------------------- filesystem safety


@needs_native
def test_symlinked_workdir_and_runtime_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(ValueError):
        benchmark.run_benchmarks(
            link, iterations=5, warmups=2, algorithms=["ECDSA-P-256"], include_tls=False
        )
    work = tmp_path / "work"
    work.mkdir()
    (work / "benchmark-lab").symlink_to(real)
    with pytest.raises(ValueError):
        benchmark.run_benchmarks(
            work, iterations=5, warmups=2, algorithms=["ECDSA-P-256"], include_tls=False
        )
    assert list(real.iterdir()) == []


@pytest.mark.integration
def test_keys_never_outlive_successful_run(tmp_path: Path) -> None:
    data = benchmark.run_benchmarks(
        tmp_path,
        iterations=5,
        warmups=2,
        algorithms=["ML-KEM-768", "SLH-DSA-SHAKE-128f"],
        include_tls=False,
    )
    benchmark.validate_results(data)
    assert [e["status"] for e in data["results"]] == ["SUCCESS"] * 3
    leftovers = [p for p in tmp_path.rglob("*") if p.is_file() and p.name != ".gitignore"]
    assert leftovers == []
    assert os.listdir(tmp_path) == ["benchmark-lab"]
