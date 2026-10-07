"""Repeatable operation and TLS handshake measurements on the pinned native OpenSSL.

Every measured operation is a real invocation of the pinned OpenSSL command line (genpkey,
pkeyutl, s_server/s_client through cryptoagility.tls); no cryptography is implemented here.
Each sample is checked for correctness before it is accepted: every produced signature is
verified, every ML-KEM decapsulation must reproduce its encapsulation's shared secret, and
every TLS handshake must complete, verify the synthetic chain and match its strict profile.
Tampered-signature and tampered-ciphertext controls run alongside. Any failure turns the
whole benchmark entry into ERROR with no samples; unavailable algorithms are UNSUPPORTED.

Only public metadata leaves this module: timings, byte sizes (DER keys, signatures,
ciphertexts, certificates, handshake counters) and algorithm names. Private keys and shared
secrets live only in a mode-0700, git-ignored runtime directory or in memory and are deleted
when the run ends.

Timing scope: each operation sample is the wall-clock time (time.perf_counter_ns) of one
complete OpenSSL process, so it includes process start-up, provider initialisation, PEM key
parsing and file I/O. It is not an isolated primitive latency. The process-overhead baseline
(openssl version) is reported so readers can see that floor. Results describe this lab host
only and do not represent production performance.
"""

from __future__ import annotations

import hmac
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from cryptoagility import openssl, tls
from cryptoagility.models import SCHEMA_VERSION

RESULT_KIND = "cryptoagility.benchmark"

SUCCESS = "SUCCESS"
UNSUPPORTED = "UNSUPPORTED"
ERROR = "ERROR"
STATUSES = (SUCCESS, UNSUPPORTED, ERROR)

MIN_ITERATIONS = 5
MAX_ITERATIONS = 500
MIN_WARMUPS = 2
MAX_WARMUPS = 50
P95_MIN_SAMPLES = 20
MIN_TIMEOUT = 1.0
MAX_TIMEOUT = 300.0
DEFAULT_TIMEOUT = 60.0

MESSAGE = (b"CryptoAgility Lab synthetic benchmark message; contains no real data.\n" * 15)[:1024]

TIMING_CLOCK = "time.perf_counter_ns"
P95_METHOD = f"nearest-rank on sorted samples; omitted when fewer than {P95_MIN_SAMPLES} samples"
PROCESS_SCOPE = (
    "One sample = one complete openssl CLI process timed with time.perf_counter_ns around "
    "cryptoagility.openssl.run: fork/exec, dynamic loading, provider initialisation "
    "(OPENSSL_CONF=/dev/null), PEM key parsing, file and pipe I/O, then the operation. "
    "It is not an isolated in-library primitive latency."
)
TLS_TIMING_SCOPE = (
    "TLS samples are tls.handshake client_process_ms (time.perf_counter around one whole "
    "s_client process, rounded by tls to 1 microsecond) converted to integer nanoseconds. "
    + tls.LATENCY_SEMANTICS
)
HANDSHAKE_BYTES_DEFINITION = (
    "handshake_bytes_read/written are the client-side OpenSSL BIO counters printed by "
    "s_client as 'SSL handshake has read N bytes and written M bytes' when it prints the "
    "session summary after the TLS 1.3 handshake: TLS record bytes (record headers, "
    "handshake messages, any compatibility ChangeCipherSpec) on the client connection. "
    "They exclude TCP/IP/Ethernet framing and are not derived from packet capture. Session "
    "tickets are disabled on both sides (-no_ticket, -num_tickets 0)."
)
CAVEATS = (
    PROCESS_SCOPE,
    "Compare operation timings with the baseline:openssl-version entry, which measures the "
    "same subprocess path for a command that performs no cryptography.",
    "Samples are taken sequentially on a shared host without CPU pinning or frequency "
    "control; scheduler, cache and virtualisation noise are not removed.",
    "Results describe this lab environment only; they are not production, hardware-module "
    "or network performance figures and do not rank algorithms in general.",
    "Warmup samples are recorded but excluded from statistics.",
    "Private key DER sizes are the OpenSSL default PKCS#8 encodings; ML-KEM and ML-DSA "
    "encodings from OpenSSL 3.5 can include both seed and expanded key.",
    tls.STANDARDIZATION_NOTE,
)

_SAFE_ENV = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _.,()=+-:@#/"
_RUNTIME_DIR = "benchmark-lab"


class BenchmarkError(RuntimeError):
    """A measurement failed; the message is already sanitized."""


@dataclass(frozen=True)
class AlgorithmSpec:
    name: str
    kind: str
    family: str
    list_name: str
    genpkey_args: tuple[str, ...]
    sign_args: tuple[str, ...]
    standard: str
    scheme: str


def _sig(name: str, standard: str, scheme: str) -> AlgorithmSpec:
    return AlgorithmSpec(name, "signature", "pqc", name, ("-algorithm", name), (), standard, scheme)


def _known_algorithms() -> dict[str, AlgorithmSpec]:
    specs = [
        AlgorithmSpec(
            "RSA-3072",
            "signature",
            "classical",
            "RSA",
            ("-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"),
            (
                "-digest",
                "sha256",
                "-pkeyopt",
                "rsa_padding_mode:pss",
                "-pkeyopt",
                "rsa_pss_saltlen:digest",
            ),
            "RFC 8017 RSASSA-PSS",
            "RSASSA-PSS, SHA-256, salt length = digest length",
        ),
        AlgorithmSpec(
            "ECDSA-P-256",
            "signature",
            "classical",
            "ECDSA",
            ("-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"),
            ("-digest", "sha256"),
            "FIPS 186-5 ECDSA",
            "ECDSA over P-256 with SHA-256, DER-encoded signature",
        ),
    ]
    for level in ("44", "65", "87"):
        specs.append(_sig(f"ML-DSA-{level}", "FIPS 204", "pure ML-DSA, empty context"))
    for family in ("SHA2", "SHAKE"):
        for size in ("128", "192", "256"):
            for variant in ("s", "f"):
                specs.append(
                    _sig(
                        f"SLH-DSA-{family}-{size}{variant}",
                        "FIPS 205",
                        "pure SLH-DSA, empty context",
                    )
                )
    for level in ("512", "768", "1024"):
        name = f"ML-KEM-{level}"
        specs.append(
            AlgorithmSpec(
                name,
                "kem",
                "pqc",
                name,
                ("-algorithm", name),
                (),
                "FIPS 203",
                "ML-KEM encapsulation/decapsulation",
            )
        )
    return {spec.name: spec for spec in specs}


KNOWN_ALGORITHMS: dict[str, AlgorithmSpec] = _known_algorithms()

PROFILE_ALGORITHMS: dict[str, tuple[str, ...]] = {
    "classical": ("RSA-3072", "ECDSA-P-256"),
    "hybrid": ("ML-KEM-768", "RSA-3072"),
    "pqc": ("ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128s"),
}
PROFILE_CLIENTS: dict[str, str] = {
    "classical": "classical-only",
    "hybrid": "hybrid-only",
    "pqc": "pqc-only",
}
PROFILES = tuple(PROFILE_ALGORITHMS)


# --------------------------------------------------------------------------- helpers


def _clean(value: Any, limit: int = 160) -> str | None:
    if value is None:
        return None
    text = "".join(ch if ch in _SAFE_ENV else " " for ch in str(value))
    return " ".join(text.split())[:limit] or None


def _bounded_int(value: Any, low: int, high: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{what} must be an integer between {low} and {high}")
    return value


def _names(value: Any, allowed: Sequence[str], what: str, *, empty: bool = False) -> list[str]:
    if not isinstance(value, list | tuple) or (not value and not empty):
        raise ValueError(f"{what} must be a non-empty list")
    names: list[str] = []
    for item in value:
        if not isinstance(item, str) or item not in allowed:
            raise ValueError(f"Unknown {what[:-1]}")
        if item not in names:
            names.append(item)
    return names


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def _run(args: list[str], timeout: float, *, input: bytes | None = None) -> tuple[int, bytes]:
    start = time.perf_counter_ns()
    try:
        out = openssl.run(args, input=input, timeout=timeout)
    except openssl.OpenSSLError as exc:
        raise BenchmarkError(tls.sanitize_reason(str(exc)) or "OpenSSL command failed") from exc
    return time.perf_counter_ns() - start, out


def p95_nearest_rank(samples: Sequence[int]) -> int | None:
    if len(samples) < P95_MIN_SAMPLES:
        return None
    ordered = sorted(samples)
    return ordered[math.ceil(0.95 * len(ordered)) - 1]


def summarize(samples: Sequence[int]) -> dict[str, Any]:
    """Statistics over measured (non-warmup) samples in nanoseconds."""
    if not samples:
        raise ValueError("no samples")
    median = statistics.median(samples)
    p95 = p95_nearest_rank(samples)
    return {
        "count": len(samples),
        "median_ns": median,
        "min_ns": min(samples),
        "max_ns": max(samples),
        "p95_ns": p95,
        "median_ms": round(median / 1e6, 4),
        "min_ms": round(min(samples) / 1e6, 4),
        "max_ms": round(max(samples) / 1e6, 4),
        "p95_ms": round(p95 / 1e6, 4) if p95 is not None else None,
    }


def _distribution(values: Sequence[int]) -> dict[str, int]:
    return {"min": min(values), "max": max(values)}


class _Plan:
    def __init__(self, warmups: int, iterations: int, timeout: float):
        self.warmups = warmups
        self.iterations = iterations
        self.timeout = timeout

    @property
    def total(self) -> int:
        return self.warmups + self.iterations

    def measure(self, sample: Callable[[int], int], source: str = TIMING_CLOCK) -> dict[str, Any]:
        """Run warmups then iterations; any exception aborts (no partial success)."""
        values = []
        for index in range(self.total):
            elapsed = sample(index)
            if isinstance(elapsed, bool) or not isinstance(elapsed, int) or elapsed <= 0:
                raise BenchmarkError("measurement produced an invalid duration")
            values.append(elapsed)
        measured = values[self.warmups :]
        return {
            "status": SUCCESS,
            "timing_source": source,
            "warmup_samples_ns": values[: self.warmups],
            "samples_ns": measured,
            "statistics": summarize(measured),
        }


class _Workspace:
    """<workdir>/benchmark-lab/run-*: mode 0700, git-ignored, removed on exit."""

    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.run_dir: Path | None = None

    def __enter__(self) -> _Workspace:
        root = self.workdir / _RUNTIME_DIR
        if root.is_symlink():
            raise ValueError("benchmark runtime directory must not be a symlink")
        self.workdir.mkdir(parents=True, exist_ok=True)
        root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(root, 0o700)
        ignore = root / ".gitignore"
        if not ignore.exists():
            _write_private(ignore, b"*\n")
        self.run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        return self

    def __exit__(self, *exc: object) -> None:
        if self.run_dir is not None:
            shutil.rmtree(self.run_dir, ignore_errors=True)

    def subdir(self, name: str) -> Path:
        assert self.run_dir is not None
        path = Path(tempfile.mkdtemp(prefix=f"{name}-", dir=self.run_dir))
        os.chmod(path, 0o700)
        return path


# --------------------------------------------------------------------------- environment


def _read_small(path: str, limit: int = 65536) -> str:
    try:
        with open(path, "rb") as stream:
            return stream.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def _cpu_model() -> str | None:
    for line in _read_small("/proc/cpuinfo", 262144).splitlines():
        key, _, value = line.partition(":")
        if key.strip() in ("model name", "Hardware", "Processor") and value.strip():
            return _clean(value)
    return _clean(platform.processor()) or None


def _os_release() -> str | None:
    for line in _read_small("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            return _clean(line.partition("=")[2].strip().strip('"'))
    return None


def detect_container() -> dict[str, Any]:
    """Best-effort container indicators; absence is not proof of bare metal."""
    indicators: list[str] = []
    runtime: str | None = None
    if Path("/.dockerenv").exists():
        indicators.append("/.dockerenv present")
        runtime = "docker"
    if Path("/run/.containerenv").exists():
        indicators.append("/run/.containerenv present")
        runtime = runtime or "podman"
    marker = os.environ.get("container")
    if marker:
        indicators.append(f"container environment variable = {_clean(marker, 32)}")
        runtime = runtime or _clean(marker, 32)
    cgroup = _read_small("/proc/1/cgroup").lower()
    for token in ("docker", "kubepods", "containerd", "libpod", "lxc"):
        if token in cgroup:
            indicators.append(f"pid 1 cgroup mentions {token}")
            runtime = runtime or token
    virt = None
    tool = shutil.which("systemd-detect-virt")
    if tool:
        try:
            out = subprocess.run([tool], capture_output=True, timeout=5, check=False)
            virt = _clean(out.stdout[:64].decode("utf-8", "replace"), 32)
        except (OSError, subprocess.TimeoutExpired):
            virt = None
    return {
        "detected": bool(indicators),
        "runtime": runtime,
        "indicators": indicators,
        "virtualization": virt,
        "note": "best-effort detection from local indicators",
    }


def _loadavg() -> list[float] | None:
    try:
        return [round(v, 2) for v in os.getloadavg()]
    except OSError:
        return None


def _openssl_source() -> str:
    if os.environ.get("CRYPTOAGILITY_OPENSSL"):
        return "CRYPTOAGILITY_OPENSSL"
    if os.environ.get("CRYPTOAGILITY_TOOLS_DIR"):
        return "CRYPTOAGILITY_TOOLS_DIR"
    pinned = Path(__file__).resolve().parent.parent / ".tools" / "openssl" / "bin" / "openssl"
    if pinned.is_file():
        return "checkout .tools (scripts/setup-openssl.sh)"
    return "system (CRYPTOAGILITY_ALLOW_SYSTEM_OPENSSL=1)"


def environment(caps: dict[str, Any]) -> dict[str, Any]:
    try:
        affinity: int | None = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        affinity = None
    return {
        "timestamp_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": {
            "cpu_model": _cpu_model(),
            "logical_cpus": os.cpu_count(),
            "usable_cpus": affinity,
            "architecture": _clean(platform.machine()),
            "load_average_start": _loadavg(),
        },
        "os": {
            "system": _clean(platform.system()),
            "release": _clean(platform.release()),
            "distribution": _os_release(),
            "platform": _clean(platform.platform()),
        },
        "python": {
            "version": _clean(platform.python_version()),
            "implementation": _clean(platform.python_implementation()),
        },
        "openssl": {
            **{k: _clean(v) for k, v in caps.get("openssl", {}).items()},
            "source": _openssl_source(),
            "providers": caps.get("providers", []),
            "oqs_provider_loaded": bool(caps.get("oqs_provider_loaded")),
            "oqs_required": False,
            "config": "OPENSSL_CONF=/dev/null",
        },
        "container": detect_container(),
    }


# --------------------------------------------------------------------------- capability


def _provider(caps: dict[str, Any], kind: str, list_name: str) -> str | None:
    key = "kem_algorithms" if kind == "kem" else "signature_algorithms"
    for entry in caps.get(key, []):
        if list_name in entry.get("names", []):
            return _clean(entry.get("provider"))
    return None


def capability_inventory(caps: dict[str, Any], benchmarked: Sequence[str]) -> dict[str, Any]:
    """What the stack exposes versus what this run measured in depth."""
    available = [n for n, s in KNOWN_ALGORITHMS.items() if _provider(caps, s.kind, s.list_name)]
    return {
        "standardized": caps.get("standardized", {}),
        "tls_group_classes": caps.get("tls_group_classes", {}),
        "x509": caps.get("x509", {}),
        "tls_profiles": caps.get("profiles", {}),
        "unavailable_queries": caps.get("unavailable_queries", []),
        "known_algorithms_available": available,
        "benchmarked_algorithms": [n for n in benchmarked if n in available],
        "available_not_benchmarked": [n for n in available if n not in benchmarked],
        "standardization_note": tls.STANDARDIZATION_NOTE,
    }


# --------------------------------------------------------------------------- entries


def _entry(
    entry_id: str, kind: str, algorithm: str, profiles: list[str], **extra: Any
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": entry_id,
        "kind": kind,
        "algorithm": algorithm,
        "profiles": profiles,
        "status": ERROR,
        "reason": None,
        "sizes": {},
        "checks": {},
        "operations": {},
    }
    entry.update(extra)
    return entry


def _fail(entry: dict[str, Any], status: str, reason: str) -> dict[str, Any]:
    entry.update(
        status=status,
        reason=tls.sanitize_reason(reason) or status.lower(),
        sizes={},
        checks={},
        operations={},
    )
    return entry


def _keygen(spec: AlgorithmSpec, plan: _Plan) -> tuple[dict[str, Any], bytes]:
    keys: list[bytes] = []

    def sample(_: int) -> int:
        elapsed, out = _run(["genpkey", *spec.genpkey_args], plan.timeout)
        if b"-----BEGIN PRIVATE KEY-----" not in out:
            raise BenchmarkError("genpkey did not return a PKCS#8 private key")
        keys[:] = [out]
        return elapsed

    result = plan.measure(sample)
    return result, keys[0]


def _key_material(
    spec: AlgorithmSpec, pem: bytes, keydir: Path, timeout: float
) -> tuple[Path, Path, dict[str, int]]:
    key = keydir / "key.pem"
    _write_private(key, pem)
    _, pub_pem = _run(["pkey", "-in", str(key), "-pubout"], timeout)
    pub = keydir / "public.pem"
    _write_private(pub, pub_pem)
    _, pub_der = _run(["pkey", "-pubin", "-in", str(pub), "-outform", "DER"], timeout)
    _, priv_der = _run(["pkey", "-in", str(key), "-outform", "DER"], timeout)
    sizes = {"public_key_der_bytes": len(pub_der), "private_key_der_bytes": len(priv_der)}
    del priv_der
    if not all(sizes.values()):
        raise BenchmarkError("empty key encoding")
    return key, pub, sizes


def _flip(data: bytes) -> bytes:
    tampered = bytearray(data)
    tampered[len(tampered) // 2] ^= 0x01
    return bytes(tampered)


def _verify_args(spec: AlgorithmSpec, pub: Path, message: Path, signature: Path) -> list[str]:
    return [
        "pkeyutl",
        "-verify",
        "-rawin",
        *spec.sign_args,
        "-pubin",
        "-inkey",
        str(pub),
        "-in",
        str(message),
        "-sigfile",
        str(signature),
    ]


def _rejected(args: list[str], timeout: float) -> bool:
    try:
        _, out = _run(args, timeout)
    except BenchmarkError:
        return True
    return b"Signature Verified Successfully" not in out


def bench_signature(spec: AlgorithmSpec, plan: _Plan, workspace: _Workspace) -> dict[str, Any]:
    entry = _entry(f"signature:{spec.name}", "signature", spec.name, [])
    keydir = workspace.subdir("sig")
    keygen, pem = _keygen(spec, plan)
    key, pub, sizes = _key_material(spec, pem, keydir, plan.timeout)
    del pem
    message = keydir / "message.bin"
    _write_private(message, MESSAGE)
    signatures: list[bytes] = []

    def sign(_: int) -> int:
        elapsed, sig = _run(
            [
                "pkeyutl",
                "-sign",
                "-rawin",
                *spec.sign_args,
                "-inkey",
                str(key),
                "-in",
                str(message),
            ],
            plan.timeout,
        )
        if not sig:
            raise BenchmarkError("empty signature")
        signatures.append(sig)
        return elapsed

    sign_result = plan.measure(sign)
    sig_files = []
    for index, sig in enumerate(signatures):
        path = keydir / f"sig-{index}.bin"
        _write_private(path, sig)
        sig_files.append(path)

    def verify(index: int) -> int:
        elapsed, out = _run(_verify_args(spec, pub, message, sig_files[index]), plan.timeout)
        if b"Signature Verified Successfully" not in out:
            raise BenchmarkError("signature verification did not succeed")
        return elapsed

    verify_result = plan.measure(verify)
    tampered = keydir / "tampered.bin"
    _write_private(tampered, _flip(signatures[-1]))
    other = keydir / "other-message.bin"
    _write_private(other, _flip(MESSAGE))
    tampered_rejected = _rejected(_verify_args(spec, pub, message, tampered), plan.timeout)
    message_rejected = _rejected(_verify_args(spec, pub, other, sig_files[-1]), plan.timeout)
    if not tampered_rejected:
        raise BenchmarkError("negative control failed: tampered signature accepted")
    if not message_rejected:
        raise BenchmarkError("negative control failed: modified message accepted")
    sig_sizes = [len(s) for s in signatures]
    entry.update(
        status=SUCCESS,
        sizes={**sizes, "signature_bytes": _distribution(sig_sizes), "message_bytes": len(MESSAGE)},
        checks={
            "every_signature_verified": len(signatures) == plan.total,
            "tampered_signature_rejected": True,
            "modified_message_rejected": True,
        },
        operations={"keygen": keygen, "sign": sign_result, "verify": verify_result},
    )
    return entry


def bench_kem(spec: AlgorithmSpec, plan: _Plan, workspace: _Workspace) -> dict[str, Any]:
    entry = _entry(f"kem:{spec.name}", "kem", spec.name, [])
    keydir = workspace.subdir("kem")
    keygen, pem = _keygen(spec, plan)
    key, pub, sizes = _key_material(spec, pem, keydir, plan.timeout)
    del pem
    secrets: list[bytes] = []
    ciphertexts: list[Path] = []

    def encap(index: int) -> int:
        ct = keydir / f"ct-{index}.bin"
        elapsed, secret = _run(
            [
                "pkeyutl",
                "-encap",
                "-pubin",
                "-inkey",
                str(pub),
                "-out",
                str(ct),
                "-secret",
                "/dev/stdout",
            ],
            plan.timeout,
        )
        if not secret or not ct.is_file():
            raise BenchmarkError("encapsulation produced no output")
        secrets.append(secret)
        ciphertexts.append(ct)
        return elapsed

    def decap(index: int) -> int:
        elapsed, secret = _run(
            ["pkeyutl", "-decap", "-inkey", str(key), "-in", str(ciphertexts[index])], plan.timeout
        )
        if not hmac.compare_digest(secret, secrets[index]):
            raise BenchmarkError("decapsulated shared secret does not match encapsulation")
        return elapsed

    try:
        encap_result = plan.measure(encap)
        if len({bytes(s) for s in secrets}) != len(secrets):
            raise BenchmarkError("repeated shared secret across encapsulations")
        decap_result = plan.measure(decap)
        ct_sizes = [p.stat().st_size for p in ciphertexts]
        secret_sizes = [len(s) for s in secrets]
        last_ct = ciphertexts[-1].read_bytes()
        tampered = keydir / "tampered-ct.bin"
        _write_private(tampered, _flip(last_ct))
        try:
            _, implicit = _run(
                ["pkeyutl", "-decap", "-inkey", str(key), "-in", str(tampered)], plan.timeout
            )
            if hmac.compare_digest(implicit, secrets[-1]):
                raise BenchmarkError(
                    "negative control failed: tampered ciphertext gave the original shared secret"
                )
            tamper_outcome = "implicit_rejection_different_secret"
        except BenchmarkError as exc:
            if "negative control" in str(exc):
                raise
            tamper_outcome = "rejected_with_error"
        truncated = keydir / "truncated-ct.bin"
        _write_private(truncated, last_ct[: len(last_ct) // 2])
        try:
            _run(["pkeyutl", "-decap", "-inkey", str(key), "-in", str(truncated)], plan.timeout)
        except BenchmarkError:
            pass
        else:
            raise BenchmarkError("negative control failed: truncated ciphertext accepted")
    finally:
        secrets.clear()
    entry.update(
        status=SUCCESS,
        sizes={
            **sizes,
            "ciphertext_bytes": _distribution(ct_sizes),
            "shared_secret_bytes": _distribution(secret_sizes),
        },
        checks={
            "every_shared_secret_matched": True,
            "shared_secrets_distinct": True,
            "tampered_ciphertext": tamper_outcome,
            "truncated_ciphertext_rejected": True,
            "shared_secret_values_published": False,
        },
        operations={"keygen": keygen, "encapsulate": encap_result, "decapsulate": decap_result},
    )
    return entry


def bench_baseline(plan: _Plan) -> dict[str, Any]:
    entry = _entry(
        "baseline:openssl-version",
        "baseline",
        "none",
        [],
        description="Subprocess floor: 'openssl version' performs no cryptography",
    )

    def sample(_: int) -> int:
        elapsed, out = _run(["version"], plan.timeout)
        if not out.startswith(b"OpenSSL"):
            raise BenchmarkError("unexpected version output")
        return elapsed

    entry.update(status=SUCCESS, operations={"process": plan.measure(sample)})
    return entry


def bench_tls(name: str, plan: _Plan, workdir: Path, caps: dict[str, Any]) -> dict[str, Any]:
    profile = tls.PROFILES[name]
    client = tls.CLIENT_VARIANTS[PROFILE_CLIENTS[name]]
    spec = tls.SERVER_SPECS[name]
    entry = _entry(
        f"tls:{name}",
        "tls_handshake",
        profile.group,
        [name],
        group=profile.group,
        group_kind=profile.group_kind,
        certificate_key=profile.certificate_key,
        authentication=profile.authentication,
        client_variant=client.name,
        network_attempted=False,
    )
    try:
        tls.resolve_profile(name, caps)
    except tls.UnsupportedProfileError as exc:
        return _fail(entry, UNSUPPORTED, "; ".join(exc.missing))
    groups = caps.get("tls13_groups", [])
    missing = [g for g in client.groups or () if not tls.group_in(g, groups)]
    if missing:
        return _fail(entry, UNSUPPORTED, "client group unavailable: " + "; ".join(missing))
    try:
        return _measure_tls(entry, spec, client, plan, workdir)
    except (BenchmarkError, openssl.OpenSSLError, tls.TLSLabError, OSError, ValueError) as exc:
        return _fail(entry, ERROR, str(exc) or type(exc).__name__)


def _measure_tls(
    entry: dict[str, Any],
    spec: tls.ServerSpec,
    client: tls.ClientVariant,
    plan: _Plan,
    workdir: Path,
) -> dict[str, Any]:
    profile = tls.PROFILES[entry["profiles"][0]]
    policy = dict(tls.DEFAULT_POLICY)
    rows: list[dict[str, Any]] = []
    with tls.LabPKI(workdir) as pki:
        credential = pki.issue(spec.credential_key, spec.credential_variant)
        with tls.LoopbackServer(credential, profile.group, timeout=plan.timeout) as server:
            assert server.port is not None
            entry["network_attempted"] = True
            port = server.port

            def sample(index: int) -> int:
                result = tls.handshake(
                    port, client, pki.trust_bundle, timeout=plan.timeout, server=server
                )
                row = tls.result_row(spec, client, result, policy)
                if row["status"] != tls.SUCCESS:
                    raise BenchmarkError(
                        f"handshake {index} {row['status']}: "
                        f"{row['error_reason'] or row['failure_kind']}"
                    )
                if (
                    result.client_process_ms is None
                    or result.handshake_bytes_read is None
                    or result.handshake_bytes_written is None
                ):
                    raise BenchmarkError("handshake instrumentation counters missing")
                rows.append(row)
                return int(round(result.client_process_ms * 1_000_000))

            measured = plan.measure(sample, source=TLS_TIMING_SCOPE)
    observed = {
        key: sorted({str(r[key]) for r in rows})
        for key in (
            "negotiated_group",
            "tls_version",
            "cipher_suite",
            "certificate_type",
            "certificate_signature_algorithm",
            "peer_signature_type",
            "chain_der_bytes",
            "chain_length",
        )
    }
    unstable = [
        key
        for key, values in observed.items()
        if key not in ("cipher_suite", "peer_signature_type") and len(values) != 1
    ]
    if unstable:
        raise BenchmarkError(
            "handshake observations changed between samples: " + ", ".join(unstable)
        )
    first = rows[0]
    if first["chain_der_bytes"] != credential.served_chain_der_bytes:
        raise BenchmarkError("observed chain size differs from served DER chain")
    read = [r["handshake_bytes_read"] for r in rows]
    written = [r["handshake_bytes_written"] for r in rows]
    entry.update(
        status=SUCCESS,
        negotiated_group=first["negotiated_group"],
        negotiated_group_kind=first["negotiated_group_kind"],
        tls_version=first["tls_version"],
        cipher_suites=observed["cipher_suite"],
        certificate_type=first["certificate_type"],
        certificate_signature_algorithm=first["certificate_signature_algorithm"],
        peer_signature_types=observed["peer_signature_type"],
        policy={
            "name": policy["name"],
            "pass": first["policy_pass"],
            "reasons": first["policy_reasons"],
        },
        sizes={
            "leaf_certificate_der_bytes": credential.certificate_der_bytes,
            "served_chain_der_bytes": credential.served_chain_der_bytes,
            "served_chain_length": credential.served_chain_length,
            "observed_chain_der_bytes": first["chain_der_bytes"],
            "handshake_bytes_read": _distribution(read),
            "handshake_bytes_written": _distribution(written),
            "handshake_bytes_total": _distribution(
                [a + b for a, b in zip(read, written, strict=True)]
            ),
            "handshake_bytes_definition": HANDSHAKE_BYTES_DEFINITION,
        },
        checks={
            "every_handshake_verified_and_profile_matched": len(rows) == plan.total,
            "client": client.name,
            "trust": "synthetic lab root only, hostname and strict X.509 verification",
        },
        operations={"handshake": measured},
    )
    return entry


# --------------------------------------------------------------------------- public API


def run_benchmarks(
    workdir: Path,
    iterations: int = 20,
    warmups: int = 3,
    profiles: list[str] | None = None,
    *,
    algorithms: list[str] | None = None,
    include_tls: bool = True,
    caps: dict[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Measure keygen/sign/verify, ML-KEM encap/decap and strict-profile TLS handshakes.

    profiles narrows to classical/hybrid/pqc (default all); algorithms, if given, replaces the
    profiles' default primitive set with explicitly named known algorithms. Unavailable
    algorithms or profiles are UNSUPPORTED; any failed measurement is ERROR without samples.
    """
    iterations = _bounded_int(iterations, MIN_ITERATIONS, MAX_ITERATIONS, "iterations")
    warmups = _bounded_int(warmups, MIN_WARMUPS, MAX_WARMUPS, "warmups")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int | float)
        or not (MIN_TIMEOUT <= timeout <= MAX_TIMEOUT)
    ):
        raise ValueError(f"timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds")
    if not isinstance(include_tls, bool):
        raise ValueError("include_tls must be a boolean")
    selected = _names(list(PROFILES) if profiles is None else profiles, PROFILES, "profiles")
    if algorithms is not None:
        chosen = _names(algorithms, list(KNOWN_ALGORITHMS), "algorithms", empty=True)
    else:
        chosen = []
        for name in selected:
            chosen += [a for a in PROFILE_ALGORITHMS[name] if a not in chosen]
    if not chosen and not include_tls:
        raise ValueError("nothing to benchmark")
    workdir = Path(workdir)
    if workdir.is_symlink():
        raise ValueError("workdir must not be a symlink")
    caps = caps if caps is not None else tls.capabilities()
    plan = _Plan(warmups, iterations, float(timeout))
    env = environment(caps)
    started = time.monotonic()
    results: list[dict[str, Any]] = []
    runnable = [
        n
        for n in chosen
        if _provider(caps, KNOWN_ALGORITHMS[n].kind, KNOWN_ALGORITHMS[n].list_name)
    ]
    with _Workspace(workdir) if runnable else _NullWorkspace() as workspace:
        results.append(
            _guard(
                _entry("baseline:openssl-version", "baseline", "none", []),
                partial(bench_baseline, plan),
            )
        )
        for name in chosen:
            spec = KNOWN_ALGORITHMS[name]
            member = [p for p in selected if name in PROFILE_ALGORITHMS[p]]
            entry = _entry(f"{spec.kind}:{name}", spec.kind, name, member)
            if name not in runnable:
                entry = _fail(
                    entry,
                    UNSUPPORTED,
                    f"ALGORITHM NOT AVAILABLE: {name} not listed by the pinned OpenSSL providers",
                )
            else:
                bench = bench_signature if spec.kind == "signature" else bench_kem
                entry = _guard(entry, partial(bench, spec, plan, workspace))
            entry.update(
                profiles=member,
                family=spec.family,
                standard=spec.standard,
                scheme=spec.scheme,
                provider=_provider(caps, spec.kind, spec.list_name),
                interface="openssl genpkey/pkey/pkeyutl CLI",
            )
            results.append(entry)
        if include_tls:
            for name in selected:
                fallback = _entry(
                    f"tls:{name}",
                    "tls_handshake",
                    tls.PROFILES[name].group,
                    [name],
                    network_attempted=True,
                )
                results.append(_guard(fallback, partial(bench_tls, name, plan, workdir, caps)))
    env["host"]["load_average_end"] = _loadavg()
    env["wall_time_s"] = round(time.monotonic() - started, 3)
    summary = {status: sum(1 for r in results if r["status"] == status) for status in STATUSES}
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RESULT_KIND,
        "environment": env,
        "methodology": {
            "timing_clock": TIMING_CLOCK,
            "sample_unit": "ns",
            "iterations": iterations,
            "warmups": warmups,
            "warmups_excluded_from_statistics": True,
            "statistics": ["median", "min", "max", "p95"],
            "p95_method": P95_METHOD,
            "p95_min_samples": P95_MIN_SAMPLES,
            "execution": "sequential; one OpenSSL process or handshake at a time",
            "operation_scope": PROCESS_SCOPE,
            "tls_timing_scope": TLS_TIMING_SCOPE,
            "handshake_bytes_definition": HANDSHAKE_BYTES_DEFINITION,
            "message_bytes": len(MESSAGE),
            "timeout_s": float(timeout),
            "caveats": list(CAVEATS),
        },
        "requested": {"profiles": selected, "algorithms": chosen, "include_tls": include_tls},
        "capabilities": capability_inventory(caps, chosen),
        "statuses": list(STATUSES),
        "summary": summary,
        "results": results,
    }


class _NullWorkspace(_Workspace):
    def __init__(self) -> None:
        super().__init__(Path(os.devnull))

    def __enter__(self) -> _Workspace:
        return self

    def subdir(self, name: str) -> Path:
        raise BenchmarkError("no runtime workspace")


def _guard(entry: dict[str, Any], bench: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return bench()
    except (BenchmarkError, openssl.OpenSSLError, tls.TLSLabError, OSError, ValueError) as exc:
        return _fail(entry, ERROR, str(exc) or type(exc).__name__)


# --------------------------------------------------------------------------- validation


_FORBIDDEN = ("PRIVATE KEY", "-----BEGIN", "Master-Key", "PSK")


def _check_operation(op: Any, iterations: int, warmups: int, where: str) -> None:
    if not isinstance(op, dict) or op.get("status") != SUCCESS:
        raise ValueError(f"{where}: operation must be SUCCESS")
    samples, warm = op.get("samples_ns"), op.get("warmup_samples_ns")
    for name, values, count in (
        ("samples_ns", samples, iterations),
        ("warmup_samples_ns", warm, warmups),
    ):
        if (
            not isinstance(values, list)
            or len(values) != count
            or not all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in values)
        ):
            raise ValueError(f"{where}: {name} must hold {count} positive integers")
    assert isinstance(samples, list)
    if op.get("statistics") != summarize(samples):
        raise ValueError(f"{where}: statistics do not match raw samples")


def validate_results(data: Any) -> dict[str, Any]:
    """Strict consistency check for benchmark evidence (e.g. before reporting).

    Recomputes statistics from raw samples, enforces bounds and status rules (only SUCCESS
    entries may carry samples) and rejects private-key or secret markers.
    """
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported benchmark schema version")
    if data.get("kind") != RESULT_KIND:
        raise ValueError("Not a benchmark result")
    text = json.dumps(data)
    if any(marker in text for marker in _FORBIDDEN):
        raise ValueError("Benchmark evidence contains private or secret material markers")
    env = data.get("environment")
    if not isinstance(env, dict) or not all(
        k in env for k in ("timestamp_utc", "host", "os", "python", "openssl", "container")
    ):
        raise ValueError("Benchmark environment metadata incomplete")
    if not env["openssl"].get("version") or "cpu_model" not in env["host"]:
        raise ValueError("Benchmark environment metadata incomplete")
    method = data.get("methodology")
    if not isinstance(method, dict):
        raise ValueError("Benchmark methodology missing")
    iterations = _bounded_int(
        method.get("iterations"), MIN_ITERATIONS, MAX_ITERATIONS, "iterations"
    )
    warmups = _bounded_int(method.get("warmups"), MIN_WARMUPS, MAX_WARMUPS, "warmups")
    results = data.get("results")
    if not isinstance(results, list):
        raise ValueError("Benchmark results missing")
    ids = set()
    for entry in results:
        if not isinstance(entry, dict) or entry.get("status") not in STATUSES:
            raise ValueError("Invalid benchmark entry status")
        where = str(entry.get("id"))
        if where in ids:
            raise ValueError(f"{where}: duplicate entry")
        ids.add(where)
        ops = entry.get("operations")
        if not isinstance(ops, dict):
            raise ValueError(f"{where}: operations missing")
        if entry["status"] == SUCCESS:
            if not ops:
                raise ValueError(f"{where}: SUCCESS without measurements")
            for name, op in ops.items():
                _check_operation(op, iterations, warmups, f"{where}/{name}")
        elif ops or entry.get("sizes") or not entry.get("reason"):
            raise ValueError(f"{where}: {entry['status']} must have a reason and no samples")
    summary = {s: sum(1 for r in results if r["status"] == s) for s in STATUSES}
    if data.get("summary") != summary:
        raise ValueError("Benchmark summary does not match entries")
    return data


def render_text(data: dict[str, Any]) -> str:
    """Readable terminal table of validated benchmark evidence."""
    validate_results(data)
    env = data["environment"]
    method = data["methodology"]
    lines = [
        f"CryptoAgility Lab benchmarks ({env['timestamp_utc']}) - this lab environment only",
        f"OpenSSL: {env['openssl'].get('version')}  CPU: {env['host'].get('cpu_model')}  "
        f"arch: {env['host'].get('architecture')}  container: "
        f"{env['container'].get('runtime') or 'not detected'}",
        f"iterations={method['iterations']} warmups={method['warmups']} "
        f"clock={method['timing_clock']} (whole OpenSSL process per sample)",
        "",
        f"{'entry':32} {'operation':12} {'status':11} {'median ms':>10} {'p95 ms':>9} "
        f"{'min ms':>9} {'max ms':>9}",
    ]
    for entry in data["results"]:
        if entry["status"] != SUCCESS:
            lines.append(
                f"{entry['id'][:32]:32} {'-':12} {entry['status']:11} {entry['reason'][:60]}"
            )
            continue
        for name, op in entry["operations"].items():
            stats = op["statistics"]
            p95 = "n/a" if stats["p95_ms"] is None else f"{stats['p95_ms']:.3f}"
            lines.append(
                f"{entry['id'][:32]:32} {name:12} {SUCCESS:11} "
                f"{stats['median_ms']:>10.3f} {p95:>9} {stats['min_ms']:>9.3f} "
                f"{stats['max_ms']:>9.3f}"
            )
    return "\n".join(lines) + "\n"
