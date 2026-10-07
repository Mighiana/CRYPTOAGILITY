"""Native OpenSSL TLS 1.3 capability discovery and strict-profile loopback experiments.

Everything here drives the pinned OpenSSL command line (s_server, s_client, req); no
cryptography is implemented in Python. Experiments use synthetic identities under the
reserved .test domain (or localhost), loopback-only servers on ephemeral ports and
disposable private keys that are written only to mode-0600 files inside a git-ignored,
mode-0700 runtime directory and deleted when the lab closes. Private keys, session secrets
and raw OpenSSL transcripts are never placed in returned evidence.

Latency semantics: client_process_ms is the wall-clock time of one complete s_client
process (process start-up, key/trust loading, TCP connect, TLS 1.3 handshake including any
HelloRetryRequest, certificate verification and shutdown). It is an end-to-end CLI figure,
not an isolated in-library handshake latency, and must be reported as such.

Standardization: ML-KEM (FIPS 203) and ML-DSA (FIPS 204) are standardized algorithms. Their
TLS 1.3 group code points (e.g. X25519MLKEM768, MLKEM768) and ML-DSA X.509 / TLS signature
integrations are treated as laboratory experiments, not final protocol standards or
FIPS 140 validated deployments.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any

from cryptoagility import openssl
from cryptoagility.models import SCHEMA_VERSION

DEFAULT_HOSTNAME = "localhost.test"
LOOPBACK = "127.0.0.1"
MAX_PROCESS_OUTPUT = 1024 * 1024
MAX_REASONS = 6

SUCCESS = "SUCCESS"
FAIL_NEGOTIATION = "FAIL_NEGOTIATION"
FAIL_CERTIFICATE = "FAIL_CERTIFICATE"
FAIL_PROFILE_MISMATCH = "FAIL_PROFILE_MISMATCH"
UNSUPPORTED = "UNSUPPORTED"
ERROR = "ERROR"
STATUSES = (SUCCESS, FAIL_NEGOTIATION, FAIL_CERTIFICATE, FAIL_PROFILE_MISMATCH, UNSUPPORTED, ERROR)

CERTIFICATE_FAILURES = frozenset(
    {"certificate_expired", "hostname_mismatch", "untrusted_issuer", "certificate_verification"}
)

LATENCY_SEMANTICS = (
    "client_process_ms is wall-clock time of one complete s_client process: start-up, "
    "trust loading, TCP connect, TLS 1.3 handshake, certificate verification and shutdown. "
    "It is not an isolated in-library handshake latency."
)
STANDARDIZATION_NOTE = (
    "ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) are standardized algorithms; "
    "TLS 1.3 hybrid/PQC group code points and PQ X.509/TLS signature integrations are "
    "laboratory experiments. The OpenSSL default provider is not claimed FIPS 140 validated."
)

_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+/\-]{0,63}$")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_PEM_CERT = re.compile(
    rb"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]{1,131072}?-----END CERTIFICATE-----"
)
_ERR_LINE = re.compile(r"error:[0-9A-Fa-f]{8}:[^:\n]{0,64}:[^:\n]{0,64}:([^:\n]{1,160})")
_VERIFY_LINE = re.compile(r"verify error:num=(\d{1,3}):([^\n]{1,160})")
_ALERT = re.compile(r"SSL alert number (\d{1,3})")
_ACCEPT = re.compile(r"^ACCEPT 127\.0\.0\.1:(\d{1,5})\s*$")
_UNSAFE_REASON = re.compile(r"[^A-Za-z0-9 _.,()=+\-:]")


class UnsupportedProfileError(ValueError):
    """Requested profile cannot run on this local stack; never downgraded silently."""

    status = UNSUPPORTED

    def __init__(self, profile: str, missing: Sequence[str]):
        self.profile = profile
        self.missing = list(missing)
        super().__init__(
            f"UNSUPPORTED CRYPTO PROFILE: {profile} (ALGORITHM NOT AVAILABLE: "
            + "; ".join(self.missing)
            + ")"
        )


class TLSLabError(RuntimeError):
    """Lab process failure with an already-sanitized reason."""


@dataclass(frozen=True)
class KeySpec:
    name: str
    genpkey_args: tuple[str, ...]
    signature_algorithm: str
    tls_signature_algorithms: tuple[str, ...]


KEY_SPECS: dict[str, KeySpec] = {
    "RSA-3072": KeySpec(
        "RSA-3072",
        ("-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"),
        "RSA",
        ("rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512"),
    ),
    "ML-DSA-65": KeySpec("ML-DSA-65", ("-algorithm", "ML-DSA-65"), "ML-DSA-65", ("mldsa65",)),
}

CLASSICAL_SIGALGS = (
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
)
CLASSICAL_CERT_TYPES = ("RSA-3072", "ECDSA-P-256", "ECDSA-P-384")


@dataclass(frozen=True)
class TLSProfile:
    """One strict TLS 1.3 configuration: exactly one key-establishment group, one cert type."""

    name: str
    group: str
    group_kind: str
    certificate_key: str
    authentication: str
    description: str


PROFILES: dict[str, TLSProfile] = {
    "classical": TLSProfile(
        "classical",
        "X25519",
        "classical",
        "RSA-3072",
        "classical",
        "TLS 1.3, X25519 key establishment, synthetic RSA-3072 certificate chain",
    ),
    "hybrid": TLSProfile(
        "hybrid",
        "X25519MLKEM768",
        "hybrid",
        "RSA-3072",
        "classical",
        "TLS 1.3, X25519MLKEM768 hybrid key establishment; authentication remains classical "
        "(synthetic RSA-3072 chain)",
    ),
    "pqc": TLSProfile(
        "pqc",
        "MLKEM768",
        "pqc",
        "ML-DSA-65",
        "pqc",
        "TLS 1.3 experiment: pure MLKEM768 key establishment with a synthetic ML-DSA-65 chain",
    ),
}


@dataclass(frozen=True)
class ClientVariant:
    """A client configuration. groups=None means the binary's own defaults (legacy)."""

    name: str
    groups: tuple[str, ...] | None
    sigalgs: tuple[str, ...] | None
    accepted_certificate_types: tuple[str, ...] | None
    binary: str = "pinned"
    strict_tls13: bool = True
    description: str = ""


CLIENT_VARIANTS: dict[str, ClientVariant] = {
    "classical-only": ClientVariant(
        "classical-only",
        ("X25519",),
        CLASSICAL_SIGALGS,
        CLASSICAL_CERT_TYPES,
        description="Offers only X25519 and classical RSA-PSS/ECDSA signatures",
    ),
    "hybrid-only": ClientVariant(
        "hybrid-only",
        ("X25519MLKEM768",),
        CLASSICAL_SIGALGS,
        CLASSICAL_CERT_TYPES,
        description="Offers only X25519MLKEM768; explicit classical authentication",
    ),
    "pqc-only": ClientVariant(
        "pqc-only",
        ("MLKEM768",),
        ("mldsa65",),
        ("ML-DSA-65",),
        description="Offers only MLKEM768 and accepts only ML-DSA-65 authentication",
    ),
    "modern-agile": ClientVariant(
        "modern-agile",
        ("X25519MLKEM768", "MLKEM768", "X25519"),
        ("mldsa65", *CLASSICAL_SIGALGS),
        ("ML-DSA-65", *CLASSICAL_CERT_TYPES),
        description="Prefers hybrid, then PQC, then classical; accepts ML-DSA-65 or classical",
    ),
    "system-legacy": ClientVariant(
        "system-legacy",
        None,
        None,
        None,
        binary="system",
        strict_tls13=False,
        description="Distribution OpenSSL s_client with its default groups and signatures",
    ),
}


@dataclass(frozen=True)
class ServerSpec:
    name: str
    profile: str
    credential_key: str
    credential_variant: str = "valid"
    experiment: str = "interop"
    description: str = ""


SERVER_SPECS: dict[str, ServerSpec] = {
    "classical": ServerSpec("classical", "classical", "RSA-3072"),
    "hybrid": ServerSpec("hybrid", "hybrid", "RSA-3072"),
    "pqc": ServerSpec("pqc", "pqc", "ML-DSA-65"),
    "classical-expired-cert": ServerSpec(
        "classical-expired-cert",
        "classical",
        "RSA-3072",
        "expired",
        "negative",
        "Leaf validity ended in 2020",
    ),
    "classical-wrong-host-cert": ServerSpec(
        "classical-wrong-host-cert",
        "classical",
        "RSA-3072",
        "wrong-host",
        "negative",
        "Leaf SAN is wrong-host.test",
    ),
    "classical-untrusted-ca": ServerSpec(
        "classical-untrusted-ca",
        "classical",
        "RSA-3072",
        "untrusted",
        "negative",
        "Leaf issued by a synthetic root that is not in the client trust bundle",
    ),
    "pqc-group-rsa-cert": ServerSpec(
        "pqc-group-rsa-cert",
        "pqc",
        "RSA-3072",
        "valid",
        "negative",
        "Misconfigured PQC profile: MLKEM768 group but RSA-3072 certificate",
    ),
}

INTEROP_SERVERS = ("classical", "hybrid", "pqc")
INTEROP_CLIENTS = ("classical-only", "hybrid-only", "pqc-only", "modern-agile", "system-legacy")
NEGATIVE_PAIRS = (
    ("classical-expired-cert", "classical-only"),
    ("classical-wrong-host-cert", "classical-only"),
    ("classical-untrusted-ca", "classical-only"),
    ("pqc-group-rsa-cert", "pqc-only"),
    ("pqc-group-rsa-cert", "modern-agile"),
)

DEFAULT_POLICY: dict[str, Any] = {
    "name": "hybrid-key-establishment-required",
    "required_tls_version": "TLSv1.3",
    "allowed_group_kinds": ["hybrid"],
}
_POLICY_KEYS = {
    "name",
    "required_tls_version",
    "allowed_group_kinds",
    "allowed_groups",
    "allowed_certificate_types",
}


# --------------------------------------------------------------------------- helpers


def _token(value: Any) -> str | None:
    if isinstance(value, str) and _TOKEN.fullmatch(value):
        return value
    return None


def _require_token(value: str, what: str) -> str:
    if _token(value) is None:
        raise ValueError(f"Invalid {what}")
    return value


def sanitize_reason(text: str) -> str:
    """Collapse to a short single line of safe characters (no paths, quotes or controls)."""
    cleaned = _UNSAFE_REASON.sub(" ", text)
    return " ".join(cleaned.split())[:160]


def extract_reasons(text: str) -> list[str]:
    """Return short, path-free OpenSSL reason strings; never raw transcripts."""
    reasons: list[str] = []
    for line in text.splitlines()[:2000]:
        found: str | None = None
        verify = _VERIFY_LINE.search(line)
        err = _ERR_LINE.search(line)
        if verify:
            found = f"verify error {verify.group(1)}: {verify.group(2)}"
        elif err:
            found = err.group(1)
            alert = _ALERT.search(line)
            if alert:
                found += f" (alert {alert.group(1)})"
        if found:
            reason = sanitize_reason(found)
            if reason and reason not in reasons:
                reasons.append(reason)
        if len(reasons) >= MAX_REASONS:
            break
    return reasons


def classify_failure(reasons: Iterable[str]) -> str:
    text = " | ".join(reasons).lower()
    checks = (
        ("no suitable key share", "group_disjoint"),
        ("no shared group", "group_disjoint"),
        ("no suitable signature algorithm", "signature_disjoint"),
        ("no shared signature algorithms", "signature_disjoint"),
        ("certificate has expired", "certificate_expired"),
        ("hostname mismatch", "hostname_mismatch"),
        ("unable to get local issuer", "untrusted_issuer"),
        ("unable to get issuer certificate", "untrusted_issuer"),
        ("self-signed certificate in certificate chain", "untrusted_issuer"),
        ("unknown ca", "untrusted_issuer"),
        ("certificate verify failed", "certificate_verification"),
        ("unsupported protocol", "protocol_version"),
        ("protocol version", "protocol_version"),
        ("handshake failure", "handshake_failure"),
    )
    for needle, kind in checks:
        if needle in text:
            return kind
    return "unknown"


def group_kind(group: str | None) -> str | None:
    if group is None:
        return None
    upper = group.upper()
    if re.fullmatch(r"MLKEM\d+", upper):
        return "pqc"
    if "MLKEM" in upper:
        return "hybrid"
    return "classical"


def same_group(a: str | None, b: str | None) -> bool:
    """OpenSSL group names are case-insensitive (it lists x25519, reports X25519)."""
    return a is not None and b is not None and a.casefold() == b.casefold()


def group_in(group: str | None, groups: Iterable[str]) -> bool:
    return any(same_group(group, g) for g in groups)


def validate_hostname(hostname: str) -> str:
    """Only synthetic names: localhost or names under the reserved .test TLD."""
    if not isinstance(hostname, str) or len(hostname) > 253:
        raise ValueError("Invalid synthetic hostname")
    labels = hostname.split(".")
    if not all(_HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Invalid synthetic hostname")
    if hostname != "localhost" and (len(labels) < 2 or labels[-1] != "test"):
        raise ValueError("Hostname must be localhost or under the reserved .test domain")
    return hostname


def _env() -> dict[str, str]:
    env = dict(os.environ)
    for name in ("OPENSSL_CONF", "OPENSSL_MODULES", "SSLKEYLOGFILE", "OPENSSL_ENGINES"):
        env.pop(name, None)
    env["OPENSSL_CONF"] = os.devnull
    return env


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def _single_pem(output: bytes) -> bytes:
    match = _PEM_CERT.search(output)
    if not match:
        raise TLSLabError("OpenSSL did not return a certificate")
    return match.group(0).replace(b"\r\n", b"\n") + b"\n"


def pem_der_length(pem: bytes) -> int:
    return len(ssl.PEM_cert_to_DER_cert(pem.decode("ascii")))


# --------------------------------------------------------------------------- capabilities


def _parse_algorithm_list(text: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in text.splitlines()[:2000]:
        line = line.strip()
        if "@" not in line:
            continue
        body, _, provider = line.rpartition("@")
        body = body.strip().strip("{}").strip()
        names = [n.strip() for n in body.split(",")]
        names = [n for n in names if _token(n) and not re.fullmatch(r"[\d.]+", n)]
        prov = provider.strip()
        if names and _token(prov):
            entries.append({"names": names, "provider": prov})
    return entries


def _parse_providers(text: str) -> list[dict[str, str]]:
    providers: list[dict[str, str]] = []
    for line in text.splitlines()[:500]:
        if re.fullmatch(r"  \S+\s*", line):
            providers.append({"id": sanitize_reason(line.strip())})
        elif providers and re.fullmatch(r"    (name|version|status|build info): .{1,120}", line):
            key, _, value = line.strip().partition(": ")
            providers[-1][key.replace(" ", "_")] = sanitize_reason(value)
    return providers


def _names(entries: list[dict[str, Any]]) -> set[str]:
    return {name for entry in entries for name in entry["names"]}


def _list(args: list[str], unavailable: list[str]) -> str:
    """Output of an 'openssl list' query; unsupported queries are recorded, not guessed."""
    try:
        return openssl.run(["list", *args]).decode("utf-8", "replace")
    except openssl.OpenSSLError:
        unavailable.append(" ".join(args))
        return ""


def _probe_certificate(spec: KeySpec) -> dict[str, Any]:
    """Self-signed throwaway certificate; the private key goes only to the null device."""
    try:
        out = openssl.run(
            [
                "req",
                "-x509",
                "-newkey",
                spec.genpkey_args[1],
                *spec.genpkey_args[2:],
                "-keyout",
                os.devnull,
                "-noenc",
                "-subj",
                "/CN=capability-probe.test",
                "-days",
                "1",
            ],
            timeout=30,
        )
        info = certificate_info(_single_pem(out))
    except (openssl.OpenSSLError, TLSLabError, ValueError):
        return {"supported": False, "reason": "certificate generation failed"}
    ok = info.get("certificate_type") == spec.name
    return {
        "supported": ok,
        "certificate_type": info.get("certificate_type"),
        "signature_algorithm": info.get("signature_algorithm"),
        **({} if ok else {"reason": "unexpected certificate key type"}),
    }


def profile_support(profile: TLSProfile, caps: dict[str, Any], key: str | None = None) -> list[str]:
    """Missing local capabilities for a profile (empty list means runnable)."""
    missing: list[str] = []
    if not group_in(profile.group, caps.get("tls13_groups", [])):
        missing.append(f"TLS 1.3 group {profile.group}")
    key_name = key or profile.certificate_key
    spec = KEY_SPECS.get(key_name)
    if spec is None:
        missing.append(f"certificate key {key_name}")
        return missing
    if not caps.get("x509", {}).get(key_name, {}).get("supported"):
        missing.append(f"X.509 certificate with {key_name}")
    tls_sigalgs = set(caps.get("tls_signature_algorithms", []))
    if not tls_sigalgs.intersection(spec.tls_signature_algorithms):
        missing.append(f"TLS signature algorithm for {key_name}")
    return missing


def capabilities() -> dict[str, Any]:
    """Actual version, provider, algorithm and TLS group support of the pinned OpenSSL."""
    version = openssl.run(["version"]).decode("utf-8", "replace").strip()
    detail = openssl.run(["version", "-a"]).decode("utf-8", "replace")
    build: dict[str, str] = {}
    for line in detail.splitlines():
        key, _, value = line.partition(": ")
        if key in ("built on", "platform"):
            build[key.replace(" ", "_")] = sanitize_reason(value)
    match = re.search(r"OpenSSL (\d+\.\d+\.\d+)", version)
    unavailable: list[str] = []
    groups_text = _list(["-tls1_3", "-tls-groups"], unavailable)
    groups = [g for g in groups_text.strip().split(":") if _token(g)]
    sig_text = _list(["-tls-signature-algorithms"], unavailable)
    tls_sigalgs = [s for s in sig_text.strip().split(":") if _token(s)]
    kems = _parse_algorithm_list(_list(["-kem-algorithms"], unavailable))
    sigs = _parse_algorithm_list(_list(["-signature-algorithms"], unavailable))
    providers = _parse_providers(_list(["-providers", "-verbose"], unavailable))
    kem_names, sig_names = _names(kems), _names(sigs)
    caps: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "openssl": {
            "version": sanitize_reason(version),
            "version_number": match.group(1) if match else None,
            **build,
        },
        "providers": providers,
        "oqs_provider_loaded": any("oqs" in " ".join(p.values()).lower() for p in providers),
        "oqs_required": False,
        "unavailable_queries": unavailable,
        "tls13_groups": groups,
        "tls_signature_algorithms": tls_sigalgs,
        "kem_algorithms": kems,
        "signature_algorithms": sigs,
        "standardized": {
            "ml_kem": sorted(n for n in kem_names if re.fullmatch(r"ML-KEM-\d+", n)),
            "ml_dsa": sorted(n for n in sig_names if re.fullmatch(r"ML-DSA-\d+", n)),
            "slh_dsa": sorted(
                n for n in sig_names if re.fullmatch(r"SLH-DSA-(SHA2|SHAKE)-\d+[sf]", n)
            ),
        },
        "tls_group_classes": {
            kind: [g for g in groups if group_kind(g) == kind]
            for kind in ("classical", "hybrid", "pqc")
        },
        "x509": {},
        "notes": STANDARDIZATION_NOTE,
    }
    for name, spec in KEY_SPECS.items():
        if spec.signature_algorithm in sig_names:
            caps["x509"][name] = _probe_certificate(spec)
        else:
            caps["x509"][name] = {"supported": False, "reason": "signature algorithm absent"}
    caps["profiles"] = {}
    for name, profile in PROFILES.items():
        missing = profile_support(profile, caps)
        caps["profiles"][name] = {
            "group": profile.group,
            "group_kind": profile.group_kind,
            "certificate_key": profile.certificate_key,
            "authentication": profile.authentication,
            "supported": not missing,
            "missing": missing,
        }
    return caps


def resolve_profile(name: str, caps: dict[str, Any] | None = None) -> TLSProfile:
    """Return the named profile only if fully supported; raise instead of downgrading."""
    if not isinstance(name, str) or name not in PROFILES:
        raise ValueError("Unknown TLS profile")
    profile = PROFILES[name]
    missing = profile_support(profile, caps if caps is not None else capabilities())
    if missing:
        raise UnsupportedProfileError(name, missing)
    return profile


# --------------------------------------------------------------------------- certificates


def certificate_info(pem: bytes) -> dict[str, Any]:
    """Public metadata of one certificate parsed by the pinned OpenSSL."""
    text = openssl.run(["x509", "-noout", "-text"], input=pem).decode("utf-8", "replace")
    pub = re.search(r"Public Key Algorithm: (\S+)", text)
    bits = re.search(r"Public-Key: \((\d+) bit\)", text)
    sig = re.search(r"Signature Algorithm: (\S+)", text)
    curve = re.search(r"NIST CURVE: (\S+)", text)
    algorithm = _token(pub.group(1)) if pub else None
    cert_type = algorithm
    if algorithm == "rsaEncryption" and bits:
        cert_type = f"RSA-{bits.group(1)}"
    elif algorithm == "id-ecPublicKey" and curve and _token(curve.group(1)):
        cert_type = f"ECDSA-{curve.group(1)}"
    return {
        "certificate_type": cert_type,
        "public_key_algorithm": algorithm,
        "signature_algorithm": _token(sig.group(1)) if sig else None,
        "der_bytes": pem_der_length(pem),
    }


@dataclass(frozen=True)
class Credential:
    key_type: str
    variant: str
    certificate: Path
    key: Path
    chain: Path | None
    certificate_der_bytes: int
    served_chain_der_bytes: int
    served_chain_length: int


class LabPKI:
    """Synthetic root -> intermediate -> leaf PKI under workdir/tls-lab.

    Use as a context manager; all private keys (and by default certificates) are deleted on
    exit. Directories are mode 0700, every file mode 0600, and the lab root carries its own
    .gitignore so nothing generated is committed.
    """

    def __init__(
        self, workdir: Path, hostname: str = DEFAULT_HOSTNAME, *, keep_certificates: bool = False
    ):
        self.hostname = validate_hostname(hostname)
        self.keep_certificates = keep_certificates
        workdir = Path(workdir)
        if workdir.is_symlink():
            raise ValueError("workdir must not be a symlink")
        workdir.mkdir(parents=True, exist_ok=True)
        root = workdir / "tls-lab"
        if root.is_symlink():
            raise ValueError("tls-lab runtime directory must not be a symlink")
        root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(root, 0o700)
        ignore = root / ".gitignore"
        if not ignore.exists():
            _write_private(ignore, b"*\n")
        self.run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        self.keys_dir = self.run_dir / "keys"
        self.certs_dir = self.run_dir / "certs"
        self.keys_dir.mkdir(mode=0o700)
        self.certs_dir.mkdir(mode=0o700)
        self._roots: dict[str, tuple[Path, Path]] = {}
        self._intermediates: dict[str, tuple[Path, Path]] = {}
        self._credentials: dict[tuple[str, str], Credential] = {}
        self._leaf_keys: dict[str, Path] = {}
        self.trust_bundle = self.certs_dir / "trust-bundle.pem"
        _write_private(self.trust_bundle, b"")
        self.closed = False

    def __enter__(self) -> LabPKI:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.keep_certificates:
            shutil.rmtree(self.keys_dir, ignore_errors=True)
        else:
            shutil.rmtree(self.run_dir, ignore_errors=True)

    def _key(self, key_type: str, label: str) -> Path:
        spec = KEY_SPECS[key_type]
        path = self.keys_dir / f"{label}.key"
        _write_private(path, openssl.run(["genpkey", *spec.genpkey_args], timeout=60))
        return path

    def _cert(self, label: str, args: list[str]) -> Path:
        path = self.certs_dir / f"{label}.pem"
        _write_private(path, _single_pem(openssl.run(["req", *args], timeout=60)))
        return path

    def _root(self, key_type: str, trusted: bool) -> tuple[Path, Path]:
        slot = key_type if trusted else f"{key_type}-untrusted"
        if slot not in self._roots:
            label = f"root-{slot}"
            key = self._key(key_type, label)
            cert = self._cert(
                label,
                [
                    "-x509",
                    "-new",
                    "-key",
                    str(key),
                    "-days",
                    "2",
                    "-subj",
                    f"/O=CryptoAgility Lab Synthetic/CN=Synthetic {slot} Root",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                ],
            )
            self._roots[slot] = (cert, key)
            if trusted:
                with self.trust_bundle.open("ab") as bundle:
                    bundle.write(cert.read_bytes())
        return self._roots[slot]

    def _intermediate(self, key_type: str) -> tuple[Path, Path]:
        if key_type not in self._intermediates:
            root_cert, root_key = self._root(key_type, True)
            label = f"intermediate-{key_type}"
            key = self._key(key_type, label)
            cert = self._cert(
                label,
                [
                    "-new",
                    "-key",
                    str(key),
                    "-CA",
                    str(root_cert),
                    "-CAkey",
                    str(root_key),
                    "-days",
                    "2",
                    "-subj",
                    f"/O=CryptoAgility Lab Synthetic/CN=Synthetic {key_type} Issuing CA",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE,pathlen:0",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                ],
            )
            self._intermediates[key_type] = (cert, key)
        return self._intermediates[key_type]

    def issue(self, key_type: str, variant: str = "valid") -> Credential:
        """Server credential: valid, expired, wrong-host or untrusted."""
        if key_type not in KEY_SPECS:
            raise ValueError("Unsupported certificate key type")
        if variant not in ("valid", "expired", "wrong-host", "untrusted"):
            raise ValueError("Unknown credential variant")
        if self.closed:
            raise TLSLabError("PKI already closed")
        cached = self._credentials.get((key_type, variant))
        if cached:
            return cached
        if key_type not in self._leaf_keys:
            self._leaf_keys[key_type] = self._key(key_type, f"leaf-{key_type}")
        leaf_key = self._leaf_keys[key_type]
        chain: Path | None
        if variant == "untrusted":
            issuer_cert, issuer_key = self._root(key_type, False)
            chain = None
        else:
            issuer_cert, issuer_key = self._intermediate(key_type)
            chain = issuer_cert
        name = "wrong-host.test" if variant == "wrong-host" else self.hostname
        validity = (
            ["-not_before", "20200101000000Z", "-not_after", "20200102000000Z"]
            if variant == "expired"
            else ["-days", "1"]
        )
        cert = self._cert(
            f"leaf-{key_type}-{variant}",
            [
                "-new",
                "-key",
                str(leaf_key),
                "-CA",
                str(issuer_cert),
                "-CAkey",
                str(issuer_key),
                *validity,
                "-subj",
                f"/O=CryptoAgility Lab Synthetic/CN={name}",
                "-addext",
                f"subjectAltName=DNS:{name}",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=serverAuth",
            ],
        )
        leaf_len = pem_der_length(cert.read_bytes())
        chain_len = pem_der_length(chain.read_bytes()) if chain else 0
        credential = Credential(
            key_type,
            variant,
            cert,
            leaf_key,
            chain,
            leaf_len,
            leaf_len + chain_len,
            2 if chain else 1,
        )
        self._credentials[(key_type, variant)] = credential
        return credential


# --------------------------------------------------------------------------- server


class LoopbackServer:
    """s_server pinned to TLS 1.3 and exactly one group, bound to 127.0.0.1:ephemeral.

    Readiness is a bounded real TCP connect. The process is always terminated on exit.
    Server output is drained in memory; only sanitized OpenSSL reason strings are retained.
    """

    def __init__(self, credential: Credential, group: str, *, timeout: float = 10.0):
        self.credential = credential
        self.group = _require_token(group, "TLS group")
        self.timeout = timeout
        self.port: int | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self._reasons: deque[tuple[float, str]] = deque(maxlen=200)
        self._port_ready = threading.Event()
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()

    def __enter__(self) -> LoopbackServer:
        try:
            self.start()
        except BaseException:
            self.stop()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    def _record(self, line: str) -> None:
        for reason in extract_reasons(line):
            with self._lock:
                self._reasons.append((time.monotonic(), reason))

    def _pump(self, stream: Any, parse_accept: bool) -> None:
        for raw in iter(lambda: stream.readline(8192), b""):
            line = raw.decode("utf-8", "replace")
            if parse_accept and self.port is None:
                match = _ACCEPT.match(line)
                if match and 0 < int(match.group(1)) < 65536:
                    self.port = int(match.group(1))
                    self._port_ready.set()
            self._record(line)

    def start(self) -> None:
        cred = self.credential
        argv = [
            openssl.executable(),
            "s_server",
            "-accept",
            f"{LOOPBACK}:0",
            "-cert",
            str(cred.certificate),
            "-key",
            str(cred.key),
            "-tls1_3",
            "-groups",
            self.group,
            "-num_tickets",
            "0",
        ]
        if cred.chain is not None:
            argv += ["-cert_chain", str(cred.chain)]
        self.process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_env(),
            close_fds=True,
        )
        for stream, parse_accept in ((self.process.stdout, True), (self.process.stderr, False)):
            thread = threading.Thread(target=self._pump, args=(stream, parse_accept), daemon=True)
            thread.start()
            self._threads.append(thread)
        deadline = time.monotonic() + self.timeout
        while not self._port_ready.wait(0.05):
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise TLSLabError(self._startup_failure())
        assert self.port is not None
        while True:
            try:
                with socket.create_connection((LOOPBACK, self.port), timeout=1.0):
                    break
            except OSError as exc:
                if self.process.poll() is not None or time.monotonic() > deadline:
                    raise TLSLabError(self._startup_failure()) from exc
                time.sleep(0.05)
        # Let the readiness probe's own EOF diagnostic drain so it is not attributed later.
        settle = time.monotonic() + 0.3
        while time.monotonic() < settle and not self._reasons:
            time.sleep(0.01)
        if self.process.poll() is not None:
            raise TLSLabError(self._startup_failure())

    def _startup_failure(self) -> str:
        time.sleep(0.05)
        reasons = [r for _, r in list(self._reasons)]
        return "TLS server failed to become ready" + (f": {'; '.join(reasons)}" if reasons else "")

    def reasons_since(self, since: float) -> list[str]:
        with self._lock:
            found = [r for t, r in self._reasons if t >= since]
        return list(dict.fromkeys(found))[:MAX_REASONS]

    def stop(self) -> None:
        proc = self.process
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
        finally:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
            for thread in self._threads:
                thread.join(timeout=2)


# --------------------------------------------------------------------------- client


@dataclass
class HandshakeResult:
    client: str
    returncode: int | None
    completed: bool
    tls_version: str | None = None
    cipher_suite: str | None = None
    negotiated_group: str | None = None
    peer_signature_type: str | None = None
    peer_signing_digest: str | None = None
    verify_code: int | None = None
    verified_peername: str | None = None
    certificate_type: str | None = None
    certificate_public_key_algorithm: str | None = None
    certificate_signature_algorithm: str | None = None
    certificate_der_bytes: int | None = None
    chain_der_bytes: int | None = None
    chain_length: int | None = None
    handshake_bytes_read: int | None = None
    handshake_bytes_written: int | None = None
    client_process_ms: float | None = None
    failure_kind: str | None = None
    error_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _search(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, re.MULTILINE)
    return _token(match.group(1)) if match else None


def parse_client_output(stdout: bytes) -> dict[str, Any]:
    """Extract public handshake facts from s_client stdout; secrets are discarded."""
    data = stdout[:MAX_PROCESS_OUTPUT]
    text = data.decode("utf-8", "replace")
    group = _search(r"^Negotiated TLS1\.3 group: (\S+)\s*$", text) or _search(
        r"^(?:Peer|Server) Temp Key: ([^,\s]+)", text
    )
    version = _search(r"^\s*Protocol\s*:\s*(\S+)\s*$", text) or _search(
        r"^New, (\S+), Cipher is", text
    )
    cipher = _search(r"^New, \S+, Cipher is (\S+)\s*$", text) or _search(
        r"^\s*Cipher\s*:\s*(\S+)\s*$", text
    )
    verify = re.search(r"^Verify return code: (\d{1,3}) ", text, re.MULTILINE)
    sizes = re.search(r"SSL handshake has read (\d+) bytes and written (\d+) bytes", text)
    certs = [m.group(0) for m in _PEM_CERT.finditer(data)][:10]
    return {
        "negotiated_group": group,
        "tls_version": version,
        "cipher_suite": cipher,
        "peer_signature_type": _search(r"^Peer signature type: (\S+)\s*$", text),
        "peer_signing_digest": _search(r"^Peer signing digest: (\S+)\s*$", text),
        "verify_code": int(verify.group(1)) if verify else None,
        "verified_peername": _search(r"^Verified peername: (\S+)\s*$", text),
        "handshake_bytes_read": int(sizes.group(1)) if sizes else None,
        "handshake_bytes_written": int(sizes.group(2)) if sizes else None,
        "certificates": [c.replace(b"\r\n", b"\n") + b"\n" for c in certs],
    }


def binary_version(binary: str) -> str | None:
    try:
        result = subprocess.run(
            [binary, "version"], capture_output=True, timeout=10, check=False, env=_env()
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    return sanitize_reason(result.stdout.decode("utf-8", "replace").strip()) or None


def find_legacy_openssl(path: str | None = None) -> str | None:
    """A distribution OpenSSL distinct from the pinned lab build, if present."""
    candidate = path or shutil.which("openssl")
    if not candidate or not Path(candidate).is_file() or not os.access(candidate, os.X_OK):
        return None
    try:
        pinned: Path | None = Path(openssl.executable()).resolve()
    except openssl.OpenSSLError:
        pinned = None
    if pinned is not None and Path(candidate).resolve() == pinned:
        return None
    return candidate


def handshake(
    port: int,
    client: ClientVariant,
    trust_bundle: Path,
    *,
    hostname: str = DEFAULT_HOSTNAME,
    timeout: float = 10.0,
    server: LoopbackServer | None = None,
    binary: str | None = None,
) -> HandshakeResult:
    """One verified TLS client connection to 127.0.0.1:port via s_client.

    The client trusts only trust_bundle, verifies the hostname with strict X.509 checks and
    aborts on any verification error. Pinned variants also pin TLS 1.3 and their exact groups
    and signature algorithms. Latency is LATENCY_SEMANTICS (whole client process).
    """
    if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
        raise ValueError("Invalid port")
    hostname = validate_hostname(hostname)
    exe = binary or (openssl.executable() if client.binary == "pinned" else None)
    if exe is None:
        raise TLSLabError("Client binary unavailable")
    argv = [
        exe,
        "s_client",
        "-connect",
        f"{LOOPBACK}:{port}",
        "-servername",
        hostname,
        "-verify_hostname",
        hostname,
        "-verify_return_error",
        "-x509_strict",
        "-CAfile",
        str(trust_bundle),
        "-no-CApath",
        "-no-CAstore",
        "-showcerts",
        "-no_ticket",
    ]
    if client.strict_tls13:
        argv.append("-tls1_3")
    if client.groups is not None:
        argv += ["-groups", ":".join(_require_token(g, "TLS group") for g in client.groups)]
    if client.sigalgs is not None:
        argv += [
            "-sigalgs",
            ":".join(_require_token(s, "signature algorithm") for s in client.sigalgs),
        ]
    result = HandshakeResult(client=client.name, returncode=None, completed=False)
    started = time.monotonic()
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=_env(),
        )
    except subprocess.TimeoutExpired:
        result.failure_kind = "timeout"
        result.error_reasons = ["client timed out"]
        return result
    except OSError:
        result.failure_kind = "process_error"
        result.error_reasons = ["client process could not start"]
        return result
    result.client_process_ms = round((time.perf_counter() - t0) * 1000, 3)
    result.returncode = proc.returncode
    parsed = parse_client_output(proc.stdout)
    certs: list[bytes] = parsed.pop("certificates")
    for key, value in parsed.items():
        setattr(result, key, value)
    if certs:
        try:
            leaf = certificate_info(certs[0])
            result.certificate_type = leaf["certificate_type"]
            result.certificate_public_key_algorithm = leaf["public_key_algorithm"]
            result.certificate_signature_algorithm = leaf["signature_algorithm"]
            result.certificate_der_bytes = leaf["der_bytes"]
            result.chain_der_bytes = sum(pem_der_length(c) for c in certs)
            result.chain_length = len(certs)
        except (openssl.OpenSSLError, ValueError):
            result.error_reasons.append("peer certificate could not be parsed")
    result.completed = (
        proc.returncode == 0
        and result.verify_code == 0
        and result.tls_version is not None
        and result.cipher_suite is not None
        and result.cipher_suite != "0000"
    )
    if not result.completed:
        reasons = extract_reasons(proc.stderr[:MAX_PROCESS_OUTPUT].decode("utf-8", "replace"))
        reasons += [
            r
            for r in extract_reasons(proc.stdout[:MAX_PROCESS_OUTPUT].decode("utf-8", "replace"))
            if r not in reasons
        ]
        if server is not None:
            deadline = time.monotonic() + 0.3
            while time.monotonic() < deadline and not server.reasons_since(started):
                time.sleep(0.02)
            reasons += [f"server: {r}" for r in server.reasons_since(started)]
        if not reasons:
            reasons = [f"client exited with status {proc.returncode}"]
        result.error_reasons = reasons[:MAX_REASONS]
        result.failure_kind = classify_failure(reasons)
    return result


# --------------------------------------------------------------------------- policy


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(policy, dict) or set(policy) - _POLICY_KEYS:
        raise ValueError("Invalid TLS policy")
    for key in ("allowed_group_kinds", "allowed_groups", "allowed_certificate_types"):
        value = policy.get(key)
        if value is not None and (not isinstance(value, list) or not all(_token(v) for v in value)):
            raise ValueError(f"Invalid TLS policy field {key}")
    for key in ("name", "required_tls_version"):
        if policy.get(key) is not None and _token(policy[key]) is None:
            raise ValueError(f"Invalid TLS policy field {key}")
    return policy


def evaluate_policy(
    observed: dict[str, Any], policy: dict[str, Any]
) -> tuple[bool | None, list[str]]:
    """Policy compliance of an observed connection, independent of negotiation success."""
    group = observed.get("negotiated_group")
    if not group:
        return None, ["no negotiated connection to evaluate"]
    reasons: list[str] = []
    required = policy.get("required_tls_version")
    if required and observed.get("tls_version") != required:
        reasons.append(f"TLS version {observed.get('tls_version')} is not {required}")
    kinds = policy.get("allowed_group_kinds")
    if kinds is not None and group_kind(group) not in kinds:
        reasons.append(
            f"negotiated {group_kind(group)} group {group}; policy requires " + "/".join(kinds)
        )
    groups = policy.get("allowed_groups")
    if groups is not None and not group_in(group, groups):
        reasons.append(f"negotiated group {group} not allowed")
    cert_types = policy.get("allowed_certificate_types")
    if cert_types is not None and observed.get("certificate_type") not in cert_types:
        reasons.append(f"certificate type {observed.get('certificate_type')} not allowed")
    return not reasons, reasons


# --------------------------------------------------------------------------- matrix


def check_observation(
    result: HandshakeResult, spec: ServerSpec, client: ClientVariant
) -> list[str]:
    """Fail-closed comparison of what was negotiated against server profile and client."""
    profile = PROFILES[spec.profile]
    problems: list[str] = []
    if result.tls_version != "TLSv1.3":
        problems.append(f"TLS version {result.tls_version} is not TLSv1.3")
    if not same_group(result.negotiated_group, profile.group):
        problems.append(
            f"negotiated group {result.negotiated_group} differs from required {profile.group}"
        )
    if client.groups is not None and not group_in(result.negotiated_group, client.groups):
        problems.append("negotiated group was not offered by the client")
    if result.certificate_type != profile.certificate_key:
        problems.append(
            f"certificate type {result.certificate_type} differs from profile "
            f"{profile.certificate_key}"
        )
    accepted = client.accepted_certificate_types
    if accepted is not None and result.certificate_type not in accepted:
        problems.append(f"certificate type {result.certificate_type} not accepted by client")
    return problems


def _client_missing(client: ClientVariant, caps: dict[str, Any], legacy: str | None) -> list[str]:
    if client.binary == "system":
        return [] if legacy else ["system OpenSSL client not available"]
    groups = caps.get("tls13_groups", [])
    missing = [f"TLS 1.3 group {g}" for g in client.groups or () if not group_in(g, groups)]
    tls_sigalgs = set(caps.get("tls_signature_algorithms", []))
    missing += [
        f"TLS signature algorithm {s}"
        for s in client.sigalgs or ()
        if tls_sigalgs and s not in tls_sigalgs
    ]
    return missing


def _row(spec: ServerSpec, client: ClientVariant, **values: Any) -> dict[str, Any]:
    profile = PROFILES[spec.profile]
    row: dict[str, Any] = {
        "client": client.name,
        "server": spec.name,
        "experiment": spec.experiment,
        "server_profile": profile.name,
        "server_group": profile.group,
        "server_certificate_key": spec.credential_key,
        "server_credential_variant": spec.credential_variant,
        "client_groups": list(client.groups) if client.groups is not None else None,
        "status": ERROR,
        "network_attempted": False,
        "negotiated_group": None,
        "negotiated_group_kind": None,
        "tls_version": None,
        "cipher_suite": None,
        "certificate_type": None,
        "certificate_signature_algorithm": None,
        "peer_signature_type": None,
        "certificate_der_bytes": None,
        "chain_der_bytes": None,
        "chain_length": None,
        "handshake_bytes_read": None,
        "handshake_bytes_written": None,
        "client_process_ms": None,
        "client_binary_version": None,
        "failure_kind": None,
        "error_reason": None,
        "policy_pass": None,
        "policy_reasons": [],
    }
    row.update(values)
    return row


def result_row(
    spec: ServerSpec,
    client: ClientVariant,
    result: HandshakeResult,
    policy: dict[str, Any],
    client_version: str | None = None,
) -> dict[str, Any]:
    """Matrix row for an attempted connection: status and policy_pass judged separately."""
    observed = {
        "negotiated_group": result.negotiated_group if result.completed else None,
        "tls_version": result.tls_version,
        "certificate_type": result.certificate_type,
    }
    policy_pass, policy_reasons = evaluate_policy(observed, policy)
    reason: str | None
    if result.completed:
        problems = check_observation(result, spec, client)
        status = FAIL_PROFILE_MISMATCH if problems else SUCCESS
        failure_kind = "profile_mismatch" if problems else None
        reason = "; ".join(problems) or None
    else:
        failure_kind = result.failure_kind or "unknown"
        if failure_kind in CERTIFICATE_FAILURES:
            status = FAIL_CERTIFICATE
        elif failure_kind in ("timeout", "process_error"):
            status = ERROR
        else:
            status = FAIL_NEGOTIATION
        reason = "; ".join(result.error_reasons) or None
    done = result.completed
    return _row(
        spec,
        client,
        status=status,
        network_attempted=True,
        negotiated_group=observed["negotiated_group"],
        negotiated_group_kind=group_kind(observed["negotiated_group"]),
        tls_version=result.tls_version if done else None,
        cipher_suite=result.cipher_suite if done else None,
        certificate_type=result.certificate_type,
        certificate_signature_algorithm=result.certificate_signature_algorithm,
        peer_signature_type=result.peer_signature_type if done else None,
        certificate_der_bytes=result.certificate_der_bytes,
        chain_der_bytes=result.chain_der_bytes,
        chain_length=result.chain_length,
        handshake_bytes_read=result.handshake_bytes_read if done else None,
        handshake_bytes_written=result.handshake_bytes_written if done else None,
        client_process_ms=result.client_process_ms,
        client_binary_version=client_version,
        failure_kind=failure_kind,
        error_reason=sanitize_reason(reason)[:400] if reason else None,
        policy_pass=policy_pass,
        policy_reasons=policy_reasons,
    )


def run_matrix(
    workdir: Path,
    *,
    servers: Sequence[str] | None = None,
    clients: Sequence[str] | None = None,
    include_negative: bool = True,
    policy: dict[str, Any] | None = None,
    caps: dict[str, Any] | None = None,
    hostname: str = DEFAULT_HOSTNAME,
    timeout: float = 10.0,
    legacy_openssl: str | None = None,
    keep_certificates: bool = False,
) -> dict[str, Any]:
    """Synthetic authenticated loopback interoperability matrix.

    Unsupported server/client configurations are reported as UNSUPPORTED before any network
    activity; algorithm-disjoint handshakes are FAIL_NEGOTIATION; trust/host/validity errors
    are FAIL_CERTIFICATE; a completed handshake that does not match the server profile or the
    client's acceptance rules is FAIL_PROFILE_MISMATCH. policy_pass is computed from the
    observed connection only and is independent of status.
    """
    hostname = validate_hostname(hostname)
    policy = validate_policy(dict(policy if policy is not None else DEFAULT_POLICY))
    server_names = list(servers) if servers is not None else list(INTEROP_SERVERS)
    client_names = list(clients) if clients is not None else list(INTEROP_CLIENTS)
    for name in server_names:
        if name not in SERVER_SPECS:
            raise ValueError("Unknown server specification")
    for name in client_names:
        if name not in CLIENT_VARIANTS:
            raise ValueError("Unknown client variant")
    pairs = [(s, c) for s in server_names for c in client_names]
    if include_negative:
        pairs += [p for p in NEGATIVE_PAIRS if p not in pairs]
    caps = caps if caps is not None else capabilities()
    wants_legacy = any(CLIENT_VARIANTS[c].binary == "system" for _, c in pairs)
    legacy = find_legacy_openssl(legacy_openssl) if wants_legacy else None
    legacy_version = binary_version(legacy) if legacy else None
    if wants_legacy and legacy and legacy_version is None:
        legacy = None
    pinned_version = caps.get("openssl", {}).get("version")
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    runnable: dict[str, list[ClientVariant]] = {}
    for server_name, client_name in pairs:
        spec, client = SERVER_SPECS[server_name], CLIENT_VARIANTS[client_name]
        missing = profile_support(PROFILES[spec.profile], caps, spec.credential_key)
        side = "server"
        if not missing:
            missing, side = _client_missing(client, caps, legacy), "client"
        if missing:
            rows[(server_name, client_name)] = _row(
                spec,
                client,
                status=UNSUPPORTED,
                failure_kind=f"{side}_unsupported_locally",
                error_reason=sanitize_reason(f"{side} unsupported locally: " + "; ".join(missing)),
                policy_reasons=["no negotiated connection to evaluate"],
            )
        else:
            runnable.setdefault(server_name, []).append(client)
    if runnable:
        with LabPKI(workdir, hostname, keep_certificates=keep_certificates) as pki:
            for server_name, variants in runnable.items():
                spec = SERVER_SPECS[server_name]
                try:
                    credential = pki.issue(spec.credential_key, spec.credential_variant)
                    with LoopbackServer(
                        credential, PROFILES[spec.profile].group, timeout=timeout
                    ) as server:
                        assert server.port is not None
                        for client in variants:
                            system = client.binary == "system"
                            result = handshake(
                                server.port,
                                client,
                                pki.trust_bundle,
                                hostname=hostname,
                                timeout=timeout,
                                server=server,
                                binary=legacy if system else None,
                            )
                            rows[(server_name, client.name)] = result_row(
                                spec,
                                client,
                                result,
                                policy,
                                legacy_version if system else pinned_version,
                            )
                except (openssl.OpenSSLError, TLSLabError, OSError) as exc:
                    reason = sanitize_reason(str(exc)) or "lab setup failed"
                    for client in variants:
                        rows.setdefault(
                            (server_name, client.name),
                            _row(
                                spec,
                                client,
                                status=ERROR,
                                failure_kind="lab_error",
                                error_reason=reason,
                                policy_reasons=["no negotiated connection to evaluate"],
                            ),
                        )
    return {
        "schema_version": SCHEMA_VERSION,
        "environment": {
            "openssl": caps.get("openssl", {}),
            "providers": caps.get("providers", []),
            "oqs_provider_loaded": caps.get("oqs_provider_loaded"),
            "legacy_client": legacy_version,
            "platform": sanitize_reason(platform.platform()),
            "hostname": hostname,
            "bind_address": LOOPBACK,
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "latency_semantics": LATENCY_SEMANTICS,
            "standardization": STANDARDIZATION_NOTE,
            "synthetic_identities": True,
        },
        "policy": policy,
        "profiles": {name: asdict(p) for name, p in PROFILES.items()},
        "statuses": list(STATUSES),
        "rows": [rows[pair] for pair in pairs],
    }
