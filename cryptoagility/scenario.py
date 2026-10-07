"""Synthetic fictional-organization scenario used for repeatable inventory demonstrations.

Static service/client configuration files live in scenario/fictional-org/. Certificates are
generated fresh with the pinned OpenSSL into the output directory; their private keys are
created in a private temporary directory and deleted before this function returns, so the
scenario contains public certificate material only.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptoagility import openssl

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = ROOT / "scenario" / "fictional-org"
SUBJECT_O = "/O=Fictional Org (synthetic)"


@dataclass(frozen=True)
class CertSpec:
    name: str
    key: tuple[str, ...]
    hostname: str
    digest: str = "-sha256"
    validity: tuple[str, ...] = ("-days", "365")
    chain: bool = False


_RSA = ("-algorithm", "RSA", "-pkeyopt")
_EC = ("-algorithm", "EC", "-pkeyopt")

CERTIFICATES: tuple[CertSpec, ...] = (
    CertSpec("rsa2048-public-web", (*_RSA, "rsa_keygen_bits:2048"), "www.fictional.test"),
    CertSpec("rsa2048-customer-api", (*_RSA, "rsa_keygen_bits:2048"), "api.fictional.test",
             chain=True),
    CertSpec("rsa2048-legacy-portal-sha1", (*_RSA, "rsa_keygen_bits:2048"),
             "portal.fictional.test", digest="-sha1"),
    CertSpec("rsa2048-expired-reporting", (*_RSA, "rsa_keygen_bits:2048"),
             "reports.fictional.test",
             validity=("-not_before", "20230101000000Z", "-not_after", "20240101000000Z")),
    CertSpec("rsa3072-identity", (*_RSA, "rsa_keygen_bits:3072"), "idp.fictional.test"),
    CertSpec("rsa3072-payments", (*_RSA, "rsa_keygen_bits:3072"), "pay.fictional.test"),
    CertSpec("rsa4096-backup", (*_RSA, "rsa_keygen_bits:4096"), "backup.fictional.test"),
    CertSpec("ecdsa-p256-mobile", (*_EC, "ec_paramgen_curve:P-256"), "m.fictional.test"),
    CertSpec("ecdsa-p256-telemetry", (*_EC, "ec_paramgen_curve:P-256"),
             "telemetry.fictional.test"),
    CertSpec("ecdsa-p384-admin", (*_EC, "ec_paramgen_curve:P-384"), "admin.fictional.test",
             digest="-sha384"),
    CertSpec("mldsa65-pilot", ("-algorithm", "ML-DSA-65"), "pqc-pilot.fictional.test",
             digest=""),
)


def _private_write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def _certificate(spec: CertSpec, keydir: Path, ca: tuple[Path, Path] | None) -> bytes:
    key = keydir / f"{spec.name}.key"
    _private_write(key, openssl.run(["genpkey", *spec.key], timeout=120))
    args = ["req", "-new", "-key", str(key), *spec.validity,
            "-subj", f"{SUBJECT_O}/CN={spec.hostname}",
            "-addext", f"subjectAltName=DNS:{spec.hostname}",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "extendedKeyUsage=serverAuth"]
    if spec.digest:
        args.append(spec.digest)
    if ca:
        args += ["-CA", str(ca[0]), "-CAkey", str(ca[1])]
    else:
        args.insert(1, "-x509")
    return openssl.run(args, timeout=60)


def _issuing_ca(keydir: Path) -> tuple[Path, Path]:
    key = keydir / "issuing-ca.key"
    _private_write(key, openssl.run(["genpkey", *_RSA, "rsa_keygen_bits:3072"], timeout=120))
    cert = keydir / "issuing-ca.pem"
    _private_write(cert, openssl.run([
        "req", "-x509", "-new", "-key", str(key), "-days", "730", "-sha256",
        "-subj", f"{SUBJECT_O}/CN=Fictional Org Issuing CA (synthetic)",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    ], timeout=60))
    return cert, key


def generate(output: Path, source: Path = DEFAULT_SOURCE) -> Path:
    """Copy the static scenario configs and generate public-only synthetic certificates."""
    output = Path(output)
    if output.is_symlink() or (output.exists() and any(output.iterdir())):
        raise ValueError("Scenario output must be a new or empty, non-symlink directory")
    shutil.copytree(source, output, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("README.md"))
    certs = output / "certs"
    certs.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cryptoagility-scenario-") as tmp:
        keydir = Path(tmp)
        os.chmod(keydir, 0o700)
        ca = _issuing_ca(keydir)
        for spec in CERTIFICATES:
            pem = _certificate(spec, keydir, ca if spec.chain else None)
            if spec.chain:
                pem += ca[0].read_bytes()
            (certs / f"{spec.name}.pem").write_bytes(pem)
    return output
