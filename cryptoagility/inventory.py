"""Explicit, bounded and non-executing cryptographic asset discovery.

scan(path) inventories PEM/DER certificates and chains, public keys, private-key *metadata*,
OpenSSL .cnf files and synthetic JSON/YAML application crypto configs. inspect_endpoint()
observes one authenticated TLS handshake with the pinned OpenSSL client and, separately, probes
which protocol versions / TLS 1.3 groups that probe client could negotiate.

Safety contract:

* Inputs are untrusted. Files are opened with O_NOFOLLOW and must be regular files within
  size, count, depth and total-byte limits. Symlinks, special files, unsupported, encrypted and
  malformed inputs are reported in Inventory.errors; nothing is skipped silently.
* No private values, PEM bodies or arbitrary config fields are emitted. Private keys are reduced to
  public metadata; identifiers derive from public material (certificate DER or SPKI DER).
* Configuration is parsed as data only: includes, providers/engines/modules, variable expansion
  and YAML tags/aliases are never processed.
* Output is deterministic for unchanged input (sorted traversal; certificate validity status is
  evaluated against the supplied or current time).

Vocabulary: algorithm_family is one of RSA, EC, EdDSA, XDH, ECDH, FFDH, DSA, ML-KEM, ML-DSA,
SLH-DSA, HYBRID-KEM, SYMMETRIC, HASH, TLS-PROTOCOL, PROFILE or unknown; evidence['crypto_class']
is one of classical-public-key, post-quantum, hybrid, symmetric, hash, protocol, profile, unknown.
Policy conclusions are left to the policy engine; migration_status stays UNKNOWN.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x448, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID

from cryptoagility import openssl
from cryptoagility.models import Asset, Inventory

MAX_FILE_BYTES = openssl.MAX_FILE_BYTES
MAX_DEPTH = 8
MAX_ENTRIES = 2000
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_PEM_BLOCKS = 32
MAX_ASSETS_PER_FILE = 128
MAX_CONFIG_LINES = 5000
MAX_CONFIG_NODES = 10000
MAX_CONFIG_DEPTH = 16
MAX_SANS = 64
MAX_TEXT = 256
MAX_TLS_OUTPUT = 1024 * 1024
MAX_CHAIN_CERTS = 10
MAX_PROBE_GROUPS = 32

CERT_SUFFIXES = {".pem", ".crt", ".cer", ".der", ".key", ".pub"}
OPENSSL_CONFIG_SUFFIXES = {".cnf"}
APP_CONFIG_SUFFIXES = {".json", ".yaml", ".yml"}

FIPS = {"ML-KEM": "NIST FIPS 203", "ML-DSA": "NIST FIPS 204", "SLH-DSA": "NIST FIPS 205"}
CLASS_BY_FAMILY = {
    "RSA": "classical-public-key", "EC": "classical-public-key", "EdDSA": "classical-public-key",
    "XDH": "classical-public-key", "ECDH": "classical-public-key", "FFDH": "classical-public-key",
    "DSA": "classical-public-key", "ML-KEM": "post-quantum", "ML-DSA": "post-quantum",
    "SLH-DSA": "post-quantum", "HYBRID-KEM": "hybrid", "SYMMETRIC": "symmetric", "HASH": "hash",
    "TLS-PROTOCOL": "protocol", "PROFILE": "profile",
}
_SLH = [f"SLH-DSA-{h}-{n}{v}" for h in ("SHA2", "SHAKE") for n in (128, 192, 256) for v in "sf"]
PQ_OIDS = {
    "2.16.840.1.101.3.4.3.17": ("ML-DSA", "ML-DSA-44"),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA", "ML-DSA-65"),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA", "ML-DSA-87"),
    "2.16.840.1.101.3.4.4.1": ("ML-KEM", "ML-KEM-512"),
    "2.16.840.1.101.3.4.4.2": ("ML-KEM", "ML-KEM-768"),
    "2.16.840.1.101.3.4.4.3": ("ML-KEM", "ML-KEM-1024"),
    **{f"2.16.840.1.101.3.4.3.{20 + i}": ("SLH-DSA", name) for i, name in enumerate(_SLH)},
}
PQ_NAMES = {name for _, name in PQ_OIDS.values()}
CLASSICAL_SIG_OIDS = {
    "1.2.840.113549.1.1.4": ("RSA", "md5WithRSAEncryption"),
    "1.2.840.113549.1.1.5": ("RSA", "sha1WithRSAEncryption"),
    "1.2.840.113549.1.1.10": ("RSA", "rsassaPss"),
    "1.2.840.113549.1.1.11": ("RSA", "sha256WithRSAEncryption"),
    "1.2.840.113549.1.1.12": ("RSA", "sha384WithRSAEncryption"),
    "1.2.840.113549.1.1.13": ("RSA", "sha512WithRSAEncryption"),
    "1.2.840.113549.1.1.14": ("RSA", "sha224WithRSAEncryption"),
    "1.2.840.10045.4.1": ("EC", "ecdsa-with-SHA1"),
    "1.2.840.10045.4.3.1": ("EC", "ecdsa-with-SHA224"),
    "1.2.840.10045.4.3.2": ("EC", "ecdsa-with-SHA256"),
    "1.2.840.10045.4.3.3": ("EC", "ecdsa-with-SHA384"),
    "1.2.840.10045.4.3.4": ("EC", "ecdsa-with-SHA512"),
    "1.3.101.112": ("EdDSA", "Ed25519"),
    "1.3.101.113": ("EdDSA", "Ed448"),
    "1.2.840.10040.4.3": ("DSA", "dsa-with-sha1"),
    "2.16.840.1.101.3.4.3.2": ("DSA", "dsa-with-sha256"),
}
CURVES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
VERIFY_REASONS = {
    2: "unable to get issuer certificate",
    7: "certificate signature failure",
    9: "certificate is not yet valid",
    10: "certificate has expired",
    18: "self-signed certificate",
    19: "self-signed certificate in certificate chain",
    20: "unable to get local issuer certificate",
    21: "unable to verify the first certificate",
    62: "hostname mismatch",
    64: "IP address mismatch",
}

_PEM_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]{1,40})-----\r?\n(.*?)-----END ([A-Z0-9 ]{1,40})-----", re.DOTALL
)
_B64_LINE = re.compile(rb"^[A-Za-z0-9+/=]*$")
_TOKEN = re.compile(r"^[A-Za-z0-9_.+\-@!=]{1,64}$")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.(?!-)[A-Za-z0-9-]{1,63})*\.?$")
_OPENSSL_PUB_HEADER = re.compile(r"^([A-Za-z0-9-]{2,40}) Public-Key:", re.MULTILINE)


class _Limit(Exception):
    pass


class _Encrypted(Exception):
    pass


class _Unsafe(Exception):
    pass


@dataclass
class _ScanState:
    now: datetime
    assets: list[Asset] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    entries: int = 0
    total_bytes: int = 0

    def error(self, source: str, code: str, message: str) -> None:
        self.errors.append({"source": source, "code": code, "message": message})


# --------------------------------------------------------------------------- helpers


def clean_text(value: object, limit: int = MAX_TEXT) -> str:
    """Replace control/format characters in untrusted metadata and bound its length."""
    text = str(value)[: limit * 2]
    text = "".join(
        " " if unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} else ch for ch in text
    )
    return text[:limit]


def _digest(*parts: str | bytes) -> str:
    h = hashlib.sha256()
    for part in parts:
        data = part.encode() if isinstance(part, str) else part
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    return h.hexdigest()


def _asset_id(prefix: str, source: str, position: str, public_identity: str) -> str:
    return f"{prefix}-{_digest(prefix, source, position, public_identity)[:24]}"


def classify_family(family: str) -> str:
    return CLASS_BY_FAMILY.get(family, "unknown")


def _crypto_evidence(family: str) -> dict[str, Any]:
    evidence: dict[str, Any] = {"crypto_class": classify_family(family)}
    if family in FIPS:
        evidence["algorithm_standard"] = FIPS[family]
    return evidence


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_regular_file(path: Path) -> bytes:
    """Open without following symlinks or blocking on FIFOs; enforce regular file and size."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("not a regular file")
        if info.st_size > MAX_FILE_BYTES:
            raise _Limit("file exceeds 4 MiB limit")
        chunks = []
        remaining = MAX_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if len(data) > MAX_FILE_BYTES:
        raise _Limit("file exceeds 4 MiB limit")
    return data


# --------------------------------------------------------------------------- key metadata


@dataclass
class _KeyInfo:
    family: str
    algorithm: str
    key_size: int | None
    parameter_set: str | None
    spki_der: bytes | None
    parser: str


def _python_key_info(key: object) -> tuple[str, str, int | None, str | None] | None:
    if isinstance(key, rsa.RSAPublicKey | rsa.RSAPrivateKey):
        return "RSA", "RSA", key.key_size, f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey):
        curve = CURVES.get(key.curve.name, key.curve.name)
        return "EC", "ECDSA", key.curve.key_size, curve
    if isinstance(key, ed25519.Ed25519PublicKey | ed25519.Ed25519PrivateKey):
        return "EdDSA", "Ed25519", 256, "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey | ed448.Ed448PrivateKey):
        return "EdDSA", "Ed448", 456, "Ed448"
    if isinstance(key, x25519.X25519PublicKey | x25519.X25519PrivateKey):
        return "XDH", "X25519", 255, "X25519"
    if isinstance(key, x448.X448PublicKey | x448.X448PrivateKey):
        return "XDH", "X448", 448, "X448"
    if isinstance(key, dsa.DSAPublicKey | dsa.DSAPrivateKey):
        return "DSA", "DSA", key.key_size, f"DSA-{key.key_size}"
    if isinstance(key, dh.DHPublicKey | dh.DHPrivateKey):
        return "FFDH", "DH", key.key_size, f"DH-{key.key_size}"
    return None


def _spki(public_key: Any) -> bytes:
    der: bytes = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return der


def _openssl_describe_spki(spki_der: bytes) -> _KeyInfo:
    """Public-only OpenSSL text fallback; only the algorithm header line is consumed."""
    text = openssl.run(
        ["pkey", "-pubin", "-inform", "DER", "-noout", "-text_pub"], input=spki_der
    ).decode("ascii", "replace")[:4096]
    match = _OPENSSL_PUB_HEADER.search(text)
    name = match.group(1) if match else ""
    if name in PQ_NAMES:
        family = name.rsplit("-", 1)[0] if name.startswith("ML-") else "SLH-DSA"
        return _KeyInfo(family, name, None, name, spki_der, "openssl-public-text")
    raise UnsupportedAlgorithm("unrecognized public key algorithm")


def _public_key_info(der: bytes) -> _KeyInfo:
    try:
        key = serialization.load_der_public_key(der)
    except UnsupportedAlgorithm:
        return _openssl_describe_spki(der)
    except ValueError as exc:
        if "Unknown key type" in str(exc):
            return _openssl_describe_spki(der)
        raise
    info = _python_key_info(key)
    if info is None:
        return _openssl_describe_spki(der)
    return _KeyInfo(*info, spki_der=_spki(key), parser="python-cryptography")


def _private_key_info(der: bytes) -> _KeyInfo:
    """Reduce an unencrypted PKCS#8/traditional DER private key to public metadata."""
    try:
        key = serialization.load_der_private_key(der, password=None)
    except TypeError as exc:
        raise _Encrypted() from exc
    except (UnsupportedAlgorithm, ValueError) as exc:
        # Python cannot parse native PQ PKCS#8; derive only the public half with OpenSSL.
        try:
            spki = openssl.run(
                ["pkey", "-inform", "DER", "-passin", "pass:", "-pubout", "-outform", "DER"],
                input=der,
            )
        except openssl.OpenSSLError:
            raise ValueError("not a supported private key") from exc
        return _openssl_describe_spki(spki)
    info = _python_key_info(key)
    public = _spki(key.public_key())
    if info is None:
        return _openssl_describe_spki(public)
    return _KeyInfo(*info, spki_der=public, parser="python-cryptography")


# --------------------------------------------------------------------------- certificates


def _oid_name(oid: x509.ObjectIdentifier, table: dict[str, tuple[str, str]]) -> tuple[str, str]:
    dotted = oid.dotted_string
    if dotted in PQ_OIDS:
        return PQ_OIDS[dotted]
    if dotted in table:
        return table[dotted]
    return "unknown", dotted


def _cert_key_info(cert: x509.Certificate) -> _KeyInfo:
    try:
        key = cert.public_key()
    except (UnsupportedAlgorithm, ValueError):
        family, name = _oid_name(cert.public_key_algorithm_oid, {})
        param = name if family != "unknown" else None
        return _KeyInfo(family, name, None, param, None, "oid-table")
    info = _python_key_info(key)
    if info is None:
        family, name = _oid_name(cert.public_key_algorithm_oid, {})
        return _KeyInfo(family, name, None, None, None, "oid-table")
    return _KeyInfo(*info, spki_der=_spki(key), parser="python-cryptography")


def _cert_role(cert: x509.Certificate) -> str:
    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return "ca"
    except x509.ExtensionNotFound:
        pass
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH in eku:
            return "tls_server"
        if ExtendedKeyUsageOID.CLIENT_AUTH in eku:
            return "tls_client"
    except x509.ExtensionNotFound:
        pass
    return "end_entity"


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    values: list[str] = []
    for name in ext:
        if isinstance(name, x509.DNSName | x509.RFC822Name | x509.UniformResourceIdentifier):
            values.append(clean_text(name.value, 253))
        elif isinstance(name, x509.IPAddress):
            values.append(str(name.value))
        if len(values) >= MAX_SANS:
            break
    return values


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> str:
    if cert.issuer != issuer.subject:
        return "issuer_name_mismatch"
    try:
        cert.verify_directly_issued_by(issuer)
    except InvalidSignature:
        return "signature_invalid"
    except (UnsupportedAlgorithm, ValueError, TypeError):
        return "not_checked_unsupported_algorithm"
    return "verified"


def certificate_assets(
    certs: list[x509.Certificate], source: str, now: datetime, prefix: str = "cert"
) -> list[Asset]:
    """Metadata for an ordered list of certificates (a file or a presented chain).

    The subject public key (algorithm_family/algorithm/parameter_set) is reported separately
    from the issuer's signature over the certificate (signature_algorithm).
    """
    assets = []
    for index, cert in enumerate(certs):
        der = cert.public_bytes(serialization.Encoding.DER)
        key = _cert_key_info(cert)
        sig_family, sig_name = _oid_name(cert.signature_algorithm_oid, CLASSICAL_SIG_OIDS)
        not_before, not_after = cert.not_valid_before_utc, cert.not_valid_after_utc
        if now > not_after:
            validity = "expired"
        else:
            validity = "not_yet_valid" if now < not_before else "valid"
        if index + 1 < len(certs):
            linkage = _issued_by(cert, certs[index + 1])
        elif cert.issuer == cert.subject:
            linkage = "self_signed_" + _issued_by(cert, cert)
        else:
            linkage = "issuer_not_present"
        fingerprint = hashlib.sha256(der).hexdigest()
        evidence = _crypto_evidence(key.family)
        evidence.update({
            "certificate_sha256": fingerprint,
            "certificate_der_bytes": len(der),
            "serial_number": format(cert.serial_number, "x")[:64],
            "not_before": _iso(not_before),
            "validity": validity,
            "certificate_role": _cert_role(cert),
            "self_signed": cert.issuer == cert.subject,
            "chain_position": index,
            "issuer_linkage": linkage,
            "subject_key_parser": key.parser,
            "signature_algorithm_family": sig_family,
            "signature_crypto_class": classify_family(sig_family),
        })
        if sig_family in FIPS:
            evidence["signature_algorithm_standard"] = FIPS[sig_family]
        if key.family in FIPS or sig_family in FIPS:
            evidence["integration_status"] = "experimental-x509-lab-integration"
        if key.spki_der is not None:
            evidence["public_key_sha256"] = hashlib.sha256(key.spki_der).hexdigest()
            evidence["spki_der_bytes"] = len(key.spki_der)
        assets.append(Asset(
            asset_id=_asset_id(prefix, source, str(index), fingerprint),
            asset_type="certificate",
            source=source,
            algorithm_family=key.family,
            algorithm=key.algorithm,
            key_size=key.key_size,
            parameter_set=key.parameter_set,
            signature_algorithm=sig_name,
            certificate_subject=clean_text(cert.subject.rfc4514_string()),
            issuer=clean_text(cert.issuer.rfc4514_string()),
            expiry=_iso(not_after),
            sans=_sans(cert),
            chain_length=len(certs),
            evidence=evidence,
        ))
    return assets


def _key_asset(asset_type: str, source: str, position: int, info: _KeyInfo) -> Asset:
    public_id = hashlib.sha256(info.spki_der).hexdigest() if info.spki_der else ""
    evidence = _crypto_evidence(info.family)
    evidence.update({"public_key_sha256": public_id, "parser": info.parser, "position": position})
    if info.spki_der:
        evidence["spki_der_bytes"] = len(info.spki_der)
    if info.family in FIPS:
        evidence["integration_status"] = "standardized-algorithm-native-openssl"
    if asset_type == "private_key":
        evidence["private_material_exported"] = False
        evidence["identity_basis"] = "derived public key (SPKI) hash"
    prefix = "privkey" if asset_type == "private_key" else "pubkey"
    return Asset(
        asset_id=_asset_id(prefix, source, str(position), public_id),
        asset_type=asset_type,
        source=source,
        algorithm_family=info.family,
        algorithm=info.algorithm,
        key_size=info.key_size,
        parameter_set=info.parameter_set,
        evidence=evidence,
    )


# --------------------------------------------------------------------------- crypto files


def _pem_blocks(data: bytes) -> tuple[list[tuple[str, bytes, bool]], int]:
    """Return (label, der, legacy_encrypted) blocks and the count of malformed blocks."""
    begins = data.count(b"-----BEGIN ")
    if begins > MAX_PEM_BLOCKS:
        raise _Limit("too many PEM blocks")
    blocks = []
    for match in _PEM_RE.finditer(data):
        label, body, end_label = match.group(1), match.group(2), match.group(3)
        if label != end_label:
            continue
        encrypted = False
        payload = []
        bad = False
        for line in body.splitlines():
            stripped = line.strip()
            if b":" in stripped:
                if stripped.startswith(b"Proc-Type:") and b"ENCRYPTED" in stripped:
                    encrypted = True
                continue
            if not _B64_LINE.match(stripped):
                bad = True
                break
            payload.append(stripped)
        if bad:
            continue
        try:
            der = base64.b64decode(b"".join(payload), validate=True)
        except (binascii.Error, ValueError):
            continue
        blocks.append((label.decode(), der, encrypted))
    return blocks, begins - len(blocks)


def _rewrap(label: str, der: bytes) -> bytes:
    armor = label.encode()
    return b"-----BEGIN " + armor + b"-----\n" + base64.encodebytes(der) + b"-----END " + armor \
        + b"-----\n"


def _scan_pem(data: bytes, source: str, state: _ScanState) -> list[Asset]:
    blocks, malformed = _pem_blocks(data)
    if malformed:
        state.error(source, "malformed_pem", f"{malformed} PEM block(s) have malformed armor/body")
    certs: list[x509.Certificate] = []
    assets: list[Asset] = []
    for index, (label, der, legacy_encrypted) in enumerate(blocks):
        where = f"PEM block {index}"
        if label in {"CERTIFICATE", "X509 CERTIFICATE"}:
            try:
                certs.append(x509.load_der_x509_certificate(der))
            except ValueError:
                state.error(source, "malformed_certificate", f"{where} is not a valid certificate")
        elif label in {"PUBLIC KEY", "RSA PUBLIC KEY"}:
            try:
                if label == "RSA PUBLIC KEY":
                    der = _spki(serialization.load_pem_public_key(_rewrap(label, der)))
                assets.append(_key_asset("public_key", source, index, _public_key_info(der)))
            except (ValueError, UnsupportedAlgorithm, openssl.OpenSSLError):
                state.error(source, "malformed_key", f"{where} is not a supported public key")
        elif label == "ENCRYPTED PRIVATE KEY" or (
            label.endswith("PRIVATE KEY") and legacy_encrypted
        ):
            state.error(source, "encrypted_private_key", f"{where} is encrypted; not decrypted")
        elif label in {"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"}:
            try:
                pkcs8 = der
                if label != "PRIVATE KEY":
                    pkcs8 = serialization.load_pem_private_key(
                        _rewrap(label, der), password=None
                    ).private_bytes(
                        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                assets.append(_key_asset("private_key", source, index, _private_key_info(pkcs8)))
            except _Encrypted:
                state.error(source, "encrypted_private_key", f"{where} is encrypted; not decrypted")
            except (ValueError, TypeError, UnsupportedAlgorithm, openssl.OpenSSLError):
                state.error(source, "malformed_key", f"{where} is not a supported private key")
        else:
            safe_label = re.sub(r"[^A-Z0-9 ]", "", label)[:40]
            state.error(source, "unsupported_pem_type",
                        f"{where} of type '{safe_label}' is not inventoried")
    if certs:
        assets[:0] = certificate_assets(certs, source, state.now)
    if not blocks and not malformed:
        state.error(source, "malformed_pem", "No PEM blocks found")
    return assets


def _scan_der(data: bytes, source: str, state: _ScanState) -> list[Asset]:
    if not data:
        state.error(source, "malformed_der", "File is empty")
        return []
    try:
        return certificate_assets([x509.load_der_x509_certificate(data)], source, state.now)
    except ValueError:
        pass
    try:
        return [_key_asset("public_key", source, 0, _public_key_info(data))]
    except (ValueError, UnsupportedAlgorithm, openssl.OpenSSLError):
        pass
    try:
        return [_key_asset("private_key", source, 0, _private_key_info(data))]
    except _Encrypted:
        state.error(source, "encrypted_private_key", "DER private key is encrypted; not decrypted")
        return []
    except (ValueError, TypeError, UnsupportedAlgorithm, openssl.OpenSSLError):
        pass
    state.error(source, "malformed_der", "Not a supported DER certificate or key")
    return []


# --------------------------------------------------------------------------- algorithm tokens

_GROUPS = {
    "x25519": ("XDH", "X25519"), "x448": ("XDH", "X448"),
    "secp256r1": ("ECDH", "secp256r1"), "prime256v1": ("ECDH", "secp256r1"),
    "p-256": ("ECDH", "secp256r1"), "secp384r1": ("ECDH", "secp384r1"),
    "p-384": ("ECDH", "secp384r1"), "secp521r1": ("ECDH", "secp521r1"),
    "p-521": ("ECDH", "secp521r1"),
    "brainpoolp256r1tls13": ("ECDH", "brainpoolP256r1tls13"),
    "brainpoolp384r1tls13": ("ECDH", "brainpoolP384r1tls13"),
    "brainpoolp512r1tls13": ("ECDH", "brainpoolP512r1tls13"),
    **{f"ffdhe{n}": ("FFDH", f"ffdhe{n}") for n in (2048, 3072, 4096, 6144, 8192)},
    **{f"mlkem{n}": ("ML-KEM", f"MLKEM{n}") for n in (512, 768, 1024)},
    **{f"ml-kem-{n}": ("ML-KEM", f"ML-KEM-{n}") for n in (512, 768, 1024)},
    "x25519mlkem768": ("HYBRID-KEM", "X25519MLKEM768"),
    "secp256r1mlkem768": ("HYBRID-KEM", "SecP256r1MLKEM768"),
    "secp384r1mlkem1024": ("HYBRID-KEM", "SecP384r1MLKEM1024"),
    "x448mlkem1024": ("HYBRID-KEM", "X448MLKEM1024"),
}
_SIGALGS = {
    **{f"rsa_pss_{v}_sha{n}": ("RSA", f"rsa_pss_{v}_sha{n}") for v in ("rsae", "pss")
       for n in (256, 384, 512)},
    **{f"rsa_pkcs1_sha{n}": ("RSA", f"rsa_pkcs1_sha{n}") for n in (1, 256, 384, 512)},
    "ecdsa_secp256r1_sha256": ("EC", "ecdsa_secp256r1_sha256"),
    "ecdsa_secp384r1_sha384": ("EC", "ecdsa_secp384r1_sha384"),
    "ecdsa_secp521r1_sha512": ("EC", "ecdsa_secp521r1_sha512"),
    "ecdsa_sha1": ("EC", "ecdsa_sha1"),
    "ed25519": ("EdDSA", "ed25519"), "ed448": ("EdDSA", "ed448"),
    **{f"mldsa{n}": ("ML-DSA", f"mldsa{n}") for n in (44, 65, 87)},
}
_KEYALGS = {
    "rsa": ("RSA", "RSA"), "ec": ("EC", "ECDSA"), "ecdsa": ("EC", "ECDSA"),
    "ed25519": ("EdDSA", "Ed25519"), "ed448": ("EdDSA", "Ed448"),
    "x25519": ("XDH", "X25519"), "x448": ("XDH", "X448"), "dsa": ("DSA", "DSA"),
    **{name.lower(): (family, name) for family, name in PQ_OIDS.values()},
    **{f"mldsa{n}": ("ML-DSA", f"ML-DSA-{n}") for n in (44, 65, 87)},
    **{f"mlkem{n}": ("ML-KEM", f"ML-KEM-{n}") for n in (512, 768, 1024)},
}
_SUITES = {
    s.lower(): ("SYMMETRIC", s) for s in (
        "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_CCM_SHA256", "TLS_AES_128_CCM_8_SHA256", "AES-128-GCM", "AES-256-GCM",
        "ChaCha20-Poly1305", "AES-128-CBC", "AES-256-CBC", "3DES", "RC4",
    )
}
_HASHES = {
    h.lower(): ("HASH", h) for h in (
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3-256", "sha3-384",
        "sha3-512", "SHA-256", "SHA-384", "SHA-512",
    )
}
_PROTOCOLS = {
    "tlsv1": "TLSv1", "tlsv1.0": "TLSv1", "tlsv1.1": "TLSv1.1", "tlsv1.2": "TLSv1.2",
    "tlsv1.3": "TLSv1.3", "tls1.2": "TLSv1.2", "tls1.3": "TLSv1.3", "1.2": "TLSv1.2",
    "1.3": "TLSv1.3", "dtlsv1": "DTLSv1", "dtlsv1.2": "DTLSv1.2", "sslv3": "SSLv3",
    "none": "None",
}
_PROFILES = {p: ("PROFILE", p) for p in ("classical", "hybrid", "pqc")}
_CIPHER_STRING = re.compile(r"^(?:[!+\-]?[A-Z0-9][A-Z0-9+\-]{0,63}|@SECLEVEL=[0-5]|@STRENGTH)$")
_COMBINED_SIGALG = re.compile(
    r"^(RSA|RSA-PSS|ECDSA|ED25519|ED448)\+(SHA1|SHA224|SHA256|SHA384|SHA512)$"
)


def classify_token(kind: str, token: str) -> tuple[str, str] | None:
    """Map a configured algorithm token to (family, canonical name), or None if unrecognized."""
    low = token.lower()
    if kind == "group":
        return _GROUPS.get(low)
    if kind == "sigalg":
        if low in _SIGALGS:
            return _SIGALGS[low]
        match = _COMBINED_SIGALG.match(token.upper())
        if match:
            family = {"RSA": "RSA", "RSA-PSS": "RSA", "ECDSA": "EC"}.get(match.group(1), "EdDSA")
            return family, token.upper()
        return _KEYALGS.get(low)
    if kind == "suite":
        return _SUITES.get(low)
    if kind == "cipher_string":
        return ("TLS-PROTOCOL", token) if _CIPHER_STRING.match(token) else None
    if kind == "hash":
        return _HASHES.get(low)
    if kind == "protocol":
        name = _PROTOCOLS.get(low)
        return ("TLS-PROTOCOL", name) if name else None
    if kind == "key":
        return _KEYALGS.get(low)
    if kind == "profile":
        return _PROFILES.get(low)
    return None


_PURPOSE = {
    "group": "tls_key_establishment", "sigalg": "signature", "suite": "cipher_suite",
    "cipher_string": "tls12_cipher_string", "hash": "digest", "protocol": "tls_protocol_bound",
    "key": "key_algorithm", "profile": "crypto_profile",
}


def _token_asset(
    asset_type: str, source: str, setting: str, kind: str, token: str, index: int,
    location: str,
) -> Asset:
    found = classify_token(kind, token) if _TOKEN.match(token) else None
    family, name = found if found else ("unknown", "unrecognized")
    evidence = _crypto_evidence(family)
    evidence.update({"setting": setting, "purpose": _PURPOSE[kind], "location": location})
    if not found:
        evidence["value_redacted"] = True
    if kind in {"group", "sigalg"} and family in {"ML-KEM", "ML-DSA", "HYBRID-KEM"}:
        evidence["integration_status"] = "experimental-tls-integration"
        if family == "HYBRID-KEM":
            evidence["algorithm_standard"] = FIPS["ML-KEM"] + " component in hybrid group"
    asset = Asset(
        asset_id=_asset_id("cfg", source, f"{location}#{setting}#{index}", name),
        asset_type=asset_type, source=source, algorithm_family=family, algorithm=name,
        evidence=evidence,
    )
    if kind == "protocol" and found:
        asset.tls_version = name
    if kind == "suite" and found:
        asset.cipher_suite = name
    if kind == "group" and found:
        asset.parameter_set = name
    if kind == "key" and family in FIPS:
        asset.parameter_set = name
    return asset


def _split_tokens(value: str) -> list[str]:
    return [t.strip() for t in re.split(r"[:,]", value) if t.strip()]


# --------------------------------------------------------------------------- OpenSSL config

_CNF_KEYS = {
    "groups": "group", "curves": "group", "signaturealgorithms": "sigalg",
    "clientsignaturealgorithms": "sigalg", "ciphersuites": "suite",
    "cipherstring": "cipher_string", "minprotocol": "protocol", "maxprotocol": "protocol",
    "default_md": "hash", "default_bits": "key_size",
}
_CNF_UNSAFE_KEYS = {
    "module", "dynamic_path", "so_path", "providers", "engines", "init", "activate",
    "engine_id", "load", "openssl_conf", "default_keyfile", "random", "random_seed",
    "alg_section", "ssl_conf", "default_properties", "fips",
}
_CNF_KEY = re.compile(r"[A-Za-z0-9_.\-]{1,64}")


def _scan_openssl_cnf(data: bytes, source: str, state: _ScanState) -> list[Asset]:
    """Read OpenSSL config text as inert data. Nothing is loaded, included or expanded."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        state.error(source, "malformed_config", "OpenSSL config is not UTF-8 text")
        return []
    lines = text.splitlines()
    if len(lines) > MAX_CONFIG_LINES:
        state.error(source, "config_limit_exceeded", "OpenSSL config exceeds line limit")
        return []
    assets: list[Asset] = []
    section = "default"
    for number, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        where = f"line {number}"
        if line.startswith("."):
            directive = re.sub(r"[^a-z]", "", line[1:10].lower()) or "unknown"
            state.error(source, "config_directive_not_processed",
                        f"{where}: .{directive} directive ignored (never followed or executed)")
            continue
        header = re.fullmatch(r"\[\s*([A-Za-z0-9_.\-]{1,64})\s*\]", line)
        if header:
            section = header.group(1)
            continue
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("\"'")
        if line.startswith("[") or not sep or not _CNF_KEY.fullmatch(key):
            state.error(source, "malformed_config", f"{where}: not a section or key = value line")
            continue
        low = key.lower()
        base_key = low.rsplit(".", 1)[-1]
        if low in _CNF_UNSAFE_KEYS or base_key in _CNF_UNSAFE_KEYS or section.endswith(
            ("provider_sect", "engine_section", "engines")
        ):
            state.error(source, "config_directive_not_processed",
                        f"{where}: '{low}' in [{section}] not processed "
                        "(no providers/engines/modules/files are loaded)")
            continue
        kind = _CNF_KEYS.get(low)
        if kind is None:
            continue
        if "$" in value:
            state.error(source, "config_value_not_expanded",
                        f"{where}: variable reference in '{key}' not expanded")
            continue
        location = f"[{section}] line {number}"
        if kind == "key_size":
            if value.isdigit() and 512 <= int(value) <= 16384:
                assets.append(Asset(
                    asset_id=_asset_id("cfg", source, location, value),
                    asset_type="openssl_config", source=source, algorithm_family="RSA",
                    algorithm="RSA", key_size=int(value), parameter_set=f"RSA-{value}",
                    evidence={**_crypto_evidence("RSA"), "setting": key,
                              "purpose": "default_generated_key_bits", "location": location},
                ))
            else:
                state.error(source, "invalid_config_value", f"{where}: invalid default_bits")
            continue
        tokens = _split_tokens(value) if kind != "hash" else [value]
        for index, token in enumerate(tokens):
            assets.append(_token_asset("openssl_config", source, key, kind, token, index, location))
        if len(assets) > MAX_ASSETS_PER_FILE:
            state.error(source, "config_limit_exceeded", "Too many crypto settings in file")
            return assets[:MAX_ASSETS_PER_FILE]
    if not assets:
        state.error(source, "no_crypto_metadata", "No recognized crypto settings in OpenSSL config")
    return assets


# --------------------------------------------------------------------------- app config

_APP_KEYS = {
    "key_exchange": "group", "kem": "group", "tls_groups": "group", "groups": "group",
    "curves": "group", "key_agreement": "group",
    "signature_algorithm": "sigalg", "signature_algorithms": "sigalg", "sigalgs": "sigalg",
    "signing_algorithm": "sigalg",
    "cipher_suites": "suite", "ciphersuites": "suite", "cipher_suite": "suite",
    "cipher": "suite", "ciphers": "suite",
    "tls_version": "protocol", "min_tls_version": "protocol", "max_tls_version": "protocol",
    "min_protocol": "protocol", "max_protocol": "protocol",
    "key_algorithm": "key", "public_key_algorithm": "key", "algorithm": "key",
    "hash": "hash", "digest": "hash", "hash_algorithm": "hash",
    "crypto_profile": "profile",
    "key_size": "key_size", "key_bits": "key_size", "rsa_bits": "key_size",
}
_YAML_SAFE_TAGS = {
    f"tag:yaml.org,2002:{name}"
    for name in ("str", "int", "float", "bool", "null", "seq", "map")
} | {"!"}


def _yaml_load(text: str) -> Any:
    """Load plain YAML data only: no aliases/anchors, no non-core tags, single document."""
    events = 0
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        events += 1
        if events > MAX_CONFIG_NODES * 2:
            raise _Limit("YAML document too large")
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
            raise _Unsafe("YAML anchors/aliases are not accepted")
        tag = getattr(event, "tag", None)
        if tag and tag not in _YAML_SAFE_TAGS:
            raise _Unsafe("YAML custom tags are not accepted")
    documents = list(yaml.safe_load_all(text))
    if len(documents) != 1:
        raise ValueError("expected exactly one YAML document")
    return documents[0]


_SettingPath = tuple[str, ...]


def _walk_config(
    node: Any, path: _SettingPath, depth: int, counter: list[int]
) -> Iterator[tuple[_SettingPath, str, Any]]:
    counter[0] += 1
    if counter[0] > MAX_CONFIG_NODES or depth > MAX_CONFIG_DEPTH:
        raise _Limit("config nesting or node limit exceeded")
    if isinstance(node, dict):
        for key in sorted(node, key=str):
            name = str(key)
            safe = name if re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", name) else "?"
            norm = name.lower().replace("-", "_")
            child = node[key]
            if norm in _APP_KEYS and not isinstance(child, dict):
                yield (*path, safe), norm, child
            else:
                yield from _walk_config(child, (*path, safe), depth + 1, counter)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _walk_config(item, (*path, str(index)), depth + 1, counter)


def _scan_app_config(data: bytes, source: str, suffix: str, state: _ScanState) -> list[Asset]:
    """Extract only recognized crypto settings; values of other fields are never emitted."""
    try:
        text = data.decode("utf-8")
        document = json.loads(text) if suffix == ".json" else _yaml_load(text)
        settings = list(_walk_config(document, (), 0, [0]))
    except _Unsafe as exc:
        state.error(source, "unsafe_config_construct", str(exc))
        return []
    except (_Limit, RecursionError):
        state.error(source, "config_limit_exceeded", "Config exceeds node/depth limit")
        return []
    except (UnicodeDecodeError, ValueError, yaml.YAMLError):
        state.error(source, "malformed_config", "Config is not valid JSON/YAML data")
        return []
    assets: list[Asset] = []
    for path, key, value in settings:
        location = ".".join(path)
        kind = _APP_KEYS[key]
        if kind == "key_size":
            if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65536:
                assets.append(Asset(
                    asset_id=_asset_id("cfg", source, location, str(value)),
                    asset_type="application_config", source=source, key_size=value,
                    evidence={"crypto_class": "unknown", "setting": key, "purpose": "key_size",
                              "location": location},
                ))
            else:
                state.error(source, "invalid_config_value", f"{location}: invalid key size")
            continue
        if isinstance(value, str):
            tokens = _split_tokens(value)
        elif isinstance(value, list) and all(isinstance(v, str) for v in value):
            tokens = [t for v in value for t in _split_tokens(v)]
        else:
            state.error(source, "invalid_config_value", f"{location}: unsupported value type")
            continue
        for index, token in enumerate(tokens):
            assets.append(
                _token_asset("application_config", source, key, kind, token, index, location)
            )
        if len(assets) > MAX_ASSETS_PER_FILE:
            state.error(source, "config_limit_exceeded", "Too many crypto settings in file")
            return assets[:MAX_ASSETS_PER_FILE]
    if not assets:
        state.error(source, "no_crypto_metadata", "No recognized crypto settings in config")
    return assets


# --------------------------------------------------------------------------- traversal


def _scan_file(path: Path, source: str, state: _ScanState) -> None:
    suffix = path.suffix.lower()
    if suffix not in CERT_SUFFIXES | OPENSSL_CONFIG_SUFFIXES | APP_CONFIG_SUFFIXES:
        state.error(source, "unsupported_file_type",
                    f"File type '{clean_text(suffix, 16)}' is not inventoried")
        return
    try:
        data = _read_regular_file(path)
    except _Limit as exc:
        state.error(source, "file_too_large", str(exc))
        return
    except (OSError, ValueError):
        state.error(source, "read_rejected", "Not a readable regular non-symlink file")
        return
    state.total_bytes += len(data)
    if state.total_bytes > MAX_TOTAL_BYTES:
        raise _Limit("total scanned bytes limit exceeded")
    try:
        if suffix in OPENSSL_CONFIG_SUFFIXES:
            assets = _scan_openssl_cnf(data, source, state)
        elif suffix in APP_CONFIG_SUFFIXES:
            assets = _scan_app_config(data, source, suffix, state)
        elif b"-----BEGIN " in data:
            assets = _scan_pem(data, source, state)
        else:
            assets = _scan_der(data, source, state)
    except _Limit as exc:
        state.error(source, "file_limit_exceeded", str(exc))
        return
    if len(assets) > MAX_ASSETS_PER_FILE:
        state.error(source, "file_limit_exceeded", "Too many assets in one file")
        assets = assets[:MAX_ASSETS_PER_FILE]
    state.assets.extend(assets)


def _walk(directory: Path, rel: str, depth: int, state: _ScanState) -> None:
    try:
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda e: e.name)
    except OSError:
        state.error(rel or ".", "read_rejected", "Directory cannot be listed")
        return
    for entry in entries:
        state.entries += 1
        if state.entries > MAX_ENTRIES:
            raise _Limit("directory entry limit exceeded")
        source = clean_text(f"{rel}/{entry.name}" if rel else entry.name, 1024)
        if entry.is_symlink():
            state.error(source, "symlink_rejected", "Symlinks are not followed")
        elif entry.is_dir(follow_symlinks=False):
            if depth + 1 > MAX_DEPTH:
                state.error(source, "depth_limit_exceeded", f"Directory deeper than {MAX_DEPTH}")
            else:
                _walk(Path(entry.path), source, depth + 1, state)
        elif entry.is_file(follow_symlinks=False):
            _scan_file(Path(entry.path), source, state)
        else:
            state.error(source, "special_file_rejected", "Only regular files are inventoried")


def scan(path: Path, *, now: datetime | None = None) -> Inventory:
    """Inventory an explicit file or directory with bounded, deterministic discovery.

    Sources are reported relative to the scan root so results do not leak host paths and are
    stable across checkouts. The optional now argument pins certificate validity evaluation.
    """
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Scan root must not be a symlink")
    if not path.exists():
        raise ValueError("Scan root does not exist")
    state = _ScanState(now=now or datetime.now(UTC))
    try:
        if path.is_dir():
            _walk(path, "", 0, state)
        elif path.is_file():
            state.entries = 1
            _scan_file(path, clean_text(path.name, 1024), state)
        else:
            raise ValueError("Scan root must be a regular file or directory")
    except _Limit as exc:
        state.error(".", "scan_limit_exceeded", f"{exc}; remaining entries not scanned")
    return Inventory(assets=state.assets, errors=state.errors)


# --------------------------------------------------------------------------- TLS endpoints


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _validate_target(host: str, port: int, allow_remote: bool) -> tuple[str, str]:
    """Return (connect_address, display_host); reject non-loopback unless explicitly allowed."""
    if not isinstance(host, str) or not host or len(host) > 255 or host.startswith("-"):
        raise ValueError("Invalid host")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Port must be an integer in 1..65535")
    bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    literal = _is_ip(bare)
    if not literal and not _HOSTNAME.match(bare):
        raise ValueError("Invalid host")
    if not literal and not allow_remote and bare.lower().rstrip(".") != "localhost":
        raise PermissionError(
            "Only loopback addresses or 'localhost' are inspected without allow_remote=True"
        )
    if literal:
        addresses = [ipaddress.ip_address(bare)]
    else:
        try:
            infos = socket.getaddrinfo(bare, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ValueError("Host could not be resolved") from exc
        addresses = sorted(
            {ipaddress.ip_address(str(info[4][0]).split("%")[0]) for info in infos},
            key=lambda a: (a.version, int(a)),
        )
    if not addresses:
        raise ValueError("Host could not be resolved")
    for address in addresses:
        effective = getattr(address, "ipv4_mapped", None) or address
        if effective.is_unspecified or effective.is_multicast:
            raise ValueError("Unspecified or multicast destinations are rejected")
        if not effective.is_loopback and not allow_remote:
            raise PermissionError("Remote destination requires explicit allow_remote=True")
    chosen = addresses[0]
    connect = f"[{chosen}]:{port}" if chosen.version == 6 else f"{chosen}:{port}"
    return connect, bare


def _name_args(name: str) -> list[str]:
    if _is_ip(name):
        return ["-noservername", "-verify_ip", name]
    return ["-servername", name.rstrip("."), "-verify_hostname", name.rstrip(".")]


def _safe_token(value: str | None) -> str | None:
    if value is None or not _TOKEN.match(value):
        return None
    return value


def _parse_s_client(text: str) -> dict[str, Any]:
    """Extract an allowlist of negotiation facts. Session secrets/tickets are never read."""

    def first(pattern: str) -> str | None:
        match = re.search(pattern, text, re.MULTILINE)
        return match.group(1) if match else None

    new_line = re.search(r"^New, (TLSv1(?:\.[0-3])?|SSLv3|\(NONE\)), Cipher is (\S+)", text, re.M)
    code = first(r"^\s*Verify return code: (\d{1,4}) ")
    if new_line:
        version, suite = new_line.group(1), new_line.group(2)
    else:
        version = first(r"^Protocol version: (\S+)$")
        suite = first(r"^Ciphersuite: (\S+)$")
    return {
        "tls_version": _safe_token(version),
        "cipher_suite": _safe_token(suite),
        "negotiated_group": _safe_token(first(r"^Negotiated TLS1\.3 group: (\S+)$")),
        "temp_key": _safe_token(first(r"^(?:Peer|Server) Temp Key: (?:ECDH, )?([A-Za-z0-9-]+),")),
        "peer_signature_type": _safe_token(first(r"^Peer signature type: (\S+)$")),
        "verify_code": int(code) if code is not None else None,
        "verified_ok": bool(re.search(r"^Verification: OK$", text, re.M)),
    }


def tls13_groups() -> list[str]:
    """TLS 1.3 groups supported by the pinned OpenSSL client, detected at runtime."""
    out = openssl.run(["list", "-tls1_3", "-tls-groups"]).decode("ascii", "replace")
    groups = [g for g in out.strip().split(":") if _TOKEN.match(g)]
    return groups[:MAX_PROBE_GROUPS]


def _probe(connect: str, args: list[str], timeout: float) -> dict[str, Any] | None:
    try:
        out = openssl.run(
            ["s_client", "-connect", connect, *args, "-no-interactive", "-verify_return_error"],
            input=b"", timeout=timeout,
        )
    except openssl.OpenSSLError:
        return None
    return _parse_s_client(out[:MAX_TLS_OUTPUT].decode("ascii", "replace"))


def inspect_endpoint(
    host: str,
    port: int,
    cafile: str | Path | None = None,
    server_name: str | None = None,
    allow_remote: bool = False,
    *,
    timeout: float = 5.0,
    probe: bool = True,
    now: datetime | None = None,
) -> Inventory:
    """Authenticate one TLS endpoint and record observed negotiation and probe support.

    Only loopback destinations are contacted unless allow_remote=True. The peer must pass chain
    and hostname/IP verification against cafile (or the pinned OpenSSL default store); otherwise
    the result fails closed with an error and no endpoint asset. evidence['observed'] is the
    default handshake; evidence['probe_supported'] lists single-offer probe results.
    """
    connect, display = _validate_target(host, port, allow_remote)
    if isinstance(timeout, bool) or not isinstance(timeout, int | float) or not (
        0.1 <= float(timeout) <= 30
    ):
        raise ValueError("timeout must be between 0.1 and 30 seconds")
    name = server_name if server_name is not None else display
    if not isinstance(name, str) or not (_HOSTNAME.match(name) or _is_ip(name)):
        raise ValueError("Invalid server_name")
    trust: list[str] = []
    if cafile is not None:
        ca = Path(cafile)
        try:
            ca_data = _read_regular_file(ca)
        except (OSError, ValueError, _Limit) as exc:
            raise ValueError("cafile must be a readable regular non-symlink file") from exc
        if b"-----BEGIN CERTIFICATE-----" not in ca_data:
            raise ValueError("cafile must contain PEM certificates")
        trust = ["-CAfile", str(ca.resolve())]
    source = clean_text(f"tls://{display}:{port}", 300)
    base = [*_name_args(name), *trust]
    try:
        raw = openssl.run(
            ["s_client", "-connect", connect, *base, "-showcerts", "-no-interactive"],
            input=b"", timeout=float(timeout),
        )
    except openssl.OpenSSLError:
        return Inventory(errors=[{"source": source, "code": "tls_connection_failed",
                                  "message": "TLS connection or handshake failed or timed out"}])
    text = raw[:MAX_TLS_OUTPUT].decode("ascii", "replace")
    observed = _parse_s_client(text)
    if observed["verify_code"] != 0 or not observed["verified_ok"]:
        code = observed["verify_code"]
        reason = VERIFY_REASONS.get(code, f"verification error {code}") if code else (
            "peer not authenticated")
        return Inventory(errors=[{"source": source, "code": "tls_verification_failed",
                                  "message": f"Peer authentication failed: {reason}"}])
    if not observed["tls_version"] or observed["cipher_suite"] in {None, "(NONE)"}:
        return Inventory(errors=[{"source": source, "code": "tls_handshake_incomplete",
                                  "message": "Handshake did not complete"}])
    errors: list[dict[str, str]] = []
    certs: list[x509.Certificate] = []
    for match in _PEM_RE.finditer(text.encode("ascii", "replace")):
        if match.group(1) != b"CERTIFICATE":
            continue
        if len(certs) >= MAX_CHAIN_CERTS:
            errors.append({"source": source, "code": "chain_limit_exceeded",
                           "message": f"Only the first {MAX_CHAIN_CERTS} certificates parsed"})
            break
        try:
            body = b"".join(match.group(2).split())
            certs.append(x509.load_der_x509_certificate(base64.b64decode(body, validate=True)))
        except (ValueError, binascii.Error):
            errors.append({"source": source, "code": "malformed_certificate",
                           "message": "Presented certificate could not be parsed"})
    moment = now or datetime.now(UTC)
    cert_assets = certificate_assets(certs, f"{source}#presented-chain", moment, prefix="tlscert")

    probes: dict[str, dict[str, str]] | None = None
    if probe:
        probes = {"protocols": {}, "tls13_groups": {}}
        for label, flag in (("TLSv1.2", "-tls1_2"), ("TLSv1.3", "-tls1_3")):
            result = _probe(connect, [*base, flag], float(timeout))
            ok = result is not None and result["tls_version"] == label
            probes["protocols"][label] = "negotiated" if ok else "not_negotiated"
        try:
            groups = tls13_groups()
        except openssl.OpenSSLError:
            groups = []
        for group in groups:
            result = _probe(connect, [*base, "-tls1_3", "-groups", group], float(timeout))
            # Only one group is offered, so a completed TLS 1.3 handshake means it was accepted.
            ok = (
                result is not None
                and result["tls_version"] == "TLSv1.3"
                and result["cipher_suite"] not in {None, "(NONE)"}
            )
            probes["tls13_groups"][group] = "negotiated" if ok else "not_negotiated"

    group = observed["negotiated_group"] or observed["temp_key"]
    found = classify_token("group", group) if group else None
    family = found[0] if found else "unknown"
    leaf = cert_assets[0] if cert_assets else None
    evidence = _crypto_evidence(family)
    if family in {"ML-KEM", "HYBRID-KEM"}:
        evidence["integration_status"] = "experimental-tls-integration"
    evidence.update({
        "authentication": {
            "verified": True,
            "verified_name": name,
            "trust_anchor": "cafile" if trust else "pinned-openssl-default-store",
        },
        "peer_address": connect.rsplit(":", 1)[0].strip("[]"),
        "observed": {
            "tls_version": observed["tls_version"],
            "cipher_suite": observed["cipher_suite"],
            "negotiated_group": group,
            "peer_signature_type": observed["peer_signature_type"],
            "presented_chain_length": len(certs),
        },
        "probe_supported": probes,
        "probe_note": "Single-offer handshakes by the pinned OpenSSL client; not a complete "
        "server configuration audit.",
    })
    if leaf is not None:
        evidence["leaf_certificate_sha256"] = leaf.evidence["certificate_sha256"]
        evidence["leaf_asset_id"] = leaf.asset_id
    endpoint = Asset(
        asset_id=_asset_id("tls", source, name, f"{display}:{port}"),
        asset_type="tls_endpoint",
        source=source,
        algorithm_family=family,
        algorithm=group or "unknown",
        signature_algorithm=observed["peer_signature_type"],
        tls_version=observed["tls_version"],
        cipher_suite=observed["cipher_suite"],
        negotiated_group=group,
        certificate_subject=leaf.certificate_subject if leaf else None,
        issuer=leaf.issuer if leaf else None,
        expiry=leaf.expiry if leaf else None,
        sans=list(leaf.sans) if leaf else [],
        chain_length=len(certs),
        evidence=evidence,
    )
    return Inventory(assets=[endpoint, *cert_assets], errors=errors)
