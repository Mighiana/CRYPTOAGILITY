"""Real-behavior tests for bounded crypto asset discovery and loopback TLS inspection."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from cryptoagility import inventory, openssl
from cryptoagility.models import Inventory


def _openssl_available() -> bool:
    try:
        openssl.executable()
    except openssl.OpenSSLError:
        return False
    return True


requires_openssl = pytest.mark.skipif(not _openssl_available(), reason="pinned OpenSSL missing")
NOW = datetime(2026, 6, 1, tzinfo=UTC)


def ossl(*args: str, data: bytes | None = None) -> bytes:
    return openssl.run(list(args), input=data)


def openssl_has(kind: str, name: str) -> bool:
    if not _openssl_available():
        return False
    return name in ossl("list", f"-{kind}-algorithms").decode()


def make_cert(
    cn: str,
    key,
    issuer: tuple[x509.Certificate, object] | None = None,
    *,
    sans: tuple[str, ...] = ("localhost",),
    ca: bool = False,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer_name = issuer[0].subject if issuer else subject
    signer = issuer[1] if issuer else key
    start = not_before or datetime.now(UTC) - timedelta(days=1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(not_after or datetime.now(UTC) + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    names: list[x509.GeneralName] = []
    for name in sans:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            names.append(x509.DNSName(name))
    if names and not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    algorithm = None if isinstance(signer, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(signer, algorithm)  # type: ignore[arg-type]


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key, fmt=serialization.PrivateFormat.PKCS8, password: bytes | None = None) -> bytes:
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(serialization.Encoding.PEM, fmt, enc)


def by_type(inv: Inventory, asset_type: str) -> list:
    return [a for a in inv.assets if a.asset_type == asset_type]


def codes(inv: Inventory) -> set[str]:
    return {e["code"] for e in inv.errors}


# --------------------------------------------------------------------------- file discovery


def test_chain_distinguishes_subject_key_from_signature_and_links_issuer(tmp_path: Path) -> None:
    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca = make_cert("Lab Root", ca_key, ca=True)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = make_cert("svc.lab.test", leaf_key, (ca, ca_key), sans=("svc.lab.test", "127.0.0.1"))
    (tmp_path / "chain.pem").write_bytes(pem(leaf) + pem(ca))

    inv = inventory.scan(tmp_path, now=NOW)
    leaf_a, ca_a = by_type(inv, "certificate")
    assert inv.errors == []
    assert (leaf_a.algorithm_family, leaf_a.key_size) == ("RSA", 2048)
    assert leaf_a.signature_algorithm == "ecdsa-with-SHA256"
    assert leaf_a.evidence["signature_algorithm_family"] == "EC"
    assert leaf_a.evidence["issuer_linkage"] == "verified"
    assert leaf_a.chain_length == 2 and leaf_a.sans == ["svc.lab.test", "127.0.0.1"]
    assert (ca_a.algorithm, ca_a.parameter_set) == ("ECDSA", "P-384")
    assert ca_a.evidence["certificate_role"] == "ca"
    assert ca_a.evidence["issuer_linkage"] == "self_signed_verified"


def test_wrong_issuer_order_and_expired_certificate_are_reported(tmp_path: Path) -> None:
    ca_key = ed25519.Ed25519PrivateKey.generate()
    ca = make_cert("Root", ca_key, ca=True)
    other_key = ed25519.Ed25519PrivateKey.generate()
    other = make_cert("Root", other_key, ca=True)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    expired = make_cert(
        "old.lab.test",
        leaf_key,
        (ca, ca_key),
        not_before=NOW - timedelta(days=60),
        not_after=NOW - timedelta(days=1),
    )
    (tmp_path / "bad-chain.pem").write_bytes(pem(expired) + pem(other))
    leaf_a = by_type(inventory.scan(tmp_path, now=NOW), "certificate")[0]
    assert leaf_a.evidence["validity"] == "expired"
    assert leaf_a.evidence["issuer_linkage"] == "signature_invalid"
    assert leaf_a.signature_algorithm == "Ed25519"
    assert leaf_a.algorithm_family == "EC"


def test_private_keys_never_leak_and_identity_comes_from_public_key(tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pkcs8 = key_pem(key)
    target = tmp_path / "svc.key"
    target.write_bytes(pkcs8)
    first = inventory.scan(tmp_path, now=NOW)
    target.write_bytes(key_pem(key, serialization.PrivateFormat.TraditionalOpenSSL))
    second = inventory.scan(tmp_path, now=NOW)

    (asset,) = first.assets
    assert asset.asset_type == "private_key" and asset.key_size == 2048
    assert asset.asset_id == second.assets[0].asset_id
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    import hashlib

    assert asset.evidence["public_key_sha256"] == hashlib.sha256(spki).hexdigest()
    dumped = json.dumps(first.to_dict())
    body_lines = pkcs8.decode().splitlines()[1:-1]
    assert not any(line in dumped for line in body_lines)
    assert "PRIVATE KEY-----" not in dumped
    assert format(key.private_numbers().d, "x")[:32] not in dumped
    assert str(key.private_numbers().d)[:32] not in dumped


def test_encrypted_non_cert_and_malformed_inputs_are_errors(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "enc.key").write_bytes(key_pem(key, password=b"synthetic-lab-pass"))
    (tmp_path / "legacy-enc.key").write_bytes(
        key_pem(key, serialization.PrivateFormat.TraditionalOpenSSL, password=b"x")
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "csr")]))
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "req.pem").write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "ssh.key").write_bytes(
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    (tmp_path / "broken.pem").write_bytes(
        b"-----BEGIN CERTIFICATE-----\n!!notbase64!!\n-----END CERTIFICATE-----\n"
    )
    (tmp_path / "junk-cert.pem").write_bytes(
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    )
    (tmp_path / "random.der").write_bytes(os.urandom(64))
    (tmp_path / "notes.txt").write_text("not crypto")

    inv = inventory.scan(tmp_path, now=NOW)
    assert inv.assets == []
    by_source = {(e["source"], e["code"]) for e in inv.errors}
    assert ("enc.key", "encrypted_private_key") in by_source
    assert ("legacy-enc.key", "encrypted_private_key") in by_source
    assert ("req.pem", "unsupported_pem_type") in by_source
    assert ("ssh.key", "unsupported_pem_type") in by_source
    assert ("broken.pem", "malformed_pem") in by_source
    assert ("junk-cert.pem", "malformed_certificate") in by_source
    assert ("random.der", "malformed_der") in by_source
    assert ("notes.txt", "unsupported_file_type") in by_source
    assert "synthetic-lab-pass" not in json.dumps(inv.to_dict())


def test_symlinks_special_files_and_limits_are_rejected(tmp_path: Path, monkeypatch) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.pem"
    secret.write_bytes(pem(make_cert("outside", ec.generate_private_key(ec.SECP256R1()))))
    root = tmp_path / "root"
    root.mkdir()
    (root / "link.pem").symlink_to(secret)
    (root / "linkdir").symlink_to(outside, target_is_directory=True)
    os.mkfifo(root / "pipe.pem")
    deep = root
    for index in range(inventory.MAX_DEPTH + 1):
        deep = deep / f"d{index}"
        deep.mkdir()
    (root / "big.pem").write_bytes(b"x" * 64)
    monkeypatch.setattr(inventory, "MAX_FILE_BYTES", 32)

    inv = inventory.scan(root, now=NOW)
    found = {(e["source"], e["code"]) for e in inv.errors}
    assert ("link.pem", "symlink_rejected") in found
    assert ("linkdir", "symlink_rejected") in found
    assert ("pipe.pem", "special_file_rejected") in found
    assert ("big.pem", "file_too_large") in found
    assert any(code == "depth_limit_exceeded" for _, code in found)
    assert inv.assets == []
    with pytest.raises(ValueError):
        inventory.scan(root / "link.pem")

    monkeypatch.setattr(inventory, "MAX_ENTRIES", 2)
    limited = inventory.scan(root, now=NOW)
    assert "scan_limit_exceeded" in codes(limited)


def test_repeated_scan_is_deterministic(tmp_path: Path) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "c.pem").write_bytes(pem(make_cert("c", key)))
    (tmp_path / "a.key").write_bytes(key_pem(key))
    (tmp_path / "app.yaml").write_text("tls:\n  key_exchange: X25519MLKEM768:X25519\n")
    first = inventory.scan(tmp_path, now=NOW).to_dict()
    second = inventory.scan(tmp_path, now=NOW).to_dict()
    assert first == second
    assert [a["source"] for a in first["assets"]] == ["a.key", "app.yaml", "app.yaml", "b/c.pem"]


# --------------------------------------------------------------------------- configs


def test_hostile_openssl_config_is_never_executed_or_followed(tmp_path: Path) -> None:
    included = tmp_path / "inc"
    included.mkdir()
    (included / "extra.cnf").write_text("[x]\nGroups = MLKEM1024\n")
    canary = tmp_path / "canary"
    root = tmp_path / "scan"
    root.mkdir()
    (root / "lab.cnf").write_text(
        f".include {included}/extra.cnf\n"
        ".pragma dollarid:true\n"
        "openssl_conf = openssl_init\n"
        "[openssl_init]\nproviders = provider_sect\nengines = engine_section\n"
        "[provider_sect]\nevil = evil_sect\n"
        f"[evil_sect]\nmodule = /tmp/evil-provider.so\nactivate = 1\n"
        f"[engine_section]\ndynamic_path = /tmp/evil-engine.so\ninit = 1\n"
        "[system_default_sect]\n"
        "MinProtocol = TLSv1.2\n"
        "Groups = X25519MLKEM768:X25519:$ENV::HOME\n"
        "CipherString = $ENV::CIPHERS\n"
        "Ciphersuites = TLS_AES_256_GCM_SHA384:=HYPERLINK(evil)\n"
        f"SignatureAlgorithms = mldsa65:ed25519 # touch {canary}\n"
        "Password = hunter2\n"
        "[ bad header\n"
    )
    inv = inventory.scan(root, now=NOW)
    assert not canary.exists()
    names = [a.algorithm for a in inv.assets]
    assert "MLKEM1024" not in names
    assert names.count("unrecognized") == 1
    assert {"TLSv1.2", "TLS_AES_256_GCM_SHA384", "mldsa65", "ed25519"} <= set(names)
    assert "X25519MLKEM768" not in names
    dumped = json.dumps(inv.to_dict())
    for forbidden in ("evil-provider", "evil-engine", "hunter2", "HYPERLINK", "extra.cnf", "HOME"):
        assert forbidden not in dumped
    errs = [e for e in inv.errors if e["code"] == "config_directive_not_processed"]
    assert len(errs) >= 8
    assert "config_value_not_expanded" in codes(inv)
    assert "malformed_config" in codes(inv)
    mldsa = next(a for a in inv.assets if a.algorithm == "mldsa65")
    assert mldsa.evidence["integration_status"] == "experimental-tls-integration"


def test_openssl_config_groups_classified(tmp_path: Path) -> None:
    (tmp_path / "groups.cnf").write_text(
        "[s]\nGroups = X25519MLKEM768:SecP256r1MLKEM768:MLKEM768:x25519:ffdhe2048\n"
    )
    assets = inventory.scan(tmp_path, now=NOW).assets
    assert [(a.algorithm_family, a.algorithm) for a in assets] == [
        ("HYBRID-KEM", "X25519MLKEM768"),
        ("HYBRID-KEM", "SecP256r1MLKEM768"),
        ("ML-KEM", "MLKEM768"),
        ("XDH", "X25519"),
        ("FFDH", "ffdhe2048"),
    ]
    assert assets[0].evidence["crypto_class"] == "hybrid"
    assert assets[2].evidence["algorithm_standard"] == "NIST FIPS 203"


def test_hostile_yaml_and_json_are_rejected_without_execution(tmp_path: Path) -> None:
    canary = tmp_path / "pwned"
    (tmp_path / "rce.yaml").write_text(
        f'key_exchange: !!python/object/apply:os.system ["touch {canary}"]\n'
    )
    (tmp_path / "bomb.yaml").write_text("a: &a [x, x, x]\nb: &b [*a, *a, *a]\nc: [*b, *b, *b]\n")
    (tmp_path / "multi.yaml").write_text("a: 1\n---\nb: 2\n")
    (tmp_path / "deep.json").write_text("[" * 50 + "]" * 50)
    (tmp_path / "bad.json").write_text("{not json")
    (tmp_path / "custom.yml").write_text("hash: !secret sha256\n")
    inv = inventory.scan(tmp_path, now=NOW)
    assert not canary.exists()
    assert inv.assets == []
    found = {(e["source"], e["code"]) for e in inv.errors}
    assert ("rce.yaml", "unsafe_config_construct") in found
    assert ("bomb.yaml", "unsafe_config_construct") in found
    assert ("custom.yml", "unsafe_config_construct") in found
    assert ("multi.yaml", "malformed_config") in found
    assert ("deep.json", "config_limit_exceeded") in found
    assert ("bad.json", "malformed_config") in found


def test_app_config_emits_only_recognized_crypto_settings(tmp_path: Path) -> None:
    (tmp_path / "service.json").write_text(
        json.dumps(
            {
                "name": "payments",
                "db_password": "hunter2-synthetic",
                "api": {"token": "tok_synthetic", "notes": "=cmd|' /C calc'!A0"},
                "tls": {
                    "min_tls_version": "TLSv1.2",
                    "key_exchange": ["X25519MLKEM768", "x25519"],
                    "cipher_suites": "TLS_AES_128_GCM_SHA256:@SUM(1)",
                    "signature_algorithm": "ML-DSA-65",
                    "key_size": 3072,
                },
                "signing": {"algorithm": "rsa", "digest": "sha1", "rsa_bits": "big"},
                "crypto_profile": "hybrid",
            }
        )
    )
    inv = inventory.scan(tmp_path, now=NOW)
    pairs = sorted((a.evidence["location"], a.algorithm) for a in inv.assets)
    assert ("tls.key_exchange", "X25519MLKEM768") in pairs
    assert ("tls.signature_algorithm", "ML-DSA-65") in pairs
    assert ("signing.digest", "sha1") in pairs
    assert ("crypto_profile", "hybrid") in pairs
    assert ("tls.cipher_suites", "unrecognized") in pairs
    assert any(a.key_size == 3072 for a in inv.assets)
    assert ("signing.rsa_bits" in e["message"] for e in inv.errors)
    dumped = json.dumps(inv.to_dict())
    for forbidden in ("hunter2", "tok_synthetic", "payments", "calc", "@SUM"):
        assert forbidden not in dumped
    tls = next(a for a in inv.assets if a.tls_version)
    assert tls.tls_version == "TLSv1.2"


# --------------------------------------------------------------------------- post-quantum


@requires_openssl
@pytest.mark.skipif(not openssl_has("signature", "ML-DSA-65"), reason="ML-DSA unavailable")
def test_native_ml_dsa_certificate_and_keys(tmp_path: Path) -> None:
    key = tmp_path / "mldsa.key"
    ossl("genpkey", "-algorithm", "ML-DSA-65", "-out", str(key))
    ossl(
        "req",
        "-x509",
        "-new",
        "-key",
        str(key),
        "-subj",
        "/CN=pq.lab.test",
        "-days",
        "30",
        "-out",
        str(tmp_path / "mldsa.crt"),
    )
    ossl("pkey", "-in", str(key), "-pubout", "-out", str(tmp_path / "mldsa.pub"))
    pub_der = ossl("pkey", "-in", str(key), "-pubout", "-outform", "DER")

    inv = inventory.scan(tmp_path)
    assert inv.errors == []
    cert = by_type(inv, "certificate")[0]
    priv = by_type(inv, "private_key")[0]
    pub = by_type(inv, "public_key")[0]
    assert (cert.algorithm_family, cert.parameter_set) == ("ML-DSA", "ML-DSA-65")
    assert cert.signature_algorithm == "ML-DSA-65"
    assert cert.evidence["algorithm_standard"] == "NIST FIPS 204"
    assert cert.evidence["integration_status"] == "experimental-x509-lab-integration"
    assert cert.evidence["subject_key_parser"] == "oid-table"
    import hashlib

    expected = hashlib.sha256(pub_der).hexdigest()
    assert priv.evidence["public_key_sha256"] == expected == pub.evidence["public_key_sha256"]
    assert priv.evidence["parser"] == "openssl-public-text"
    assert priv.algorithm == pub.algorithm == "ML-DSA-65"
    private_body = key.read_text().splitlines()[1]
    assert private_body not in json.dumps(inv.to_dict())


@requires_openssl
@pytest.mark.skipif(not openssl_has("signature", "ML-DSA-44"), reason="ML-DSA unavailable")
def test_pq_subject_key_signed_by_classical_ca(tmp_path: Path) -> None:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = make_cert("Classical Root", ca_key, ca=True)
    work = tmp_path / "work"
    work.mkdir()
    (work / "ca.crt").write_bytes(pem(ca))
    (work / "ca.key").write_bytes(key_pem(ca_key))
    ossl("genpkey", "-algorithm", "ML-DSA-44", "-out", str(work / "leaf.key"))
    ossl(
        "req",
        "-new",
        "-key",
        str(work / "leaf.key"),
        "-subj",
        "/CN=pq-leaf",
        "-out",
        str(work / "leaf.csr"),
    )
    out = tmp_path / "scan"
    out.mkdir()
    ossl(
        "x509",
        "-req",
        "-in",
        str(work / "leaf.csr"),
        "-CA",
        str(work / "ca.crt"),
        "-CAkey",
        str(work / "ca.key"),
        "-days",
        "10",
        "-out",
        str(out / "leaf.crt"),
    )
    (out / "leaf.crt").write_bytes((out / "leaf.crt").read_bytes() + pem(ca))
    leaf = by_type(inventory.scan(out), "certificate")[0]
    assert leaf.algorithm == "ML-DSA-44"
    assert leaf.signature_algorithm == "sha256WithRSAEncryption"
    assert leaf.evidence["signature_crypto_class"] == "classical-public-key"
    assert leaf.evidence["crypto_class"] == "post-quantum"
    assert leaf.evidence["issuer_linkage"] == "verified"


@requires_openssl
@pytest.mark.parametrize(
    ("kind", "algorithm", "family"),
    [
        ("kem", "ML-KEM-768", "ML-KEM"),
        ("kem", "ML-KEM-1024", "ML-KEM"),
        ("signature", "SLH-DSA-SHA2-128f", "SLH-DSA"),
        ("signature", "ML-DSA-87", "ML-DSA"),
    ],
)
def test_pq_public_and_private_key_metadata(
    tmp_path: Path, kind: str, algorithm: str, family: str
) -> None:
    if not openssl_has(kind, algorithm):
        pytest.skip(f"{algorithm} not available in pinned OpenSSL")
    key = tmp_path / "k.pem"
    ossl("genpkey", "-algorithm", algorithm, "-out", str(key))
    ossl("pkey", "-in", str(key), "-pubout", "-outform", "DER", "-out", str(tmp_path / "k.der"))
    inv = inventory.scan(tmp_path)
    assert inv.errors == []
    assert {(a.asset_type, a.algorithm_family, a.parameter_set) for a in inv.assets} == {
        ("private_key", family, algorithm),
        ("public_key", family, algorithm),
    }
    assert {a.evidence["public_key_sha256"] for a in inv.assets} and len(
        {a.evidence["public_key_sha256"] for a in inv.assets}
    ) == 1
    assert all(a.evidence["crypto_class"] == "post-quantum" for a in inv.assets)


# --------------------------------------------------------------------------- TLS endpoints


def test_remote_and_malformed_destinations_rejected_without_network() -> None:
    for host in ("example.com", "8.8.8.8", "10.0.0.1", "[2001:db8::1]"):
        with pytest.raises(PermissionError):
            inventory.inspect_endpoint(host, 443)
    for host in ("-proxy", "a b", "0.0.0.0", "", "x" * 300, "local\nhost"):  # noqa: S104
        with pytest.raises((ValueError, PermissionError)):
            inventory.inspect_endpoint(host, 443)
    for port in (0, 70000, True, "443"):
        with pytest.raises(ValueError):
            inventory.inspect_endpoint("127.0.0.1", port)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        inventory.inspect_endpoint("127.0.0.1", 443, server_name="bad name;rm")
    with pytest.raises(ValueError):
        inventory.inspect_endpoint("127.0.0.1", 443, timeout=500)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def tls_server(*args: str) -> Iterator[int]:
    port = _free_port()
    env = {**os.environ, "OPENSSL_CONF": os.devnull}
    proc = subprocess.Popen(
        [openssl.executable(), "s_server", "-accept", f"127.0.0.1:{port}", "-quiet", *args],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert proc.poll() is None, "s_server exited"
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        yield port
    finally:
        proc.kill()
        proc.wait(timeout=5)


@pytest.fixture
def pki(tmp_path: Path) -> dict[str, Path]:
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = make_cert("Lab Root CA", root_key, ca=True)
    inter_key = ec.generate_private_key(ec.SECP256R1())
    inter = make_cert("Lab Intermediate", inter_key, (root, root_key), ca=True)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = make_cert("localhost", leaf_key, (inter, inter_key), sans=("localhost", "127.0.0.1"))
    old_key = ec.generate_private_key(ec.SECP256R1())
    old = make_cert(
        "localhost",
        old_key,
        (root, root_key),
        not_before=datetime.now(UTC) - timedelta(days=10),
        not_after=datetime.now(UTC) - timedelta(days=1),
    )
    files = {
        "root": pem(root),
        "inter": pem(inter),
        "leaf": pem(leaf),
        "leaf_key": key_pem(leaf_key),
        "old": pem(old),
        "old_key": key_pem(old_key),
    }
    paths = {}
    for name, data in files.items():
        paths[name] = tmp_path / f"{name}.pem"
        paths[name].write_bytes(data)
    return paths


def _serve_leaf(pki: dict[str, Path], *extra: str):
    return tls_server(
        "-cert",
        str(pki["leaf"]),
        "-key",
        str(pki["leaf_key"]),
        "-cert_chain",
        str(pki["inter"]),
        *extra,
    )


@requires_openssl
@pytest.mark.integration
def test_authenticated_loopback_chain_observed_separately_from_probes(pki) -> None:
    with _serve_leaf(pki, "-tls1_3", "-groups", "X25519MLKEM768:X25519") as port:
        inv = inventory.inspect_endpoint(
            "127.0.0.1", port, cafile=pki["root"], server_name="localhost"
        )
    assert inv.errors == []
    endpoint, leaf, inter = inv.assets
    assert endpoint.asset_type == "tls_endpoint"
    assert endpoint.tls_version == "TLSv1.3"
    assert endpoint.negotiated_group == "X25519MLKEM768"
    assert endpoint.algorithm_family == "HYBRID-KEM"
    assert endpoint.evidence["integration_status"] == "experimental-tls-integration"
    assert endpoint.evidence["authentication"]["verified"] is True
    observed = endpoint.evidence["observed"]
    assert observed["presented_chain_length"] == 2 and endpoint.chain_length == 2
    probes = endpoint.evidence["probe_supported"]
    assert probes["protocols"] == {"TLSv1.2": "not_negotiated", "TLSv1.3": "negotiated"}
    assert probes["tls13_groups"]["X25519MLKEM768"] == "negotiated"
    assert probes["tls13_groups"]["x25519"] == "negotiated"
    assert probes["tls13_groups"]["secp256r1"] == "not_negotiated"
    if "MLKEM768" in probes["tls13_groups"]:
        assert probes["tls13_groups"]["MLKEM768"] == "not_negotiated"
    assert set(probes["tls13_groups"]) == set(inventory.tls13_groups())
    assert leaf.algorithm == "RSA" and leaf.signature_algorithm == "ecdsa-with-SHA256"
    assert leaf.evidence["issuer_linkage"] == "verified"
    assert inter.evidence["certificate_role"] == "ca"
    assert endpoint.evidence["leaf_asset_id"] == leaf.asset_id
    dumped = json.dumps(inv.to_dict())
    for secret in ("Master-Key", "Session-ID", "TLS session ticket", "BEGIN"):
        assert secret not in dumped


@requires_openssl
@pytest.mark.integration
def test_tls12_and_localhost_name(pki) -> None:
    with _serve_leaf(pki, "-tls1_2") as port:
        inv = inventory.inspect_endpoint("localhost", port, cafile=str(pki["root"]), probe=False)
    assert inv.errors == [], inv.errors
    endpoint = inv.assets[0]
    assert endpoint.tls_version == "TLSv1.2"
    assert endpoint.cipher_suite and endpoint.cipher_suite.startswith("ECDHE-RSA")
    assert endpoint.evidence["probe_supported"] is None
    assert "Master-Key" not in json.dumps(inv.to_dict())


@requires_openssl
@pytest.mark.integration
@pytest.mark.parametrize(
    ("server_name", "cafile_key", "cert", "reason"),
    [
        ("wrong.lab.test", "root", "leaf", "hostname mismatch"),
        ("localhost", "leaf_key_as_ca", "leaf", "unable to get local issuer certificate"),
        ("localhost", "root", "old", "certificate has expired"),
    ],
)
def test_unauthenticated_endpoints_fail_closed(pki, server_name, cafile_key, cert, reason) -> None:
    other_root = make_cert("Unrelated", ec.generate_private_key(ec.SECP256R1()), ca=True)
    unrelated = pki["root"].parent / "unrelated.pem"
    unrelated.write_bytes(pem(other_root))
    cafile = unrelated if cafile_key == "leaf_key_as_ca" else pki[cafile_key]
    key = pki["old_key"] if cert == "old" else pki["leaf_key"]
    chain = [] if cert == "old" else ["-cert_chain", str(pki["inter"])]
    with tls_server("-cert", str(pki[cert]), "-key", str(key), *chain) as port:
        inv = inventory.inspect_endpoint(
            "127.0.0.1", port, cafile=cafile, server_name=server_name, probe=False
        )
    assert inv.assets == []
    assert [e["code"] for e in inv.errors] == ["tls_verification_failed"]
    assert reason in inv.errors[0]["message"]


@requires_openssl
@pytest.mark.integration
def test_closed_port_and_bad_cafile(pki, tmp_path: Path) -> None:
    inv = inventory.inspect_endpoint("127.0.0.1", _free_port(), cafile=pki["root"], timeout=2)
    assert [e["code"] for e in inv.errors] == ["tls_connection_failed"]
    link = tmp_path / "ca-link.pem"
    link.symlink_to(pki["root"])
    with pytest.raises(ValueError):
        inventory.inspect_endpoint("127.0.0.1", 4433, cafile=link)
    with pytest.raises(ValueError):
        inventory.inspect_endpoint("127.0.0.1", 4433, cafile=pki["leaf_key"])


@requires_openssl
@pytest.mark.integration
@pytest.mark.skipif(not openssl_has("signature", "ML-DSA-65"), reason="ML-DSA unavailable")
def test_pqc_profile_endpoint_with_ml_dsa_certificate(tmp_path: Path) -> None:
    key, crt = tmp_path / "pq.key", tmp_path / "pq.crt"
    ossl("genpkey", "-algorithm", "ML-DSA-65", "-out", str(key))
    ossl(
        "req",
        "-x509",
        "-new",
        "-key",
        str(key),
        "-subj",
        "/CN=localhost",
        "-days",
        "5",
        "-addext",
        "subjectAltName=DNS:localhost",
        "-out",
        str(crt),
    )
    if "X25519MLKEM768" not in inventory.tls13_groups():
        pytest.skip("X25519MLKEM768 TLS group unavailable")
    pq_only = ("-tls1_3", "-groups", "X25519MLKEM768")
    with tls_server("-cert", str(crt), "-key", str(key), *pq_only) as port:
        inv = inventory.inspect_endpoint(
            "127.0.0.1", port, cafile=crt, server_name="localhost", probe=False
        )
    assert inv.errors == [], inv.errors
    endpoint, leaf = inv.assets
    assert endpoint.negotiated_group == "X25519MLKEM768"
    assert endpoint.algorithm_family == "HYBRID-KEM"
    assert endpoint.signature_algorithm == "mldsa65"
    assert leaf.algorithm == "ML-DSA-65" and leaf.evidence["validity"] == "valid"
