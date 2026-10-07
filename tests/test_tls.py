"""Tests for cryptoagility.tls.

Unit tests exercise parsers, sanitizers and fail-closed validation with hostile input.
Integration tests (marked) run real loopback TLS 1.3 experiments on the pinned OpenSSL
3.5.9 build: they are skipped only when that build is absent, never faked.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from cryptoagility import openssl, tls


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


def _caps_without(caps: dict[str, Any], *groups: str) -> dict[str, Any]:
    reduced = json.loads(json.dumps(caps))
    drop = {g.casefold() for g in groups}
    reduced["tls13_groups"] = [g for g in reduced["tls13_groups"] if g.casefold() not in drop]
    return reduced


SYNTHETIC_CAPS: dict[str, Any] = {
    "tls13_groups": ["x25519", "X25519MLKEM768", "MLKEM768"],
    "tls_signature_algorithms": ["rsa_pss_rsae_sha256", "mldsa65"],
    "x509": {"RSA-3072": {"supported": True}, "ML-DSA-65": {"supported": True}},
    "openssl": {"version": "synthetic"},
}


# --------------------------------------------------------------------------- unit


@pytest.mark.parametrize("name", ["localhost", "localhost.test", "a-b.lab.test"])
def test_validate_hostname_accepts_synthetic_names(name: str) -> None:
    assert tls.validate_hostname(name) == name


@pytest.mark.parametrize(
    "name",
    ["example.com", "localhost.test.", "a..test", "-bad.test", "x;id.test", "LOCALHOST",
     "localhost\n", "a b.test", "test", "../../etc.test", "x" * 64 + ".test", ""],
)
def test_validate_hostname_rejects_real_or_hostile_names(name: str) -> None:
    with pytest.raises(ValueError):
        tls.validate_hostname(name)


def test_extract_reasons_strips_paths_and_control_characters() -> None:
    text = (
        "40B7:error:0A000086:SSL routines:tls_post_process_server_certificate:"
        "certificate verify failed:../ssl/statem/statem_clnt.c:2102:\n"
        "verify error:num=62:hostname mismatch\x1b[31m'\"$(id)\n"
        "random noise /home/ubuntu/secret.key\n"
    )
    reasons = tls.extract_reasons(text)
    assert reasons[0] == "certificate verify failed"
    assert reasons[1].startswith("verify error 62: hostname mismatch")
    joined = " ".join(reasons)
    for bad in ("/", "statem_clnt", "\x1b", "'", '"', "$", "secret.key"):
        assert bad not in joined
    assert len(tls.extract_reasons("error:0A000000:a:b:x\n" * 5000)) == 1


def test_classify_failure_distinguishes_kinds() -> None:
    assert tls.classify_failure(["server: no suitable key share"]) == "group_disjoint"
    assert tls.classify_failure(["no suitable signature algorithm"]) == "signature_disjoint"
    assert tls.classify_failure(["verify error 10: certificate has expired"]) == (
        "certificate_expired")
    assert tls.classify_failure(["verify error 62: hostname mismatch"]) == "hostname_mismatch"
    assert tls.classify_failure(["unable to get local issuer certificate"]) == (
        "untrusted_issuer")
    assert tls.classify_failure(["something new"]) == "unknown"


def test_parse_client_output_ignores_secrets_and_injected_values() -> None:
    stdout = (
        b"Negotiated TLS1.3 group: X25519;rm\n"
        b"Peer signature type: mldsa65 extra\n"
        b"New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
        b"    Master-Key: DEADBEEF\n"
        b"    Resumption PSK: CAFEBABE\n"
        b"Verify return code: 0 (ok)\n"
    )
    parsed = tls.parse_client_output(stdout)
    assert parsed["negotiated_group"] is None
    assert parsed["peer_signature_type"] is None
    assert parsed["tls_version"] == "TLSv1.3"
    assert parsed["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    assert parsed["verify_code"] == 0
    assert "DEADBEEF" not in json.dumps({k: v for k, v in parsed.items() if k != "certificates"})
    assert parsed["certificates"] == []


def test_group_kind_and_case_insensitive_groups() -> None:
    assert tls.group_kind("x25519") == "classical"
    assert tls.group_kind("X25519MLKEM768") == "hybrid"
    assert tls.group_kind("SecP384r1MLKEM1024") == "hybrid"
    assert tls.group_kind("MLKEM768") == "pqc"
    assert tls.group_in("X25519", ["x25519"])
    assert not tls.same_group("X25519", None)


def test_resolve_profile_refuses_unavailable_hybrid_without_downgrade() -> None:
    caps = _caps_without(SYNTHETIC_CAPS, "X25519MLKEM768")
    with pytest.raises(tls.UnsupportedProfileError) as info:
        tls.resolve_profile("hybrid", caps)
    assert info.value.status == tls.UNSUPPORTED
    assert "TLS 1.3 group X25519MLKEM768" in info.value.missing
    assert str(info.value).startswith("UNSUPPORTED CRYPTO PROFILE: hybrid")
    assert tls.resolve_profile("classical", caps).group == "X25519"
    with pytest.raises(ValueError):
        tls.resolve_profile("hybrid; rm -rf", caps)


def test_pqc_profile_requires_real_mldsa_certificate_support() -> None:
    caps = json.loads(json.dumps(SYNTHETIC_CAPS))
    caps["x509"]["ML-DSA-65"] = {"supported": False}
    with pytest.raises(tls.UnsupportedProfileError) as info:
        tls.resolve_profile("pqc", caps)
    assert "X.509 certificate with ML-DSA-65" in info.value.missing


def test_unsupported_detected_before_any_network_or_key_generation(tmp_path: Path) -> None:
    caps = _caps_without(SYNTHETIC_CAPS, "X25519MLKEM768")
    result = tls.run_matrix(tmp_path, servers=["hybrid"], clients=["hybrid-only"],
                            include_negative=False, caps=caps)
    (row,) = result["rows"]
    assert row["status"] == tls.UNSUPPORTED
    assert row["failure_kind"] == "server_unsupported_locally"
    assert row["network_attempted"] is False
    assert row["policy_pass"] is None
    assert "X25519MLKEM768" in row["error_reason"]
    assert not (tmp_path / "tls-lab").exists()


def test_client_side_unsupported_is_distinct_from_disjoint(tmp_path: Path) -> None:
    caps = _caps_without(SYNTHETIC_CAPS, "MLKEM768")
    caps["tls13_groups"].append("X25519MLKEM768")
    result = tls.run_matrix(tmp_path, servers=["hybrid"], clients=["pqc-only"],
                            include_negative=False, caps=caps)
    (row,) = result["rows"]
    assert row["status"] == tls.UNSUPPORTED
    assert row["failure_kind"] == "client_unsupported_locally"
    assert row["network_attempted"] is False


def test_run_matrix_rejects_unknown_names_and_bad_policy(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        tls.run_matrix(tmp_path, servers=["../evil"], caps=SYNTHETIC_CAPS)
    with pytest.raises(ValueError):
        tls.run_matrix(tmp_path, clients=["curl"], caps=SYNTHETIC_CAPS)
    with pytest.raises(ValueError):
        tls.run_matrix(tmp_path, policy={"exec": "x"}, caps=SYNTHETIC_CAPS)
    with pytest.raises(ValueError):
        tls.run_matrix(tmp_path, policy={"allowed_groups": "X25519"}, caps=SYNTHETIC_CAPS)
    with pytest.raises(ValueError):
        tls.run_matrix(tmp_path, hostname="example.com", caps=SYNTHETIC_CAPS)


def test_evaluate_policy_is_independent_of_success() -> None:
    policy = tls.DEFAULT_POLICY
    ok, reasons = tls.evaluate_policy(
        {"negotiated_group": "X25519", "tls_version": "TLSv1.3"}, policy)
    assert ok is False and "policy requires hybrid" in reasons[0]
    ok, reasons = tls.evaluate_policy(
        {"negotiated_group": "X25519MLKEM768", "tls_version": "TLSv1.3"}, policy)
    assert ok is True and reasons == []
    assert tls.evaluate_policy({"negotiated_group": None}, policy)[0] is None
    strict = {"allowed_groups": ["MLKEM768"], "allowed_certificate_types": ["ML-DSA-65"]}
    ok, reasons = tls.evaluate_policy(
        {"negotiated_group": "mlkem768", "certificate_type": "RSA-3072"}, strict)
    assert ok is False and reasons == ["certificate type RSA-3072 not allowed"]


def test_handshake_rejects_hostile_parameters_before_spawning(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.pem"
    client = tls.CLIENT_VARIANTS["classical-only"]
    for port in (0, 70000, True):
        with pytest.raises(ValueError):
            tls.handshake(port, client, bundle)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        tls.handshake(4433, client, bundle, hostname="evil.example")
    evil = tls.ClientVariant("evil", ("X25519 -connect 10.0.0.1:443",), None, None)
    with pytest.raises(ValueError):
        tls.handshake(4433, evil, bundle)


def test_lab_pki_rejects_symlinked_runtime_directory(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir()
    (tmp_path / "work").mkdir()
    (tmp_path / "work" / "tls-lab").symlink_to(target)
    with pytest.raises(ValueError):
        tls.LabPKI(tmp_path / "work")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ValueError):
        tls.LabPKI(link)


def test_find_legacy_openssl_never_returns_pinned_build(tmp_path: Path) -> None:
    assert tls.find_legacy_openssl(str(tmp_path / "missing")) is None
    if PINNED is not None:
        assert tls.find_legacy_openssl(openssl.executable()) is None


# --------------------------------------------------------------------------- integration


@pytest.fixture(scope="module")
def caps() -> dict[str, Any]:
    return tls.capabilities()


@pytest.fixture(scope="module")
def matrix(caps: dict[str, Any], tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    workdir = tmp_path_factory.mktemp("matrix")
    result = tls.run_matrix(workdir, caps=caps)
    result["_workdir"] = str(workdir)
    return result


def _row(matrix: dict[str, Any], server: str, client: str) -> dict[str, Any]:
    (row,) = [r for r in matrix["rows"] if r["server"] == server and r["client"] == client]
    return row


@pytest.mark.integration
@needs_native
def test_capabilities_report_native_build(caps: dict[str, Any]) -> None:
    assert caps["openssl"]["version_number"].startswith("3.5.")
    assert caps["oqs_provider_loaded"] is False and caps["oqs_required"] is False
    assert any(p.get("id") == "default" for p in caps["providers"])
    assert {"X25519MLKEM768", "MLKEM768"} <= set(caps["tls13_groups"])
    assert "X25519MLKEM768" in caps["tls_group_classes"]["hybrid"]
    assert "MLKEM768" in caps["tls_group_classes"]["pqc"]
    assert {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"} <= set(caps["standardized"]["ml_kem"])
    assert {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} <= set(caps["standardized"]["ml_dsa"])
    assert len(caps["standardized"]["slh_dsa"]) == 12
    assert caps["x509"]["ML-DSA-65"] == {
        "supported": True, "certificate_type": "ML-DSA-65", "signature_algorithm": "ML-DSA-65"}
    assert all(p["supported"] for p in caps["profiles"].values())
    assert "laboratory experiments" in caps["notes"]


@pytest.mark.integration
@pytest.mark.skipif(not Path("/usr/bin/openssl").is_file(), reason="no distribution OpenSSL")
def test_hybrid_unavailable_on_real_legacy_build(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRYPTOAGILITY_OPENSSL", "/usr/bin/openssl")
    legacy_caps = tls.capabilities()
    if "X25519MLKEM768" in legacy_caps["tls13_groups"]:
        pytest.skip("distribution OpenSSL already supports hybrid groups")
    assert legacy_caps["openssl"]["version_number"] != "3.5.9"
    with pytest.raises(tls.UnsupportedProfileError) as info:
        tls.resolve_profile("hybrid", legacy_caps)
    assert "TLS 1.3 group X25519MLKEM768" in info.value.missing
    assert legacy_caps["profiles"]["pqc"]["supported"] is False


@pytest.mark.integration
@needs_native
def test_classical_success_fails_hybrid_policy(matrix: dict[str, Any]) -> None:
    row = _row(matrix, "classical", "classical-only")
    assert row["status"] == tls.SUCCESS
    assert (row["negotiated_group"], row["tls_version"]) == ("X25519", "TLSv1.3")
    assert row["certificate_type"] == "RSA-3072"
    assert row["peer_signature_type"].startswith("rsa_pss_rsae_")
    assert row["policy_pass"] is False
    assert "policy requires hybrid" in row["policy_reasons"][0]


@pytest.mark.integration
@needs_native
def test_hybrid_success_with_explicit_classical_authentication(matrix: dict[str, Any]) -> None:
    row = _row(matrix, "hybrid", "hybrid-only")
    assert row["status"] == tls.SUCCESS
    assert row["negotiated_group"] == "X25519MLKEM768"
    assert row["negotiated_group_kind"] == "hybrid"
    assert row["certificate_type"] == "RSA-3072"
    assert row["peer_signature_type"].startswith("rsa_pss_rsae_")
    assert row["policy_pass"] is True
    assert row["chain_length"] == 2
    assert row["chain_der_bytes"] > row["certificate_der_bytes"] > 0


@pytest.mark.integration
@needs_native
def test_pqc_experiment_uses_mldsa65_certificate(matrix: dict[str, Any]) -> None:
    row = _row(matrix, "pqc", "pqc-only")
    assert row["status"] == tls.SUCCESS
    assert row["negotiated_group"] == "MLKEM768"
    assert row["certificate_type"] == "ML-DSA-65"
    assert row["certificate_signature_algorithm"] == "ML-DSA-65"
    assert row["peer_signature_type"] == "mldsa65"
    rsa = _row(matrix, "hybrid", "hybrid-only")
    assert row["certificate_der_bytes"] > rsa["certificate_der_bytes"]
    assert row["policy_pass"] is False


@pytest.mark.integration
@needs_native
@pytest.mark.parametrize(
    ("server", "client"),
    [("classical", "hybrid-only"), ("hybrid", "classical-only"), ("pqc", "hybrid-only"),
     ("hybrid", "pqc-only"), ("classical", "pqc-only")],
)
def test_algorithm_disjoint_fails_negotiation(matrix: dict[str, Any], server: str,
                                               client: str) -> None:
    row = _row(matrix, server, client)
    assert row["status"] == tls.FAIL_NEGOTIATION
    assert row["failure_kind"] == "group_disjoint"
    assert row["network_attempted"] is True
    assert "no suitable key share" in row["error_reason"]
    assert row["negotiated_group"] is None and row["policy_pass"] is None


@pytest.mark.integration
@needs_native
@pytest.mark.parametrize(("server", "group"), [("classical", "X25519"),
                                               ("hybrid", "X25519MLKEM768"),
                                               ("pqc", "MLKEM768")])
def test_modern_agile_client_gets_exactly_the_server_group(matrix: dict[str, Any], server: str,
                                                            group: str) -> None:
    row = _row(matrix, server, "modern-agile")
    assert row["status"] == tls.SUCCESS
    assert row["negotiated_group"] == group
    assert row["policy_pass"] is (group == "X25519MLKEM768")


@pytest.mark.integration
@needs_native
@pytest.mark.parametrize(
    ("server", "kind", "text"),
    [("classical-expired-cert", "certificate_expired", "certificate has expired"),
     ("classical-wrong-host-cert", "hostname_mismatch", "hostname mismatch"),
     ("classical-untrusted-ca", "untrusted_issuer", "unable to get local issuer")],
)
def test_certificate_failures(matrix: dict[str, Any], server: str, kind: str,
                              text: str) -> None:
    row = _row(matrix, server, "classical-only")
    assert row["status"] == tls.FAIL_CERTIFICATE
    assert row["failure_kind"] == kind
    assert text in row["error_reason"]
    assert row["negotiated_group"] is None and row["policy_pass"] is None


@pytest.mark.integration
@needs_native
def test_certificate_algorithm_mismatch(matrix: dict[str, Any]) -> None:
    strict = _row(matrix, "pqc-group-rsa-cert", "pqc-only")
    assert strict["status"] == tls.FAIL_NEGOTIATION
    assert strict["failure_kind"] == "signature_disjoint"
    agile = _row(matrix, "pqc-group-rsa-cert", "modern-agile")
    assert agile["status"] == tls.FAIL_PROFILE_MISMATCH
    assert agile["negotiated_group"] == "MLKEM768"
    assert "certificate type RSA-3072 differs from profile ML-DSA-65" in agile["error_reason"]


@pytest.mark.integration
@needs_native
def test_system_legacy_client(matrix: dict[str, Any]) -> None:
    row = _row(matrix, "classical", "system-legacy")
    if row["status"] == tls.UNSUPPORTED:
        pytest.skip("no distribution OpenSSL client on this host")
    assert matrix["environment"]["legacy_client"] == row["client_binary_version"]
    assert row["status"] == tls.SUCCESS and row["negotiated_group"] == "X25519"
    hybrid = _row(matrix, "hybrid", "system-legacy")
    if "OpenSSL 3.0" in (row["client_binary_version"] or ""):
        assert hybrid["status"] == tls.FAIL_NEGOTIATION
        assert _row(matrix, "pqc", "system-legacy")["status"] == tls.FAIL_NEGOTIATION


@pytest.mark.integration
@needs_native
def test_matrix_schema_evidence_and_cleanup(matrix: dict[str, Any]) -> None:
    workdir = Path(matrix.pop("_workdir"))
    assert matrix["schema_version"]
    env = matrix["environment"]
    assert env["bind_address"] == "127.0.0.1" and env["synthetic_identities"] is True
    assert "complete s_client process" in env["latency_semantics"]
    required = {"client", "server", "status", "negotiated_group", "tls_version", "cipher_suite",
                "certificate_type", "policy_pass", "error_reason"}
    for row in matrix["rows"]:
        assert required <= set(row)
        assert row["status"] in tls.STATUSES
        assert row["status"] != tls.ERROR, row
        if row["status"] == tls.SUCCESS:
            assert row["tls_version"] == "TLSv1.3"
            assert row["cipher_suite"].startswith("TLS_")
            assert row["client_process_ms"] > 0
    dumped = json.dumps(matrix)
    for secret in ("PRIVATE KEY", "BEGIN", "Master-Key", "PSK", str(workdir), ".pem"):
        assert secret not in dumped
    lab = workdir / "tls-lab"
    assert stat.S_IMODE(lab.stat().st_mode) == 0o700
    assert sorted(p.name for p in lab.iterdir()) == [".gitignore"]
    assert stat.S_IMODE((lab / ".gitignore").stat().st_mode) == 0o600


@pytest.mark.integration
@needs_native
def test_lab_pki_modes_chain_and_key_removal(tmp_path: Path) -> None:
    with tls.LabPKI(tmp_path, keep_certificates=True) as pki:
        cred = pki.issue("ML-DSA-65")
        assert pki.issue("ML-DSA-65") is cred
        for path in (*pki.keys_dir.iterdir(), *pki.certs_dir.iterdir()):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        for directory in (pki.run_dir, pki.keys_dir, pki.certs_dir):
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert cred.chain is not None and cred.served_chain_length == 2
        assert cred.served_chain_der_bytes == cred.certificate_der_bytes + tls.pem_der_length(
            cred.chain.read_bytes())
        assert b"PRIVATE KEY" in cred.key.read_bytes()
        info = tls.certificate_info(cred.certificate.read_bytes())
        assert info["certificate_type"] == "ML-DSA-65"
        with pytest.raises(ValueError):
            pki.issue("RSA-1024")
        keys_dir = pki.keys_dir
    assert not keys_dir.exists()
    assert cred.certificate.exists()
    leftovers = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert all(b"PRIVATE KEY" not in p.read_bytes() for p in leftovers)


@pytest.mark.integration
@needs_native
def test_server_loopback_binding_and_cleanup_on_error(tmp_path: Path) -> None:
    with tls.LabPKI(tmp_path) as pki:
        cred = pki.issue("RSA-3072")
        server = tls.LoopbackServer(cred, "X25519MLKEM768")
        with pytest.raises(RuntimeError, match="boom"), server:
            port = server.port
            assert port is not None
            if shutil.which("ss"):
                listing = subprocess.run(["ss", "-Hltn", f"sport = :{port}"],
                                         capture_output=True, text=True, check=False).stdout
                assert listing.split()[3] == f"127.0.0.1:{port}"
            result = tls.handshake(port, tls.CLIENT_VARIANTS["hybrid-only"],
                                   pki.trust_bundle, server=server)
            assert result.completed and result.negotiated_group == "X25519MLKEM768"
            wrong = tls.handshake(port, tls.CLIENT_VARIANTS["hybrid-only"],
                                  pki.trust_bundle, hostname="other.test", server=server)
            assert not wrong.completed and wrong.failure_kind == "hostname_mismatch"
            raise RuntimeError("boom")
        assert server.process is not None and server.process.poll() is not None
        assert port is not None
        with pytest.raises(OSError), socket.create_connection(
                ("127.0.0.1", port), timeout=1):
            pass


@pytest.mark.integration
@needs_native
def test_server_start_failure_is_sanitized_and_reaped(tmp_path: Path) -> None:
    with tls.LabPKI(tmp_path) as pki:
        cred = pki.issue("RSA-3072")
        server = tls.LoopbackServer(cred, "NOTAREALGROUP", timeout=5)
        with pytest.raises(tls.TLSLabError) as info, server:
            pass
        assert server.process is not None and server.process.poll() is not None
        assert str(pki.run_dir) not in str(info.value)
        assert "/" not in str(info.value)


@pytest.mark.integration
@needs_native
def test_handshake_against_closed_port_is_a_safe_failure(tmp_path: Path) -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with tls.LabPKI(tmp_path) as pki:
        result = tls.handshake(port, tls.CLIENT_VARIANTS["classical-only"], pki.trust_bundle)
    assert not result.completed
    assert result.error_reasons and all("/" not in r for r in result.error_reasons)
    assert os.path.basename(str(tmp_path)) not in json.dumps(result.to_dict())
