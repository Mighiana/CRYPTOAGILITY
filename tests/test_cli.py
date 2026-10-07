"""CLI behaviour: exit codes, evidence files, input validation and no silent downgrade."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cryptoagility import cli, lab, scenario, tls

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def scenario_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return scenario.generate(tmp_path_factory.mktemp("scenario") / "org")


@pytest.fixture(scope="module")
def inventory_json(scenario_dir: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("inv") / "inventory.json"
    assert cli.main(["inventory", str(scenario_dir), "-o", str(out)]) == 0
    return out


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("cryptoagility ")


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == 0
    assert "inventory" in capsys.readouterr().out


def test_inventory_writes_json_and_cbom(
    scenario_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "inventory.json"
    assert (
        cli.main(["inventory", str(scenario_dir), "-o", str(out), "--cbom-dir", str(tmp_path)]) == 0
    )
    data = json.loads(out.read_text())
    assert data["schema_version"] == "1.0" and data["assets"] and not data["errors"]
    assert (tmp_path / "cbom.csv").read_text().startswith("asset_id,")
    assert json.loads((tmp_path / "cbom.json").read_text())["cbom_format"]
    assert "assets, 0 discovery errors" in capsys.readouterr().out
    assert "PRIVATE KEY" not in out.read_text()


def test_policy_gate_and_json(inventory_json: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["policy", str(inventory_json), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["summary"]["total_assets"] > result["summary"]["compliant"]
    assert cli.main(["policy", str(inventory_json), "--fail-on-noncompliant"]) == cli.EXIT_GATE


def test_policy_is_deterministic(inventory_json: Path, tmp_path: Path) -> None:
    outputs = []
    for name in ("a.json", "b.json"):
        assert cli.main(["policy", str(inventory_json), "-o", str(tmp_path / name)]) == 0
        data = json.loads((tmp_path / name).read_text())
        data.pop("evaluated_at", None)
        outputs.append(json.dumps(data["findings"], sort_keys=True))
    assert outputs[0] == outputs[1]


def test_plan_writes_markdown_and_gates_on_blocked(inventory_json: Path, tmp_path: Path) -> None:
    md = tmp_path / "plan.md"
    args = [
        "plan",
        str(inventory_json),
        "--constraints",
        str(ROOT / "scenario/constraints.yaml"),
        "--markdown",
        str(md),
        "-o",
        str(tmp_path / "plan.json"),
    ]
    assert cli.main(args) == 0
    assert json.loads((tmp_path / "plan.json").read_text())["readiness"] == "BLOCKED"
    assert md.read_text().strip()
    assert cli.main([*args, "--fail-on-blocked"]) == cli.EXIT_GATE


@pytest.mark.parametrize(
    "payload, message",
    [
        ("not json", "not valid JSON"),
        ('{"schema_version": "9"}', "not a CryptoAgility inventory"),
        ('{"cbom_format": "cryptoagility-lab-cbom"}', "CBOM export"),
        ("[]", "not a CryptoAgility inventory"),
    ],
)
def test_invalid_inventory_input(
    tmp_path: Path, payload: str, message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "bad.json"
    path.write_text(payload)
    assert cli.main(["policy", str(path)]) == cli.EXIT_INPUT
    assert message in capsys.readouterr().err


def test_bad_policy_and_constraints(inventory_json: Path, tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("policy_id: x\n")
    assert cli.main(["policy", str(inventory_json), "--policy", str(bad)]) == cli.EXIT_INPUT
    bad.write_text("unknown_key: 1\n")
    assert cli.main(["plan", str(inventory_json), "--constraints", str(bad)]) == cli.EXIT_INPUT


def test_refuses_symlink_output(inventory_json: Path, tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("keep")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    assert cli.main(["policy", str(inventory_json), "-o", str(link)]) == cli.EXIT_INPUT
    assert target.read_text() == "keep"


def test_refuses_symlink_input(inventory_json: Path, tmp_path: Path) -> None:
    link = tmp_path / "inv.json"
    link.symlink_to(inventory_json)
    assert cli.main(["policy", str(link)]) == cli.EXIT_INPUT


def test_unsupported_profile_is_exit_3_not_downgrade(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(name: str, caps: object = None) -> tls.TLSProfile:
        raise tls.UnsupportedProfileError(name, ["TLS 1.3 group MLKEM768"])

    monkeypatch.setattr(tls, "capabilities", lambda: {})
    monkeypatch.setattr(tls, "resolve_profile", refuse)
    monkeypatch.setattr(tls, "run_matrix", lambda *a, **k: pytest.fail("must not fall back"))
    assert cli.main(["test", "--profile", "pqc"]) == cli.EXIT_UNSUPPORTED
    assert "MLKEM768" in capsys.readouterr().err


def test_missing_openssl_is_input_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CRYPTOAGILITY_OPENSSL", str(tmp_path / "absent"))
    assert cli.main(["capabilities"]) == cli.EXIT_INPUT


@pytest.mark.integration
def test_strict_profiles_handshake(capsys: pytest.CaptureFixture[str]) -> None:
    for profile in tls.PROFILES:
        assert cli.main(["test", "--profile", profile, "--json"]) == 0
        row = json.loads(capsys.readouterr().out)["rows"][0]
        assert row["status"] == tls.SUCCESS
        assert tls.same_group(row["negotiated_group"], tls.PROFILES[profile].group)


@pytest.mark.integration
def test_mismatched_client_fails_instead_of_downgrading(capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        cli.main(["test", "--profile", "pqc", "--client", "classical-only", "--json"])
        == cli.EXIT_GATE
    )
    row = json.loads(capsys.readouterr().out)["rows"][0]
    assert row["status"] == tls.FAIL_NEGOTIATION and row["negotiated_group"] is None


@pytest.mark.integration
def test_lab_pipeline_produces_loadable_evidence(tmp_path: Path) -> None:
    from cryptoagility import reporting

    summary = lab.run(
        tmp_path / "results",
        policy_path=cli.DEFAULT_POLICY,
        iterations=5,
        warmups=2,
        log=lambda _: None,
    )
    results = tmp_path / "results"
    evidence = reporting.load_evidence(results)
    assert {key: ev.status for key, ev in evidence.items()} == {
        key: reporting.LOADED for key in reporting.EVIDENCE_FILES
    }
    assert summary["readiness"] in {"BLOCKED", "PARTIALLY_READY", "READY", "UNKNOWN"}
    html = (results / "report.html").read_text()
    assert "<script src=" not in html and "PRIVATE KEY" not in html
    for path in results.iterdir():
        assert "PRIVATE KEY" not in path.read_text(errors="replace")
    assert cli.main(["report", str(results)]) == 0
