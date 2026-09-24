import json
from importlib.metadata import version
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

import scopelens.cli as cli
import scopelens.storage.cli as storage_cli
from scopelens.adapters.base import ParsedReport
from scopelens.cli import main
from scopelens.execution.process import ExecutionError


@pytest.mark.parametrize(
    ("issue", "expected_exit"),
    [
        (None, None),
        ("unreferenced", None),
        ("interrupted", None),
        ("missing", 1),
        ("corrupt", 1),
        ("busy", 1),
        ("unexpected", 1),
    ],
)
def test_history_verify_exit_reflects_referenced_evidence_integrity(
    issue: str | None,
    expected_exit: int | None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = Mock()
    issues = [] if issue is None else [{"issue": issue, "path": "evidence"}]

    class FakeHistory:
        def __init__(self, database: object, artifacts: object) -> None:
            pass

        def reconcile(self) -> list[dict[str, str]]:
            return issues

    monkeypatch.setenv("SCOPELENS_DATABASE_URL", "postgresql://local/test")
    monkeypatch.setattr(storage_cli, "database", lambda _: engine)
    monkeypatch.setattr(storage_cli, "ArtifactStore", lambda _: object())
    monkeypatch.setattr(storage_cli, "History", FakeHistory)
    arguments = ["history-verify", "--artifacts", str(tmp_path / "artifacts")]

    if expected_exit is None:
        main(arguments)
    else:
        with pytest.raises(SystemExit) as exc:
            main(arguments)
        assert exc.value.code == expected_exit

    output = capsys.readouterr()
    assert json.loads(output.out) == issues
    if expected_exit is None:
        assert output.err == ""
    else:
        assert output.err == "referenced evidence failed integrity verification\n"
    engine.dispose.assert_called_once_with()


def test_history_verify_failure_is_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = Mock()

    class UnreadableHistory:
        def __init__(self, database: object, artifacts: object) -> None:
            pass

        def reconcile(self) -> list[dict[str, str]]:
            raise OSError("private path")

    monkeypatch.setenv("SCOPELENS_DATABASE_URL", "postgresql://local/test")
    monkeypatch.setattr(storage_cli, "database", lambda _: engine)
    monkeypatch.setattr(storage_cli, "ArtifactStore", lambda _: object())
    monkeypatch.setattr(storage_cli, "History", UnreadableHistory)

    with pytest.raises(SystemExit) as exc:
        main(["history-verify", "--artifacts", str(tmp_path / "artifacts")])

    assert exc.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "artifact operation failed" in output.err
    assert "private path" not in output.err
    engine.dispose.assert_called_once_with()


def test_no_arguments_shows_help(capsys: pytest.CaptureFixture[str]) -> None:
    main([])

    output = capsys.readouterr()
    assert "usage: scopelens" in output.out
    assert "--version" in output.out
    assert output.err == ""


def test_scan_requires_config_and_profile(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan-nmap"])
    assert exc.value.code == 2
    assert "required" in capsys.readouterr().err


def test_scan_failure_does_not_print_partial_json(
    config_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = AsyncMock(
        side_effect=ExecutionError("scanner timed out", Path("private/run"))
    )
    monkeypatch.setattr(cli, "scan_nmap", scanner)
    with pytest.raises(SystemExit) as exc:
        main(["scan-nmap", str(config_path), "--profile", "conservative"])
    assert exc.value.code == 2
    output = capsys.readouterr()
    assert not output.out
    assert "timed out" in output.err
    assert "private artifacts" in output.err
    assert "Traceback" not in output.err


def test_help_exits_successfully(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])

    assert exc.value.code == 0
    output = capsys.readouterr()
    assert "usage: scopelens" in output.out
    assert output.err == ""


def test_version_matches_installed_package(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])

    assert exc.value.code == 0
    output = capsys.readouterr()
    assert output.out.strip() == f"scopelens {version('scopelens')}"
    assert output.err == ""


@pytest.mark.parametrize("argument", ["--unknown", "--ver"])
def test_unsupported_arguments_fail(
    argument: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main([argument])

    assert exc.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "unrecognized arguments" in output.err


def test_scanner_command_is_not_available(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_validate_config_command(
    config_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["validate-config", str(config_path)])
    output = capsys.readouterr()
    assert output.out == "Configuration valid for project 'local-lab'.\n"
    assert output.err == ""


def test_validate_config_rejects_missing_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["validate-config", str(tmp_path / "missing.toml")])
    assert exc.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "cannot read the configuration file" in output.err
    assert "Traceback" not in output.err


def test_validate_config_requires_path(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["validate-config"])
    assert exc.value.code == 2
    assert "required" in capsys.readouterr().err


def test_import_nmap_outputs_normalized_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = Path(__file__).parent / "fixtures/nmap/services.xml"
    main(
        ["import-nmap", str(path), "--profile-id", "fixture", "--profile-revision", "1"]
    )
    output = capsys.readouterr()
    report = ParsedReport.model_validate_json(output.out)
    assert report.evidence.profile_id == "fixture"
    assert report.observations
    assert output.err == ""


@pytest.mark.parametrize(
    "arguments", [[], ["report.xml"], ["report.xml", "--profile-id", "fixture"]]
)
def test_import_nmap_requires_path_and_provenance(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["import-nmap", *arguments])
    assert exc.value.code == 2
    output = capsys.readouterr()
    assert not output.out
    assert "required" in output.err


@pytest.mark.parametrize("kind", ["malformed", "missing", "invalid-profile"])
def test_import_nmap_errors_do_not_emit_partial_json(
    kind: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "report.xml"
    if kind != "missing":
        path.write_text("<nmaprun secret='DO-NOT-ECHO'", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "import-nmap",
                str(path),
                "--profile-id",
                "DO-NOT-ECHO" if kind == "invalid-profile" else "fixture",
                "--profile-revision",
                "1",
            ]
        )
    assert exc.value.code == 2
    output = capsys.readouterr()
    assert not output.out
    assert "DO-NOT-ECHO" not in output.err
    assert "Traceback" not in output.err
