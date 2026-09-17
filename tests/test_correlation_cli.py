from unittest.mock import Mock
from uuid import UUID

import pytest
from sqlalchemy.exc import SQLAlchemyError

from scopelens.analysis.correlation import CorrelationError, correlate
from scopelens.assessment.capture import assess_correlation
from scopelens.cli import main
from scopelens.storage import cli
from tests.test_correlation import match, source


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["--project", "lab"],
        ["--run-id", str(UUID(int=1))],
        ["--project", "lab", "--run-id", "not-a-uuid"],
        ["--project", "lab", "--run-id", str(UUID(int=1)), "--scanner", "nmap"],
    ],
)
def test_explicit_project_and_runs_required(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["history-correlate", *arguments])
    output = capsys.readouterr()
    assert exc.value.code == 2 and output.out == ""


def test_portable_cli_skips_artifacts_and_disposes_database(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = correlate("lab", (source(matches=(match(),)),))
    engine = Mock()
    projection = Mock(return_value=result)
    artifacts = Mock(side_effect=AssertionError("artifact access"))
    monkeypatch.setenv("SCOPELENS_DATABASE_URL", "test-only")
    monkeypatch.setattr(cli, "database", Mock(return_value=engine))
    monkeypatch.setattr(cli, "correlate_history", projection)
    monkeypatch.setattr(cli, "ArtifactStore", artifacts)
    main(["history-correlate", "--project", "lab", "--run-id", str(UUID(int=1))])
    assert capsys.readouterr().out == result.model_dump_json(indent=2) + "\n"
    projection.assert_called_once_with(engine, "lab", [UUID(int=1)])
    engine.dispose.assert_called_once()
    artifacts.assert_not_called()


def test_history_assess_is_read_only_and_uses_selected_projection(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    projection = correlate(
        "lab", (source(matches=(match(template="scopelens-directory-listing"),)),)
    )
    expected = assess_correlation(projection)
    engine = Mock()
    correlate_call = Mock(return_value=projection)
    artifacts = Mock(side_effect=AssertionError("artifact access"))
    monkeypatch.setenv("SCOPELENS_DATABASE_URL", "test-only")
    monkeypatch.setattr(cli, "database", Mock(return_value=engine))
    monkeypatch.setattr(cli, "correlate_history", correlate_call)
    monkeypatch.setattr(cli, "ArtifactStore", artifacts)
    main(["history-assess", "--project", "lab", "--run-id", str(UUID(int=1))])
    assert capsys.readouterr().out == expected.model_dump_json(indent=2) + "\n"
    correlate_call.assert_called_once_with(engine, "lab", [UUID(int=1)])
    engine.dispose.assert_called_once()
    artifacts.assert_not_called()


def test_cli_projection_error_has_no_partial_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    engine = Mock()
    monkeypatch.setenv("SCOPELENS_DATABASE_URL", "test-only")
    monkeypatch.setattr(cli, "database", Mock(return_value=engine))
    monkeypatch.setattr(
        cli,
        "correlate_history",
        Mock(side_effect=CorrelationError("select each run only once")),
    )
    with pytest.raises(SystemExit) as exc:
        main(["history-correlate", "--project", "lab", "--run-id", str(UUID(int=1))])
    output = capsys.readouterr()
    assert exc.value.code == 2 and output.out == ""
    assert "select each run only once" in output.err
    engine.dispose.assert_called_once()


@pytest.mark.parametrize(
    "failure", [KeyboardInterrupt(), OSError("output"), SQLAlchemyError("read")]
)
def test_read_only_errors_do_not_request_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: BaseException,
) -> None:
    engine = Mock()
    monkeypatch.setenv("SCOPELENS_DATABASE_URL", "test-only")
    monkeypatch.setattr(cli, "database", Mock(return_value=engine))
    monkeypatch.setattr(cli, "correlate_history", Mock(side_effect=failure))
    with pytest.raises(SystemExit) as exc:
        main(["history-correlate", "--project", "lab", "--run-id", str(UUID(int=1))])
    output = capsys.readouterr()
    assert exc.value.code == (130 if isinstance(failure, KeyboardInterrupt) else 2)
    assert output.out == ""
    assert "reconcile" not in output.err.splitlines()[-1]
    assert "history" in output.err
    engine.dispose.assert_called_once()
