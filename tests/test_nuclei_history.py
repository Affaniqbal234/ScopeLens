import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from scopelens.adapters.base import ParsedReport, ReportParseError
from scopelens.adapters.nuclei_templates import NUCLEI_VERSION, template_revision
from scopelens.cli import main
from scopelens.storage import schema as s
from scopelens.storage.artifacts import ArtifactStore
from scopelens.storage.database import HistoryError
from scopelens.storage.history import History
from scopelens.storage.operations import import_history
from tests.postgres import DisposablePostgres
from tests.test_history import counts
from tests.test_history import engine as engine
from tests.test_history import history as history
from tests.test_history import postgres as postgres
from tests.test_httpx import web_config
from tests.test_nuclei import CONTEXT, RAW, TARGET

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("SCOPELENS_POSTGRES_TEST") != "1",
    reason="requires disposable PostgreSQL on Linux",
)


def test_matches_persist_idempotently_with_evidence(
    history: History, tmp_path: Path
) -> None:
    path = tmp_path / "report.jsonl"
    path.write_bytes(RAW)
    run_id = uuid4()
    report = import_history(
        history,
        web_config(TARGET),
        "web",
        run_id,
        path,
        scanner="nuclei",
        web_target=TARGET,
        scanner_version=NUCLEI_VERSION,
        template_bundle=template_revision(),
        captured_at=CONTEXT.captured_at,
    )
    before = counts(history.engine)
    assert (
        import_history(
            history,
            web_config(TARGET),
            "web",
            run_id,
            path,
            scanner="nuclei",
            web_target=TARGET,
            scanner_version=NUCLEI_VERSION,
            template_bundle=template_revision(),
            captured_at=CONTEXT.captured_at,
        )
        == report
    )
    assert counts(history.engine) == before
    assert (
        History(history.engine, ArtifactStore(history.artifacts.root)).report(run_id)
        == report
    )
    assert len(report.matches) == 2
    with history.engine.connect() as connection:
        assert (
            connection.scalar(
                select(func.count())
                .select_from(s.evidence)
                .where(s.evidence.c.stage_id == run_id)
            )
            == 3
        )
        context = connection.scalar(
            select(s.stages.c.input_context).where(s.stages.c.id == run_id)
        )
        assert (
            context is not None and context["template_revision"] == template_revision()
        )
    (history.artifacts.root / str(run_id) / "stdout.jsonl").write_bytes(b"corrupt")
    assert {
        "run_id": str(run_id),
        "issue": "corrupt",
        "path": f"{run_id}/stdout.jsonl",
    } in history.reconcile()
    assert history.report(run_id) == report


@pytest.mark.parametrize("reconcile", [False, True])
def test_match_transaction_failure_and_recovery(
    history: History, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reconcile: bool
) -> None:
    path = tmp_path / "report.jsonl"
    path.write_bytes(RAW)
    run_id = uuid4()

    def fail(*_: object) -> None:
        raise RuntimeError("database write failed")

    with monkeypatch.context() as patch:
        patch.setattr(history, "_finish", fail)
        with pytest.raises(RuntimeError, match="database write failed"):
            import_history(
                history,
                web_config(TARGET),
                "web",
                run_id,
                path,
                scanner="nuclei",
                web_target=TARGET,
                scanner_version=NUCLEI_VERSION,
                template_bundle=template_revision(),
                captured_at=CONTEXT.captured_at,
            )
    assert history.artifacts.read(f"{run_id}/stdout.jsonl") == RAW
    with history.engine.connect() as connection:
        for table in (s.scanner_matches, s.evidence, s.artifacts):
            assert (
                connection.scalar(
                    select(func.count())
                    .select_from(table)
                    .where(table.c.stage_id == run_id)
                )
                == 0
            )
    if reconcile:
        assert {"run_id": str(run_id), "issue": "interrupted"} in history.reconcile()
        with pytest.raises(HistoryError, match="terminal"):
            import_history(
                history,
                web_config(TARGET),
                "web",
                run_id,
                path,
                scanner="nuclei",
                web_target=TARGET,
                scanner_version=NUCLEI_VERSION,
                template_bundle=template_revision(),
                captured_at=CONTEXT.captured_at,
            )
    else:
        report = import_history(
            history,
            web_config(TARGET),
            "web",
            run_id,
            path,
            scanner="nuclei",
            web_target=TARGET,
            scanner_version=NUCLEI_VERSION,
            template_bundle=template_revision(),
            captured_at=CONTEXT.captured_at,
        )
        assert history.report(run_id) == report


@pytest.mark.parametrize(
    "raw",
    [RAW + RAW, RAW + b"{", RAW.replace(b"127.0.0.1", b"192.0.2.1")],
    ids=["duplicate", "partial", "scope"],
)
def test_invalid_matches_never_publish(
    history: History, tmp_path: Path, raw: bytes
) -> None:
    path = tmp_path / "report.jsonl"
    path.write_bytes(raw)
    run_id = uuid4()
    with pytest.raises(ReportParseError):
        import_history(
            history,
            web_config(TARGET),
            "web",
            run_id,
            path,
            scanner="nuclei",
            web_target=TARGET,
            scanner_version=NUCLEI_VERSION,
            template_bundle=template_revision(),
            captured_at=CONTEXT.captured_at,
        )
    assert not (history.artifacts.root / str(run_id)).exists()
    with history.engine.connect() as connection:
        assert (
            connection.scalar(select(s.runs.c.status).where(s.runs.c.id == run_id))
            == "failed"
        )


@pytest.mark.parametrize("cancelled", [False, True])
def test_execution_failure_releases_idle_lock(
    history: History, monkeypatch: pytest.MonkeyPatch, cancelled: bool
) -> None:
    from scopelens.execution.process import ExecutionError
    from scopelens.storage import operations

    async def fail(*args: object, **kwargs: object) -> None:
        with history.engine.connect() as connection:
            assert connection.scalars(
                text(
                    "SELECT state FROM pg_stat_activity WHERE pid IN (SELECT pid FROM pg_locks WHERE locktype='advisory') AND pid <> pg_backend_pid() AND datname=current_database()"
                )
            ).all() == ["idle"]
        if cancelled:
            raise KeyboardInterrupt()
        raise ExecutionError("Nuclei failed")

    monkeypatch.setattr(operations, "scan_nuclei", fail)
    run_id = uuid4()
    with pytest.raises(KeyboardInterrupt if cancelled else ExecutionError):
        operations.scan_history(
            history,
            web_config(TARGET),
            "web",
            run_id,
            scanner="nuclei",
            web_target=TARGET,
        )
    with history.engine.connect() as connection:
        assert connection.scalar(
            select(s.runs.c.status).where(s.runs.c.id == run_id)
        ) == ("interrupted" if cancelled else "failed")


def test_no_match_import_persists_without_claiming_negative_result(
    history: History, tmp_path: Path
) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_bytes(b"")
    run_id = uuid4()
    report = import_history(
        history,
        web_config(TARGET),
        "web",
        run_id,
        path,
        scanner="nuclei",
        web_target=TARGET,
        scanner_version=NUCLEI_VERSION,
        template_bundle=template_revision(),
        captured_at=CONTEXT.captured_at,
    )
    assert history.report(run_id) == report
    assert report.matches == () and report.reported_exit is None


@pytest.mark.skipif(
    not os.environ.get("SCOPELENS_NUCLEI_BINARY"),
    reason="requires explicit Nuclei binary",
)
def test_real_history_scan_cli(
    history: History,
    postgres: DisposablePostgres,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from tests.test_nuclei_linux import BINARY, lab

    requested: list[tuple[str | None, str]] = []
    monkeypatch.setenv("SCOPELENS_DATABASE_URL", postgres.url)
    run_id = uuid4()
    with lab(requested) as source:
        origin = f"http://site.invalid:{source.server_port}"
        path = tmp_path / "scope.toml"
        path.write_text(f'''[project]
id = "nuclei-lab"
name = "Nuclei lab"
[[project.scope.web_targets]]
origin = "{origin}"
approved_addresses = ["127.0.0.1"]
[[profiles]]
id = "web"
''')
        main(
            [
                "history-scan",
                str(path),
                "--profile",
                "web",
                "--run-id",
                str(run_id),
                "--scanner",
                "nuclei",
                "--origin",
                origin,
                "--address",
                "127.0.0.1",
                "--nuclei-binary",
                BINARY,
                "--artifacts",
                str(history.artifacts.root),
            ]
        )
    report = ParsedReport.model_validate_json(capsys.readouterr().out)
    assert history.report(run_id) == report and len(report.matches) == 2
    assert len(requested) == 2
    assert not [
        issue for issue in history.reconcile() if issue.get("run_id") == str(run_id)
    ]
    with pytest.raises(IntegrityError), history.engine.begin() as connection:
        connection.execute(
            s.scanner_matches.update()
            .where(s.scanner_matches.c.stage_id == run_id)
            .values(metadata={"assessment": "confirmed", "scanner_severity": "medium"})
        )
