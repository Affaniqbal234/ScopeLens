import os
import sys
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Connection, Engine, func, insert, select, text, update
from sqlalchemy.exc import IntegrityError

from scopelens.config import ProjectConfig, load_config
from scopelens.storage import schema as s
from scopelens.storage.artifacts import ArtifactError, ArtifactStore
from scopelens.storage.database import HistoryError, database, locked_run, migrate
from scopelens.storage.history import History
from scopelens.storage.operations import import_history
from tests.postgres import DisposablePostgres

REPORT = b"""<nmaprun scanner="nmap" version="7.95">
<host><status state="up" reason="user-set"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8000"><state state="open"/></port></ports></host>
<runstats><finished time="1700000010" exit="success"/></runstats></nmaprun>"""

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("SCOPELENS_POSTGRES_TEST") != "1",
    reason="opt-in disposable PostgreSQL tests require Linux and SCOPELENS_POSTGRES_TEST=1",
)


@pytest.fixture(scope="module")
def postgres() -> Iterator[DisposablePostgres]:
    with DisposablePostgres() as instance:
        yield instance


@pytest.fixture
def engine(postgres: DisposablePostgres) -> Iterator[Engine]:
    value = database(postgres.url)
    migrate(value)
    yield value
    value.dispose()


@pytest.fixture
def history(engine: Engine, tmp_path: Path) -> History:
    return History(engine, ArtifactStore(tmp_path / "artifacts"))


@pytest.fixture
def config(config_path: Path) -> ProjectConfig:
    data = load_config(config_path).model_dump()
    data["project"]["id"] = "test-" + uuid4().hex
    return ProjectConfig.model_validate(data)


def imported(
    history: History, config: ProjectConfig, tmp_path: Path, run_id: UUID | None = None
) -> UUID:
    run_id = run_id or uuid4()
    path = tmp_path / "report.xml"
    path.write_bytes(REPORT)
    import_history(history, config, "conservative", run_id, path)
    return run_id


def counts(engine: Engine) -> dict[str, int]:
    with engine.connect() as connection:
        return {
            table.name: (
                connection.scalar(select(func.count()).select_from(table)) or 0
            )
            for table in s.metadata.sorted_tables
        }


def test_fresh_migration_and_repeat(engine: Engine) -> None:
    migrate(engine)
    with engine.connect() as connection:
        assert (
            connection.scalar(text("SELECT version_num FROM alembic_version"))
            == "0003_nuclei"
        )
        assert (
            compare_metadata(MigrationContext.configure(connection), s.metadata) == []
        )


def test_duplicate_ingestion_and_restart(
    history: History,
    config: ProjectConfig,
    tmp_path: Path,
    postgres: DisposablePostgres,
) -> None:
    run_id = imported(history, config, tmp_path)
    expected = history.report(run_id)
    before = counts(history.engine)
    imported(history, config, tmp_path, run_id)
    assert counts(history.engine) == before
    history.engine.dispose()
    postgres.restart()
    fresh = database(postgres.url)
    try:
        reopened = History(fresh, ArtifactStore(history.artifacts.root))
        assert reopened.report(run_id) == expected
        assert reopened.list_runs(config.project.id)[0]["status"] == "succeeded"
    finally:
        fresh.dispose()


def test_new_run_keeps_entities_and_adds_observations(
    history: History, config: ProjectConfig, tmp_path: Path
) -> None:
    imported(history, config, tmp_path)
    before = counts(history.engine)
    imported(history, config, tmp_path)
    after = counts(history.engine)
    assert after["entities"] == before["entities"]
    assert after["observations"] > before["observations"]
    assert len(history.list_runs(config.project.id)) == 2


def test_idempotency_rejects_changed_bytes_and_profile(
    history: History, config: ProjectConfig, tmp_path: Path
) -> None:
    run_id = imported(history, config, tmp_path)
    path = tmp_path / "changed.xml"
    path.write_bytes(REPORT.replace(b'"open"', b'"closed"'))
    with pytest.raises(HistoryError, match="different artifacts"):
        import_history(history, config, "conservative", run_id, path)
    data = config.model_dump()
    data["profiles"][0]["probes_per_second"] = 1
    with pytest.raises(HistoryError, match="different input"):
        import_history(
            history, ProjectConfig.model_validate(data), "conservative", run_id, path
        )


def test_rollback_after_publication_and_retry(
    history: History,
    config: ProjectConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = uuid4()

    def fail(connection: Connection, *_: object) -> None:
        connection.execute(
            insert(s.projects).values(id=config.project.id, name="duplicate")
        )

    with monkeypatch.context() as patch:
        patch.setattr(history, "_finish", fail)
        with pytest.raises(IntegrityError):
            imported(history, config, tmp_path, run_id)
    assert history.artifacts.read(f"{run_id}/stdout.xml") == REPORT
    assert history.list_runs(config.project.id)[0]["status"] == "running"
    with history.engine.connect() as connection:
        for table in (s.observations, s.artifacts, s.evidence):
            assert (
                connection.scalar(
                    select(func.count())
                    .select_from(table)
                    .where(table.c.stage_id == run_id)
                )
                == 0
            )
    imported(history, config, tmp_path, run_id)
    assert history.report(run_id).evidence.artifact_sha256


def test_partial_publication_recovery(
    history: History,
    config: ProjectConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = uuid4()
    original = history.artifacts.publish

    def fail(identifier: UUID, filename: str, raw: bytes) -> tuple[str, str, int]:
        if filename == "stderr.txt":
            raise OSError("disk full")
        return original(identifier, filename, raw)

    with monkeypatch.context() as patch:
        patch.setattr(history.artifacts, "publish", fail)
        with pytest.raises(OSError, match="disk full"):
            imported(history, config, tmp_path, run_id)
    issues = history.reconcile()
    assert {"run_id": str(run_id), "issue": "interrupted"} in issues
    assert any(
        item.get("path") == f"{run_id}/stdout.xml" and item["issue"] == "unreferenced"
        for item in issues
    )
    with pytest.raises(HistoryError, match="terminal"):
        imported(history, config, tmp_path, run_id)
    assert history.artifacts.read(f"{run_id}/stdout.xml") == REPORT


def test_artifact_health_and_orphans(
    history: History, config: ProjectConfig, tmp_path: Path
) -> None:
    run_id = imported(history, config, tmp_path)
    (history.artifacts.root / str(run_id) / "stdout.xml").write_bytes(b"corrupt")
    (history.artifacts.root / str(run_id) / "stderr.txt").unlink()
    orphan = history.artifacts.root / "orphan"
    orphan.write_bytes(b"keep")
    issues = history.reconcile()
    relevant = [item for item in issues if item.get("run_id") == str(run_id)]
    assert {item["issue"] for item in relevant} == {"corrupt", "missing"}
    assert {"issue": "unreferenced", "path": "orphan"} in issues
    assert orphan.read_bytes() == b"keep"
    assert history.list_runs(config.project.id)[0]["status"] == "succeeded"
    with pytest.raises(ArtifactError):
        imported(history, config, tmp_path, run_id)


def test_active_lock_excludes_reconciliation_and_releases(
    history: History, config: ProjectConfig
) -> None:
    run_id = uuid4()
    with locked_run(history.engine, run_id) as connection:
        history.begin(connection, run_id, config, "conservative", kind="import")
        assert not connection.in_transaction()
        with pytest.raises(HistoryError, match="busy"):
            with locked_run(history.engine, run_id):
                pass
        assert {"run_id": str(run_id), "issue": "busy"} in history.reconcile()
    assert {"run_id": str(run_id), "issue": "interrupted"} in history.reconcile()


def test_database_constraints(
    history: History, config: ProjectConfig, tmp_path: Path
) -> None:
    run_id = imported(history, config, tmp_path)
    with pytest.raises(IntegrityError), history.engine.begin() as connection:
        connection.execute(
            update(s.runs).where(s.runs.c.id == run_id).values(finished_at=None)
        )
    with pytest.raises(IntegrityError), history.engine.begin() as connection:
        connection.execute(
            update(s.observations)
            .where(s.observations.c.stage_id == run_id)
            .values(value={"invalid": True})
        )
    with pytest.raises(IntegrityError), history.engine.begin() as connection:
        connection.execute(
            insert(s.entities).values(
                id=uuid4(),
                project_id=config.project.id,
                identity="bad",
                kind="service",
                address="127.0.0.1",
                transport="tcp",
                port=0,
            )
        )
    other = config.model_dump()
    other["project"]["id"] = "other-" + uuid4().hex
    other_id = imported(history, ProjectConfig.model_validate(other), tmp_path)
    with history.engine.connect() as connection:
        entity_id = connection.scalar(
            select(s.entities.c.id).where(
                s.entities.c.project_id == other["project"]["id"]
            )
        )
        evidence_id = connection.scalar(
            select(s.evidence.c.id).where(s.evidence.c.stage_id == other_id)
        )
        observation_id = connection.scalar(
            select(s.observations.c.id).where(s.observations.c.stage_id == run_id)
        )
    with pytest.raises(IntegrityError), history.engine.begin() as connection:
        connection.execute(
            update(s.observations)
            .where(s.observations.c.id == observation_id)
            .values(entity_id=entity_id)
        )
    with pytest.raises(IntegrityError), history.engine.begin() as connection:
        connection.execute(
            insert(s.observation_evidence).values(
                observation_id=observation_id, evidence_id=evidence_id, stage_id=run_id
            )
        )


def test_scan_holds_session_lock_without_open_transaction(
    history: History, config: ProjectConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hashlib import sha256

    from scopelens.adapters.base import ImportContext
    from scopelens.adapters.nmap import NmapAdapter
    from scopelens.execution.nmap import ScanResult
    from scopelens.execution.process import RawArtifacts
    from scopelens.storage import operations

    run_id = uuid4()

    async def scanner(
        configuration: ProjectConfig, profile: str, root: Path
    ) -> ScanResult:
        with history.engine.connect() as observer:
            states = observer.scalars(
                text(
                    "SELECT state FROM pg_stat_activity WHERE pid IN (SELECT pid FROM pg_locks WHERE locktype='advisory') AND datname=current_database() AND pid <> pg_backend_pid()"
                )
            ).all()
            assert states == ["idle"]
        assert {"run_id": str(run_id), "issue": "busy"} in history.reconcile()
        capture = root / "nmap-capture"
        capture.mkdir(mode=0o700)
        stdout, stderr = capture / "stdout.xml", capture / "stderr.txt"
        stdout.write_bytes(REPORT)
        stderr.write_bytes(b"")
        report = NmapAdapter().parse(
            REPORT,
            ImportContext(
                profile_id=profile,
                profile_revision=sha256(
                    configuration.profiles[0].model_dump_json().encode()
                ).hexdigest(),
            ),
        )
        return ScanResult(RawArtifacts(capture, stdout, stderr), report)

    monkeypatch.setattr(operations, "scan_nmap", scanner)
    result = operations.scan_history(history, config, "conservative", run_id)
    assert history.report(run_id) == result
    assert sorted(
        path.name for path in history.artifacts.directory(run_id).iterdir()
    ) == ["stderr.txt", "stdout.xml"]
    with pytest.raises(HistoryError, match="already exists"):
        operations.scan_history(history, config, "conservative", run_id)


@pytest.mark.parametrize("cancelled", [False, True])
def test_scan_failure_records_terminal_state(
    history: History,
    config: ProjectConfig,
    monkeypatch: pytest.MonkeyPatch,
    cancelled: bool,
) -> None:
    from scopelens.execution.process import ExecutionError
    from scopelens.storage import operations

    run_id = uuid4()

    async def scanner(*_: object) -> None:
        if cancelled:
            raise KeyboardInterrupt()
        raise ExecutionError("scanner failed")

    monkeypatch.setattr(operations, "scan_nmap", scanner)
    with pytest.raises(KeyboardInterrupt if cancelled else ExecutionError):
        operations.scan_history(history, config, "conservative", run_id)
    record = history.list_runs(config.project.id)[0]
    assert record["status"] == ("interrupted" if cancelled else "failed")
    assert record["finished_at"] is not None
    with pytest.raises(HistoryError, match="no completed report"):
        history.report(run_id)


def test_foreign_scope_rejected_before_publication(
    history: History, config: ProjectConfig, tmp_path: Path
) -> None:
    from scopelens.domain.scope import ScopeViolation

    path = tmp_path / "foreign.xml"
    path.write_bytes(REPORT.replace(b"127.0.0.1", b"192.0.2.1"))
    run_id = uuid4()
    with pytest.raises(ScopeViolation):
        import_history(history, config, "conservative", run_id, path)
    assert not (history.artifacts.root / str(run_id)).exists()


def test_lock_released_after_exception(history: History) -> None:
    run_id = uuid4()
    with pytest.raises(RuntimeError, match="test failure"):
        with locked_run(history.engine, run_id):
            raise RuntimeError("test failure")
    with locked_run(history.engine, run_id):
        pass


def test_history_cli_round_trip(
    history: History,
    config_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    postgres: DisposablePostgres,
) -> None:
    import json

    from scopelens.cli import main

    monkeypatch.setenv("SCOPELENS_DATABASE_URL", postgres.url)
    run_id = uuid4()
    path = tmp_path / "cli.xml"
    path.write_bytes(REPORT)
    root = ["--artifacts", str(history.artifacts.root)]
    main(
        [
            "history-import",
            str(config_path),
            str(path),
            "--profile",
            "conservative",
            "--run-id",
            str(run_id),
            *root,
        ]
    )
    captured = capsys.readouterr()
    expected = json.loads(captured.out)
    assert postgres.password not in captured.err
    main(["history-show", str(run_id), *root])
    assert json.loads(capsys.readouterr().out) == expected
    main(["history-list", "--project", "local-lab", *root])
    assert any(
        record["id"] == str(run_id) for record in json.loads(capsys.readouterr().out)
    )


def test_database_disconnect_releases_lock_and_recovery_is_terminal(
    history: History, config: ProjectConfig
) -> None:
    from sqlalchemy.exc import DBAPIError

    run_id = uuid4()
    with pytest.raises(DBAPIError):
        with locked_run(history.engine, run_id) as connection:
            history.begin(connection, run_id, config, "conservative", kind="import")
            backend = connection.scalar(text("SELECT pg_backend_pid()"))
            connection.commit()
            with history.engine.begin() as observer:
                assert observer.scalar(
                    text("SELECT pg_terminate_backend(:pid)"), {"pid": backend}
                )
            connection.execute(text("SELECT 1"))
    assert {"run_id": str(run_id), "issue": "interrupted"} in history.reconcile()
    with locked_run(history.engine, run_id) as connection:
        with pytest.raises(HistoryError, match="terminal"):
            history.ingest(connection, run_id, REPORT)


def test_reported_exit_and_scalar_types_survive_storage(
    history: History, config: ProjectConfig, tmp_path: Path
) -> None:
    path = tmp_path / "observations.xml"
    # Import success means the file was ingested, not that Nmap succeeded.
    path.write_bytes(
        REPORT.replace(b'exit="success"', b'exit="error"')
        .replace(b"<host>", b'<host timedout="false">')
        .replace(b"<ports>", b'<ports><extraports state="closed" count="0"/>')
    )
    run_id = uuid4()
    expected = import_history(history, config, "conservative", run_id, path)
    assert history.report(run_id) == expected
    assert history.report(run_id).reported_exit == "error"
    assert history.list_runs(config.project.id)[0]["kind"] == "import"
    values = {item.key: item.value for item in history.report(run_id).observations}
    assert values["host.timed_out"] is False
    assert type(values["ports.closed.count"]) is int


def test_migration_downgrade_in_disposable_schema(engine: Engine) -> None:
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect

    from scopelens.storage import database as storage_database

    name = "migration_" + uuid4().hex
    config = Config()
    config.set_main_option(
        "script_location", str(Path(storage_database.__file__).parent / "migrations")
    )
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{name}"'))
        connection.execute(text(f'SET LOCAL search_path TO "{name}"'))
        config.attributes["connection"] = connection
        command.upgrade(config, "0001_scan_history")
        run_id = uuid4()
        connection.execute(insert(s.projects).values(id="legacy", name="Legacy"))
        connection.execute(
            insert(s.scope_snapshots).values(id="a" * 64, project_id="legacy", scope={})
        )
        connection.execute(
            insert(s.runs).values(
                id=run_id,
                project_id="legacy",
                scope_snapshot_id="a" * 64,
                kind="import",
                profile={},
                profile_revision="b" * 64,
                status="running",
            )
        )
        connection.execute(
            text(
                "INSERT INTO stages (id, run_id, project_id, scanner, status) VALUES (:id, :id, 'legacy', 'nmap', 'running')"
            ),
            {"id": run_id},
        )
        command.upgrade(config, "head")
        row = (
            connection.execute(select(s.stages).where(s.stages.c.id == run_id))
            .mappings()
            .one()
        )
        assert (
            row["scanner"] == "nmap"
            and row["input_context"] == {}
            and row["status"] == "running"
        )
        connection.execute(
            update(s.stages).where(s.stages.c.id == run_id).values(scanner="httpx")
        )
        with (
            pytest.raises(RuntimeError, match="httpx history exists"),
            connection.begin_nested(),
        ):
            command.downgrade(config, "0001_scan_history")
        assert (
            connection.scalar(text("SELECT version_num FROM alembic_version"))
            == "0003_nuclei"
        )
        connection.execute(
            update(s.stages).where(s.stages.c.id == run_id).values(scanner="nmap")
        )
        assert set(inspect(connection).get_table_names(schema=name)) == set(
            s.metadata.tables
        ) | {"alembic_version"}
        command.downgrade(config, "base")
        assert inspect(connection).get_table_names(schema=name) == ["alembic_version"]
        command.upgrade(config, "head")
        assert (
            connection.scalar(text("SELECT version_num FROM alembic_version"))
            == "0003_nuclei"
        )
        # This generated schema exists only in this test-owned database.
        connection.execute(text(f'DROP SCHEMA "{name}" CASCADE'))


def test_httpx_history_identity_idempotency_and_reopen(
    history: History, tmp_path: Path
) -> None:
    import json

    from scopelens.adapters.httpx import HTTPX_VERSION
    from scopelens.domain.scope import WebTarget
    from scopelens.domain.services import HttpEndpoint
    from tests.test_httpx import RAW, TARGET, web_config

    config = web_config()
    data = config.model_dump(mode="json")
    data["project"]["id"] = "httpx-" + uuid4().hex
    data["project"]["scope"]["web_targets"].append(
        {"origin": "http://site.invalid:8443", "approved_addresses": ["127.0.0.1"]}
    )
    config = ProjectConfig.model_validate(data)
    path = tmp_path / "report.jsonl"
    path.write_bytes(RAW)
    run_id = uuid4()
    expected = import_history(
        history,
        config,
        "web",
        run_id,
        path,
        scanner="httpx",
        web_target=TARGET,
        scanner_version=HTTPX_VERSION,
    )
    before = counts(history.engine)
    assert (
        import_history(
            history,
            config,
            "web",
            run_id,
            path,
            scanner="httpx",
            web_target=TARGET,
            scanner_version=HTTPX_VERSION,
        )
        == expected
    )
    assert counts(history.engine) == before
    assert (
        History(history.engine, ArtifactStore(history.artifacts.root)).report(run_id)
        == expected
    )
    assert history.artifacts.read(f"{run_id}/stdout.jsonl") == RAW
    with history.engine.connect() as connection:
        assert (
            connection.scalar(
                select(func.count())
                .select_from(s.evidence)
                .where(s.evidence.c.stage_id == run_id)
            )
            == 2
        )
        assert (
            connection.scalar(
                select(s.entities.c.kind).where(
                    s.entities.c.project_id == config.project.id
                )
            )
            == "origin"
        )
    assert all(isinstance(item.subject, HttpEndpoint) for item in expected.observations)
    other = WebTarget(
        origin="http://site.invalid:8443", approved_addresses=("127.0.0.1",)
    )
    with pytest.raises(HistoryError, match="different scanner input"):
        import_history(
            history,
            config,
            "web",
            run_id,
            path,
            scanner="httpx",
            web_target=other,
            scanner_version=HTTPX_VERSION,
        )
    record = json.loads(RAW)
    record["url"] = "http://127.0.0.1:8443"
    path.write_text(json.dumps(record), encoding="utf-8")
    import_history(
        history,
        config,
        "web",
        uuid4(),
        path,
        scanner="httpx",
        web_target=other,
        scanner_version=HTTPX_VERSION,
    )
    assert counts(history.engine)["entities"] == before["entities"] + 1
    (history.artifacts.root / str(run_id) / "stdout.jsonl").write_bytes(b"corrupt")
    assert {
        "run_id": str(run_id),
        "issue": "corrupt",
        "path": f"{run_id}/stdout.jsonl",
    } in history.reconcile()


def test_httpx_publication_failure_retries_without_duplicate_evidence(
    history: History, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scopelens.adapters.httpx import HTTPX_VERSION
    from tests.test_httpx import RAW, TARGET, web_config

    config = web_config()
    path = tmp_path / "report.jsonl"
    path.write_bytes(RAW)
    run_id = uuid4()

    def fail(*_: object) -> None:
        raise RuntimeError("write interrupted")

    with monkeypatch.context() as patch:
        patch.setattr(history, "_finish", fail)
        with pytest.raises(RuntimeError, match="write interrupted"):
            import_history(
                history,
                config,
                "web",
                run_id,
                path,
                scanner="httpx",
                web_target=TARGET,
                scanner_version=HTTPX_VERSION,
            )
    assert history.artifacts.read(f"{run_id}/stdout.jsonl") == RAW
    with history.engine.connect() as connection:
        assert (
            connection.scalar(
                select(func.count())
                .select_from(s.evidence)
                .where(s.evidence.c.stage_id == run_id)
            )
            == 0
        )
    result = import_history(
        history,
        config,
        "web",
        run_id,
        path,
        scanner="httpx",
        web_target=TARGET,
        scanner_version=HTTPX_VERSION,
    )
    assert history.report(run_id) == result


@pytest.mark.parametrize("case", ["partial", "duplicate", "scope"])
def test_httpx_invalid_import_publishes_nothing(
    history: History, tmp_path: Path, case: str
) -> None:
    from scopelens.adapters.base import ReportParseError
    from scopelens.adapters.httpx import HTTPX_VERSION
    from tests.test_httpx import RAW, TARGET, web_config

    raw = {
        "partial": RAW + b'{"partial":',
        "duplicate": RAW + RAW,
        "scope": RAW.replace(b"127.0.0.1", b"192.0.2.1"),
    }[case]
    path = tmp_path / "invalid.jsonl"
    path.write_bytes(raw)
    run_id = uuid4()
    with pytest.raises(ReportParseError):
        import_history(
            history,
            web_config(),
            "web",
            run_id,
            path,
            scanner="httpx",
            web_target=TARGET,
            scanner_version=HTTPX_VERSION,
        )
    assert not (history.artifacts.root / str(run_id)).exists()
    with history.engine.connect() as connection:
        assert (
            connection.scalar(select(s.runs.c.status).where(s.runs.c.id == run_id))
            == "failed"
        )


def test_httpx_history_cli(
    history: History,
    config_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    postgres: DisposablePostgres,
) -> None:
    from scopelens.adapters.base import ParsedReport
    from scopelens.cli import main
    from tests.test_httpx import RAW

    monkeypatch.setenv("SCOPELENS_DATABASE_URL", postgres.url)
    path = tmp_path / "cli.jsonl"
    path.write_bytes(RAW.replace(b"https://127.0.0.1:8443", b"http://127.0.0.1:8000"))
    run_id = uuid4()
    main(
        [
            "history-import",
            str(config_path),
            str(path),
            "--profile",
            "conservative",
            "--run-id",
            str(run_id),
            "--scanner",
            "httpx",
            "--origin",
            "http://localhost:8000",
            "--address",
            "127.0.0.1",
            "--scanner-version",
            "1.12.0",
            "--artifacts",
            str(history.artifacts.root),
        ]
    )
    report = ParsedReport.model_validate_json(capsys.readouterr().out)
    assert history.report(run_id) == report
    assert report.evidence.scanner == "httpx"


def test_httpx_scan_dispatch_and_lock(
    history: History, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scopelens.adapters.base import ImportContext
    from scopelens.adapters.httpx import HttpxAdapter
    from scopelens.domain.scope import WebTarget
    from scopelens.execution.base import ScanResult
    from scopelens.execution.process import RawArtifacts
    from scopelens.storage import operations
    from tests.test_httpx import RAW, TARGET, web_config

    run_id = uuid4()

    async def scanner(
        config: ProjectConfig, profile: str, root: Path, target: WebTarget, binary: str
    ) -> ScanResult:
        assert target == TARGET and binary == "/trusted/httpx"
        with history.engine.connect() as connection:
            assert connection.scalars(
                text(
                    "SELECT state FROM pg_stat_activity WHERE pid IN (SELECT pid FROM pg_locks WHERE locktype='advisory') AND pid <> pg_backend_pid() AND datname=current_database()"
                )
            ).all() == ["idle"]
        capture = root / "httpx-capture"
        capture.mkdir(mode=0o700)
        stdout, stderr = capture / "stdout.jsonl", capture / "stderr.txt"
        stdout.write_bytes(RAW)
        stderr.write_bytes(b"")
        return ScanResult(
            RawArtifacts(capture, stdout, stderr),
            HttpxAdapter().parse(
                RAW,
                ImportContext(
                    profile_id=profile,
                    profile_revision="test",
                    scanner_version="1.12.0",
                    web_target=target,
                ),
            ),
        )

    monkeypatch.setattr(operations, "scan_httpx", scanner)
    result = operations.scan_history(
        history,
        web_config(),
        "web",
        run_id,
        scanner="httpx",
        web_target=TARGET,
        binary="/trusted/httpx",
    )
    assert history.report(run_id) == result
    assert sorted(p.name for p in history.artifacts.directory(run_id).iterdir()) == [
        "stderr.txt",
        "stdout.jsonl",
    ]


@pytest.mark.skipif(
    not os.environ.get("SCOPELENS_HTTPX_BINARY"),
    reason="requires explicit httpx v1.12.0 binary",
)
def test_httpx_history_real_scan_cli(
    history: History,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    postgres: DisposablePostgres,
) -> None:
    from scopelens.adapters.base import ParsedReport
    from scopelens.cli import main
    from tests.test_httpx_linux import server

    requests: list[tuple[str | None, str]] = []
    run_id = uuid4()
    monkeypatch.setenv("SCOPELENS_DATABASE_URL", postgres.url)
    with server(requests) as source:
        origin = f"http://site.invalid:{source.server_port}"
        config_path = tmp_path / "web.toml"
        config_path.write_text(
            f'''[project]
id = "httpx-live"
name = "Local HTTP"
[[project.scope.web_targets]]
origin = "{origin}"
approved_addresses = ["127.0.0.1"]
[[profiles]]
id = "web"
''',
            encoding="utf-8",
        )
        main(
            [
                "history-scan",
                str(config_path),
                "--profile",
                "web",
                "--run-id",
                str(run_id),
                "--scanner",
                "httpx",
                "--origin",
                origin,
                "--address",
                "127.0.0.1",
                "--httpx-binary",
                os.environ["SCOPELENS_HTTPX_BINARY"],
                "--artifacts",
                str(history.artifacts.root),
            ]
        )
    report = ParsedReport.model_validate_json(capsys.readouterr().out)
    assert history.report(run_id) == report
    assert requests == [(f"site.invalid:{source.server_port}", "/")]
    assert history.artifacts.read(f"{run_id}/stdout.jsonl")
    assert not [
        item for item in history.reconcile() if item.get("run_id") == str(run_id)
    ]
