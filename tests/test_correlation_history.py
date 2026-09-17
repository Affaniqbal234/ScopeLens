import os
import sys
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Connection, text, update

from scopelens.adapters.base import ParsedReport
from scopelens.adapters.httpx import HTTPX_VERSION
from scopelens.adapters.nuclei_templates import NUCLEI_VERSION, template_revision
from scopelens.adapters.registry import adapter_for
from scopelens.analysis.correlation import CorrelationError
from scopelens.analysis.models import CorrelationResult, Host, NetworkService
from scopelens.cli import main
from scopelens.config import ProjectConfig
from scopelens.storage import correlation as storage
from scopelens.storage import schema as s
from scopelens.storage.artifacts import ArtifactStore
from scopelens.storage.history import History
from scopelens.storage.operations import import_history
from scopelens.storage.reports import read_report
from tests.postgres import DisposablePostgres
from tests.test_history import REPORT, counts
from tests.test_history import config as config
from tests.test_history import engine as engine
from tests.test_history import history as history
from tests.test_history import postgres as postgres
from tests.test_httpx import RAW as HTTPX_RAW
from tests.test_nuclei import CONTEXT, RAW, TARGET

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("SCOPELENS_POSTGRES_TEST") != "1",
    reason="requires disposable PostgreSQL on Linux",
)


def web_config(config: ProjectConfig) -> ProjectConfig:
    data = config.model_dump()
    data["project"]["scope"]["web_targets"] = [TARGET.model_dump()]
    return ProjectConfig.model_validate(data)


def imported(
    history: History,
    config: ProjectConfig,
    tmp_path: Path,
    scanner: str = "nuclei",
    run_id: UUID | None = None,
    raw: bytes | None = None,
) -> UUID:
    run_id = run_id or uuid4()
    if raw is None:
        raw = (
            RAW
            if scanner == "nuclei"
            else HTTPX_RAW.replace(b"https://127.0.0.1:8443", b"http://127.0.0.1:8000")
            if scanner == "httpx"
            else REPORT
        )
    path = tmp_path / ("report.xml" if scanner == "nmap" else "report.jsonl")
    path.write_bytes(raw)
    import_history(
        history,
        web_config(config),
        "conservative",
        run_id,
        path,
        scanner=scanner,
        web_target=None if scanner == "nmap" else TARGET,
        scanner_version=NUCLEI_VERSION
        if scanner == "nuclei"
        else HTTPX_VERSION
        if scanner == "httpx"
        else None,
        template_bundle=template_revision() if scanner == "nuclei" else None,
        captured_at=CONTEXT.captured_at if scanner == "nuclei" else None,
    )
    return run_id


def test_mixed_reports_repeat_import_and_read_only_projection(
    history: History,
    config: ProjectConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs = [
        imported(history, config, tmp_path, scanner)
        for scanner in ("nmap", "httpx", "nuclei")
    ]
    before = counts(history.engine)
    imported(history, config, tmp_path, run_id=runs[-1])
    assert counts(history.engine) == before
    copies = imported(history, config, tmp_path)
    selected = [*runs, copies]
    excluded = imported(history, config, tmp_path, raw=b"")
    reports = {run_id: history.report(run_id) for run_id in selected}
    before = counts(history.engine)
    original_reader = read_report

    def checked_reader(connection: Connection, run_id: UUID) -> ParsedReport:
        assert connection.scalar(text("SHOW transaction_read_only")) == "on"
        assert (
            connection.scalar(text("SHOW transaction_isolation")) == "repeatable read"
        )
        return original_reader(connection, run_id)

    monkeypatch.setattr(storage, "read_report", checked_reader)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("correlation touched private artifact storage")

    monkeypatch.setattr(ArtifactStore, "__init__", forbidden)
    monkeypatch.setattr(ArtifactStore, "read", forbidden)
    first = storage.correlate_history(history.engine, config.project.id, selected)
    assert (
        storage.correlate_history(history.engine, config.project.id, selected[::-1])
        == first
    )
    assert counts(history.engine) == before
    assert {item.run_id for item in first.sources} == set(selected)
    assert excluded not in {item.run_id for item in first.sources}
    assert {item.run_id: item.report for item in first.sources} == reports
    assert len(first.findings) == 2
    assert all(len(finding.occurrences) == 2 for finding in first.findings)
    duplicate = next(item for item in first.artifact_copies if item.scanner == "nuclei")
    assert set(duplicate.run_ids) == {runs[-1], copies}
    services = [
        item for item in first.inventory if isinstance(item.identity, NetworkService)
    ]
    assert len(services) == 1
    assert {ref.run_id for ref in services[0].sources} == {runs[0], runs[1]}
    for item in first.sources:
        stdout = next(
            artifact for artifact in item.artifacts if artifact.role == "stdout"
        )
        assert stdout.sha256 == item.report.evidence.artifact_sha256
        assert stdout.relative_path.startswith(str(item.run_id) + "/")
        assert item.scope_snapshot_id and item.context.profile_revision
        raw = (history.artifacts.root / stdout.relative_path).read_bytes()
        assert item.report == adapter_for(item.report.evidence.scanner).parse(
            raw, item.context
        )
    for finding in first.findings:
        for ref in finding.occurrences:
            assert ref.ordinal is not None
            original = reports[ref.run_id].matches[ref.ordinal]
            assert original.assessment == "unvalidated"


@pytest.mark.parametrize(
    "kind",
    ["empty", "duplicate", "missing", "foreign", "running", "failed", "interrupted"],
)
def test_selection_fails_whole_request(
    history: History,
    config: ProjectConfig,
    tmp_path: Path,
    kind: str,
) -> None:
    run_id = imported(history, config, tmp_path)
    ids = [run_id]
    project = config.project.id
    if kind == "empty":
        ids = []
    elif kind == "duplicate":
        ids.append(run_id)
    elif kind == "missing":
        ids.append(uuid4())
    elif kind == "foreign":
        ids.append(
            imported(
                history,
                ProjectConfig.model_validate(
                    {
                        **config.model_dump(),
                        "project": {
                            **config.project.model_dump(),
                            "id": "other-" + uuid4().hex,
                        },
                    }
                ),
                tmp_path,
            )
        )
    else:
        with history.engine.begin() as connection:
            for table in (s.runs, s.stages):
                values: dict[str, object] = {"status": kind}
                if kind == "running":
                    values["finished_at"] = None
                connection.execute(
                    update(table).where(table.c.id == run_id).values(**values)
                )
    with pytest.raises(CorrelationError):
        storage.correlate_history(history.engine, project, ids)


def test_cli_is_json_without_artifact_access(
    history: History,
    config: ProjectConfig,
    tmp_path: Path,
    postgres: DisposablePostgres,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_id = imported(history, config, tmp_path)
    expected = storage.correlate_history(history.engine, config.project.id, [run_id])
    monkeypatch.setenv("SCOPELENS_DATABASE_URL", postgres.url)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("read-only CLI constructed an artifact store")

    monkeypatch.setattr(ArtifactStore, "__init__", forbidden)
    main(["history-correlate", "--project", config.project.id, "--run-id", str(run_id)])
    output = capsys.readouterr()
    assert output.err == ""
    assert CorrelationResult.model_validate_json(output.out) == expected
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "history-correlate",
                "--project",
                config.project.id,
                "--run-id",
                str(uuid4()),
            ]
        )
    output = capsys.readouterr()
    assert exc.value.code == 2 and output.out == ""
    assert "missing or belongs to another project" in output.err


def test_artifact_metadata_uses_one_snapshot_without_rechecking_files(
    history: History,
    config: ProjectConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = imported(history, config, tmp_path)
    original_reader = read_report

    def changed_metadata(connection: Connection, selected: UUID) -> ParsedReport:
        with history.engine.begin() as other:
            other.execute(
                update(s.artifacts)
                .where(s.artifacts.c.stage_id == run_id)
                .values(health="missing")
            )
        return original_reader(connection, selected)

    with monkeypatch.context() as patch:
        patch.setattr(storage, "read_report", changed_metadata)
        first = storage.correlate_history(history.engine, config.project.id, [run_id])
    assert all(
        artifact.recorded_health == "ready" for artifact in first.sources[0].artifacts
    )
    (history.artifacts.root / str(run_id) / "stdout.jsonl").unlink()
    second = storage.correlate_history(history.engine, config.project.id, [run_id])
    assert all(
        artifact.recorded_health == "missing"
        for artifact in second.sources[0].artifacts
    )
    assert first.findings == second.findings
    assert first.sources[0].report == second.sources[0].report


def test_nuclei_only_and_empty_reports_use_declared_context(
    history: History,
    config: ProjectConfig,
    tmp_path: Path,
) -> None:
    run_id = imported(history, config, tmp_path)
    result = storage.correlate_history(history.engine, config.project.id, [run_id])
    assert len(result.findings) == 2
    assert {rel.kind for rel in result.relationships} == {
        "configured_address",
        "resource_on_origin",
    }
    hosts = [item for item in result.inventory if isinstance(item.identity, Host)]
    assert len(hosts) == 1 and all(ref.section == "context" for ref in hosts[0].sources)
    assert result.sources[0].context.template_revision == template_revision()
    empty = imported(history, config, tmp_path, raw=b"")
    result = storage.correlate_history(history.engine, config.project.id, [empty])
    assert result.findings == ()
    assert result.assertions == ()
    assert {rel.kind for rel in result.relationships} == {"configured_address"}


def test_history_comparison_is_read_only_and_rechecks_artifact_health(
    history: History,
    config: ProjectConfig,
    tmp_path: Path,
) -> None:
    baseline = imported(history, config, tmp_path)
    current = imported(history, config, tmp_path, raw=b"")
    before = counts(history.engine)
    result = storage.compare_history(
        history.engine,
        history.artifacts,
        config.project.id,
        [baseline],
        [current],
    )
    assert counts(history.engine) == before
    directory = next(
        item
        for item in result.results
        if item.claim.rule_id == "scopelens.directory-listing"
    )
    assert directory.state == "not_observed"

    (history.artifacts.root / str(baseline) / "stdout.jsonl").unlink()
    missing = storage.compare_history(
        history.engine,
        history.artifacts,
        config.project.id,
        [baseline],
        [current],
    )
    directory = next(
        item
        for item in missing.results
        if item.claim.rule_id == "scopelens.directory-listing"
    )
    assert directory.state == "unknown"
    assert directory.coverage.reason == "evidence_artifact_unhealthy"
