import os
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, event, select

from scopelens.assessment.models import (
    AcquisitionEvidence,
    CapturedResponse,
    RecheckAcquisition,
    RecheckReport,
)
from scopelens.assessment.rules import (
    DIRECTORY_RULE,
    GIT_CONFIG_RULE,
    CapturedExchange,
    assess_exposure_recheck,
    assess_hsts_recheck,
)
from scopelens.comparison.compare import ArtifactHealth, compare_assessments
from scopelens.config import ProjectConfig
from scopelens.execution.process import ExecutionError
from scopelens.orchestration.store import OrchestrationStore, build_plan
from scopelens.orchestration.worker import AssessmentWorker
from scopelens.reporting.service import load_assessment_report
from scopelens.storage import schema as s
from scopelens.storage.artifacts import ArtifactStore
from scopelens.storage.database import (
    HistoryError,
    database,
    migrate,
    single_assessment_worker,
)
from scopelens.storage.history import History
from tests.postgres import DisposablePostgres

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
def project() -> ProjectConfig:
    return ProjectConfig.model_validate(
        {
            "project": {
                "id": "orchestration-lab",
                "name": "Orchestration lab",
                "scope": {
                    "web_targets": [
                        {
                            "origin": "https://app.local",
                            "approved_addresses": ["127.0.0.1"],
                        }
                    ]
                },
            },
            "profiles": [{"id": "safe"}],
        }
    )


@pytest.fixture
def store(engine: Engine, tmp_path: Path) -> OrchestrationStore:
    return OrchestrationStore(engine, ArtifactStore(tmp_path / "history"))


def enqueue(
    store: OrchestrationStore, project: ProjectConfig, *, skip: bool = False
) -> UUID:
    identifier = uuid4()
    request = build_plan(project, "safe", ("web_recheck",))[0]
    if skip:
        request = request.model_copy(update={"skip_reason": "profile_omission"})
    store.enqueue(identifier, project, (request,))
    return identifier


def with_network_scope(project: ProjectConfig) -> ProjectConfig:
    data = project.model_dump(mode="json")
    data["project"]["scope"]["network_targets"] = [
        {"address": "127.0.0.1", "ports": [443]}
    ]
    data["profiles"][0]["tcp_ports"] = [443]
    return ProjectConfig.model_validate(data)


def exchange(
    root: Path,
    *,
    resource: str,
    started: datetime,
    status_code: int,
    body: bytes,
    hsts: bool,
) -> CapturedExchange:
    raw = (
        f"HTTP/1.1 {status_code} Test\r\n"
        f"Content-Length: {len(body)}\r\n"
        + ("Strict-Transport-Security: max-age=60\r\n" if hsts else "")
        + "\r\n"
    ).encode() + body
    path = root / f"{uuid4()}.http"
    path.write_bytes(raw)
    acquisition = RecheckAcquisition(
        id=uuid4(),
        started_at=started,
        finished_at=started + timedelta(seconds=1),
        origin="https://app.local",
        approved_address="127.0.0.1",
        resource=resource,
        status="complete",
        evidence=AcquisitionEvidence(
            artifact_path=str(path),
            artifact_sha256=sha256(raw).hexdigest(),
            size_bytes=len(raw),
        ),
        response=CapturedResponse(
            status_code=status_code,
            headers_complete=True,
            body_complete=True,
            body_sha256=sha256(body).hexdigest(),
            strict_transport_security_present=hsts,
            access_challenge_present=False,
            content_encoding_identity=True,
        ),
    )
    return CapturedExchange(acquisition, body)


def report(root: Path, started: datetime, *, vulnerable: bool) -> RecheckReport:
    listing = exchange(
        root,
        resource="/",
        started=started,
        status_code=200 if vulnerable else 404,
        body=b"<title>Index of /</title><a href='x'>x</a>" if vulnerable else b"",
        hsts=not vulnerable,
    )
    git = exchange(
        root,
        resource="/.git/config",
        started=started + timedelta(seconds=2),
        status_code=200 if vulnerable else 404,
        body=b"[core]\nrepositoryformatversion = 0\n" if vulnerable else b"",
        hsts=not vulnerable,
    )
    return RecheckReport(
        project_id="orchestration-lab",
        acquisitions=(listing.acquisition, git.acquisition),
        assessments=(
            assess_exposure_recheck("orchestration-lab", DIRECTORY_RULE, listing),
            assess_exposure_recheck("orchestration-lab", GIT_CONFIG_RULE, git),
            assess_hsts_recheck("orchestration-lab", listing),
        ),
    )


def incomplete_report(
    root: Path, started: datetime, *, root_complete: bool
) -> RecheckReport:
    if root_complete:
        listing = exchange(
            root,
            resource="/",
            started=started,
            status_code=404,
            body=b"",
            hsts=True,
        )
    else:
        listing = CapturedExchange(
            RecheckAcquisition(
                id=uuid4(),
                started_at=started,
                finished_at=started + timedelta(seconds=1),
                origin="https://app.local",
                approved_address="127.0.0.1",
                resource="/",
                status="timeout",
            ),
            b"",
        )
    git = CapturedExchange(
        RecheckAcquisition(
            id=uuid4(),
            started_at=started + timedelta(seconds=2),
            origin="https://app.local",
            approved_address="127.0.0.1",
            resource="/.git/config",
            status="not_run",
        ),
        b"",
    )
    return RecheckReport(
        project_id="orchestration-lab",
        acquisitions=(listing.acquisition, git.acquisition),
        assessments=(
            assess_exposure_recheck("orchestration-lab", DIRECTORY_RULE, listing),
            assess_exposure_recheck("orchestration-lab", GIT_CONFIG_RULE, git),
            assess_hsts_recheck("orchestration-lab", listing),
        ),
    )


def test_manifest_claim_skip_and_no_replay(
    store: OrchestrationStore, project: ProjectConfig
) -> None:
    assessment_id = enqueue(store, project, skip=True)
    first = AssessmentWorker(store).run_one(assessment_id)
    assert first is not None and first.status == "completed"
    assert first.stages[0].status == "skipped"
    assert first.stages[0].started_at is None
    assert AssessmentWorker(store).run_one(assessment_id) is None


def test_claim_is_atomic_and_owner_checked(
    store: OrchestrationStore, project: ProjectConfig
) -> None:
    assessment_id = enqueue(store, project)
    token = uuid4()
    assert store.claim(token, assessment_id) == assessment_id
    assert store.claim(uuid4(), assessment_id) is None
    stage = store.get(assessment_id).stages[0]
    with pytest.raises(HistoryError, match="current state"):
        store.start_stage(assessment_id, stage.id, uuid4())
    store.start_stage(assessment_id, stage.id, token)
    store.finish_stage(
        assessment_id,
        stage.id,
        token,
        "interrupted",
        reason="test_interruption",
    )
    assert store.finalize(assessment_id, token).status == "interrupted"


def test_planned_run_id_is_reserved_for_its_exact_stage(
    store: OrchestrationStore, project: ProjectConfig
) -> None:
    config = with_network_scope(project)
    assessment_id = uuid4()
    request = build_plan(config, "safe", ("nmap",))[0]
    run_id = request.planned_run_id
    assert run_id is not None
    store.enqueue(assessment_id, config, (request,))
    token = uuid4()
    store.claim(token, assessment_id)
    stage = store.get(assessment_id).stages[0]
    store.start_stage(assessment_id, stage.id, token)
    history = History(store.engine, store.artifacts)
    with store.engine.connect() as connection:
        with pytest.raises(HistoryError, match="reserved"):
            history.begin(connection, run_id, config, "safe", kind="scan")
        history.begin(
            connection,
            run_id,
            config,
            "safe",
            kind="scan",
            orchestration_stage_id=stage.id,
        )
    with store.engine.begin() as connection:
        History._finish(connection, run_id, "failed", "controlled_failure")
    store.finish_stage(
        assessment_id,
        stage.id,
        token,
        "failed",
        reason="controlled_failure",
        result_run_id=run_id,
    )
    assert store.finalize(assessment_id, token).status == "failed"


def test_restart_reconciles_only_running_work(
    store: OrchestrationStore, project: ProjectConfig
) -> None:
    stale = enqueue(store, project)
    pending = enqueue(store, project, skip=True)
    token = uuid4()
    store.claim(token, stale)
    stage = store.get(stale).stages[0]
    store.start_stage(stale, stage.id, token)
    assert AssessmentWorker(store).reconcile() == [stale]
    stale_result = store.get(stale)
    assert stale_result.status == "interrupted"
    assert stale_result.stages[0].status == "interrupted"
    assert store.get(pending).status == "pending"
    assert AssessmentWorker(store).run_one(stale) is None


def test_single_worker_guard_rejects_concurrent_worker(
    store: OrchestrationStore,
) -> None:
    with single_assessment_worker(store.engine):
        with pytest.raises(HistoryError, match="already running"):
            AssessmentWorker(store).reconcile()


def test_worker_preserves_completed_recheck_when_later_stage_fails(
    store: OrchestrationStore,
    project: ProjectConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessment_id = uuid4()
    store.enqueue(
        assessment_id,
        project,
        build_plan(project, "safe", ("web_recheck", "httpx")),
    )
    completed = report(tmp_path, datetime(2026, 1, 4, tzinfo=UTC), vulnerable=False)

    async def fake_recheck(*args: object, **kwargs: object) -> RecheckReport:
        return completed

    calls = 0

    def failed_scan(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        raise ExecutionError("controlled failure")

    monkeypatch.setattr("scopelens.orchestration.worker.recheck_web", fake_recheck)
    monkeypatch.setattr("scopelens.orchestration.worker.scan_history", failed_scan)
    result = AssessmentWorker(store).run_one(assessment_id)
    assert result is not None and result.status == "failed"
    assert [item.status for item in result.stages] == ["completed", "failed"]
    loaded, health = store.load_recheck(result.stages[0].id)
    assert loaded.assessments[0].outcome == "supported_negative"
    assert set(health.values()) == {"ready"}
    exported = load_assessment_report(store, assessment_id)
    assert exported.assessment_id == assessment_id
    assert exported.project.id == project.project.id
    assert exported.profile.id == "safe"
    assert exported.stages[0].status == "completed"
    display_outcomes = {item.display_outcome for item in exported.claims}
    assert "condition_not_supported_by_this_evidence" in display_outcomes
    assert "condition_supported" not in display_outcomes
    assert {item.health for item in exported.evidence_health} == {"ready"}
    assert calls == 1
    assert AssessmentWorker(store).run_one(assessment_id) is None
    assert calls == 1


def test_worker_cancellation_is_interrupted_and_not_replayed(
    store: OrchestrationStore,
    project: ProjectConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessment_id = enqueue(store, project)

    async def cancelled(*args: object, **kwargs: object) -> RecheckReport:
        raise KeyboardInterrupt

    monkeypatch.setattr("scopelens.orchestration.worker.recheck_web", cancelled)
    with pytest.raises(KeyboardInterrupt):
        AssessmentWorker(store).run_one(assessment_id)
    result = store.get(assessment_id)
    assert result.status == "interrupted"
    assert result.stages[0].status == "interrupted"
    assert AssessmentWorker(store).run_one(assessment_id) is None


def test_persisted_recheck_round_trip_and_m10_resolution(
    store: OrchestrationStore, project: ProjectConfig, tmp_path: Path
) -> None:
    baseline_time = datetime(2026, 1, 1, tzinfo=UTC)
    baseline = report(tmp_path, baseline_time, vulnerable=True)
    assessment_id = enqueue(store, project)
    token = uuid4()
    store.claim(token, assessment_id)
    stage = store.get(assessment_id).stages[0]
    store.start_stage(assessment_id, stage.id, token)
    current = report(tmp_path, baseline_time + timedelta(minutes=1), vulnerable=False)
    store.persist_recheck(assessment_id, stage.id, token, current, failed=False)
    assert store.finalize(assessment_id, token).status == "completed"

    loaded, health = store.load_recheck(stage.id)
    assert loaded == current.model_copy(
        update={
            "acquisitions": tuple(
                item.model_copy(
                    update={
                        "evidence": item.evidence.model_copy(
                            update={"artifact_path": f"{item.id}/response.http"}
                        )
                    }
                )
                for item in current.acquisitions
                if item.evidence is not None
            )
        }
    )
    assert set(health.values()) == {"ready"}
    baseline_health: dict[UUID, ArtifactHealth] = {
        item.id: "ready" for item in baseline.acquisitions
    }
    comparison = compare_assessments(
        baseline,
        loaded,
        baseline_acquisition_health=baseline_health,
        current_acquisition_health=health,
    )
    directory = next(
        item for item in comparison.results if item.claim.rule_id == DIRECTORY_RULE
    )
    assert directory.state == "resolved"

    first_artifact = loaded.acquisitions[0].evidence
    assert first_artifact is not None
    store.artifacts.path(first_artifact.artifact_path).unlink()
    _, unhealthy = store.load_recheck(stage.id)
    unhealthy_export = load_assessment_report(store, assessment_id)
    assert "missing" in {item.health for item in unhealthy_export.evidence_health}
    comparison = compare_assessments(
        baseline,
        loaded,
        baseline_acquisition_health=baseline_health,
        current_acquisition_health=unhealthy,
    )
    assert all(
        item.state != "resolved"
        for item in comparison.results
        if item.claim.resource == "/"
    )


def test_recheck_target_or_rule_substitution_is_rejected(
    store: OrchestrationStore, project: ProjectConfig, tmp_path: Path
) -> None:
    assessment_id = enqueue(store, project)
    token = uuid4()
    store.claim(token, assessment_id)
    stage = store.get(assessment_id).stages[0]
    store.start_stage(assessment_id, stage.id, token)
    current = report(tmp_path, datetime(2026, 1, 2, tzinfo=UTC), vulnerable=False)
    substituted = current.model_copy(
        update={
            "acquisitions": (
                current.acquisitions[0].model_copy(
                    update={"approved_address": "127.0.0.2"}
                ),
                current.acquisitions[1],
            )
        }
    )
    with pytest.raises(HistoryError, match="planned target"):
        store.persist_recheck(assessment_id, stage.id, token, substituted, failed=False)
    store.finish_stage(
        assessment_id,
        stage.id,
        token,
        "failed",
        reason="invalid_recheck_result",
    )
    store.finalize(assessment_id, token)


@pytest.mark.parametrize(
    "root_complete, expected_directory", [(False, "unknown"), (True, "resolved")]
)
def test_failed_recheck_preserves_only_independently_usable_evidence(
    store: OrchestrationStore,
    project: ProjectConfig,
    tmp_path: Path,
    root_complete: bool,
    expected_directory: str,
) -> None:
    baseline_time = datetime(2026, 2, 1, tzinfo=UTC)
    baseline = report(tmp_path, baseline_time, vulnerable=True)
    assessment_id = enqueue(store, project)
    token = uuid4()
    store.claim(token, assessment_id)
    stage = store.get(assessment_id).stages[0]
    store.start_stage(assessment_id, stage.id, token)
    current = incomplete_report(
        tmp_path, baseline_time + timedelta(minutes=1), root_complete=root_complete
    )
    store.persist_recheck(assessment_id, stage.id, token, current, failed=True)
    assert store.finalize(assessment_id, token).status == "failed"
    loaded, health = store.load_recheck(stage.id)
    assert loaded.assessments[1].outcome == "inconclusive"
    if not root_complete:
        assert all(item.outcome == "inconclusive" for item in loaded.assessments)
    baseline_health: dict[UUID, ArtifactHealth] = {
        item.id: "ready" for item in baseline.acquisitions
    }
    comparison = compare_assessments(
        baseline,
        loaded,
        baseline_acquisition_health=baseline_health,
        current_acquisition_health=health,
    )
    directory = next(
        item for item in comparison.results if item.claim.rule_id == DIRECTORY_RULE
    )
    assert directory.state == expected_directory
    git = next(
        item for item in comparison.results if item.claim.rule_id == GIT_CONFIG_RULE
    )
    assert git.state != "resolved"
    if not root_complete:
        assert all(item.state != "resolved" for item in comparison.results)


def test_history_reconciliation_tracks_recheck_artifact_health(
    store: OrchestrationStore, project: ProjectConfig, tmp_path: Path
) -> None:
    assessment_id = enqueue(store, project)
    token = uuid4()
    store.claim(token, assessment_id)
    stage = store.get(assessment_id).stages[0]
    store.start_stage(assessment_id, stage.id, token)
    current = report(tmp_path, datetime(2026, 1, 3, tzinfo=UTC), vulnerable=False)
    store.persist_recheck(assessment_id, stage.id, token, current, failed=False)
    store.finalize(assessment_id, token)
    loaded, _ = store.load_recheck(stage.id)
    evidence = loaded.acquisitions[0].evidence
    assert evidence is not None
    store.artifacts.path(evidence.artifact_path).write_bytes(b"corrupt")
    issues = History(store.engine, store.artifacts).reconcile()
    assert {
        "stage_id": str(stage.id),
        "issue": "corrupt",
        "path": evidence.artifact_path,
    } in issues
    with store.engine.connect() as connection:
        health = connection.scalar(
            select(s.recheck_artifacts.c.health).where(
                s.recheck_artifacts.c.acquisition_id == loaded.acquisitions[0].id
            )
        )
    assert health == "corrupt"


def test_recheck_database_failure_never_marks_published_artifact_complete(
    store: OrchestrationStore, project: ProjectConfig, tmp_path: Path
) -> None:
    assessment_id = enqueue(store, project)
    token = uuid4()
    store.claim(token, assessment_id)
    stage = store.get(assessment_id).stages[0]
    store.start_stage(assessment_id, stage.id, token)
    current = report(tmp_path, datetime(2026, 3, 1, tzinfo=UTC), vulnerable=False)

    def fail_report_insert(
        connection: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        if "INSERT INTO recheck_reports" in statement:
            raise RuntimeError("controlled transaction failure")

    event.listen(store.engine, "before_cursor_execute", fail_report_insert)
    try:
        with pytest.raises(RuntimeError, match="controlled transaction failure"):
            store.persist_recheck(assessment_id, stage.id, token, current, failed=False)
    finally:
        event.remove(store.engine, "before_cursor_execute", fail_report_insert)

    assert store.get(assessment_id).stages[0].status == "running"
    assert AssessmentWorker(store).reconcile() == [assessment_id]
    assert store.get(assessment_id).status == "interrupted"
    issues = History(store.engine, store.artifacts).reconcile()
    published = {f"{item.id}/response.http" for item in current.acquisitions}
    assert {str(item.id) for item in current.acquisitions} <= {
        item["path"] for item in issues if item["issue"] == "unreferenced"
    }
    assert all(store.artifacts.path(path).is_file() for path in published)
