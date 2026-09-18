import os
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from scopelens.adapters.nuclei_templates import NUCLEI_VERSION, template_revision
from scopelens.api.app import create_app
from scopelens.assessment.models import RecheckReport
from scopelens.assessment.models import assessment_id as compute_assessment_id
from scopelens.config import ProjectConfig
from scopelens.domain.scope import WebTarget
from scopelens.orchestration.store import OrchestrationStore, build_plan
from scopelens.orchestration.worker import AssessmentWorker
from scopelens.storage.artifacts import ArtifactStore
from scopelens.storage.database import database, migrate, single_assessment_worker
from scopelens.storage.history import History
from scopelens.storage.operations import import_history
from tests.postgres import DisposablePostgres
from tests.test_nuclei import CONTEXT, RAW, TARGET
from tests.test_orchestration_history import incomplete_report, report

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("SCOPELENS_POSTGRES_TEST") != "1",
    reason="opt-in disposable PostgreSQL tests require Linux and SCOPELENS_POSTGRES_TEST=1",
)

TOKEN = "test-local-token-0123456789abcdef"


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
                "name": "API orchestration lab",
                "scope": {
                    "network_targets": [{"address": "127.0.0.1", "ports": [8000]}],
                    "web_targets": [
                        {
                            "origin": "https://app.local",
                            "approved_addresses": ["127.0.0.1", "127.0.0.2"],
                        },
                        TARGET.model_dump(mode="json"),
                    ],
                },
            },
            "profiles": [{"id": "conservative", "tcp_ports": [8000]}],
        }
    )


@pytest.fixture
def store(engine: Engine, tmp_path: Path) -> OrchestrationStore:
    return OrchestrationStore(engine, ArtifactStore(tmp_path / "history"))


@pytest.fixture
def client(project: ProjectConfig, store: OrchestrationStore) -> TestClient:
    return TestClient(
        create_app(
            project,
            store,
            AssessmentWorker(store),
            token=TOKEN,
            allowed_origins=("http://localhost:5173",),
        ),
        raise_server_exceptions=False,
    )


def auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}"}


def persist_recheck(
    store: OrchestrationStore,
    project: ProjectConfig,
    root: Path,
    started: datetime,
    *,
    vulnerable: bool,
    address: str = "127.0.0.1",
    origin: str = "https://app.local",
    incomplete: bool = False,
) -> tuple[UUID, UUID]:
    request = next(
        item
        for item in build_plan(project, "conservative", ("web_recheck",))
        if item.web_target is not None
        and item.web_target.origin == origin
        and item.web_target.approved_addresses == (address,)
    )
    assessment_id = uuid4()
    manifest = store.enqueue(assessment_id, project, (request,))
    stage_id = manifest.stages[0].id
    token = uuid4()
    assert store.claim(token, assessment_id) == assessment_id
    store.start_stage(assessment_id, stage_id, token)
    result = (
        incomplete_report(root, started, root_complete=False)
        if incomplete
        else report(root, started, vulnerable=vulnerable)
    )
    if address != "127.0.0.1":
        result = result.model_copy(
            update={
                "acquisitions": tuple(
                    item.model_copy(update={"approved_address": address})
                    for item in result.acquisitions
                )
            }
        )
    if origin != "https://app.local":
        acquisitions = tuple(
            item.model_copy(update={"origin": origin}) for item in result.acquisitions
        )
        assessments = []
        for item in result.assessments:
            claim = item.claim.model_copy(update={"origin": origin})
            assessments.append(
                item.model_copy(
                    update={
                        "id": compute_assessment_id(result.project_id, claim),
                        "claim": claim,
                    }
                )
            )
        result = RecheckReport(
            project_id=result.project_id,
            acquisitions=acquisitions,
            assessments=tuple(assessments),
        )
    store.persist_recheck(assessment_id, stage_id, token, result, failed=incomplete)
    store.finalize(assessment_id, token)
    return assessment_id, stage_id


def persist_nuclei(
    store: OrchestrationStore, project: ProjectConfig, root: Path
) -> UUID:
    run_id = uuid4()
    source = root / f"{run_id}.jsonl"
    source.write_bytes(RAW)
    import_history(
        History(store.engine, store.artifacts),
        project,
        "conservative",
        run_id,
        source,
        scanner="nuclei",
        web_target=WebTarget.model_validate(TARGET),
        scanner_version=NUCLEI_VERSION,
        template_bundle=template_revision(),
        captured_at=CONTEXT.captured_at,
    )
    return run_id


def test_assessment_creation_is_explicit_durable_and_nonexecuting(
    client: TestClient,
) -> None:
    assessment_id = uuid4()
    payload = {
        "assessment_id": str(assessment_id),
        "project_id": "orchestration-lab",
        "profile_id": "conservative",
        "stages": ["httpx", "nuclei"],
    }
    response = client.post("/api/v1/assessments", json=payload, headers=auth())
    assert response.status_code == 201
    created = response.json()
    assert created["id"] == str(assessment_id)
    assert created["status"] == "pending"
    assert [item["request"]["kind"] for item in created["stages"]] == [
        "httpx",
        "httpx",
        "httpx",
        "nuclei",
        "nuclei",
        "nuclei",
    ]
    assert all(item["status"] == "pending" for item in created["stages"])
    assert "worker_token" not in created

    duplicate = client.post("/api/v1/assessments", json=payload, headers=auth())
    assert duplicate.status_code == 409
    detail = client.get(f"/api/v1/assessments/{assessment_id}", headers=auth())
    assert detail.status_code == 200
    assert detail.json() == created


@pytest.mark.parametrize(
    "payload,status_code",
    [
        (
            {
                "assessment_id": "00000000-0000-4000-8000-000000000001",
                "project_id": "unknown",
                "profile_id": "conservative",
                "stages": ["httpx"],
            },
            404,
        ),
        (
            {
                "assessment_id": "00000000-0000-4000-8000-000000000002",
                "project_id": "orchestration-lab",
                "profile_id": "unknown",
                "stages": ["httpx"],
            },
            404,
        ),
        (
            {
                "assessment_id": "00000000-0000-4000-8000-000000000003",
                "project_id": "orchestration-lab",
                "profile_id": "conservative",
                "stages": ["httpx", "httpx"],
            },
            409,
        ),
        (
            {
                "assessment_id": "00000000-0000-4000-8000-000000000004",
                "project_id": "orchestration-lab",
                "profile_id": "conservative",
                "stages": ["other"],
            },
            422,
        ),
        (
            {
                "assessment_id": "00000000-0000-4000-8000-000000000005",
                "project_id": "orchestration-lab",
                "profile_id": "conservative",
                "stages": ["httpx"],
                "origin": "https://untrusted.example",
            },
            422,
        ),
    ],
)
def test_creation_rejects_unknown_or_client_defined_plan_data(
    client: TestClient, payload: dict[str, object], status_code: int
) -> None:
    response = client.post("/api/v1/assessments", json=payload, headers=auth())
    assert response.status_code == status_code


def test_web_only_configuration_cannot_create_nmap_plan(
    engine: Engine, tmp_path: Path
) -> None:
    config = ProjectConfig.model_validate(
        {
            "project": {
                "id": "web-only",
                "name": "Web only",
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
    store = OrchestrationStore(engine, ArtifactStore(tmp_path / "web-only"))
    api = TestClient(
        create_app(config, store, AssessmentWorker(store), token=TOKEN),
        raise_server_exceptions=False,
    )
    response = api.post(
        "/api/v1/assessments",
        json={
            "assessment_id": str(uuid4()),
            "project_id": "web-only",
            "profile_id": "safe",
            "stages": ["nmap"],
        },
        headers=auth(),
    )
    assert response.status_code == 403


def test_focused_retest_accepts_only_configured_origin_and_address(
    client: TestClient,
) -> None:
    payload = {
        "assessment_id": str(uuid4()),
        "project_id": "orchestration-lab",
        "profile_id": "conservative",
        "origin": "https://app.local",
        "approved_address": "127.0.0.1",
    }
    accepted = client.post("/api/v1/retests", json=payload, headers=auth())
    assert accepted.status_code == 201
    stages = accepted.json()["stages"]
    assert len(stages) == 1
    assert stages[0]["request"]["kind"] == "web_recheck"
    assert stages[0]["request"]["resources"] == ["/", "/.git/config"]

    for key, value in (
        ("origin", "https://new.example"),
        ("approved_address", "127.0.0.3"),
    ):
        rejected = dict(payload, assessment_id=str(uuid4()), **{key: value})
        response = client.post("/api/v1/retests", json=rejected, headers=auth())
        assert response.status_code == 403

    unsafe_fields: tuple[tuple[str, object], ...] = (
        ("resource", "/admin"),
        ("method", "POST"),
        ("flags", ["--unsafe"]),
        ("template", "/tmp/custom.yaml"),
        ("peer_address", "127.0.0.3"),
        ("redirect", "https://new.example"),
    )
    for field, unsafe_value in unsafe_fields:
        arbitrary = dict(payload, assessment_id=str(uuid4()), **{field: unsafe_value})
        assert (
            client.post("/api/v1/retests", json=arbitrary, headers=auth()).status_code
            == 422
        )


def test_worker_executes_once_and_respects_single_worker_lock(
    client: TestClient, store: OrchestrationStore, project: ProjectConfig
) -> None:
    request = build_plan(project, "conservative", ("web_recheck",))[0]
    skipped = request.model_copy(update={"skip_reason": "profile_omission"})
    assessment_id = uuid4()
    store.enqueue(assessment_id, project, (skipped,))
    response = client.post(
        f"/api/v1/assessments/{assessment_id}/execute", headers=auth()
    )
    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert response.json()["stages"][0]["status"] == "skipped"
    replay = client.post(f"/api/v1/assessments/{assessment_id}/execute", headers=auth())
    assert replay.status_code == 409

    pending_id = uuid4()
    store.enqueue(pending_id, project, (skipped,))
    with single_assessment_worker(store.engine):
        busy = client.post(f"/api/v1/assessments/{pending_id}/execute", headers=auth())
    assert busy.status_code == 409
    assert busy.json()["error"]["code"] == "worker_busy"
    assert store.get(pending_id).status == "pending"


@pytest.mark.parametrize("terminal", ["failed", "interrupted"])
def test_terminal_assessments_cannot_be_replayed(
    client: TestClient,
    store: OrchestrationStore,
    project: ProjectConfig,
    terminal: str,
) -> None:
    request = build_plan(project, "conservative", ("web_recheck",))[0]
    assessment_id = uuid4()
    stage = store.enqueue(assessment_id, project, (request,)).stages[0]
    token = uuid4()
    assert store.claim(token, assessment_id) == assessment_id
    store.start_stage(assessment_id, stage.id, token)
    store.finish_stage(
        assessment_id,
        stage.id,
        token,
        terminal,
        reason=f"test_{terminal}",
    )
    store.finalize(assessment_id, token)
    response = client.post(
        f"/api/v1/assessments/{assessment_id}/execute", headers=auth()
    )
    assert response.status_code == 409
    assert store.get(assessment_id).status == terminal


def test_correlation_and_assessment_use_explicit_run_membership(
    client: TestClient,
    store: OrchestrationStore,
    project: ProjectConfig,
    tmp_path: Path,
) -> None:
    run_id = persist_nuclei(store, project, tmp_path)
    payload = {"project_id": "orchestration-lab", "run_ids": [str(run_id)]}
    correlation = client.post(
        "/api/v1/analysis/correlation", json=payload, headers=auth()
    )
    assessment = client.post(
        "/api/v1/analysis/assessment", json=payload, headers=auth()
    )
    assert correlation.status_code == 200
    assert correlation.json()["sources"][0]["run_id"] == str(run_id)
    assert "relative_path" not in correlation.text
    assert assessment.status_code == 200
    assert assessment.json()["run_ids"] == [str(run_id)]
    assert all(item["evidence_used"] for item in assessment.json()["assessments"])
    assert all(item["limitations"] for item in assessment.json()["assessments"])
    assert (
        client.post(
            "/api/v1/analysis/correlation",
            json={"project_id": "orchestration-lab"},
            headers=auth(),
        ).status_code
        == 422
    )


def test_persisted_recheck_exposes_current_health_without_paths(
    client: TestClient,
    store: OrchestrationStore,
    project: ProjectConfig,
    tmp_path: Path,
) -> None:
    assessment_id, stage_id = persist_recheck(
        store,
        project,
        tmp_path,
        datetime(2026, 9, 18, 10, tzinfo=UTC),
        vulnerable=False,
    )
    route = f"/api/v1/assessments/{assessment_id}/stages/{stage_id}/recheck"
    response = client.get(route, headers=auth())
    assert response.status_code == 200
    body = response.json()
    assert body["assessment_id"] == str(assessment_id)
    assert body["stage_id"] == str(stage_id)
    assert body["acquisitions"][0]["approved_address"] == "127.0.0.1"
    assert body["acquisitions"][0]["started_at"].startswith("2026-09-18T10:00:00")
    assert body["acquisitions"][0]["evidence"]["health"] == "ready"
    assert "artifact_path" not in response.text
    assert str(store.artifacts.root) not in response.text

    durable, _ = store.load_recheck(stage_id)
    relative = durable.acquisitions[0].evidence
    assert relative is not None
    store.artifacts.path(relative.artifact_path).write_bytes(b"corrupt")
    damaged = client.get(route, headers=auth())
    assert damaged.status_code == 200
    assert damaged.json()["acquisitions"][0]["evidence"]["health"] == "corrupt"
    store.artifacts.path(relative.artifact_path).unlink()
    missing = client.get(route, headers=auth())
    assert missing.status_code == 200
    assert missing.json()["acquisitions"][0]["evidence"]["health"] == "missing"


def test_persisted_recheck_comparison_preserves_m10_resolution_rules(
    client: TestClient,
    store: OrchestrationStore,
    project: ProjectConfig,
    tmp_path: Path,
) -> None:
    baseline_id, baseline_stage = persist_recheck(
        store,
        project,
        tmp_path,
        datetime(2026, 9, 18, 11, tzinfo=UTC),
        vulnerable=True,
    )
    current_id, current_stage = persist_recheck(
        store,
        project,
        tmp_path,
        datetime(2026, 9, 18, 12, tzinfo=UTC),
        vulnerable=False,
    )
    payload = {
        "project_id": "orchestration-lab",
        "baseline": {
            "basis": "persisted_recheck",
            "assessment_id": str(baseline_id),
            "stage_id": str(baseline_stage),
        },
        "current": {
            "basis": "persisted_recheck",
            "assessment_id": str(current_id),
            "stage_id": str(current_stage),
        },
    }
    response = client.post("/api/v1/analysis/comparison", json=payload, headers=auth())
    assert response.status_code == 200
    resolved = [
        item for item in response.json()["results"] if item["state"] == "resolved"
    ]
    assert resolved
    assert all(
        item["baseline"]["outcome"] == "supported_positive"
        and item["current"]["outcome"] == "supported_negative"
        and item["coverage"]["status"] == "comparable"
        for item in resolved
    )

    incomplete_id, incomplete_stage = persist_recheck(
        store,
        project,
        tmp_path,
        datetime(2026, 9, 18, 13, tzinfo=UTC),
        vulnerable=False,
        incomplete=True,
    )
    payload["current"] = {
        "basis": "persisted_recheck",
        "assessment_id": str(incomplete_id),
        "stage_id": str(incomplete_stage),
    }
    uncertain = client.post("/api/v1/analysis/comparison", json=payload, headers=auth())
    assert uncertain.status_code == 200
    assert "resolved" not in {item["state"] for item in uncertain.json()["results"]}


def test_different_backend_cannot_resolve_baseline_condition(
    client: TestClient,
    store: OrchestrationStore,
    project: ProjectConfig,
    tmp_path: Path,
) -> None:
    baseline_id, baseline_stage = persist_recheck(
        store,
        project,
        tmp_path,
        datetime(2026, 9, 18, 14, tzinfo=UTC),
        vulnerable=True,
        address="127.0.0.1",
    )
    current_id, current_stage = persist_recheck(
        store,
        project,
        tmp_path,
        datetime(2026, 9, 18, 15, tzinfo=UTC),
        vulnerable=False,
        address="127.0.0.2",
    )
    response = client.post(
        "/api/v1/analysis/comparison",
        json={
            "project_id": "orchestration-lab",
            "baseline": {
                "basis": "persisted_recheck",
                "assessment_id": str(baseline_id),
                "stage_id": str(baseline_stage),
            },
            "current": {
                "basis": "persisted_recheck",
                "assessment_id": str(current_id),
                "stage_id": str(current_stage),
            },
        },
        headers=auth(),
    )
    assert response.status_code == 200
    assert "resolved" not in {item["state"] for item in response.json()["results"]}


def test_stored_nuclei_without_backend_context_cannot_be_resolved(
    client: TestClient,
    store: OrchestrationStore,
    project: ProjectConfig,
    tmp_path: Path,
) -> None:
    baseline_run = persist_nuclei(store, project, tmp_path)
    current_id, current_stage = persist_recheck(
        store,
        project,
        tmp_path,
        datetime.now(UTC) + timedelta(hours=1),
        vulnerable=False,
        origin=TARGET.origin,
    )
    response = client.post(
        "/api/v1/analysis/comparison",
        json={
            "project_id": "orchestration-lab",
            "baseline": {
                "basis": "stored_runs",
                "run_ids": [str(baseline_run)],
            },
            "current": {
                "basis": "persisted_recheck",
                "assessment_id": str(current_id),
                "stage_id": str(current_stage),
            },
        },
        headers=auth(),
    )
    assert response.status_code == 200
    results = response.json()["results"]
    assert "resolved" not in {item["state"] for item in results}
    baseline_results = [item for item in results if item["baseline"] is not None]
    assert baseline_results
    assert all(
        item["state"] == "unknown" and item["reason"] == "backend_context_unavailable"
        for item in baseline_results
    )
