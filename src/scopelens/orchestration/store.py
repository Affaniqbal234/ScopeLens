import json
from collections.abc import Sequence
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import Engine, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from scopelens.adapters.nuclei_templates import template_revision
from scopelens.assessment.models import AcquisitionEvidence, RecheckReport
from scopelens.assessment.rules import (
    DIRECTORY_RULE,
    GIT_CONFIG_RULE,
    HSTS_RULE,
    RULE_VERSION,
)
from scopelens.comparison.compare import ArtifactHealth
from scopelens.config import ProjectConfig
from scopelens.domain.scope import NetworkTarget, ScopeViolation, WebTarget
from scopelens.execution.httpx import HTTPX_EXECUTABLE
from scopelens.execution.httpx import build_command as httpx_command
from scopelens.execution.nmap import build_command as nmap_command
from scopelens.execution.nuclei import NUCLEI_EXECUTABLE
from scopelens.execution.nuclei import build_command as nuclei_command
from scopelens.orchestration.models import (
    AssessmentManifest,
    PlannedStage,
    StageKind,
    StageRequest,
)
from scopelens.storage import schema as s
from scopelens.storage.artifacts import ArtifactError, ArtifactStore
from scopelens.storage.database import HistoryError
from scopelens.storage.operations import read_input
from scopelens.storage.snapshots import scope_snapshot


def build_plan(
    config: ProjectConfig, profile_id: str, kinds: Sequence[StageKind]
) -> tuple[StageRequest, ...]:
    config = ProjectConfig.model_validate(config.model_dump())
    if not kinds:
        raise HistoryError("select at least one assessment stage")
    if len(set(kinds)) != len(kinds):
        raise HistoryError("select each assessment stage kind once")
    requests: list[StageRequest] = []
    for kind in kinds:
        if kind == "nmap":
            nmap_command(config, profile_id)
            profile = next(item for item in config.profiles if item.id == profile_id)
            requests.append(
                StageRequest(
                    kind=kind,
                    profile_id=profile_id,
                    network_targets=tuple(
                        NetworkTarget(address=item.address, ports=profile.tcp_ports)
                        for item in config.project.scope.network_targets
                    ),
                    resources=("network-services",),
                    planned_run_id=uuid4(),
                )
            )
            continue
        for configured in sorted(
            config.project.scope.web_targets, key=lambda item: item.origin
        ):
            for address in configured.approved_addresses:
                target = WebTarget(
                    origin=configured.origin, approved_addresses=(address,)
                )
                if kind == "httpx":
                    httpx_command(config, profile_id, target, HTTPX_EXECUTABLE)
                    resources: tuple[str, ...] = ("/",)
                    revision = None
                    run_id = uuid4()
                elif kind == "nuclei":
                    nuclei_command(config, profile_id, target, NUCLEI_EXECUTABLE)
                    resources = tuple(sorted(("/", "/.git/config")))
                    revision = template_revision()
                    run_id = uuid4()
                else:
                    config.project.scope.authorize_web(target.origin, (address,))
                    resources = ("/", "/.git/config")
                    revision = f"assessment-v1:{RULE_VERSION}"
                    run_id = None
                requests.append(
                    StageRequest(
                        kind=kind,
                        profile_id=profile_id,
                        web_target=target,
                        resources=resources,
                        rule_revision=revision,
                        planned_run_id=run_id,
                    )
                )
    return tuple(requests)


class OrchestrationStore:
    def __init__(self, engine: Engine, artifacts: ArtifactStore) -> None:
        self.engine = engine
        self.artifacts = artifacts

    @staticmethod
    def _validate_request(config: ProjectConfig, request: StageRequest) -> None:
        profile = next(
            (item for item in config.profiles if item.id == request.profile_id), None
        )
        if profile is None:
            raise HistoryError("unknown assessment profile")
        if request.kind == "nmap":
            expected = tuple(
                NetworkTarget(address=item.address, ports=profile.tcp_ports)
                for item in config.project.scope.network_targets
            )
            if request.network_targets != expected:
                raise ScopeViolation("Nmap plan differs from authorized network scope")
            nmap_command(config, request.profile_id)
            return
        assert request.web_target is not None
        target = request.web_target
        config.project.scope.authorize_web(target.origin, target.approved_addresses)
        if request.kind == "httpx":
            if request.resources != ("/",) or request.rule_revision is not None:
                raise HistoryError("invalid httpx stage contract")
            httpx_command(config, request.profile_id, target, HTTPX_EXECUTABLE)
        elif request.kind == "nuclei":
            if request.resources != ("/", "/.git/config"):
                raise HistoryError("invalid Nuclei resources")
            if request.rule_revision != template_revision():
                raise HistoryError("invalid Nuclei template revision")
            nuclei_command(config, request.profile_id, target, NUCLEI_EXECUTABLE)
        elif request.resources != ("/", "/.git/config") or request.rule_revision != (
            f"assessment-v1:{RULE_VERSION}"
        ):
            raise HistoryError("invalid web recheck rule set")

    def enqueue(
        self,
        assessment_id: UUID,
        config: ProjectConfig,
        requests: Sequence[StageRequest],
    ) -> AssessmentManifest:
        config = ProjectConfig.model_validate(config.model_dump())
        if not requests:
            raise HistoryError("assessment requires at least one stage")
        fingerprints = {
            json.dumps(
                request.model_dump(mode="json", exclude={"planned_run_id"}),
                sort_keys=True,
                separators=(",", ":"),
            )
            for request in requests
        }
        if len(fingerprints) != len(requests):
            raise HistoryError("assessment cannot repeat identical planned work")
        for request in requests:
            self._validate_request(config, request)
        snapshot_id, scope = scope_snapshot(config)
        with self.engine.begin() as connection:
            planned_run_ids = tuple(
                request.planned_run_id
                for request in requests
                if request.planned_run_id is not None
            )
            if len(planned_run_ids) != len(set(planned_run_ids)):
                raise HistoryError("planned scanner run identifiers must be unique")
            if (
                planned_run_ids
                and connection.scalar(
                    select(s.runs.c.id).where(s.runs.c.id.in_(planned_run_ids)).limit(1)
                )
                is not None
            ):
                raise HistoryError("planned scanner run identifier already exists")
            if (
                connection.scalar(
                    select(s.assessment_manifests.c.id).where(
                        s.assessment_manifests.c.id == assessment_id
                    )
                )
                is not None
            ):
                raise HistoryError("assessment identifier already exists")
            connection.execute(
                pg_insert(s.projects)
                .values(id=config.project.id, name=config.project.name)
                .on_conflict_do_nothing()
            )
            connection.execute(
                pg_insert(s.scope_snapshots)
                .values(id=snapshot_id, project_id=config.project.id, scope=scope)
                .on_conflict_do_nothing()
            )
            connection.execute(
                insert(s.assessment_manifests).values(
                    id=assessment_id,
                    project_id=config.project.id,
                    scope_snapshot_id=snapshot_id,
                    config_snapshot=config.model_dump(mode="json"),
                    status="pending",
                )
            )
            for ordinal, request in enumerate(requests):
                connection.execute(
                    insert(s.assessment_stages).values(
                        id=uuid4(),
                        assessment_id=assessment_id,
                        project_id=config.project.id,
                        ordinal=ordinal,
                        kind=request.kind,
                        request=request.model_dump(mode="json"),
                        planned_run_id=request.planned_run_id,
                        status="pending",
                    )
                )
        return self.get(assessment_id)

    def get(self, assessment_id: UUID) -> AssessmentManifest:
        with self.engine.connect() as connection:
            row = (
                connection.execute(
                    select(s.assessment_manifests).where(
                        s.assessment_manifests.c.id == assessment_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise HistoryError("assessment does not exist")
            stage_rows = (
                connection.execute(
                    select(s.assessment_stages)
                    .where(s.assessment_stages.c.assessment_id == assessment_id)
                    .order_by(s.assessment_stages.c.ordinal)
                )
                .mappings()
                .all()
            )
        parsed_stages = []
        for item in stage_rows:
            request = StageRequest.model_validate(item["request"])
            if (
                item["kind"] != request.kind
                or item["planned_run_id"] != request.planned_run_id
            ):
                raise HistoryError("stored assessment stage contract is inconsistent")
            parsed_stages.append(
                PlannedStage(
                    id=item["id"],
                    ordinal=item["ordinal"],
                    request=request,
                    status=item["status"],
                    result_run_id=item["result_run_id"],
                    started_at=item["started_at"],
                    finished_at=item["finished_at"],
                    reason=item["reason"],
                )
            )
        return AssessmentManifest(
            id=row["id"],
            project_id=row["project_id"],
            scope_snapshot_id=row["scope_snapshot_id"],
            status=row["status"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            worker_token=row["worker_token"],
            reason=row["reason"],
            stages=tuple(parsed_stages),
        )

    def config(self, assessment_id: UUID) -> ProjectConfig:
        with self.engine.connect() as connection:
            row = (
                connection.execute(
                    select(
                        s.assessment_manifests.c.project_id,
                        s.assessment_manifests.c.scope_snapshot_id,
                        s.assessment_manifests.c.config_snapshot,
                    ).where(s.assessment_manifests.c.id == assessment_id)
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise HistoryError("assessment does not exist")
        config = ProjectConfig.model_validate(row["config_snapshot"])
        snapshot_id, _ = scope_snapshot(config)
        if (
            config.project.id != row["project_id"]
            or snapshot_id != row["scope_snapshot_id"]
        ):
            raise HistoryError(
                "stored assessment authorization snapshot is inconsistent"
            )
        return config

    def validate_stage(self, config: ProjectConfig, request: StageRequest) -> None:
        self._validate_request(config, request)

    def list_manifests(self, project_id: str) -> list[AssessmentManifest]:
        with self.engine.connect() as connection:
            identifiers = connection.scalars(
                select(s.assessment_manifests.c.id)
                .where(s.assessment_manifests.c.project_id == project_id)
                .order_by(
                    s.assessment_manifests.c.created_at,
                    s.assessment_manifests.c.id,
                )
            ).all()
        return [self.get(identifier) for identifier in identifiers]

    def reconcile_stale(self) -> list[UUID]:
        with self.engine.begin() as connection:
            rows = connection.execute(
                select(s.assessment_manifests.c.id)
                .where(s.assessment_manifests.c.status == "running")
                .with_for_update()
            ).all()
            identifiers = [row.id for row in rows]
            if identifiers:
                connection.execute(
                    update(s.assessment_stages)
                    .where(
                        s.assessment_stages.c.assessment_id.in_(identifiers),
                        s.assessment_stages.c.status == "running",
                    )
                    .values(
                        status="interrupted",
                        finished_at=func.now(),
                        reason="worker_disconnected",
                    )
                )
                running_runs = connection.scalars(
                    select(s.assessment_stages.c.planned_run_id).where(
                        s.assessment_stages.c.assessment_id.in_(identifiers),
                        s.assessment_stages.c.planned_run_id.is_not(None),
                    )
                ).all()
                if running_runs:
                    values = {
                        "status": "interrupted",
                        "finished_at": func.now(),
                        "error_code": "owner_disconnected",
                    }
                    connection.execute(
                        update(s.runs)
                        .where(
                            s.runs.c.id.in_(running_runs), s.runs.c.status == "running"
                        )
                        .values(**values)
                    )
                    connection.execute(
                        update(s.stages)
                        .where(
                            s.stages.c.run_id.in_(running_runs),
                            s.stages.c.status == "running",
                        )
                        .values(**values)
                    )
                connection.execute(
                    update(s.assessment_manifests)
                    .where(
                        s.assessment_manifests.c.id.in_(identifiers),
                        s.assessment_manifests.c.status == "running",
                    )
                    .values(
                        status="interrupted",
                        worker_token=None,
                        finished_at=func.now(),
                        reason="worker_disconnected",
                    )
                )
        return identifiers

    def claim(
        self, worker_token: UUID, assessment_id: UUID | None = None
    ) -> UUID | None:
        with self.engine.begin() as connection:
            query = select(s.assessment_manifests.c.id).where(
                s.assessment_manifests.c.status == "pending"
            )
            if assessment_id is not None:
                query = query.where(s.assessment_manifests.c.id == assessment_id)
            claimed_value = connection.scalar(
                query.order_by(
                    s.assessment_manifests.c.created_at,
                    s.assessment_manifests.c.id,
                )
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if claimed_value is None:
                return None
            claimed = UUID(str(claimed_value))
            result = connection.execute(
                update(s.assessment_manifests)
                .where(
                    s.assessment_manifests.c.id == claimed,
                    s.assessment_manifests.c.status == "pending",
                )
                .values(
                    status="running", worker_token=worker_token, started_at=func.now()
                )
            )
            if result.rowcount != 1:
                raise HistoryError("assessment claim changed concurrently")
            return claimed

    def start_stage(self, assessment_id: UUID, stage_id: UUID, token: UUID) -> None:
        with self.engine.begin() as connection:
            result = connection.execute(
                update(s.assessment_stages)
                .where(
                    s.assessment_stages.c.id == stage_id,
                    s.assessment_stages.c.assessment_id == assessment_id,
                    s.assessment_stages.c.status == "pending",
                    select(s.assessment_manifests.c.worker_token)
                    .where(s.assessment_manifests.c.id == assessment_id)
                    .scalar_subquery()
                    == token,
                )
                .values(status="running", started_at=func.now())
            )
            if result.rowcount != 1:
                raise HistoryError("stage cannot be started from its current state")

    def skip_stage(
        self, assessment_id: UUID, stage_id: UUID, token: UUID, reason: str
    ) -> None:
        with self.engine.begin() as connection:
            owner = connection.scalar(
                select(s.assessment_manifests.c.worker_token).where(
                    s.assessment_manifests.c.id == assessment_id,
                    s.assessment_manifests.c.status == "running",
                )
            )
            if owner != token:
                raise HistoryError("assessment is not owned by this worker")
            result = connection.execute(
                update(s.assessment_stages)
                .where(
                    s.assessment_stages.c.id == stage_id,
                    s.assessment_stages.c.assessment_id == assessment_id,
                    s.assessment_stages.c.status == "pending",
                )
                .values(status="skipped", finished_at=func.now(), reason=reason)
            )
            if result.rowcount != 1:
                raise HistoryError("stage cannot be skipped from its current state")

    def finish_stage(
        self,
        assessment_id: UUID,
        stage_id: UUID,
        token: UUID,
        status: str,
        *,
        reason: str | None = None,
        result_run_id: UUID | None = None,
    ) -> None:
        if status not in ("completed", "failed", "interrupted"):
            raise HistoryError("invalid terminal stage status")
        with self.engine.begin() as connection:
            owner = connection.scalar(
                select(s.assessment_manifests.c.worker_token).where(
                    s.assessment_manifests.c.id == assessment_id,
                    s.assessment_manifests.c.status == "running",
                )
            )
            if owner != token:
                raise HistoryError("assessment is not owned by this worker")
            result = connection.execute(
                update(s.assessment_stages)
                .where(
                    s.assessment_stages.c.id == stage_id,
                    s.assessment_stages.c.assessment_id == assessment_id,
                    s.assessment_stages.c.status == "running",
                )
                .values(
                    status=status,
                    finished_at=func.now(),
                    reason=reason,
                    result_run_id=result_run_id,
                )
            )
            if result.rowcount != 1:
                raise HistoryError("stage cannot be finished from its current state")

    def persist_recheck(
        self,
        assessment_id: UUID,
        stage_id: UUID,
        token: UUID,
        report: RecheckReport,
        *,
        failed: bool,
    ) -> None:
        manifest = self.get(assessment_id)
        if report.project_id != manifest.project_id:
            raise HistoryError("recheck report belongs to another project")
        stage = next((item for item in manifest.stages if item.id == stage_id), None)
        if stage is None or stage.request.kind != "web_recheck":
            raise HistoryError("recheck result does not match its planned stage")
        with self.engine.connect() as connection:
            owner = connection.scalar(
                select(s.assessment_manifests.c.worker_token).where(
                    s.assessment_manifests.c.id == assessment_id,
                    s.assessment_manifests.c.status == "running",
                )
            )
            running = connection.scalar(
                select(s.assessment_stages.c.id).where(
                    s.assessment_stages.c.id == stage_id,
                    s.assessment_stages.c.assessment_id == assessment_id,
                    s.assessment_stages.c.status == "running",
                )
            )
        if owner != token or running is None:
            raise HistoryError("recheck stage is not owned by this worker")
        target = stage.request.web_target
        assert target is not None
        if (
            tuple(item.resource for item in report.acquisitions)
            != stage.request.resources
            or any(
                item.origin != target.origin
                or (item.approved_address,) != target.approved_addresses
                for item in report.acquisitions
            )
            or {item.claim.rule_id for item in report.assessments}
            != {DIRECTORY_RULE, GIT_CONFIG_RULE, HSTS_RULE}
        ):
            raise HistoryError(
                "recheck result differs from the planned target or rules"
            )
        artifacts: list[dict[str, object]] = []
        acquisitions = []
        for acquisition in report.acquisitions:
            evidence = acquisition.evidence
            if evidence is None:
                acquisitions.append(acquisition)
                continue
            raw = read_input(Path(evidence.artifact_path))
            if (
                len(raw) != evidence.size_bytes
                or sha256(raw).hexdigest() != evidence.artifact_sha256
            ):
                raise ArtifactError("recheck artifact differs from captured evidence")
            relative, digest, size = self.artifacts.publish(
                acquisition.id, "response.http", raw
            )
            artifacts.append(
                {
                    "acquisition_id": acquisition.id,
                    "stage_id": stage_id,
                    "project_id": report.project_id,
                    "relative_path": relative,
                    "sha256": digest,
                    "size_bytes": size,
                    "health": "ready",
                }
            )
            acquisitions.append(
                acquisition.model_copy(
                    update={
                        "evidence": AcquisitionEvidence(
                            artifact_path=relative,
                            artifact_sha256=digest,
                            size_bytes=size,
                        )
                    }
                )
            )
        durable = report.model_copy(update={"acquisitions": tuple(acquisitions)})
        with self.engine.begin() as connection:
            owner = connection.scalar(
                select(s.assessment_manifests.c.worker_token).where(
                    s.assessment_manifests.c.id == assessment_id,
                    s.assessment_manifests.c.status == "running",
                )
            )
            if owner != token:
                raise HistoryError("assessment is not owned by this worker")
            connection.execute(
                insert(s.recheck_reports).values(
                    stage_id=stage_id,
                    project_id=report.project_id,
                    report=durable.model_dump(mode="json"),
                )
            )
            if artifacts:
                connection.execute(insert(s.recheck_artifacts), artifacts)
            result = connection.execute(
                update(s.assessment_stages)
                .where(
                    s.assessment_stages.c.id == stage_id,
                    s.assessment_stages.c.assessment_id == assessment_id,
                    s.assessment_stages.c.status == "running",
                )
                .values(
                    status="failed" if failed else "completed",
                    finished_at=func.now(),
                    reason="incomplete_recheck" if failed else None,
                )
            )
            if result.rowcount != 1:
                raise HistoryError("recheck stage cannot be completed")

    def load_recheck(
        self, stage_id: UUID
    ) -> tuple[RecheckReport, dict[UUID, ArtifactHealth]]:
        with self.engine.connect() as connection:
            row = (
                connection.execute(
                    select(s.recheck_reports).where(
                        s.recheck_reports.c.stage_id == stage_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise HistoryError("recheck result does not exist")
            artifact_rows = (
                connection.execute(
                    select(s.recheck_artifacts).where(
                        s.recheck_artifacts.c.stage_id == stage_id
                    )
                )
                .mappings()
                .all()
            )
        report = RecheckReport.model_validate(row["report"])
        recorded = {item["acquisition_id"]: item for item in artifact_rows}
        evidence_ids = {
            acquisition.id
            for acquisition in report.acquisitions
            if acquisition.evidence is not None
        }
        if set(recorded) != evidence_ids:
            raise HistoryError("stored recheck artifact linkage is inconsistent")
        health: dict[UUID, ArtifactHealth] = {}
        for acquisition in report.acquisitions:
            evidence = acquisition.evidence
            if evidence is None:
                continue
            item = recorded.get(acquisition.id)
            state: ArtifactHealth = "ready"
            if (
                item is None
                or item["relative_path"] != evidence.artifact_path
                or item["sha256"] != evidence.artifact_sha256
                or item["size_bytes"] != evidence.size_bytes
            ):
                state = "corrupt"
            else:
                try:
                    raw = self.artifacts.read(item["relative_path"])
                    if (
                        len(raw) != item["size_bytes"]
                        or sha256(raw).hexdigest() != item["sha256"]
                    ):
                        state = "corrupt"
                except FileNotFoundError:
                    state = "missing"
                except OSError, ArtifactError:
                    state = "corrupt"
            health[acquisition.id] = state
        return report, health

    def finalize(self, assessment_id: UUID, token: UUID) -> AssessmentManifest:
        with self.engine.begin() as connection:
            owner = connection.scalar(
                select(s.assessment_manifests.c.worker_token).where(
                    s.assessment_manifests.c.id == assessment_id,
                    s.assessment_manifests.c.status == "running",
                )
            )
            if owner != token:
                raise HistoryError("assessment is not owned by this worker")
            states = tuple(
                connection.scalars(
                    select(s.assessment_stages.c.status).where(
                        s.assessment_stages.c.assessment_id == assessment_id
                    )
                )
            )
            if "running" in states or (
                "pending" in states and "interrupted" not in states
            ):
                raise HistoryError("assessment still has unfinished stages")
            if "interrupted" in states:
                status, reason = "interrupted", "stage_interrupted"
            elif "failed" in states:
                status, reason = "failed", "stage_failed"
            else:
                status, reason = "completed", None
            result = connection.execute(
                update(s.assessment_manifests)
                .where(
                    s.assessment_manifests.c.id == assessment_id,
                    s.assessment_manifests.c.status == "running",
                    s.assessment_manifests.c.worker_token == token,
                )
                .values(
                    status=status,
                    worker_token=None,
                    finished_at=func.now(),
                    reason=reason,
                )
            )
            if result.rowcount != 1:
                raise HistoryError("assessment could not be finalized")
        return self.get(assessment_id)
