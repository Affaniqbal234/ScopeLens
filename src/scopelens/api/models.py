from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from scopelens.adapters.base import ImportContext, ParsedReport
from scopelens.analysis.models import (
    ArtifactCopies,
    AssertionGroup,
    CorrelationResult,
    Digest,
    FindingGroup,
    InventoryItem,
    Relationship,
)
from scopelens.assessment.models import (
    AcquisitionStatus,
    AssessmentResult,
    CapturedResponse,
)
from scopelens.comparison.compare import ArtifactHealth
from scopelens.domain.scope import AssessmentProject, ScanProfile
from scopelens.domain.targets import DomainModel, Identifier, IPv4, Origin
from scopelens.orchestration.models import (
    AssessmentManifest,
    AssessmentStatus,
    PlannedStage,
    StageKind,
    StageRequest,
    StageStatus,
)


class ErrorDetail(DomainModel):
    code: str
    message: str


class ErrorResponse(DomainModel):
    error: ErrorDetail


class HealthResponse(DomainModel):
    status: Literal["ok"] = "ok"


class ProjectSummary(DomainModel):
    project: AssessmentProject
    profiles: tuple[ScanProfile, ...]


class AssessmentCreateRequest(DomainModel):
    assessment_id: UUID
    project_id: Identifier
    profile_id: Identifier
    stages: Annotated[tuple[StageKind, ...], Field(min_length=1, max_length=4)]


class FocusedRetestRequest(DomainModel):
    assessment_id: UUID
    project_id: Identifier
    profile_id: Identifier
    origin: Origin
    approved_address: IPv4


class StageResponse(DomainModel):
    id: UUID
    ordinal: int
    request: StageRequest
    status: StageStatus
    result_run_id: UUID | None
    started_at: AwareDatetime | None
    finished_at: AwareDatetime | None
    reason: str | None


class AssessmentResponse(DomainModel):
    id: UUID
    project_id: Identifier
    scope_snapshot_id: str
    status: AssessmentStatus
    created_at: AwareDatetime
    started_at: AwareDatetime | None
    finished_at: AwareDatetime | None
    reason: str | None
    stages: tuple[StageResponse, ...]


def assessment_response(manifest: AssessmentManifest) -> AssessmentResponse:
    return AssessmentResponse(
        id=manifest.id,
        project_id=manifest.project_id,
        scope_snapshot_id=manifest.scope_snapshot_id,
        status=manifest.status,
        created_at=manifest.created_at,
        started_at=manifest.started_at,
        finished_at=manifest.finished_at,
        reason=manifest.reason,
        stages=tuple(stage_response(stage) for stage in manifest.stages),
    )


def stage_response(stage: PlannedStage) -> StageResponse:
    return StageResponse(
        id=stage.id,
        ordinal=stage.ordinal,
        request=stage.request,
        status=stage.status,
        result_run_id=stage.result_run_id,
        started_at=stage.started_at,
        finished_at=stage.finished_at,
        reason=stage.reason,
    )


class RunSelection(DomainModel):
    basis: Literal["stored_runs"] = "stored_runs"
    run_ids: Annotated[tuple[UUID, ...], Field(min_length=1)]


class PersistedRecheckSelection(DomainModel):
    basis: Literal["persisted_recheck"] = "persisted_recheck"
    assessment_id: UUID
    stage_id: UUID


ComparisonSide = Annotated[
    RunSelection | PersistedRecheckSelection, Field(discriminator="basis")
]


class RunAnalysisRequest(DomainModel):
    project_id: Identifier
    run_ids: Annotated[tuple[UUID, ...], Field(min_length=1)]


class StoredArtifactResponse(DomainModel):
    role: Literal["stdout", "stderr"]
    sha256: Digest
    size_bytes: int
    recorded_health: ArtifactHealth


class RunSourceResponse(DomainModel):
    run_id: UUID
    project_id: Identifier
    kind: Literal["scan", "import"]
    created_at: AwareDatetime
    finished_at: AwareDatetime | None
    scope_snapshot_id: Digest
    profile: ScanProfile
    context: ImportContext
    report: ParsedReport
    artifacts: tuple[StoredArtifactResponse, ...]


class CorrelationResponse(DomainModel):
    version: Literal["correlation-v1"] = "correlation-v1"
    project_id: Identifier
    sources: tuple[RunSourceResponse, ...]
    inventory: tuple[InventoryItem, ...]
    relationships: tuple[Relationship, ...]
    assertions: tuple[AssertionGroup, ...]
    findings: tuple[FindingGroup, ...]
    artifact_copies: tuple[ArtifactCopies, ...]


def correlation_response(result: CorrelationResult) -> CorrelationResponse:
    return CorrelationResponse(
        project_id=result.project_id,
        sources=tuple(
            RunSourceResponse(
                run_id=source.run_id,
                project_id=source.project_id,
                kind=source.kind,
                created_at=source.created_at,
                finished_at=source.finished_at,
                scope_snapshot_id=source.scope_snapshot_id,
                profile=source.profile,
                context=source.context,
                report=source.report,
                artifacts=tuple(
                    StoredArtifactResponse(
                        role=artifact.role,
                        sha256=artifact.sha256,
                        size_bytes=artifact.size_bytes,
                        recorded_health=artifact.recorded_health,
                    )
                    for artifact in source.artifacts
                ),
            )
            for source in result.sources
        ),
        inventory=result.inventory,
        relationships=result.relationships,
        assertions=result.assertions,
        findings=result.findings,
        artifact_copies=result.artifact_copies,
    )


class ComparisonRequest(DomainModel):
    project_id: Identifier
    baseline: ComparisonSide
    current: ComparisonSide


class ReconcileResponse(DomainModel):
    interrupted_assessment_ids: tuple[UUID, ...]


class RecheckEvidenceResponse(DomainModel):
    acquisition_id: UUID
    sha256: str
    size_bytes: int
    health: ArtifactHealth


class RecheckAcquisitionResponse(DomainModel):
    id: UUID
    started_at: AwareDatetime
    finished_at: AwareDatetime | None
    origin: Origin
    approved_address: IPv4
    method: Literal["GET"]
    resource: str
    status: AcquisitionStatus
    response: CapturedResponse | None
    evidence: RecheckEvidenceResponse | None


class RecheckReportResponse(DomainModel):
    version: Literal["assessment-v1"] = "assessment-v1"
    basis: Literal["fresh_recheck"] = "fresh_recheck"
    project_id: Identifier
    assessment_id: UUID
    stage_id: UUID
    acquisitions: tuple[RecheckAcquisitionResponse, ...]
    assessments: tuple[AssessmentResult, ...]
