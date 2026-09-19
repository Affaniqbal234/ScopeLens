from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from scopelens.analysis.models import (
    AssertionGroup,
    FindingGroup,
    InventoryItem,
    Relationship,
)
from scopelens.assessment.models import AssessmentResult
from scopelens.comparison.models import HistoricalComparisonReport
from scopelens.domain.scope import AuthorizedScope, ScanProfile
from scopelens.domain.targets import DomainModel, Identifier
from scopelens.orchestration.models import (
    AssessmentStatus,
    StageKind,
    StageRequest,
    StageStatus,
)

EvidenceHealth = Literal["ready", "missing", "corrupt", "unavailable"]
DisplayOutcome = Literal[
    "condition_supported",
    "condition_not_supported_by_this_evidence",
    "inconclusive",
]


class ProjectIdentity(DomainModel):
    id: Identifier
    name: str


class EvidenceHealthRecord(DomainModel):
    source_kind: Literal["scanner_run", "fresh_recheck"]
    source_id: UUID
    artifact_sha256: str | None
    role: Literal["stdout", "stderr", "response"]
    health: EvidenceHealth
    size_bytes: int | None


class StageReport(DomainModel):
    id: UUID
    ordinal: int
    kind: StageKind
    request: StageRequest
    status: StageStatus
    started_at: AwareDatetime | None
    finished_at: AwareDatetime | None
    reason: str | None
    result_run_id: UUID | None
    acquisition_ids: tuple[UUID, ...]
    evidence_health: tuple[EvidenceHealthRecord, ...]


class CoverageSummary(DomainModel):
    requested: int
    pending: int
    running: int
    completed: int
    skipped: int
    failed: int
    interrupted: int
    inconclusive_claims: int
    partial: bool


class ClaimReport(DomainModel):
    stage_id: UUID | None
    source_basis: Literal["existing_capture", "fresh_recheck"]
    run_ids: tuple[UUID, ...]
    acquisition_ids: tuple[UUID, ...]
    artifact_sha256s: tuple[str, ...]
    display_outcome: DisplayOutcome
    result: AssessmentResult


class AssessmentReport(DomainModel):
    version: Literal["report-v1"] = "report-v1"
    kind: Literal["assessment"] = "assessment"
    project: ProjectIdentity
    assessment_id: UUID
    scope_snapshot_id: str
    status: AssessmentStatus
    created_at: AwareDatetime
    started_at: AwareDatetime | None
    finished_at: AwareDatetime | None
    reason: str | None
    authorized_scope: AuthorizedScope
    profile: ScanProfile
    stages: Annotated[tuple[StageReport, ...], Field(min_length=1)]
    coverage: CoverageSummary
    inventory: tuple[InventoryItem, ...]
    relationships: tuple[Relationship, ...]
    assertions: tuple[AssertionGroup, ...]
    findings: tuple[FindingGroup, ...]
    claims: tuple[ClaimReport, ...]
    evidence_health: tuple[EvidenceHealthRecord, ...]
    qualifications: tuple[str, ...]


class ComparisonReport(DomainModel):
    version: Literal["report-v1"] = "report-v1"
    kind: Literal["comparison"] = "comparison"
    project: ProjectIdentity
    comparison: HistoricalComparisonReport
    resolved_qualification: str
    state_definitions: dict[str, str]


Report = AssessmentReport | ComparisonReport


class StoredRunSelection(DomainModel):
    basis: Literal["stored_runs"] = "stored_runs"
    run_ids: Annotated[tuple[UUID, ...], Field(min_length=1)]


class RecheckSelection(DomainModel):
    basis: Literal["persisted_recheck"] = "persisted_recheck"
    assessment_id: UUID
    stage_id: UUID


ReportSelection = StoredRunSelection | RecheckSelection


class PublicContext(DomainModel):
    kind: Literal["host", "network_service", "http_origin", "http_resource"]
    address: str | None = None
    protocol: str | None = None
    port: int | None = None
    origin: str | None = None
    resource: str | None = None


class PublicStage(DomainModel):
    ordinal: int
    kind: StageKind
    status: StageStatus
    capabilities: tuple[str, ...]
    context: PublicContext | None


class PublicClaim(DomainModel):
    rule_id: str
    rule_version: str
    statement: str
    origin: str
    resource: str
    outcome: DisplayOutcome
    evidence_health: EvidenceHealth
    provenance_refs: tuple[str, ...]
    limitation: str


class PublicLifecycleResult(DomainModel):
    rule_id: str
    rule_version: str
    origin: str
    resource: str
    address: str | None
    state: Literal["new", "changed", "unchanged", "resolved", "not_observed", "unknown"]
    coverage: Literal["comparable", "insufficient", "unusable", "not_assessed"]
    baseline_health: Literal["ready", "unavailable"] | None
    current_health: Literal["ready", "unavailable"] | None
    provenance_refs: tuple[str, ...]
    explanation: str
    limitation: str


class PublicSnapshot(DomainModel):
    version: Literal["public-snapshot-v1"] = "public-snapshot-v1"
    source_report_version: Literal["report-v1"] = "report-v1"
    source_kind: Literal["assessment", "comparison"]
    display_name: str
    source_ref: str
    contexts: tuple[PublicContext, ...]
    stages: tuple[PublicStage, ...]
    claims: tuple[PublicClaim, ...]
    lifecycle: tuple[PublicLifecycleResult, ...]
    coverage_note: str
    recorded_data_notice: Literal[
        "Recorded and sanitized ScopeLens data; no live target activity occurs during export."
    ] = "Recorded and sanitized ScopeLens data; no live target activity occurs during export."
