from collections import Counter
from collections.abc import Mapping, Sequence
from typing import cast
from uuid import UUID

from scopelens.analysis.models import CorrelationResult
from scopelens.assessment.models import (
    CaptureAssessmentReport,
    ExistingCaptureUse,
    FreshRecheckUse,
    RecheckReport,
)
from scopelens.comparison.compare import ArtifactHealth
from scopelens.comparison.models import HistoricalComparisonReport
from scopelens.config import ProjectConfig
from scopelens.orchestration.models import AssessmentManifest, PlannedStage

from .models import (
    AssessmentReport,
    ClaimReport,
    ComparisonReport,
    CoverageSummary,
    DisplayOutcome,
    EvidenceHealthRecord,
    ProjectIdentity,
    StageReport,
)

RESOLVED_QUALIFICATION = (
    "The previously supported condition was not supported by a later comparable "
    "recheck within the assessed scope, route, address or backend context, and "
    "evidence limitations. This does not prove an underlying code fix or safety "
    "outside that context."
)

STATE_DEFINITIONS = {
    "new": "The condition is supported in the current selection without comparable baseline support; this does not establish when it began.",
    "changed": "Comparable evidence materially differs for the same condition; the state does not imply improvement or regression unless the underlying assessment says so.",
    "unchanged": "Comparable evidence supports the same conclusion in both selections.",
    "resolved": RESOLVED_QUALIFICATION,
    "not_observed": "The later selection did not establish the condition again, but no usable comparable negative established absence.",
    "unknown": "A failure, interruption, incompatible context, or evidence problem prevented a responsible conclusion.",
}


def _display_outcome(outcome: str) -> DisplayOutcome:
    value = {
        "supported_positive": "condition_supported",
        "supported_negative": "condition_not_supported_by_this_evidence",
        "inconclusive": "inconclusive",
    }[outcome]
    return cast(DisplayOutcome, value)


def _scanner_health(
    correlation: CorrelationResult | None,
) -> tuple[EvidenceHealthRecord, ...]:
    if correlation is None:
        return ()
    records = []
    for source in correlation.sources:
        for artifact in source.artifacts:
            records.append(
                EvidenceHealthRecord(
                    source_kind="scanner_run",
                    source_id=source.run_id,
                    artifact_sha256=artifact.sha256,
                    role=artifact.role,
                    health=artifact.recorded_health,
                    size_bytes=artifact.size_bytes,
                )
            )
    return tuple(sorted(records, key=lambda item: (str(item.source_id), item.role)))


def _recheck_health(
    report: RecheckReport, health: Mapping[UUID, ArtifactHealth]
) -> tuple[EvidenceHealthRecord, ...]:
    records = []
    for acquisition in report.acquisitions:
        evidence = acquisition.evidence
        records.append(
            EvidenceHealthRecord(
                source_kind="fresh_recheck",
                source_id=acquisition.id,
                artifact_sha256=(evidence.artifact_sha256 if evidence else None),
                role="response",
                health=(
                    health.get(acquisition.id, "unavailable")
                    if evidence
                    else "unavailable"
                ),
                size_bytes=(evidence.size_bytes if evidence else None),
            )
        )
    return tuple(sorted(records, key=lambda item: str(item.source_id)))


def _stage_report(
    stage: PlannedStage,
    recheck: tuple[RecheckReport, Mapping[UUID, ArtifactHealth]] | None,
    scanner_health: Sequence[EvidenceHealthRecord],
) -> StageReport:
    if recheck is None:
        acquisitions: tuple[UUID, ...] = ()
        health = tuple(
            item
            for item in scanner_health
            if stage.result_run_id is not None and item.source_id == stage.result_run_id
        )
    else:
        acquisitions = tuple(item.id for item in recheck[0].acquisitions)
        health = _recheck_health(*recheck)
    return StageReport(
        id=stage.id,
        ordinal=stage.ordinal,
        kind=stage.request.kind,
        request=stage.request,
        status=stage.status,
        started_at=stage.started_at,
        finished_at=stage.finished_at,
        reason=stage.reason,
        result_run_id=stage.result_run_id,
        acquisition_ids=acquisitions,
        evidence_health=health,
    )


def build_assessment_report(
    config: ProjectConfig,
    manifest: AssessmentManifest,
    *,
    capture: CaptureAssessmentReport | None = None,
    correlation: CorrelationResult | None = None,
    rechecks: Mapping[UUID, tuple[RecheckReport, Mapping[UUID, ArtifactHealth]]]
    | None = None,
) -> AssessmentReport:
    if config.project.id != manifest.project_id:
        raise ValueError("assessment and configuration projects do not match")
    profile_ids = {stage.request.profile_id for stage in manifest.stages}
    if len(profile_ids) != 1:
        raise ValueError("assessment stages must use one profile")
    profile_id = next(iter(profile_ids))
    profile = next((item for item in config.profiles if item.id == profile_id), None)
    if profile is None:
        raise ValueError("assessment profile is absent from its configuration snapshot")
    selected_runs = tuple(
        stage.result_run_id
        for stage in manifest.stages
        if stage.result_run_id is not None
    )
    if capture is not None and (
        capture.project_id != manifest.project_id
        or set(capture.run_ids) != set(selected_runs)
    ):
        raise ValueError("capture assessment does not match manifest run membership")
    if correlation is not None and (
        correlation.project_id != manifest.project_id
        or {item.run_id for item in correlation.sources} != set(selected_runs)
    ):
        raise ValueError("correlation does not match manifest run membership")
    rechecks = rechecks or {}
    if any(
        stage_id not in {item.id for item in manifest.stages} for stage_id in rechecks
    ):
        raise ValueError("recheck report does not belong to the assessment")
    scanner_health = _scanner_health(correlation)
    stages = tuple(
        _stage_report(stage, rechecks.get(stage.id), scanner_health)
        for stage in manifest.stages
    )
    claims = []
    if capture is not None:
        for result in capture.assessments:
            capture_uses = tuple(
                use
                for use in result.evidence_used
                if isinstance(use, ExistingCaptureUse)
            )
            claims.append(
                ClaimReport(
                    stage_id=None,
                    source_basis="existing_capture",
                    run_ids=tuple(sorted({use.source.run_id for use in capture_uses})),
                    acquisition_ids=(),
                    artifact_sha256s=tuple(
                        sorted({use.evidence.artifact_sha256 for use in capture_uses})
                    ),
                    display_outcome=_display_outcome(result.outcome),
                    result=result,
                )
            )
    for stage_id, (report, _) in sorted(
        rechecks.items(), key=lambda item: str(item[0])
    ):
        for result in report.assessments:
            recheck_uses = tuple(
                use for use in result.evidence_used if isinstance(use, FreshRecheckUse)
            )
            claims.append(
                ClaimReport(
                    stage_id=stage_id,
                    source_basis="fresh_recheck",
                    run_ids=(),
                    acquisition_ids=tuple(
                        sorted({use.acquisition_id for use in recheck_uses})
                    ),
                    artifact_sha256s=(),
                    display_outcome=_display_outcome(result.outcome),
                    result=result,
                )
            )
    claims.sort(key=lambda item: (item.result.id, str(item.stage_id or "")))
    counts = Counter(stage.status for stage in manifest.stages)
    partial = any(counts[name] for name in ("skipped", "failed", "interrupted"))
    health = tuple(
        sorted(
            (
                *scanner_health,
                *(
                    item
                    for stage in stages
                    for item in stage.evidence_health
                    if item.source_kind == "fresh_recheck"
                ),
            ),
            key=lambda item: (item.source_kind, str(item.source_id), item.role),
        )
    )
    qualifications = [
        "Assessment completion describes only the persisted stage plan; it does not imply complete security coverage."
    ]
    if partial:
        qualifications.append(
            "This assessment is partial because at least one planned stage was skipped, failed, or interrupted. Completed evidence remains independently inspectable."
        )
    if any(item.result.outcome == "inconclusive" for item in claims):
        qualifications.append(
            "At least one deterministic claim is inconclusive; it must not be read as absent, safe, or resolved."
        )
    return AssessmentReport(
        project=ProjectIdentity(id=config.project.id, name=config.project.name),
        assessment_id=manifest.id,
        scope_snapshot_id=manifest.scope_snapshot_id,
        status=manifest.status,
        created_at=manifest.created_at,
        started_at=manifest.started_at,
        finished_at=manifest.finished_at,
        reason=manifest.reason,
        authorized_scope=config.project.scope,
        profile=profile,
        stages=stages,
        coverage=CoverageSummary(
            requested=len(stages),
            pending=counts["pending"],
            running=counts["running"],
            completed=counts["completed"],
            skipped=counts["skipped"],
            failed=counts["failed"],
            interrupted=counts["interrupted"],
            inconclusive_claims=sum(
                item.result.outcome == "inconclusive" for item in claims
            ),
            partial=partial,
        ),
        inventory=correlation.inventory if correlation else (),
        relationships=correlation.relationships if correlation else (),
        assertions=correlation.assertions if correlation else (),
        findings=correlation.findings if correlation else (),
        claims=tuple(claims),
        evidence_health=health,
        qualifications=tuple(qualifications),
    )


def build_comparison_report(
    project_id: str, project_name: str, comparison: HistoricalComparisonReport
) -> ComparisonReport:
    if comparison.project_id != project_id:
        raise ValueError("comparison belongs to another project")
    ordered = comparison.model_copy(
        update={
            "results": tuple(
                sorted(
                    comparison.results,
                    key=lambda item: (
                        item.claim.rule_id,
                        item.claim.origin,
                        item.claim.resource,
                        item.claim.address or "",
                    ),
                )
            )
        }
    )
    return ComparisonReport(
        project=ProjectIdentity(id=project_id, name=project_name),
        comparison=ordered,
        resolved_qualification=RESOLVED_QUALIFICATION,
        state_definitions=STATE_DEFINITIONS,
    )
