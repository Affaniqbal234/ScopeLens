from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from scopelens.adapters.nuclei_templates import reviewed_templates
from scopelens.analysis.models import CorrelationResult, RunSource
from scopelens.assessment.models import (
    AssessmentResult,
    CaptureAssessmentReport,
    EvidenceUse,
    ExistingCaptureUse,
    FreshRecheckUse,
    RecheckAcquisition,
    RecheckReport,
)
from scopelens.assessment.rules import DIRECTORY_RULE, GIT_CONFIG_RULE
from scopelens.comparison.models import (
    AssessmentReference,
    ClaimKey,
    ComparisonSelection,
    CoverageDecision,
    CoverageStatus,
    HistoricalComparison,
    HistoricalComparisonReport,
    HistoricalState,
    comparison_id,
)

type AssessmentReport = CaptureAssessmentReport | RecheckReport
type SemanticKey = tuple[str, str, str]
type ContextKey = tuple[str, str, str, str | None]
type ArtifactHealth = Literal["ready", "missing", "corrupt"]

_NOT_OBSERVED_REASONS = {"check_not_run", "no_supported_negative_evidence"}
_MATERIAL_FACTS = {"http.header.strict_transport_security"}
_TEMPLATE_IDS = {
    DIRECTORY_RULE: "scopelens-directory-listing",
    GIT_CONFIG_RULE: "scopelens-exposed-git-config",
}


class ComparisonError(ValueError):
    """Selected assessment inputs cannot be compared safely."""


@dataclass(frozen=True)
class _Entry:
    assessment: AssessmentResult
    address: str | None
    evidence: tuple[EvidenceUse, ...]
    observed_at: tuple[datetime, ...]
    healthy: bool
    health_reason: str | None


@dataclass(frozen=True)
class _Side:
    report: AssessmentReport
    entries: dict[ContextKey, _Entry]
    selection: ComparisonSelection


def _selection(report: AssessmentReport) -> ComparisonSelection:
    if isinstance(report, CaptureAssessmentReport):
        identifiers = tuple(str(value) for value in sorted(report.run_ids))
    else:
        identifiers = tuple(
            str(item.id)
            for item in sorted(report.acquisitions, key=lambda item: item.id)
        )
    return ComparisonSelection(basis=report.basis, identifiers=identifiers)


def _capture_sources(
    report: CaptureAssessmentReport, correlation: CorrelationResult | None
) -> dict[UUID, RunSource]:
    if correlation is None:
        raise ComparisonError(
            "captured assessments require their correlation projection"
        )
    if correlation.project_id != report.project_id or set(report.run_ids) != {
        source.run_id for source in correlation.sources
    }:
        raise ComparisonError("assessment and correlation selections do not match")
    return {source.run_id: source for source in correlation.sources}


def _evidence_health(
    source: RunSource, use: ExistingCaptureUse
) -> tuple[bool, str | None]:
    artifacts = [
        artifact
        for artifact in source.artifacts
        if artifact.sha256 == use.evidence.artifact_sha256
    ]
    if not artifacts:
        return False, "evidence_artifact_unavailable"
    if any(artifact.recorded_health != "ready" for artifact in artifacts):
        return False, "evidence_artifact_unhealthy"
    return True, None


def _semantic_key(assessment: AssessmentResult) -> SemanticKey:
    claim = assessment.claim
    return claim.rule_id, claim.origin, claim.resource


def _build_side(
    report: AssessmentReport,
    correlation: CorrelationResult | None,
    acquisition_health: Mapping[UUID, ArtifactHealth] | None,
) -> _Side:
    sources: dict[UUID, RunSource] = {}
    acquisitions: dict[UUID, RecheckAcquisition] = {}
    if isinstance(report, CaptureAssessmentReport):
        if acquisition_health is not None:
            raise ComparisonError("captured assessments cannot use acquisition health")
        sources = _capture_sources(report, correlation)
    else:
        if correlation is not None:
            raise ComparisonError("fresh rechecks cannot use a correlation projection")
        acquisitions = {item.id: item for item in report.acquisitions}

    entries: dict[ContextKey, _Entry] = {}
    semantic_versions: dict[SemanticKey, str] = {}
    for assessment in report.assessments:
        semantic = _semantic_key(assessment)
        previous_version = semantic_versions.setdefault(
            semantic, assessment.claim.rule_version
        )
        if previous_version != assessment.claim.rule_version:
            raise ComparisonError("one selection contains ambiguous rule versions")

        grouped: dict[str | None, list[EvidenceUse]] = {}
        observed_at: dict[str | None, list[datetime]] = {}
        health: dict[str | None, tuple[bool, str | None]] = {}
        for use in assessment.evidence_used:
            address: str | None = None
            healthy = True
            reason = None
            if isinstance(use, ExistingCaptureUse):
                source = sources[use.source.run_id]
                target = source.context.web_target
                if target is not None and len(target.approved_addresses) == 1:
                    address = target.approved_addresses[0]
                healthy, reason = _evidence_health(source, use)
                captured_at = use.evidence.captured_at
            elif isinstance(use, FreshRecheckUse):
                acquisition = acquisitions[use.acquisition_id]
                address = acquisition.approved_address
                captured_at = acquisition.started_at
                if acquisition.evidence is not None:
                    recorded = (
                        acquisition_health.get(acquisition.id)
                        if acquisition_health is not None
                        else None
                    )
                    healthy = recorded == "ready"
                    reason = (
                        "fresh_evidence_health_unverified"
                        if recorded is None
                        else "fresh_evidence_artifact_unhealthy"
                        if recorded != "ready"
                        else None
                    )
            grouped.setdefault(address, []).append(use)
            observed_at.setdefault(address, []).append(captured_at)
            prior = health.get(address, (True, None))
            health[address] = (
                prior[0] and healthy,
                prior[1] or reason,
            )
        if not grouped:
            grouped[None] = []
            observed_at[None] = []
            health[None] = (False, "assessment_has_no_evidence_context")

        for address, uses in grouped.items():
            key = (*semantic, address)
            if key in entries:
                raise ComparisonError("one selection contains duplicate claim context")
            is_healthy, reason = health[address]
            entries[key] = _Entry(
                assessment=assessment,
                address=address,
                evidence=tuple(uses),
                observed_at=tuple(sorted(observed_at[address])),
                healthy=is_healthy,
                health_reason=reason,
            )
    return _Side(report=report, entries=entries, selection=_selection(report))


def _reference(entry: _Entry | None) -> AssessmentReference | None:
    if entry is None:
        return None
    assessment = entry.assessment
    return AssessmentReference(
        assessment_id=assessment.id,
        rule_version=assessment.claim.rule_version,
        outcome=assessment.outcome,
        reason=assessment.reason,
        evidence_health="ready" if entry.healthy else "unavailable",
        observed_at=entry.observed_at,
        evidence_used=entry.evidence,
    )


def _coverage(
    status: CoverageStatus, reason: str, explanation: str
) -> CoverageDecision:
    return CoverageDecision(status=status, reason=reason, explanation=explanation)


def _facts(entry: _Entry) -> dict[str, frozenset[str]]:
    values: dict[str, set[str]] = {}
    for use in entry.evidence:
        for fact in use.facts:
            if fact.key in _MATERIAL_FACTS:
                values.setdefault(fact.key, set()).add(str(fact.value))
    return {key: frozenset(items) for key, items in values.items()}


def _material_facts_changed(baseline: _Entry, current: _Entry) -> bool:
    before = _facts(baseline)
    after = _facts(current)
    return bool(before) and before.keys() == after.keys() and before != after


def _template_revisions(entry: _Entry) -> set[str]:
    return {
        str(fact.value)
        for use in entry.evidence
        for fact in use.facts
        if fact.key == "scanner.template_revision"
    }


def _reviewed_revision(rule_id: str) -> str | None:
    template_id = _TEMPLATE_IDS.get(rule_id)
    return next(
        (
            template.sha256
            for template in reviewed_templates()
            if template.id == template_id
        ),
        None,
    )


def _compatible(baseline: _Entry, current: _Entry) -> bool:
    expected_revision = _reviewed_revision(baseline.assessment.claim.rule_id)
    revisions = _template_revisions(baseline) | _template_revisions(current)
    return (
        baseline.assessment.claim.rule_id == current.assessment.claim.rule_id
        and baseline.assessment.claim.rule_version
        == current.assessment.claim.rule_version
        and baseline.assessment.claim.origin == current.assessment.claim.origin
        and baseline.assessment.claim.resource == current.assessment.claim.resource
        and baseline.address is not None
        and baseline.address == current.address
        and (not revisions or revisions == {expected_revision})
    )


def _is_later(baseline: _Entry, current: _Entry) -> bool:
    return (
        bool(baseline.observed_at)
        and bool(current.observed_at)
        and min(current.observed_at) > max(baseline.observed_at)
    )


def _result(
    project_id: str,
    key: ContextKey,
    baseline: _Entry | None,
    current: _Entry | None,
) -> HistoricalComparison:
    rule_id, origin, resource, address = key
    claim = ClaimKey(rule_id=rule_id, origin=origin, resource=resource, address=address)
    state: HistoricalState
    reason: str
    explanation: str
    limitations = (
        "Historical state applies only to this exact claim, resource, and address context.",
        "Resolved does not establish remediation, root-cause removal, or safety elsewhere.",
    )

    if baseline is not None and not baseline.healthy:
        state, reason = "unknown", "required_evidence_unavailable"
        explanation = "Required baseline evidence is unavailable or unhealthy."
        coverage = _coverage(
            "unusable",
            baseline.health_reason or "required_evidence_unavailable",
            "Missing or corrupt baseline evidence prevents a historical conclusion.",
        )
    elif current is None:
        state, reason = "not_observed", "current_check_not_selected"
        explanation = (
            "The current selection contains no assessment for this exact context."
        )
        coverage = _coverage(
            "insufficient",
            "current_check_not_selected",
            "Current scope, profile, or selected runs did not cover this exact check context.",
        )
    elif not current.healthy:
        state, reason = "unknown", "required_evidence_unavailable"
        explanation = (
            "Required baseline or current evidence is unavailable or unhealthy."
        )
        coverage = _coverage(
            "unusable",
            current.health_reason or "required_evidence_unavailable",
            "Missing or corrupt required evidence cannot support historical absence.",
        )
    elif baseline is None:
        if current.assessment.outcome == "supported_positive":
            state, reason = "new", "no_comparable_baseline_support"
            explanation = "The condition is currently supported, with no comparable baseline support."
        else:
            state, reason = "unknown", "baseline_not_assessed"
            explanation = "No baseline assessment exists for this exact context."
        coverage = _coverage(
            "not_assessed",
            "baseline_not_assessed",
            "The baseline selection did not assess this exact check context.",
        )
    elif (
        current.assessment.outcome == "supported_positive"
        and baseline.assessment.outcome != "supported_positive"
        and not _compatible(baseline, current)
    ):
        state, reason = "new", "no_comparable_baseline_support"
        explanation = "The condition is currently supported; baseline semantics were not comparable."
        coverage = _coverage(
            "unusable",
            "incompatible_baseline_semantics",
            "The baseline cannot establish when the currently supported condition began.",
        )
    elif not _compatible(baseline, current):
        state, reason = "unknown", "incompatible_check_semantics"
        explanation = (
            "The rule version or backend context is not semantically comparable."
        )
        coverage = _coverage(
            "unusable",
            "incompatible_check_semantics",
            "Exact rule versions and address contexts are required for comparison.",
        )
    elif current.assessment.outcome == "inconclusive":
        if current.assessment.reason in _NOT_OBSERVED_REASONS:
            state, reason = "not_observed", "current_check_not_completed"
            explanation = "The current selection did not produce usable evidence for this condition."
            coverage = _coverage(
                "insufficient",
                current.assessment.reason,
                "The exact check was omitted or lacked supported negative evidence.",
            )
        else:
            state, reason = "unknown", "current_check_unusable"
            explanation = "The current check was attempted but its result is unusable."
            coverage = _coverage(
                "unusable",
                current.assessment.reason,
                "Failed, interrupted, malformed, incomplete, or blocked checks cannot prove absence.",
            )
    elif baseline.assessment.outcome == "inconclusive":
        if current.assessment.outcome == "supported_positive":
            state, reason = "new", "baseline_support_absent"
            explanation = "The condition is currently supported; baseline evidence was inconclusive."
        else:
            state, reason = "unknown", "baseline_check_unusable"
            explanation = (
                "The baseline did not establish a comparable supported conclusion."
            )
        coverage = _coverage(
            "insufficient",
            "baseline_check_inconclusive",
            "The baseline cannot establish when the current condition began or changed.",
        )
    else:
        before = baseline.assessment.outcome
        after = current.assessment.outcome
        coverage = _coverage(
            "comparable",
            "exact_check_covered",
            "The exact rule version, origin, resource, address, and required evidence are comparable.",
        )
        if before == "supported_positive" and after == "supported_negative":
            if _is_later(baseline, current):
                state, reason = "resolved", "comparable_negative_evidence"
                explanation = "The previously supported condition was absent in this later comparable assessment."
            else:
                state, reason = "unknown", "current_evidence_not_later"
                explanation = "The negative evidence was not captured after all baseline evidence."
                coverage = _coverage(
                    "unusable",
                    "current_evidence_not_later",
                    "Resolution requires a later comparable negative acquisition.",
                )
        elif before == "supported_negative" and after == "supported_positive":
            state, reason = "new", "condition_now_supported"
            explanation = (
                "The condition is supported now after a comparable baseline negative."
            )
        elif before == after == "supported_positive" and _material_facts_changed(
            baseline, current
        ):
            state, reason = "changed", "material_evidence_changed"
            explanation = "The condition remains supported, but comparable material evidence changed."
        else:
            state, reason = "unchanged", "supported_conclusion_unchanged"
            explanation = "The comparable supported conclusion did not change."

    return HistoricalComparison(
        id=comparison_id(project_id, claim),
        claim=claim,
        state=state,
        reason=reason,
        explanation=explanation,
        coverage=coverage,
        baseline=_reference(baseline),
        current=_reference(current),
        limitations=limitations,
    )


def compare_assessments(
    baseline: AssessmentReport,
    current: AssessmentReport,
    *,
    baseline_correlation: CorrelationResult | None = None,
    current_correlation: CorrelationResult | None = None,
    baseline_acquisition_health: Mapping[UUID, ArtifactHealth] | None = None,
    current_acquisition_health: Mapping[UUID, ArtifactHealth] | None = None,
) -> HistoricalComparisonReport:
    if baseline.project_id != current.project_id:
        raise ComparisonError("baseline and current selections must use one project")
    baseline_side = _build_side(
        baseline, baseline_correlation, baseline_acquisition_health
    )
    current_side = _build_side(current, current_correlation, current_acquisition_health)
    keys = sorted(set(baseline_side.entries) | set(current_side.entries))
    return HistoricalComparisonReport(
        project_id=baseline.project_id,
        baseline=baseline_side.selection,
        current=current_side.selection,
        results=tuple(
            _result(
                baseline.project_id,
                key,
                baseline_side.entries.get(key),
                current_side.entries.get(key),
            )
            for key in keys
        ),
    )
