from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from scopelens.adapters.nuclei_templates import reviewed_templates
from scopelens.analysis.models import CorrelationResult, RunSource
from scopelens.assessment.capture import assess_correlation
from scopelens.assessment.models import (
    AssessmentResult,
    CaptureAssessmentReport,
    EvidenceUse,
    ExistingCaptureUse,
    FreshRecheckUse,
    RecheckAcquisition,
    RecheckReport,
)
from scopelens.assessment.rules import DIRECTORY_RULE, GIT_CONFIG_RULE, HSTS_RULE
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
from scopelens.domain.services import HttpEndpoint

type AssessmentReport = CaptureAssessmentReport | RecheckReport
type SemanticKey = tuple[str, str, str]
type ContextKey = tuple[str, str, str, str | None]
type ArtifactHealth = Literal["ready", "missing", "corrupt"]
type CaptureHealth = Mapping[tuple[UUID, str], ArtifactHealth]

_NOT_OBSERVED_REASONS = {"check_not_run", "no_supported_negative_evidence"}
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
    semantics_valid: bool
    started_at: datetime | None
    finished_at: datetime | None
    artifact_digests: frozenset[str]


@dataclass(frozen=True)
class _Side:
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
    if any(source.project_id != report.project_id for source in correlation.sources):
        raise ComparisonError("correlation sources must belong to the selected project")
    return {source.run_id: source for source in correlation.sources}


def _evidence_health(
    source: RunSource, use: ExistingCaptureUse, verified: CaptureHealth | None
) -> tuple[bool, str | None]:
    artifacts = [
        artifact
        for artifact in source.artifacts
        if artifact.role == "stdout" and artifact.sha256 == use.evidence.artifact_sha256
    ]
    if not artifacts:
        return False, "evidence_artifact_unavailable"
    health = (
        verified.get((source.run_id, use.evidence.artifact_sha256))
        if verified is not None
        else None
    )
    if health is None:
        return False, "capture_evidence_health_unverified"
    if health != "ready":
        return False, "evidence_artifact_unhealthy"
    return True, None


def _semantic_key(assessment: AssessmentResult) -> SemanticKey:
    claim = assessment.claim
    return claim.rule_id, claim.origin, claim.resource


def _capture_address(source: RunSource, use: ExistingCaptureUse) -> str | None:
    target = source.context.web_target
    if target is None:
        return None
    if use.evidence.scanner == "httpx":
        # A peer belongs to one response record, not every response at the origin.
        peers = {
            observation.value
            for observation in source.report.observations
            if observation.key == "http.peer_address"
            and observation.subject == HttpEndpoint(origin=target.origin)
            and use.evidence in observation.evidence
        }
        if len(peers) == 1:
            peer = next(iter(peers))
            if isinstance(peer, str) and peer in target.approved_addresses:
                return peer
        attempted = {
            observation.key: observation.value
            for observation in source.report.observations
            if observation.subject == HttpEndpoint(origin=target.origin)
            and use.evidence in observation.evidence
            and observation.key in ("http.probe_succeeded", "http.target_address")
        }
        address = attempted.get("http.target_address")
        if (
            not peers
            and attempted.get("http.probe_succeeded") is False
            and isinstance(address, str)
            and address in target.approved_addresses
        ):
            return address
        return None
    if (
        use.evidence.scanner == "nuclei"
        and source.kind == "scan"
        and len(target.approved_addresses) == 1
    ):
        # Completed managed Nuclei executions use a literal destination with redirects disabled.
        return target.approved_addresses[0]
    return None


def _same_assessment_evidence(
    assessment: AssessmentResult, expected: AssessmentResult | None
) -> bool:
    return expected is not None and (
        assessment.outcome == expected.outcome
        and assessment.reason == expected.reason
        and {
            use.model_copy(
                update={"facts": tuple(sorted(use.facts, key=lambda fact: fact.key))}
            )
            for use in assessment.evidence_used
        }
        == {
            use.model_copy(
                update={"facts": tuple(sorted(use.facts, key=lambda fact: fact.key))}
            )
            for use in expected.evidence_used
        }
        and {(item.id, item.state) for item in assessment.prerequisites}
        == {(item.id, item.state) for item in expected.prerequisites}
    )


def _fresh_context_valid(
    assessment: AssessmentResult, acquisition: RecheckAcquisition, use: FreshRecheckUse
) -> bool:
    claim = assessment.claim
    if claim.origin != acquisition.origin or claim.resource != acquisition.resource:
        return False
    if assessment.outcome == "inconclusive":
        return assessment.reason != "no_supported_negative_evidence" and (
            assessment.reason != "check_not_run" or acquisition.status == "not_run"
        )
    required = (
        {
            "https_origin",
            "hostname_origin",
            "intended_resource",
            "complete_headers",
            "usable_response",
        }
        if claim.rule_id == HSTS_RULE
        else {"authorized_target", "intended_resource", "complete_response"}
    )
    response = acquisition.response
    if (
        acquisition.evidence is None
        or response is None
        or not response.headers_complete
        or response.access_challenge_present
        or not response.content_encoding_identity
        or any(item.state != "met" for item in assessment.prerequisites)
        or {item.id for item in assessment.prerequisites} != required
    ):
        return False
    facts = {fact.key: fact.value for fact in use.facts}
    if (
        len(facts) != len(use.facts)
        or facts.get("http.status_code") != response.status_code
    ):
        return False
    positive = assessment.outcome == "supported_positive"
    if claim.rule_id == HSTS_RULE:
        present = not positive
        return (
            acquisition.status in ("complete", "truncated")
            and response.status_code == 200
            and facts.get("http.headers_complete") is True
            and response.strict_transport_security_present == present
            and facts.get("http.header.strict_transport_security_present") is present
        )
    return (
        acquisition.status == "complete"
        and response.body_complete
        and response.status_code in ((200,) if positive else (200, 404, 410))
        and facts.get("http.body_complete") is True
        and facts.get("http.body_sha256") == response.body_sha256
        and facts.get("rule.markers_present") is positive
    )


def _build_side(
    report: AssessmentReport,
    correlation: CorrelationResult | None,
    acquisition_health: Mapping[UUID, ArtifactHealth] | None,
    capture_health: CaptureHealth | None,
) -> _Side:
    sources: dict[UUID, RunSource] = {}
    acquisitions: dict[UUID, RecheckAcquisition] = {}
    expected: dict[str, AssessmentResult] = {}
    if isinstance(report, CaptureAssessmentReport):
        if acquisition_health is not None:
            raise ComparisonError("captured assessments cannot use acquisition health")
        sources = _capture_sources(report, correlation)
        assert correlation is not None
        expected = {
            item.id: item for item in assess_correlation(correlation).assessments
        }
    else:
        if correlation is not None or capture_health is not None:
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
        health: dict[str | None, dict[str, tuple[bool, str | None]]] = {}
        windows: dict[str | None, list[tuple[datetime, datetime] | None]] = {}
        valid: dict[str | None, bool] = {}
        known_rule = (
            assessment.claim.rule_version == "1"
            and assessment.claim.resource
            == {
                DIRECTORY_RULE: "/",
                GIT_CONFIG_RULE: "/.git/config",
                HSTS_RULE: "/",
            }.get(assessment.claim.rule_id)
        )
        for use in assessment.evidence_used:
            address: str | None = None
            healthy = True
            reason = None
            window = None
            digest = ""
            semantics_valid = known_rule
            if isinstance(use, ExistingCaptureUse):
                source = sources[use.source.run_id]
                address = _capture_address(source, use)
                healthy, reason = _evidence_health(source, use, capture_health)
                captured_at = use.evidence.captured_at
                digest = use.evidence.artifact_sha256
                semantics_valid &= _same_assessment_evidence(
                    assessment, expected.get(assessment.id)
                )
                if (
                    source.kind == "scan"
                    and source.finished_at is not None
                    and source.finished_at >= source.created_at
                ):
                    window = (source.created_at, source.finished_at)
                elif source.kind == "import":
                    originals = [
                        original
                        for original in sources.values()
                        if original.kind == "scan"
                        and original.context.web_target == source.context.web_target
                        and original.report.evidence.scanner == use.evidence.scanner
                        and original.report.evidence.artifact_sha256 == digest
                    ]
                    addresses = {
                        _capture_address(original, use) for original in originals
                    }
                    if len(addresses) == 1 and None not in addresses:
                        address = next(iter(addresses))
                        intervals = [
                            (original.created_at, original.finished_at)
                            for original in originals
                            if original.finished_at is not None
                            and original.finished_at >= original.created_at
                        ]
                        if intervals and len(intervals) == len(originals):
                            window = (
                                min(start for start, _ in intervals),
                                max(end for _, end in intervals),
                            )
            elif isinstance(use, FreshRecheckUse):
                acquisition = acquisitions[use.acquisition_id]
                address = acquisition.approved_address
                captured_at = acquisition.started_at
                semantics_valid &= _fresh_context_valid(assessment, acquisition, use)
                if (
                    acquisition.finished_at is not None
                    and acquisition.finished_at >= acquisition.started_at
                ):
                    window = (acquisition.started_at, acquisition.finished_at)
                if acquisition.evidence is not None:
                    digest = acquisition.evidence.artifact_sha256
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
            windows.setdefault(address, []).append(window)
            valid[address] = valid.get(address, True) and semantics_valid
            copies = health.setdefault(address, {})
            prior = copies.get(digest)
            # One readable identical copy suffices; duplicate imports are not corroboration.
            if prior is None or healthy:
                copies[digest] = (healthy, reason)
        if not grouped:
            grouped[None] = []
            observed_at[None] = []
            health[None] = {"": (False, "assessment_has_no_evidence_context")}
            windows[None] = []
            valid[None] = False

        for address, uses in grouped.items():
            key = (*semantic, address)
            if key in entries:
                raise ComparisonError("one selection contains duplicate claim context")
            failures = sorted(
                reason or "required_evidence_unavailable"
                for healthy, reason in health[address].values()
                if not healthy
            )
            complete_windows = [
                window for window in windows[address] if window is not None
            ]
            timing_known = bool(complete_windows) and len(complete_windows) == len(
                windows[address]
            )
            entries[key] = _Entry(
                assessment=assessment,
                address=address,
                evidence=tuple(uses),
                observed_at=tuple(sorted(set(observed_at[address]))),
                healthy=not failures,
                health_reason=failures[0] if failures else None,
                semantics_valid=valid[address],
                started_at=min(window[0] for window in complete_windows)
                if timing_known
                else None,
                finished_at=max(window[1] for window in complete_windows)
                if timing_known
                else None,
                artifact_digests=frozenset(
                    digest for digest in health[address] if digest
                ),
            )
    return _Side(entries=entries, selection=_selection(report))


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
        acquisition_started_at=entry.started_at,
        acquisition_finished_at=entry.finished_at,
        evidence_used=entry.evidence,
    )


def _coverage(
    status: CoverageStatus, reason: str, explanation: str
) -> CoverageDecision:
    return CoverageDecision(status=status, reason=reason, explanation=explanation)


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
        baseline.semantics_valid
        and current.semantics_valid
        and baseline.assessment.claim.rule_id == current.assessment.claim.rule_id
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
        baseline.finished_at is not None
        and current.started_at is not None
        and current.started_at > baseline.finished_at
        and baseline.artifact_digests.isdisjoint(current.artifact_digests)
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
        "Artifact health describes verification for this comparison, not historical file availability.",
    )

    if baseline is not None and not baseline.healthy:
        state, reason = "unknown", "required_evidence_unavailable"
        explanation = "Required baseline evidence is unavailable or unhealthy."
        coverage = _coverage(
            "unusable",
            baseline.health_reason or "required_evidence_unavailable",
            "Missing or corrupt baseline evidence prevents a historical conclusion.",
        )
    elif current is None and address is None:
        state, reason = "unknown", "backend_context_unavailable"
        explanation = "The baseline evidence does not identify a comparable backend."
        coverage = _coverage(
            "unusable",
            reason,
            "Configured authorization addresses do not establish response provenance.",
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
    elif not current.semantics_valid:
        state, reason = "unknown", "incompatible_check_semantics"
        explanation = "The assessment does not match the reviewed rule or its acquisition evidence."
        coverage = _coverage(
            "unusable",
            reason,
            "The current check context is inconsistent or unreviewed.",
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
        current.semantics_valid
        and current.assessment.outcome == "supported_positive"
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
    elif current.semantics_valid and current.assessment.outcome == "inconclusive":
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
    elif not _compatible(baseline, current):
        state, reason = "unknown", "incompatible_check_semantics"
        explanation = (
            "The reviewed check semantics or backend context are not comparable."
        )
        coverage = _coverage(
            "unusable",
            reason,
            "Reviewed rule/template/matcher semantics and an acquisition-bound address are required.",
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
        same_capture = (
            bool(baseline.artifact_digests)
            and baseline.artifact_digests == current.artifact_digests
        )
        if same_capture and before == after:
            state, reason = "unchanged", "same_capture_no_new_acquisition"
            explanation = "The selected evidence supports the same conclusion; duplicate bytes establish no new acquisition."
        elif not _is_later(baseline, current):
            state, reason = "unknown", "current_evidence_not_later"
            explanation = "Distinct current evidence could not be placed after completion of all baseline acquisitions."
            coverage = _coverage(
                "unusable",
                reason,
                "Comparison requires non-overlapping acquisition timing, not scanner event or import timestamps.",
            )
        elif before == "supported_positive" and after == "supported_negative":
            state, reason = "resolved", "comparable_negative_evidence"
            explanation = "The previously supported condition was absent in this later comparable assessment."
        elif before == "supported_negative" and after == "supported_positive":
            state, reason = "new", "condition_now_supported"
            explanation = (
                "The condition is supported now after a comparable baseline negative."
            )
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
    baseline_capture_health: CaptureHealth | None = None,
    current_capture_health: CaptureHealth | None = None,
) -> HistoricalComparisonReport:
    """Compare M9 results using health maps from current artifact verification."""
    if baseline.project_id != current.project_id:
        raise ComparisonError("baseline and current selections must use one project")
    baseline_side = _build_side(
        baseline,
        baseline_correlation,
        baseline_acquisition_health,
        baseline_capture_health,
    )
    current_side = _build_side(
        current, current_correlation, current_acquisition_health, current_capture_health
    )
    keys = sorted(
        set(baseline_side.entries) | set(current_side.entries),
        key=lambda key: (*key[:3], key[3] or ""),
    )
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
