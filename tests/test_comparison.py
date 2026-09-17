import socket
import subprocess
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Literal
from unittest.mock import Mock
from uuid import UUID

import pytest

from scopelens.adapters.base import ImportContext, ParsedReport
from scopelens.adapters.nuclei_templates import reviewed_templates
from scopelens.analysis.correlation import correlate
from scopelens.analysis.models import (
    CorrelationResult,
    RunSource,
    StoredArtifact,
)
from scopelens.assessment.capture import assess_correlation
from scopelens.assessment.models import (
    AcquisitionEvidence,
    AcquisitionStatus,
    CaptureAssessmentReport,
    CapturedResponse,
    ExistingCaptureUse,
    RecheckAcquisition,
    RecheckReport,
    assessment_id,
)
from scopelens.assessment.rules import (
    DIRECTORY_RULE,
    GIT_CONFIG_RULE,
    HSTS_RULE,
    CapturedExchange,
    assess_exposure_recheck,
    assess_hsts_recheck,
)
from scopelens.comparison.compare import (
    ArtifactHealth,
    ComparisonError,
)
from scopelens.comparison.compare import (
    compare_assessments as compare_reports,
)
from scopelens.comparison.models import HistoricalComparisonReport
from scopelens.domain.evidence import EvidenceReference, Observation
from scopelens.domain.findings import ScannerMatch
from scopelens.domain.scope import ScanProfile, WebTarget
from scopelens.domain.services import HttpEndpoint

NOW = datetime(2026, 9, 17, tzinfo=UTC)
ORIGIN = "https://site.invalid"
FALSE_RESOLUTION_MATRIX = (
    ("timeout", "unknown"),
    ("transport_error", "unknown"),
    ("cancelled", "unknown"),
    ("malformed", "unknown"),
    ("truncated", "unknown"),
    ("not_run", "not_observed"),
)


def compare_assessments(
    baseline: CaptureAssessmentReport | RecheckReport,
    current: CaptureAssessmentReport | RecheckReport,
    *,
    baseline_correlation: CorrelationResult | None = None,
    current_correlation: CorrelationResult | None = None,
) -> HistoricalComparisonReport:
    baseline_health: dict[UUID, ArtifactHealth] | None = (
        {
            item.id: "ready"
            for item in baseline.acquisitions
            if item.evidence is not None
        }
        if isinstance(baseline, RecheckReport)
        else None
    )
    current_health: dict[UUID, ArtifactHealth] | None = (
        {item.id: "ready" for item in current.acquisitions if item.evidence is not None}
        if isinstance(current, RecheckReport)
        else None
    )
    return compare_reports(
        baseline,
        current,
        baseline_correlation=baseline_correlation,
        current_correlation=current_correlation,
        baseline_acquisition_health=baseline_health,
        current_acquisition_health=current_health,
        baseline_capture_health={
            (source.run_id, artifact.sha256): artifact.recorded_health
            for source in baseline_correlation.sources
            for artifact in source.artifacts
            if artifact.role == "stdout"
        }
        if baseline_correlation is not None
        else None,
        current_capture_health={
            (source.run_id, artifact.sha256): artifact.recorded_health
            for source in current_correlation.sources
            for artifact in source.artifacts
            if artifact.role == "stdout"
        }
        if current_correlation is not None
        else None,
    )


def exchange(
    *,
    number: int,
    address: str = "127.0.0.1",
    origin: str = ORIGIN,
    resource: str = "/",
    body: bytes = b"",
    status: AcquisitionStatus = "complete",
    status_code: int = 200,
) -> CapturedExchange:
    response = None
    evidence = None
    if status in ("complete", "truncated"):
        response = CapturedResponse(
            status_code=status_code,
            headers_complete=True,
            body_complete=status == "complete",
            body_sha256=sha256(body).hexdigest(),
            strict_transport_security_present=False,
            access_challenge_present=False,
            content_encoding_identity=True,
        )
        evidence = AcquisitionEvidence(
            artifact_path=f"private/{number}/response.http",
            artifact_sha256=sha256(f"raw-{number}".encode()).hexdigest(),
            size_bytes=len(body),
        )
    return CapturedExchange(
        RecheckAcquisition(
            id=UUID(int=number),
            started_at=NOW + timedelta(seconds=number),
            finished_at=NOW + timedelta(seconds=number, milliseconds=100),
            origin=origin,
            approved_address=address,
            resource=resource,
            status=status,
            evidence=evidence,
            response=response,
        ),
        body,
    )


def fresh_report(
    *,
    number: int,
    rule_id: str = DIRECTORY_RULE,
    address: str = "127.0.0.1",
    origin: str = ORIGIN,
    status: AcquisitionStatus = "complete",
    status_code: int = 200,
    positive: bool = False,
    rule_version: str = "1",
) -> RecheckReport:
    resource = "/" if rule_id == DIRECTORY_RULE else "/.git/config"
    vulnerable = (
        b"<title>Directory listing for /</title><a href='a'>a</a>"
        if rule_id == DIRECTORY_RULE
        else b"[core]\nrepositoryformatversion = 0\n"
    )
    capture = exchange(
        number=number,
        address=address,
        origin=origin,
        resource=resource,
        body=(vulnerable if positive else b"Not found")
        if status in ("complete", "truncated")
        else b"",
        status=status,
        status_code=status_code,
    )
    assessment = assess_exposure_recheck("lab", rule_id, capture)
    if rule_version != "1":
        claim = assessment.claim.model_copy(update={"rule_version": rule_version})
        assessment = assessment.model_copy(
            update={"claim": claim, "id": assessment_id("lab", claim)}
        )
    return RecheckReport(
        project_id="lab",
        acquisitions=(capture.acquisition,),
        assessments=(assessment,),
    )


def nuclei_projection(
    *,
    run_numbers: tuple[int, ...],
    positive: bool,
    address: str = "127.0.0.1",
    origin: str = ORIGIN,
    health: Literal["ready", "missing", "corrupt"] = "ready",
    kind: Literal["scan", "import"] = "scan",
) -> tuple[CorrelationResult, CaptureAssessmentReport]:
    template = reviewed_templates()[0]
    digest = sha256(b"artifact").hexdigest()
    evidence = EvidenceReference(
        artifact_sha256=digest,
        record_locator="$[1]",
        scanner="nuclei",
        scanner_version="3.11.1",
        adapter_version="1",
        profile_id="web",
        profile_revision="1",
        captured_at=NOW,
    )
    matches = (
        (
            ScannerMatch(
                origin=origin,
                matched_location=origin + "/",
                template_id=template.id,
                template_revision=template.sha256,
                matcher=template.matcher,
                scanner_severity="low",
                evidence=(evidence,),
            ),
        )
        if positive
        else ()
    )
    sources = tuple(
        RunSource(
            run_id=UUID(int=number),
            project_id="lab",
            kind=kind,
            created_at=NOW,
            finished_at=NOW + timedelta(milliseconds=100),
            scope_snapshot_id="c" * 64,
            profile=ScanProfile(id="web"),
            context=ImportContext(
                profile_id="web",
                profile_revision="1",
                web_target=WebTarget(origin=origin, approved_addresses=(address,)),
            ),
            report=ParsedReport(
                evidence=evidence,
                reported_exit=None,
                observations=(),
                matches=matches,
            ),
            artifacts=(
                StoredArtifact(
                    role="stdout",
                    relative_path=f"{number}/stdout.jsonl",
                    sha256=digest,
                    size_bytes=len(b"artifact"),
                    recorded_health=health,
                ),
            ),
        )
        for number in run_numbers
    )
    projection = correlate("lab", sources)
    return projection, assess_correlation(projection)


def state(
    report: HistoricalComparisonReport,
    rule_id: str = DIRECTORY_RULE,
    address: str = "127.0.0.1",
) -> str:
    return next(
        item.state
        for item in report.results
        if item.claim.rule_id == rule_id and item.claim.address == address
    )


def test_comparable_positive_to_negative_is_resolved() -> None:
    result = compare_assessments(
        fresh_report(number=1, positive=True),
        fresh_report(number=2, status_code=404),
    )
    item = result.results[0]
    assert item.state == "resolved"
    assert item.coverage.status == "comparable"
    assert item.baseline is not None and item.baseline.outcome == "supported_positive"
    assert item.current is not None and item.current.outcome == "supported_negative"


def test_unverified_fresh_artifact_health_cannot_resolve() -> None:
    result = compare_reports(
        fresh_report(number=1, positive=True),
        fresh_report(number=2, status_code=404),
    )
    assert state(result) == "unknown"
    assert result.results[0].coverage.reason == "fresh_evidence_health_unverified"


def test_negative_evidence_that_is_not_later_cannot_resolve() -> None:
    result = compare_assessments(
        fresh_report(number=2, positive=True),
        fresh_report(number=1, status_code=404),
    )
    assert state(result) == "unknown"
    assert result.results[0].coverage.reason == "current_evidence_not_later"


@pytest.mark.parametrize(
    ("status", "expected"),
    FALSE_RESOLUTION_MATRIX,
)
def test_failed_incomplete_or_skipped_check_never_resolves(
    status: AcquisitionStatus, expected: str
) -> None:
    result = compare_assessments(
        fresh_report(number=1, positive=True),
        fresh_report(number=2, status=status),
    )
    assert state(result) == expected


def test_empty_later_nuclei_output_is_not_observed_not_resolved() -> None:
    current_projection, current = nuclei_projection(run_numbers=(2,), positive=False)
    result = compare_assessments(
        fresh_report(number=1, positive=True),
        current,
        current_correlation=current_projection,
    )
    assert state(result) == "not_observed"


def test_positive_remains_unchanged_and_negative_to_positive_is_new() -> None:
    unchanged = compare_assessments(
        fresh_report(number=1, positive=True),
        fresh_report(number=2, positive=True),
    )
    new = compare_assessments(
        fresh_report(number=3, status_code=404),
        fresh_report(number=4, positive=True),
    )
    assert state(unchanged) == "unchanged"
    assert state(new) == "new"
    assert new.results[0].coverage.reason == "exact_check_covered"


def test_current_positive_without_baseline_context_is_new_without_introduction_claim() -> (
    None
):
    baseline = fresh_report(number=1, rule_id=GIT_CONFIG_RULE, status_code=404)
    current = fresh_report(number=2, positive=True)
    result = compare_assessments(baseline, current)
    item = next(item for item in result.results if item.claim.rule_id == DIRECTORY_RULE)
    assert item.state == "new"
    assert item.coverage.reason == "baseline_not_assessed"
    assert "introduced" not in item.explanation


def test_scope_or_profile_omission_is_not_observed() -> None:
    result = compare_assessments(
        fresh_report(number=1, positive=True),
        fresh_report(number=2, rule_id=GIT_CONFIG_RULE, status_code=404),
    )
    assert state(result) == "not_observed"
    item = next(item for item in result.results if item.claim.rule_id == DIRECTORY_RULE)
    assert item.coverage.reason == "current_check_not_selected"


def test_incompatible_rule_version_cannot_resolve() -> None:
    result = compare_assessments(
        fresh_report(number=1, positive=True),
        fresh_report(number=2, status_code=404, rule_version="2"),
    )
    assert state(result) == "unknown"
    assert result.results[0].coverage.reason == "incompatible_check_semantics"


def test_current_positive_with_incompatible_negative_baseline_is_new_with_limits() -> (
    None
):
    result = compare_assessments(
        fresh_report(number=1, status_code=404, rule_version="2"),
        fresh_report(number=2, positive=True),
    )
    assert state(result) == "new"
    assert result.results[0].coverage.reason == "incompatible_baseline_semantics"
    assert "began" in result.results[0].coverage.explanation


def test_unreviewed_serialized_template_revision_cannot_resolve() -> None:
    projection, baseline = nuclei_projection(run_numbers=(1,), positive=True)
    assessment = next(
        item for item in baseline.assessments if item.claim.rule_id == DIRECTORY_RULE
    )
    use = assessment.evidence_used[0]
    assert isinstance(use, ExistingCaptureUse)
    facts = tuple(
        fact.model_copy(update={"value": "b" * 64})
        if fact.key == "scanner.template_revision"
        else fact
        for fact in use.facts
    )
    changed_use = use.model_copy(update={"facts": facts})
    changed_assessment = assessment.model_copy(update={"evidence_used": (changed_use,)})
    baseline = baseline.model_copy(update={"assessments": (changed_assessment,)})
    result = compare_assessments(
        baseline,
        fresh_report(number=2, status_code=404),
        baseline_correlation=projection,
    )
    assert state(result) == "unknown"
    assert result.results[0].coverage.reason == "incompatible_check_semantics"


def test_different_backend_produces_not_observed_and_no_resolution() -> None:
    result = compare_assessments(
        fresh_report(number=1, positive=True, address="127.0.0.1"),
        fresh_report(number=2, status_code=404, address="127.0.0.2"),
    )
    assert state(result, address="127.0.0.1") == "not_observed"
    assert state(result, address="127.0.0.2") == "unknown"
    assert all(item.state != "resolved" for item in result.results)


def test_virtual_hosts_and_resources_remain_separate() -> None:
    first = fresh_report(number=1, positive=True, origin="https://one.invalid")
    second = fresh_report(number=2, status_code=404, origin="https://two.invalid")
    hosts = compare_assessments(first, second)
    resources = compare_assessments(
        fresh_report(number=3, positive=True),
        fresh_report(number=4, rule_id=GIT_CONFIG_RULE, status_code=404),
    )
    assert {item.claim.origin for item in hosts.results} == {
        "https://one.invalid",
        "https://two.invalid",
    }
    assert all(
        item.state != "resolved" for item in (*hosts.results, *resources.results)
    )


def test_unreachable_backend_does_not_resolve_application_condition() -> None:
    result = compare_assessments(
        fresh_report(number=1, positive=True),
        fresh_report(number=2, status="transport_error"),
    )
    assert state(result) == "unknown"


@pytest.mark.parametrize("health", ["missing", "corrupt"])
def test_unhealthy_required_artifact_cannot_resolve(
    health: Literal["missing", "corrupt"],
) -> None:
    baseline_projection, baseline = nuclei_projection(
        run_numbers=(1,), positive=True, health=health
    )
    result = compare_assessments(
        baseline,
        fresh_report(number=2, status_code=404),
        baseline_correlation=baseline_projection,
    )
    assert state(result) == "unknown"
    assert result.results[0].coverage.reason == "evidence_artifact_unhealthy"


def test_unhealthy_baseline_is_unknown_even_when_current_check_is_omitted() -> None:
    baseline_projection, baseline = nuclei_projection(
        run_numbers=(1,), positive=True, health="missing"
    )
    current = fresh_report(number=2, rule_id=GIT_CONFIG_RULE, status_code=404)
    result = compare_assessments(
        baseline, current, baseline_correlation=baseline_projection
    )
    assert state(result) == "unknown"


def test_blocked_current_response_is_unknown_not_resolved() -> None:
    result = compare_assessments(
        fresh_report(number=1, positive=True),
        fresh_report(number=2, status_code=403),
    )
    assert state(result) == "unknown"


def test_partial_current_assessment_can_resolve_independent_completed_check() -> None:
    completed = fresh_report(number=2, status_code=404)
    failed = fresh_report(number=3, rule_id=GIT_CONFIG_RULE, status="timeout")
    current = RecheckReport(
        project_id="lab",
        acquisitions=completed.acquisitions + failed.acquisitions,
        assessments=completed.assessments + failed.assessments,
    )
    result = compare_assessments(fresh_report(number=1, positive=True), current)
    assert state(result) == "resolved"


def test_order_and_repeated_capture_do_not_change_conclusion() -> None:
    one_projection, one = nuclei_projection(run_numbers=(1,), positive=True)
    two_projection, two = nuclei_projection(run_numbers=(1, 2), positive=True)
    current = fresh_report(number=3, status_code=404)
    first = compare_assessments(one, current, baseline_correlation=one_projection)
    repeated = compare_assessments(two, current, baseline_correlation=two_projection)
    assert state(first) == state(repeated) == "resolved"
    assert first.results[0].id == repeated.results[0].id
    reversed_projection = one_projection.model_copy(
        update={"sources": tuple(reversed(one_projection.sources))}
    )
    ordered = compare_assessments(one, current, baseline_correlation=one_projection)
    reversed_input = compare_assessments(
        one, current, baseline_correlation=reversed_projection
    )
    assert ordered.model_dump_json() == reversed_input.model_dump_json()


def test_project_mixing_and_missing_capture_context_are_rejected() -> None:
    other = fresh_report(number=2, status_code=404).model_copy(
        update={"project_id": "other"}
    )
    with pytest.raises(ComparisonError, match="one project"):
        compare_assessments(fresh_report(number=1, positive=True), other)
    _, stored = nuclei_projection(run_numbers=(3,), positive=True)
    with pytest.raises(ComparisonError, match="correlation projection"):
        compare_assessments(stored, fresh_report(number=4, status_code=404))


def stored_hsts(
    *, run_number: int, value: str
) -> tuple[CorrelationResult, CaptureAssessmentReport]:
    digest = f"{run_number:064x}"
    evidence = EvidenceReference(
        artifact_sha256=digest,
        record_locator="$[1]",
        scanner="httpx",
        scanner_version="1.12.0",
        adapter_version="1",
        profile_id="web",
        profile_revision="1",
        captured_at=NOW,
    )
    source = RunSource(
        run_id=UUID(int=run_number),
        project_id="lab",
        kind="scan",
        created_at=NOW + timedelta(seconds=run_number),
        finished_at=NOW + timedelta(seconds=run_number, milliseconds=100),
        scope_snapshot_id="c" * 64,
        profile=ScanProfile(id="web"),
        context=ImportContext(
            profile_id="web",
            profile_revision="1",
            web_target=WebTarget(origin=ORIGIN, approved_addresses=("127.0.0.1",)),
        ),
        report=ParsedReport(
            evidence=evidence,
            reported_exit=None,
            observations=(
                Observation(
                    subject=HttpEndpoint(origin=ORIGIN),
                    key="http.header.strict_transport_security",
                    value=value,
                    evidence=(evidence,),
                ),
                Observation(
                    subject=HttpEndpoint(origin=ORIGIN),
                    key="http.probe_succeeded",
                    value=True,
                    evidence=(evidence,),
                ),
                Observation(
                    subject=HttpEndpoint(origin=ORIGIN),
                    key="http.status_code",
                    value=200,
                    evidence=(evidence,),
                ),
                Observation(
                    subject=HttpEndpoint(origin=ORIGIN),
                    key="http.peer_address",
                    value="127.0.0.1",
                    evidence=(evidence,),
                ),
            ),
            matches=(),
        ),
        artifacts=(
            StoredArtifact(
                role="stdout",
                relative_path=f"{run_number}/stdout.jsonl",
                sha256=digest,
                size_bytes=10,
                recorded_health="ready",
            ),
        ),
    )
    projection = correlate("lab", (source,))
    return projection, assess_correlation(projection)


def test_material_hsts_header_change_is_changed_without_policy_claim() -> None:
    baseline_projection, baseline = stored_hsts(run_number=1, value="max-age=60")
    current_projection, current = stored_hsts(run_number=2, value="max-age=31536000")
    result = compare_assessments(
        baseline,
        current,
        baseline_correlation=baseline_projection,
        current_correlation=current_projection,
    )
    item = next(item for item in result.results if item.claim.rule_id == HSTS_RULE)
    assert item.state == "changed"
    assert "does not evaluate policy strength" in item.explanation


def test_different_evidence_representation_alone_is_not_changed() -> None:
    baseline_projection, baseline = nuclei_projection(run_numbers=(1,), positive=True)
    current = fresh_report(number=2, positive=True)
    result = compare_assessments(
        baseline,
        current,
        baseline_correlation=baseline_projection,
    )
    assert state(result) == "unchanged"


def test_comparison_identity_ignores_acquisition_ids_and_does_not_mutate_inputs() -> (
    None
):
    baseline = fresh_report(number=1, positive=True)
    current = fresh_report(number=2, status_code=404)
    before = baseline.model_dump_json(), current.model_dump_json()
    first = compare_assessments(baseline, current)
    second = compare_assessments(
        fresh_report(number=10, positive=True),
        fresh_report(number=11, status_code=404),
    )
    assert first.results[0].id == second.results[0].id
    assert first.results[0].state == second.results[0].state == "resolved"
    assert before == (baseline.model_dump_json(), current.model_dump_json())


def test_comparison_performs_no_network_dns_scanner_or_process_activity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("comparison attempted external activity")

    for name in ("getaddrinfo", "gethostbyname", "create_connection", "socket"):
        monkeypatch.setattr(socket, name, forbidden)
    for name in ("Popen", "run"):
        monkeypatch.setattr(subprocess, name, forbidden)
    result = compare_assessments(
        fresh_report(number=1, positive=True),
        fresh_report(number=2, status_code=404),
    )
    assert state(result) == "resolved"


def test_stored_comparison_reads_explicit_sides_from_one_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scopelens.storage import correlation as storage

    baseline_projection, _ = nuclei_projection(run_numbers=(1,), positive=True)
    current_projection, _ = nuclei_projection(run_numbers=(2,), positive=False)
    combined = correlate(
        "lab", baseline_projection.sources + current_projection.sources
    )
    load = Mock(return_value=combined)
    monkeypatch.setattr(storage, "correlate_history", load)
    engine = Mock()
    artifacts = Mock(read=Mock(return_value=b"artifact"))
    result = storage.compare_history(
        engine, artifacts, "lab", [UUID(int=1)], [UUID(int=2)]
    )
    load.assert_called_once_with(engine, "lab", (UUID(int=1), UUID(int=2)))
    assert state(result) == "not_observed"


def test_stored_comparison_rejects_duplicate_side_selection() -> None:
    from scopelens.analysis.correlation import CorrelationError
    from scopelens.storage.correlation import compare_history

    with pytest.raises(CorrelationError, match="once per comparison side"):
        compare_history(
            Mock(),
            Mock(),
            "lab",
            [UUID(int=1), UUID(int=1)],
            [UUID(int=2)],
        )


def test_stored_comparison_rechecks_artifact_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scopelens.storage import correlation as storage

    baseline_projection, _ = nuclei_projection(run_numbers=(1,), positive=True)
    current_projection, _ = nuclei_projection(run_numbers=(2,), positive=False)
    combined = correlate(
        "lab", baseline_projection.sources + current_projection.sources
    )
    monkeypatch.setattr(storage, "correlate_history", Mock(return_value=combined))
    missing = Mock()
    missing.read.side_effect = FileNotFoundError
    result = storage.compare_history(
        Mock(), missing, "lab", [UUID(int=1)], [UUID(int=2)]
    )
    assert all(item.state != "resolved" for item in result.results)
    assert state(result) == "unknown"
    assert missing.read.call_count == 2


def test_import_authorization_is_not_observed_backend_or_acquisition_time() -> None:
    projection, baseline = nuclei_projection(
        run_numbers=(1,), positive=True, kind="import"
    )
    result = compare_assessments(
        baseline,
        fresh_report(number=2, status_code=404),
        baseline_correlation=projection,
    )
    assert all(item.state != "resolved" for item in result.results)


def test_unknown_and_known_backend_contexts_can_coexist() -> None:
    projection, baseline = nuclei_projection(run_numbers=(1,), positive=True)
    source = projection.sources[0]
    source = source.model_copy(
        update={
            "context": source.context.model_copy(
                update={
                    "web_target": WebTarget(
                        origin=ORIGIN, approved_addresses=("127.0.0.1", "127.0.0.2")
                    )
                }
            )
        }
    )
    projection = correlate("lab", (source,))
    result = compare_assessments(
        baseline,
        fresh_report(number=2, status_code=404),
        baseline_correlation=projection,
    )
    assert all(item.state != "resolved" for item in result.results)


def test_negative_assessment_cannot_borrow_another_resources_acquisition() -> None:
    current = fresh_report(number=2, status_code=404)
    acquisition = current.acquisitions[0].model_copy(update={"resource": "/other"})
    current = current.model_copy(update={"acquisitions": (acquisition,)})
    result = compare_assessments(fresh_report(number=1, positive=True), current)
    assert state(result) == "unknown"


def test_failed_acquisition_cannot_carry_a_supported_negative_assessment() -> None:
    current = fresh_report(number=2, status_code=404)
    failed = exchange(number=2, status="timeout").acquisition
    current = current.model_copy(update={"acquisitions": (failed,)})
    result = compare_assessments(fresh_report(number=1, positive=True), current)
    assert state(result) == "unknown"


def test_unknown_equal_rule_versions_do_not_inherit_current_semantics() -> None:
    result = compare_assessments(
        fresh_report(number=1, positive=True, rule_version="unreviewed"),
        fresh_report(number=2, status_code=404, rule_version="unreviewed"),
    )
    assert state(result) == "unknown"


@pytest.mark.parametrize("finish", [None, NOW + timedelta(seconds=3)])
def test_missing_completion_or_overlapping_acquisitions_cannot_resolve(
    finish: datetime | None,
) -> None:
    baseline = fresh_report(number=1, positive=True)
    acquisition = baseline.acquisitions[0].model_copy(update={"finished_at": finish})
    baseline = baseline.model_copy(update={"acquisitions": (acquisition,)})
    result = compare_assessments(baseline, fresh_report(number=2, status_code=404))
    assert state(result) == "unknown"
    assert result.results[0].reason == "current_evidence_not_later"


@pytest.mark.parametrize(
    "scanner_time", [NOW - timedelta(days=365), NOW + timedelta(days=365)]
)
def test_scanner_event_timestamps_do_not_order_managed_acquisitions(
    scanner_time: datetime,
) -> None:
    projection, _ = nuclei_projection(run_numbers=(1,), positive=True)
    source = projection.sources[0]
    match = source.report.matches[0]
    match = match.model_copy(
        update={
            "evidence": tuple(
                ref.model_copy(update={"captured_at": scanner_time})
                for ref in match.evidence
            )
        }
    )
    source = source.model_copy(
        update={"report": source.report.model_copy(update={"matches": (match,)})}
    )
    projection = correlate("lab", (source,))
    result = compare_assessments(
        assess_correlation(projection),
        fresh_report(number=2, status_code=404),
        baseline_correlation=projection,
    )
    assert state(result) == "resolved"
    late_run = source.model_copy(update={"finished_at": NOW + timedelta(days=1)})
    projection = correlate("lab", (late_run,))
    result = compare_assessments(
        assess_correlation(projection),
        fresh_report(number=2, status_code=404),
        baseline_correlation=projection,
    )
    assert state(result) == "unknown"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("template_revision", "b" * 64),
        ("matcher", "unreviewed"),
        ("template_id", "unreviewed"),
        ("matched_location", ORIGIN + "/other"),
    ],
)
def test_nuclei_compatibility_requires_reviewed_matcher_revision_and_resource(
    field: str, value: str
) -> None:
    projection, _ = nuclei_projection(run_numbers=(1,), positive=True)
    source = projection.sources[0]
    match = source.report.matches[0].model_copy(update={field: value})
    source = source.model_copy(
        update={"report": source.report.model_copy(update={"matches": (match,)})}
    )
    projection = correlate("lab", (source,))
    result = compare_assessments(
        assess_correlation(projection),
        fresh_report(number=2, status_code=404),
        baseline_correlation=projection,
    )
    assert all(item.state != "resolved" for item in result.results)


@pytest.mark.parametrize("status_code", [302, 401, 403, 407, 429, 500])
def test_redirect_auth_and_block_responses_do_not_resolve(status_code: int) -> None:
    result = compare_assessments(
        fresh_report(number=1, positive=True),
        fresh_report(number=2, status_code=status_code),
    )
    assert state(result) == "unknown"


def test_same_claim_on_another_resource_cannot_resolve() -> None:
    current = fresh_report(number=2, status_code=404)
    assessment = current.assessments[0]
    claim = assessment.claim.model_copy(update={"resource": "/other"})
    current = current.model_copy(
        update={
            "assessments": (
                assessment.model_copy(
                    update={"claim": claim, "id": assessment_id("lab", claim)}
                ),
            ),
            "acquisitions": (
                current.acquisitions[0].model_copy(update={"resource": "/other"}),
            ),
        }
    )
    result = compare_assessments(fresh_report(number=1, positive=True), current)
    assert all(item.state != "resolved" for item in result.results)
    assert (
        next(item.state for item in result.results if item.claim.resource == "/")
        == "not_observed"
    )


def test_closed_nmap_port_is_not_an_application_negative() -> None:
    from scopelens.adapters.nmap import NmapAdapter

    report = NmapAdapter().parse(
        b'<nmaprun scanner="nmap" version="7.95" start="1"><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="closed"/></port></ports></host><runstats><finished time="2" exit="success"/></runstats></nmaprun>',
        ImportContext(profile_id="local", profile_revision="1"),
    )
    template, _ = nuclei_projection(run_numbers=(2,), positive=False)
    source = template.sources[0].model_copy(
        update={
            "report": report,
            "context": ImportContext(profile_id="local", profile_revision="1"),
            "artifacts": (),
        }
    )
    projection = correlate("lab", (source,))
    assert any(
        observation.key == "service.state" and observation.value == "closed"
        for observation in report.observations
    )
    result = compare_assessments(
        fresh_report(number=1, positive=True),
        assess_correlation(projection),
        current_correlation=projection,
    )
    assert state(result) == "not_observed"


def test_httpx_backend_is_taken_from_its_response_record() -> None:
    first, _ = stored_hsts(run_number=1, value="max-age=60")
    source = first.sources[0]
    target = WebTarget(origin=ORIGIN, approved_addresses=("127.0.0.1", "127.0.0.2"))
    source = source.model_copy(
        update={"context": source.context.model_copy(update={"web_target": target})}
    )
    baseline = correlate("lab", (source,))
    second, _ = stored_hsts(run_number=2, value="max-age=60")
    source = second.sources[0]
    observations = tuple(
        item.model_copy(update={"value": "127.0.0.2"})
        if item.key == "http.peer_address"
        else item
        for item in source.report.observations
    )
    source = source.model_copy(
        update={
            "context": source.context.model_copy(update={"web_target": target}),
            "report": source.report.model_copy(update={"observations": observations}),
        }
    )
    current = correlate("lab", (source,))
    result = compare_assessments(
        assess_correlation(baseline),
        assess_correlation(current),
        baseline_correlation=baseline,
        current_correlation=current,
    )
    assert {item.claim.address for item in result.results} == {"127.0.0.1", "127.0.0.2"}
    assert state(result, HSTS_RULE, "127.0.0.1") == "not_observed"
    assert state(result, HSTS_RULE, "127.0.0.2") == "new"


def test_import_dates_and_duplicate_copies_do_not_manufacture_progression() -> None:
    first, _ = stored_hsts(run_number=1, value="max-age=60")
    source = first.sources[0].model_copy(update={"kind": "import"})
    baseline = correlate("lab", (source,))
    copy = source.model_copy(
        update={
            "run_id": UUID(int=2),
            "created_at": NOW + timedelta(days=365),
            "finished_at": NOW + timedelta(days=366),
        }
    )
    current = correlate("lab", (copy, source))
    result = compare_assessments(
        assess_correlation(baseline),
        assess_correlation(current),
        baseline_correlation=baseline,
        current_correlation=current,
    )
    assert state(result, HSTS_RULE) == "unchanged"
    assert result.results[0].reason == "same_capture_no_new_acquisition"
    reordered = correlate("lab", (source, copy))
    second = compare_assessments(
        assess_correlation(baseline),
        assess_correlation(reordered),
        baseline_correlation=baseline,
        current_correlation=reordered,
    )
    assert result == second


def test_duplicate_missing_copy_does_not_discard_a_healthy_identical_copy() -> None:
    projection, _ = nuclei_projection(run_numbers=(1, 2), positive=True)
    first, copy = projection.sources
    copy = copy.model_copy(
        update={
            "artifacts": tuple(
                item.model_copy(update={"recorded_health": "missing"})
                for item in copy.artifacts
            )
        }
    )
    projection = correlate("lab", (first, copy))
    result = compare_assessments(
        assess_correlation(projection),
        fresh_report(number=3, status_code=404),
        baseline_correlation=projection,
    )
    assert state(result) == "resolved"


def test_stale_recorded_capture_health_does_not_establish_resolution() -> None:
    projection, baseline = nuclei_projection(run_numbers=(1,), positive=True)
    current = fresh_report(number=2, status_code=404)
    result = compare_reports(
        baseline,
        current,
        baseline_correlation=projection,
        current_acquisition_health={UUID(int=2): "ready"},
    )
    assert state(result) == "unknown"
    assert result.results[0].coverage.reason == "capture_evidence_health_unverified"


def test_evidence_fact_order_and_presentation_do_not_change_identity_or_state() -> None:
    projection, baseline = nuclei_projection(run_numbers=(1, 2), positive=True)
    current = fresh_report(number=3, status_code=404)
    expected = compare_assessments(baseline, current, baseline_correlation=projection)
    changed = tuple(
        item.model_copy(
            update={
                "evidence_used": tuple(
                    use.model_copy(update={"facts": tuple(reversed(use.facts))})
                    for use in reversed(item.evidence_used)
                ),
                "explanation": "Different presentation.",
                "claim": item.claim.model_copy(
                    update={"statement": "Different wording."}
                ),
            }
        )
        for item in reversed(baseline.assessments)
    )
    baseline = baseline.model_copy(update={"assessments": changed})
    result = compare_assessments(baseline, current, baseline_correlation=projection)
    assert [(item.id, item.state) for item in result.results] == [
        (item.id, item.state) for item in expected.results
    ]


def test_header_outer_whitespace_does_not_create_changed() -> None:
    first, baseline = stored_hsts(run_number=1, value="max-age=60")
    second, current = stored_hsts(run_number=2, value=" \tmax-age=60\t ")
    result = compare_assessments(
        baseline, current, baseline_correlation=first, current_correlation=second
    )
    assert state(result, HSTS_RULE) == "unchanged"


@pytest.mark.parametrize(
    "damage", ["missing", "digest", "traversal", "symlink", "directory_link"]
)
def test_comparison_checks_real_artifacts_without_rewriting_health(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    import sys

    from scopelens.storage import correlation as storage
    from scopelens.storage.artifacts import ArtifactStore

    if sys.platform != "linux":
        pytest.skip("private artifacts require Linux")
    store = ArtifactStore(tmp_path / "private")
    sources = []
    for number, positive in ((1, True), (2, False)):
        projection, _ = nuclei_projection(run_numbers=(number,), positive=positive)
        source = projection.sources[0]
        relative, digest, size = store.publish(
            source.run_id, "stdout.jsonl", b"artifact"
        )
        sources.append(
            source.model_copy(
                update={
                    "artifacts": (
                        StoredArtifact(
                            role="stdout",
                            relative_path=relative,
                            sha256=digest,
                            size_bytes=size,
                            recorded_health="ready",
                        ),
                    )
                }
            )
        )
    baseline = sources[0]
    artifact = baseline.artifacts[0]
    path = store.path(artifact.relative_path)
    if damage == "missing":
        path.unlink()
    elif damage == "digest":
        path.write_bytes(b"tampered")
    elif damage == "traversal":
        sources[0] = baseline.model_copy(
            update={
                "artifacts": (
                    artifact.model_copy(update={"relative_path": "../outside"}),
                )
            }
        )
    elif damage == "symlink":
        path.unlink()
        path.symlink_to(store.path(sources[1].artifacts[0].relative_path))
    else:
        moved = store.root / "moved"
        path.parent.rename(moved)
        path.parent.symlink_to(moved, target_is_directory=True)
    combined = correlate("lab", sources)
    before = combined.model_dump_json()
    monkeypatch.setattr(storage, "correlate_history", Mock(return_value=combined))
    engine = Mock()
    result = storage.compare_history(engine, store, "lab", [UUID(int=1)], [UUID(int=2)])
    assert state(result) == "unknown"
    assert all(item.state != "resolved" for item in result.results)
    assert combined.model_dump_json() == before
    assert engine.mock_calls == []


def test_reimporting_a_managed_capture_does_not_change_its_context_or_timing() -> None:
    projection, baseline = nuclei_projection(run_numbers=(1,), positive=True)
    source = projection.sources[0]
    imported = source.model_copy(
        update={
            "kind": "import",
            "run_id": UUID(int=2),
            "created_at": NOW + timedelta(days=30),
            "finished_at": NOW + timedelta(days=31),
        }
    )
    repeated = correlate("lab", (source, imported))
    current = fresh_report(number=3, status_code=404)
    first = compare_assessments(baseline, current, baseline_correlation=projection)
    second = compare_assessments(
        assess_correlation(repeated), current, baseline_correlation=repeated
    )
    assert [(item.id, item.state) for item in first.results] == [
        (item.id, item.state) for item in second.results
    ]
    assert state(second) == "resolved"


def test_failed_httpx_attempt_keeps_target_context_without_claiming_a_peer() -> None:
    baseline_projection, baseline = stored_hsts(run_number=1, value="max-age=60")
    current_projection, _ = stored_hsts(run_number=2, value="max-age=60")
    source = current_projection.sources[0]
    reference = source.report.evidence
    observations = (
        Observation(
            subject=HttpEndpoint(origin=ORIGIN),
            key="http.probe_succeeded",
            value=False,
            evidence=(reference,),
        ),
        Observation(
            subject=HttpEndpoint(origin=ORIGIN),
            key="http.target_address",
            value="127.0.0.1",
            evidence=(reference,),
        ),
    )
    source = source.model_copy(
        update={
            "report": source.report.model_copy(update={"observations": observations})
        }
    )
    current_projection = correlate("lab", (source,))
    result = compare_assessments(
        baseline,
        assess_correlation(current_projection),
        baseline_correlation=baseline_projection,
        current_correlation=current_projection,
    )
    assert state(result, HSTS_RULE) == "unknown"
    assert result.results[0].coverage.reason == "header_capture_incomplete"


@pytest.mark.parametrize("complete_headers", [True, False])
def test_hsts_resolution_requires_headers_but_not_an_entire_body(
    complete_headers: bool,
) -> None:
    first = exchange(number=1)
    assert first.acquisition.response is not None
    acquisition = first.acquisition.model_copy(
        update={
            "response": first.acquisition.response.model_copy(
                update={"strict_transport_security_present": True}
            )
        }
    )
    first = CapturedExchange(acquisition, first.body)
    second = exchange(number=2, status="truncated")
    assert second.acquisition.response is not None
    second = CapturedExchange(
        second.acquisition.model_copy(
            update={
                "response": second.acquisition.response.model_copy(
                    update={"headers_complete": complete_headers}
                )
            }
        ),
        second.body,
    )
    baseline = RecheckReport(
        project_id="lab",
        acquisitions=(first.acquisition,),
        assessments=(assess_hsts_recheck("lab", first),),
    )
    current = RecheckReport(
        project_id="lab",
        acquisitions=(second.acquisition,),
        assessments=(assess_hsts_recheck("lab", second),),
    )
    result = compare_assessments(baseline, current)
    assert state(result, HSTS_RULE) == ("resolved" if complete_headers else "unknown")


@pytest.mark.parametrize(
    "body", [b"<title>Access denied</title>", b"<input type='password'>", b"captcha"]
)
def test_ambiguous_200_bodies_are_not_historical_negatives(body: bytes) -> None:
    capture = exchange(number=2, body=body)
    current = RecheckReport(
        project_id="lab",
        acquisitions=(capture.acquisition,),
        assessments=(assess_exposure_recheck("lab", DIRECTORY_RULE, capture),),
    )
    result = compare_assessments(fresh_report(number=1, positive=True), current)
    assert state(result) == "unknown"


def test_missing_prerequisites_cannot_resolve() -> None:
    current = fresh_report(number=2, status_code=404)
    assessment = current.assessments[0]
    current = current.model_copy(
        update={
            "assessments": (
                assessment.model_copy(
                    update={"prerequisites": assessment.prerequisites[:1]}
                ),
            )
        }
    )
    assert (
        state(compare_assessments(fresh_report(number=1, positive=True), current))
        == "unknown"
    )


def test_timeout_cannot_be_presented_as_a_skipped_check() -> None:
    current = fresh_report(number=2, status="timeout")
    current = current.model_copy(
        update={
            "assessments": (
                current.assessments[0].model_copy(update={"reason": "check_not_run"}),
            )
        }
    )
    assert (
        state(compare_assessments(fresh_report(number=1, positive=True), current))
        == "unknown"
    )
