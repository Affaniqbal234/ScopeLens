import argparse
import json
import socket
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast
from uuid import UUID

import pytest

from scopelens.analysis.models import AssertionGroup, SourceReference
from scopelens.assessment.models import (
    AcquisitionEvidence,
    AssessmentResult,
    CapturedResponse,
    EvidenceFact,
    FreshRecheckUse,
    Outcome,
    Prerequisite,
    RecheckAcquisition,
    RecheckReport,
    assessment_id,
)
from scopelens.assessment.rules import (
    DIRECTORY_RULE,
    GIT_CONFIG_RULE,
    HSTS_RULE,
    exposure_claim,
    hsts_claim,
)
from scopelens.cli import main
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
from scopelens.config import ProjectConfig
from scopelens.domain.scope import (
    AssessmentProject,
    AuthorizedScope,
    ScanProfile,
    WebTarget,
)
from scopelens.orchestration.models import (
    AssessmentManifest,
    PlannedStage,
    StageRequest,
)
from scopelens.reporting.cli import recheck_selection
from scopelens.reporting.io import ReportOutputError, write_new
from scopelens.reporting.models import AssessmentReport, ComparisonReport
from scopelens.reporting.projection import (
    build_assessment_report,
    build_comparison_report,
)
from scopelens.reporting.render import render_html, render_json
from scopelens.reporting.snapshot import build_public_snapshot

NOW = datetime(2026, 4, 1, 10, tzinfo=UTC)
ASSESSMENT_ID = UUID("10000000-0000-4000-8000-000000000001")
STAGE_IDS = tuple(
    UUID(f"20000000-0000-4000-8000-{index:012d}") for index in range(1, 5)
)
ACQUISITION_ID = UUID("30000000-0000-4000-8000-000000000001")
SECOND_ACQUISITION_ID = UUID("30000000-0000-4000-8000-000000000002")
ADDRESS = "10.20.30.40"


def config() -> ProjectConfig:
    return ProjectConfig(
        project=AssessmentProject(
            id="private_lab",
            name="postgresql://operator:secret@db/private C:\\Users\\operator",
            scope=AuthorizedScope(
                web_targets=(
                    WebTarget(
                        origin="https://internal-one.scope.test",
                        approved_addresses=(ADDRESS,),
                    ),
                    WebTarget(
                        origin="https://internal-two.scope.test",
                        approved_addresses=(ADDRESS,),
                    ),
                )
            ),
        ),
        profiles=(ScanProfile(id="conservative", max_targets=4),),
    )


def request(
    kind: Literal["httpx", "nuclei", "web_recheck"],
    origin: str = "https://internal-one.scope.test",
) -> StageRequest:
    target = WebTarget(origin=origin, approved_addresses=(ADDRESS,))
    if kind == "web_recheck":
        return StageRequest(
            kind="web_recheck",
            profile_id="conservative",
            web_target=target,
            resources=("/", "/.git/config"),
            rule_revision="assessment-v1:1",
        )
    run_id = UUID(f"40000000-0000-4000-8000-{len(kind):012d}")
    return StageRequest(
        kind=kind,
        profile_id="conservative",
        web_target=target,
        resources=("/",) if kind == "httpx" else ("/", "/.git/config"),
        rule_revision="a" * 64 if kind == "nuclei" else None,
        planned_run_id=run_id,
    )


def manifest() -> AssessmentManifest:
    stages = (
        PlannedStage(
            id=STAGE_IDS[0],
            ordinal=0,
            request=request("web_recheck"),
            status="completed",
            started_at=NOW,
            finished_at=NOW + timedelta(seconds=2),
        ),
        PlannedStage(
            id=STAGE_IDS[1],
            ordinal=1,
            request=request("nuclei"),
            status="failed",
            started_at=NOW + timedelta(seconds=2),
            finished_at=NOW + timedelta(seconds=3),
            reason="Authorization: Bearer local-api-secret",
        ),
        PlannedStage(
            id=STAGE_IDS[2],
            ordinal=2,
            request=request("httpx"),
            status="skipped",
            finished_at=NOW + timedelta(seconds=3),
            reason="profile_omitted",
        ),
        PlannedStage(
            id=STAGE_IDS[3],
            ordinal=3,
            request=request("web_recheck", "https://internal-two.scope.test"),
            status="interrupted",
            started_at=NOW + timedelta(seconds=3),
            finished_at=NOW + timedelta(seconds=4),
            reason="/home/operator/private/token",
        ),
    )
    return AssessmentManifest(
        id=ASSESSMENT_ID,
        project_id="private_lab",
        scope_snapshot_id="d" * 64,
        status="interrupted",
        created_at=NOW - timedelta(minutes=1),
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=4),
        reason="worker_interrupted Cookie=session-secret",
        stages=stages,
    )


def result(
    rule_id: str,
    outcome: Outcome,
    *,
    origin: str = "https://internal-one.scope.test",
    acquisition_id: UUID = ACQUISITION_ID,
) -> AssessmentResult:
    claim = (
        hsts_claim(origin) if rule_id == HSTS_RULE else exposure_claim(rule_id, origin)
    )
    return AssessmentResult(
        id=assessment_id("private_lab", claim),
        claim=claim,
        prerequisites=(
            Prerequisite(id="usable_response", state="met", explanation="usable"),
        ),
        outcome=outcome,
        reason="deterministic_result",
        explanation="Set-Cookie: private=value; Authorization: Bearer secret-token",
        evidence_used=(
            FreshRecheckUse(
                acquisition_id=acquisition_id,
                facts=(EvidenceFact(key="http.status_code", value=200),),
            ),
        ),
        limitations=("C:\\private\\artifact and /home/operator/private",),
    )


def recheck() -> RecheckReport:
    root_acquisition = RecheckAcquisition(
        id=ACQUISITION_ID,
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
        origin="https://internal-one.scope.test",
        approved_address=ADDRESS,
        resource="/",
        status="complete",
        evidence=AcquisitionEvidence(
            artifact_path=f"{ACQUISITION_ID}/response.http",
            artifact_sha256="e" * 64,
            size_bytes=200,
        ),
        response=CapturedResponse(
            status_code=200,
            headers_complete=True,
            body_complete=True,
            body_sha256="f" * 64,
            strict_transport_security_present=False,
            access_challenge_present=False,
            content_encoding_identity=True,
        ),
    )
    git_acquisition = root_acquisition.model_copy(
        update={
            "id": SECOND_ACQUISITION_ID,
            "resource": "/.git/config",
            "evidence": AcquisitionEvidence(
                artifact_path=f"{SECOND_ACQUISITION_ID}/response.http",
                artifact_sha256="a" * 64,
                size_bytes=220,
            ),
        }
    )
    return RecheckReport(
        project_id="private_lab",
        acquisitions=(root_acquisition, git_acquisition),
        assessments=(
            result(DIRECTORY_RULE, "supported_negative"),
            result(
                GIT_CONFIG_RULE,
                "supported_positive",
                acquisition_id=SECOND_ACQUISITION_ID,
            ),
            result(HSTS_RULE, "supported_positive"),
        ),
    )


def assessment_report() -> AssessmentReport:
    report = build_assessment_report(
        config(),
        manifest(),
        rechecks={
            STAGE_IDS[0]: (
                recheck(),
                {ACQUISITION_ID: "ready", SECOND_ACQUISITION_ID: "corrupt"},
            )
        },
    )
    secret_assertion = AssertionGroup(
        subject_id=f"inventory-v1:{'a' * 64}",
        key="http.title",
        value="DATABASE_URL=postgresql://secret",
        occurrences=(
            SourceReference(run_id=UUID(int=9), section="observations", ordinal=0),
        ),
    )
    return report.model_copy(update={"assertions": (secret_assertion,)})


def reference(
    outcome: Outcome, health: Literal["ready", "unavailable"] = "ready"
) -> AssessmentReference:
    return AssessmentReference(
        assessment_id=f"assessment-v1:{'b' * 64}",
        rule_version="1",
        outcome=outcome,
        reason="fixture",
        evidence_health=health,
        observed_at=(NOW,),
        acquisition_started_at=NOW,
        acquisition_finished_at=NOW + timedelta(seconds=1),
        evidence_used=(),
    )


def historical(
    rule_id: str, origin: str, state: HistoricalState
) -> HistoricalComparison:
    resource = "/.git/config" if rule_id == GIT_CONFIG_RULE else "/"
    claim = ClaimKey(rule_id=rule_id, origin=origin, resource=resource, address=ADDRESS)
    baseline = reference("supported_positive")
    current = {
        "resolved": reference("supported_negative"),
        "unchanged": reference("supported_positive"),
        "new": reference("supported_positive"),
        "unknown": reference("inconclusive", "unavailable"),
        "not_observed": None,
    }[state]
    coverage = cast(
        CoverageStatus,
        {
            "resolved": "comparable",
            "unchanged": "comparable",
            "new": "not_assessed",
            "unknown": "unusable",
            "not_observed": "not_assessed",
        }[state],
    )
    return HistoricalComparison(
        id=comparison_id("private_lab", claim),
        claim=claim,
        state=state,
        reason=f"{state}_fixture",
        explanation="internal explanation with secret-token",
        coverage=CoverageDecision(
            status=coverage,
            reason="fixture_coverage",
            explanation="internal backend details",
        ),
        baseline=(None if state == "new" else baseline),
        current=current,
        limitations=("/home/operator/private",),
    )


def comparison_report() -> ComparisonReport:
    comparison = HistoricalComparisonReport(
        project_id="private_lab",
        baseline=ComparisonSelection(basis="fresh_recheck", identifiers=("baseline",)),
        current=ComparisonSelection(basis="fresh_recheck", identifiers=("current",)),
        results=(
            historical(HSTS_RULE, "https://internal-one.scope.test", "resolved"),
            historical(DIRECTORY_RULE, "https://internal-one.scope.test", "unknown"),
            historical(
                GIT_CONFIG_RULE, "https://internal-two.scope.test", "not_observed"
            ),
            historical(HSTS_RULE, "https://internal-two.scope.test", "new"),
        ),
    )
    return build_comparison_report(
        "private_lab", "postgresql://operator:secret@db/private", comparison
    )


def test_assessment_report_preserves_plan_execution_coverage_and_evidence() -> None:
    report = assessment_report()
    assert [item.status for item in report.stages] == [
        "completed",
        "failed",
        "skipped",
        "interrupted",
    ]
    assert report.coverage.partial is True
    assert report.coverage.completed == report.coverage.failed == 1
    assert report.coverage.skipped == report.coverage.interrupted == 1
    assert any(item.health == "corrupt" for item in report.evidence_health)
    assert {item.display_outcome for item in report.claims} == {
        "condition_supported",
        "condition_not_supported_by_this_evidence",
    }
    by_rule = {item.result.claim.rule_id: item for item in report.claims}
    assert by_rule[DIRECTORY_RULE].acquisition_ids == (ACQUISITION_ID,)
    assert by_rule[HSTS_RULE].acquisition_ids == (ACQUISITION_ID,)
    assert by_rule[GIT_CONFIG_RULE].acquisition_ids == (SECOND_ACQUISITION_ID,)


def test_json_and_html_are_deterministic_and_evidence_qualified() -> None:
    assessment = assessment_report()
    before = assessment.model_dump(mode="json")
    assert render_json(assessment) == render_json(assessment)
    html = render_html(assessment).decode()
    assert "This assessment is partial" in html
    assert "condition supported" in html
    assert "condition not supported by this evidence" in html
    assert "corrupt" in html
    assert str(ACQUISITION_ID) in html
    assert assessment.model_dump(mode="json") == before

    comparison = comparison_report()
    reversed_input = comparison.comparison.model_copy(
        update={"results": tuple(reversed(comparison.comparison.results))}
    )
    rebuilt = build_comparison_report(
        comparison.project.id, comparison.project.name, reversed_input
    )
    assert render_json(comparison) == render_json(rebuilt)
    comparison_html = render_html(comparison).decode()
    assert "This does not prove an underlying code fix" in comparison_html
    assert "not observed" in comparison_html
    assert "unknown" in comparison_html
    assert "secure now" not in comparison_html.lower()
    assert "permanently fixed" not in comparison_html.lower()


def test_public_snapshot_is_allowlisted_pure_and_preserves_demo_cases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket, "create_connection", lambda *args, **kwargs: pytest.fail("network used")
    )
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args, **kwargs: pytest.fail("DNS used")
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: pytest.fail("process used")
    )
    monkeypatch.setattr(
        subprocess, "Popen", lambda *args, **kwargs: pytest.fail("process used")
    )
    source = comparison_report()
    before = source.model_dump(mode="json")
    snapshot = build_public_snapshot(source)
    encoded = render_json(snapshot).decode()
    assert {item.state for item in snapshot.lifecycle} == {
        "resolved",
        "unknown",
        "not_observed",
        "new",
    }
    assert {item.rule_version for item in snapshot.lifecycle} == {"1"}
    resolved = next(item for item in snapshot.lifecycle if item.state == "resolved")
    assert len(resolved.provenance_refs) == 2
    assert len(set(resolved.provenance_refs)) == 2
    assert len({item.origin for item in snapshot.contexts}) == 2
    assert len({item.address for item in snapshot.contexts}) == 1
    assert "example.invalid" in encoded
    for secret in (
        "secret-token",
        "postgresql://",
        "C:\\\\private",
        "/home/operator",
        "Authorization",
        "Set-Cookie",
        "DATABASE_URL",
        "internal-one.scope.test",
    ):
        assert secret not in encoded
    assert source.model_dump(mode="json") == before


def test_assessment_snapshot_hides_nested_secrets_and_exposes_only_schema_fields() -> (
    None
):
    snapshot = build_public_snapshot(assessment_report())
    payload = json.loads(render_json(snapshot))
    assert set(payload) == {
        "claims",
        "contexts",
        "coverage_note",
        "display_name",
        "lifecycle",
        "recorded_data_notice",
        "source_kind",
        "source_ref",
        "source_report_version",
        "stages",
        "version",
    }
    encoded = json.dumps(payload)
    for secret in (
        "local-api-secret",
        "session-secret",
        "private_lab",
        "internal-one.scope.test",
        "DATABASE_URL",
        "response.http",
        "operator:secret",
        "http.title",
    ):
        assert secret not in encoded
    assert {item.outcome for item in snapshot.claims} == {
        "condition_supported",
        "condition_not_supported_by_this_evidence",
    }
    by_rule = {item.rule_id: item for item in snapshot.claims}
    assert by_rule[DIRECTORY_RULE].evidence_health == "ready"
    assert by_rule[HSTS_RULE].evidence_health == "ready"
    assert by_rule[GIT_CONFIG_RULE].evidence_health == "corrupt"


def test_output_is_atomic_and_never_overwrites(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    write_new(output, b"first")
    assert output.read_bytes() == b"first"
    with pytest.raises(ReportOutputError, match="refusing overwrite"):
        write_new(output, b"second")
    assert output.read_bytes() == b"first"


def test_recheck_selector_requires_explicit_assessment_and_stage_ids() -> None:
    selection = recheck_selection(f"{ASSESSMENT_ID}:{STAGE_IDS[0]}")
    assert selection.assessment_id == ASSESSMENT_ID
    assert selection.stage_id == STAGE_IDS[0]
    with pytest.raises(argparse.ArgumentTypeError, match="ASSESSMENT_UUID:STAGE_UUID"):
        recheck_selection(str(ASSESSMENT_ID))


@pytest.mark.parametrize(
    "arguments",
    [
        ["assessment-report", str(ASSESSMENT_ID), "--format", "json"],
        [
            "comparison-report",
            "--project",
            "private_lab",
            "--format",
            "json",
            "--output",
            "report.json",
        ],
    ],
)
def test_report_cli_requires_output_and_explicit_comparison_membership(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(arguments)
    assert exc.value.code == 2
    assert "required" in capsys.readouterr().err
