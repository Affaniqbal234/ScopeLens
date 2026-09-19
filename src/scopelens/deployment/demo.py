from datetime import UTC, datetime, timedelta
from typing import Literal, cast

from scopelens.assessment.models import Outcome
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
from scopelens.reporting.models import ComparisonReport
from scopelens.reporting.projection import build_comparison_report

RECORDED_AT = datetime(2026, 1, 15, 12, tzinfo=UTC)
PROJECT_ID = "controlled-demo"
ADDRESS = "192.0.2.44"


def _reference(
    outcome: Outcome,
    identity: str,
    *,
    health: Literal["ready", "unavailable"] = "ready",
    started_at: datetime = RECORDED_AT,
) -> AssessmentReference:
    return AssessmentReference(
        assessment_id=f"assessment-v1:{identity * 64}",
        rule_version="1",
        outcome=outcome,
        reason="recorded_controlled_fixture",
        evidence_health=health,
        observed_at=(started_at,),
        acquisition_started_at=started_at,
        acquisition_finished_at=started_at + timedelta(seconds=1),
        evidence_used=(),
    )


def _lifecycle(
    rule_id: str,
    origin: str,
    state: HistoricalState,
) -> HistoricalComparison:
    resource = "/.git/config" if rule_id == GIT_CONFIG_RULE else "/"
    claim = ClaimKey(rule_id=rule_id, origin=origin, resource=resource, address=ADDRESS)
    baseline = _reference("supported_positive", "b")
    current = {
        "resolved": _reference(
            "supported_negative", "c", started_at=RECORDED_AT + timedelta(hours=1)
        ),
        "unchanged": _reference(
            "supported_positive", "c", started_at=RECORDED_AT + timedelta(hours=1)
        ),
        "new": _reference(
            "supported_positive", "c", started_at=RECORDED_AT + timedelta(hours=1)
        ),
        "unknown": _reference(
            "inconclusive",
            "c",
            health="unavailable",
            started_at=RECORDED_AT + timedelta(hours=1),
        ),
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
        id=comparison_id(PROJECT_ID, claim),
        claim=claim,
        state=state,
        reason=f"recorded_{state}",
        explanation="Recorded controlled-lab comparison.",
        coverage=CoverageDecision(
            status=coverage,
            reason=f"recorded_{coverage}",
            explanation="Coverage is limited to the recorded route and backend.",
        ),
        baseline=None if state == "new" else baseline,
        current=current,
        limitations=("Recorded demo evidence only.",),
    )


def recorded_demo_report() -> ComparisonReport:
    comparison = HistoricalComparisonReport(
        project_id=PROJECT_ID,
        baseline=ComparisonSelection(
            basis="fresh_recheck", identifiers=("recorded-baseline",)
        ),
        current=ComparisonSelection(
            basis="fresh_recheck", identifiers=("recorded-current",)
        ),
        results=(
            _lifecycle(HSTS_RULE, "https://lab-one.example.invalid", "resolved"),
            _lifecycle(DIRECTORY_RULE, "https://lab-one.example.invalid", "unknown"),
            _lifecycle(
                GIT_CONFIG_RULE,
                "https://lab-two.example.invalid",
                "not_observed",
            ),
            _lifecycle(HSTS_RULE, "https://lab-two.example.invalid", "new"),
        ),
    )
    return build_comparison_report(PROJECT_ID, "Recorded controlled lab", comparison)
