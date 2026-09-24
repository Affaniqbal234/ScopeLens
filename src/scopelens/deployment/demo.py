from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

from scopelens.assessment.models import (
    AcquisitionEvidence,
    AcquisitionStatus,
    CapturedResponse,
    RecheckAcquisition,
    RecheckReport,
)
from scopelens.assessment.rules import (
    DIRECTORY_RULE,
    GIT_CONFIG_RULE,
    CapturedExchange,
    assess_exposure_recheck,
    assess_hsts_recheck,
)
from scopelens.comparison.compare import ArtifactHealth, compare_assessments
from scopelens.reporting.models import ComparisonReport
from scopelens.reporting.projection import build_comparison_report

RECORDED_AT = datetime(2026, 1, 15, 12, tzinfo=UTC)
PROJECT_ID = "controlled-demo"
ADDRESS = "192.0.2.44"
ORIGIN_ONE = "https://lab-one.example.invalid"
ORIGIN_TWO = "https://lab-two.example.invalid"


def _exchange(
    number: int,
    origin: str,
    resource: str,
    *,
    started_at: datetime,
    body: bytes = b"",
    hsts_present: bool = False,
    status: AcquisitionStatus = "complete",
) -> CapturedExchange:
    response = None
    evidence = None
    if status == "complete":
        response = CapturedResponse(
            status_code=200,
            headers_complete=True,
            body_complete=True,
            body_sha256=sha256(body).hexdigest(),
            strict_transport_security_present=hsts_present,
            access_challenge_present=False,
            content_encoding_identity=True,
        )
        evidence = AcquisitionEvidence(
            artifact_path=f"recorded/{number}/response.http",
            artifact_sha256=sha256(f"recorded-response-{number}".encode()).hexdigest(),
            size_bytes=len(body),
        )
    acquisition = RecheckAcquisition(
        id=UUID(int=number),
        started_at=started_at,
        finished_at=started_at + timedelta(seconds=1),
        origin=origin,
        approved_address=ADDRESS,
        resource=resource,
        status=status,
        evidence=evidence,
        response=response,
    )
    return CapturedExchange(acquisition, body)


def _reports() -> tuple[RecheckReport, RecheckReport]:
    baseline_hsts_one = _exchange(
        1, ORIGIN_ONE, "/", started_at=RECORDED_AT, hsts_present=False
    )
    baseline_directory = _exchange(
        2,
        ORIGIN_ONE,
        "/",
        started_at=RECORDED_AT + timedelta(seconds=2),
        body=b"<title>Directory listing for /</title><a href='entry'>entry</a>",
    )
    baseline_git = _exchange(
        3,
        ORIGIN_TWO,
        "/.git/config",
        started_at=RECORDED_AT + timedelta(seconds=4),
        body=b"[core]\nrepositoryformatversion = 0\n",
    )
    baseline_hsts_two = _exchange(
        4,
        ORIGIN_TWO,
        "/",
        started_at=RECORDED_AT + timedelta(seconds=6),
        hsts_present=True,
    )
    baseline = RecheckReport(
        project_id=PROJECT_ID,
        acquisitions=tuple(
            item.acquisition
            for item in (
                baseline_hsts_one,
                baseline_directory,
                baseline_git,
                baseline_hsts_two,
            )
        ),
        assessments=(
            assess_hsts_recheck(PROJECT_ID, baseline_hsts_one),
            assess_exposure_recheck(PROJECT_ID, DIRECTORY_RULE, baseline_directory),
            assess_exposure_recheck(PROJECT_ID, GIT_CONFIG_RULE, baseline_git),
            assess_hsts_recheck(PROJECT_ID, baseline_hsts_two),
        ),
    )

    current_hsts_one = _exchange(
        5,
        ORIGIN_ONE,
        "/",
        started_at=RECORDED_AT + timedelta(hours=1),
        hsts_present=True,
    )
    current_directory = _exchange(
        6,
        ORIGIN_ONE,
        "/",
        started_at=RECORDED_AT + timedelta(hours=1, seconds=2),
        status="timeout",
    )
    current_hsts_two = _exchange(
        7,
        ORIGIN_TWO,
        "/",
        started_at=RECORDED_AT + timedelta(hours=1, seconds=4),
        hsts_present=False,
    )
    current = RecheckReport(
        project_id=PROJECT_ID,
        acquisitions=tuple(
            item.acquisition
            for item in (current_hsts_one, current_directory, current_hsts_two)
        ),
        assessments=(
            assess_hsts_recheck(PROJECT_ID, current_hsts_one),
            assess_exposure_recheck(PROJECT_ID, DIRECTORY_RULE, current_directory),
            assess_hsts_recheck(PROJECT_ID, current_hsts_two),
        ),
    )
    return baseline, current


def _health(report: RecheckReport) -> dict[UUID, ArtifactHealth]:
    return {
        acquisition.id: "ready"
        for acquisition in report.acquisitions
        if acquisition.evidence is not None
    }


def recorded_demo_report() -> ComparisonReport:
    baseline, current = _reports()
    comparison = compare_assessments(
        baseline,
        current,
        baseline_acquisition_health=_health(baseline),
        current_acquisition_health=_health(current),
    )
    return build_comparison_report(PROJECT_ID, "Recorded controlled lab", comparison)
