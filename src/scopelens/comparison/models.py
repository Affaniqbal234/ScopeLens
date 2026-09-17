import json
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from scopelens.analysis.models import Resource
from scopelens.assessment.models import AssessmentId, EvidenceUse, Outcome
from scopelens.domain.evidence import Text
from scopelens.domain.targets import DomainModel, Identifier, IPv4, Origin

HistoricalState = Literal[
    "new", "changed", "unchanged", "resolved", "not_observed", "unknown"
]
CoverageStatus = Literal["comparable", "insufficient", "unusable", "not_assessed"]
ComparisonId = Annotated[
    str,
    Field(
        strict=True,
        min_length=78,
        max_length=78,
        pattern=r"^comparison-v1:[0-9a-f]{64}$",
    ),
]


class ClaimKey(DomainModel):
    rule_id: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=96, pattern=r"^[a-z][a-z0-9.-]*$"),
    ]
    origin: Origin
    resource: Resource
    address: IPv4 | None


class AssessmentReference(DomainModel):
    assessment_id: AssessmentId
    rule_version: Text
    outcome: Outcome
    reason: Text
    evidence_health: Literal["ready", "unavailable"]
    observed_at: tuple[AwareDatetime, ...]
    acquisition_started_at: AwareDatetime | None = None
    acquisition_finished_at: AwareDatetime | None = None
    evidence_used: tuple[EvidenceUse, ...]


class CoverageDecision(DomainModel):
    status: CoverageStatus
    reason: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$"),
    ]
    explanation: Text


class HistoricalComparison(DomainModel):
    id: ComparisonId
    claim: ClaimKey
    state: HistoricalState
    reason: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$"),
    ]
    explanation: Text
    coverage: CoverageDecision
    baseline: AssessmentReference | None
    current: AssessmentReference | None
    limitations: tuple[Text, ...]


class ComparisonSelection(DomainModel):
    basis: Literal["existing_capture", "fresh_recheck"]
    identifiers: Annotated[tuple[str, ...], Field(min_length=1)]


class HistoricalComparisonReport(DomainModel):
    version: Literal["comparison-v1"] = "comparison-v1"
    project_id: Identifier
    baseline: ComparisonSelection
    current: ComparisonSelection
    results: tuple[HistoricalComparison, ...]

    @model_validator(mode="after")
    def unique_and_consistent_results(self) -> Self:
        if len({item.id for item in self.results}) != len(self.results):
            raise ValueError("comparison identities must be unique")
        for item in self.results:
            if item.id != comparison_id(self.project_id, item.claim):
                raise ValueError("comparison identity does not match its claim context")
            if item.state == "resolved" and (
                item.baseline is None
                or item.current is None
                or item.baseline.outcome != "supported_positive"
                or item.current.outcome != "supported_negative"
                or item.coverage.status != "comparable"
            ):
                raise ValueError(
                    "resolved requires comparable positive-to-negative evidence"
                )
        return self


def comparison_id(project_id: str, claim: ClaimKey) -> str:
    value = [
        project_id,
        claim.rule_id,
        claim.origin,
        claim.resource,
        claim.address,
    ]
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
    return "comparison-v1:" + sha256(encoded).hexdigest()
