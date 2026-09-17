import json
from hashlib import sha256
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, StrictBool, model_validator

from scopelens.analysis.models import Digest, Resource, SourceReference
from scopelens.domain.evidence import EvidenceReference, ObservationValue, Text
from scopelens.domain.targets import DomainModel, Identifier, IPv4, Origin

AssessmentId = Annotated[
    str,
    Field(
        strict=True,
        min_length=78,
        max_length=78,
        pattern=r"^assessment-v1:[0-9a-f]{64}$",
    ),
]
Outcome = Literal["supported_positive", "supported_negative", "inconclusive"]
AcquisitionStatus = Literal[
    "complete",
    "timeout",
    "transport_error",
    "cancelled",
    "malformed",
    "truncated",
    "not_run",
]


class Claim(DomainModel):
    rule_id: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=96, pattern=r"^[a-z][a-z0-9.-]*$"),
    ]
    rule_version: Text
    origin: Origin
    resource: Resource
    statement: Text


class Prerequisite(DomainModel):
    id: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$"),
    ]
    state: Literal["met", "not_met", "unknown"]
    explanation: Text


class EvidenceFact(DomainModel):
    key: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=96, pattern=r"^[a-z][a-z0-9_.-]*$"),
    ]
    value: ObservationValue


class ExistingCaptureUse(DomainModel):
    kind: Literal["existing_capture"] = "existing_capture"
    source: SourceReference
    evidence: EvidenceReference
    facts: Annotated[tuple[EvidenceFact, ...], Field(min_length=1)]


class FreshRecheckUse(DomainModel):
    kind: Literal["fresh_recheck"] = "fresh_recheck"
    acquisition_id: UUID
    facts: Annotated[tuple[EvidenceFact, ...], Field(min_length=1)]


EvidenceUse = Annotated[
    ExistingCaptureUse | FreshRecheckUse, Field(discriminator="kind")
]


class AssessmentResult(DomainModel):
    id: AssessmentId
    claim: Claim
    prerequisites: Annotated[tuple[Prerequisite, ...], Field(min_length=1)]
    outcome: Outcome
    reason: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$"),
    ]
    explanation: Text
    evidence_used: tuple[EvidenceUse, ...]
    limitations: tuple[Text, ...]

    @model_validator(mode="after")
    def supported_results_have_evidence(self) -> Self:
        if self.outcome != "inconclusive" and not self.evidence_used:
            raise ValueError("supported assessments require evidence")
        return self


class AcquisitionEvidence(DomainModel):
    artifact_path: Annotated[str, Field(strict=True, min_length=1, max_length=4096)]
    artifact_sha256: Digest
    size_bytes: Annotated[int, Field(strict=True, ge=0, le=8 * 1024 * 1024)]


class CapturedResponse(DomainModel):
    status_code: Annotated[int, Field(strict=True, ge=100, le=599)]
    headers_complete: StrictBool
    body_complete: StrictBool
    body_sha256: Digest
    strict_transport_security_present: StrictBool
    access_challenge_present: StrictBool
    content_encoding_identity: StrictBool


class RecheckAcquisition(DomainModel):
    id: UUID
    started_at: AwareDatetime
    origin: Origin
    approved_address: IPv4
    method: Literal["GET"] = "GET"
    resource: Resource
    status: AcquisitionStatus
    evidence: AcquisitionEvidence | None = None
    response: CapturedResponse | None = None

    @model_validator(mode="after")
    def consistent_result(self) -> Self:
        if self.status == "complete":
            if self.response is None or self.evidence is None:
                raise ValueError("complete acquisitions require response evidence")
            if not self.response.headers_complete or not self.response.body_complete:
                raise ValueError("complete acquisitions require complete evidence")
        elif self.response is not None and self.status != "truncated":
            raise ValueError(
                "only complete or truncated acquisitions include a response"
            )
        if self.response is not None and self.evidence is None:
            raise ValueError("captured responses require raw artifact evidence")
        return self


class CaptureAssessmentReport(DomainModel):
    version: Literal["assessment-v1"] = "assessment-v1"
    basis: Literal["existing_capture"] = "existing_capture"
    project_id: Identifier
    correlation_version: Literal["correlation-v1"] = "correlation-v1"
    run_ids: Annotated[tuple[UUID, ...], Field(min_length=1)]
    assessments: tuple[AssessmentResult, ...]

    @model_validator(mode="after")
    def references_selected_runs(self) -> Self:
        if len(set(self.run_ids)) != len(self.run_ids):
            raise ValueError("selected run identifiers must be unique")
        selected = set(self.run_ids)
        for assessment in self.assessments:
            if assessment.id != assessment_id(self.project_id, assessment.claim):
                raise ValueError("assessment identity does not match its claim")
            for use in assessment.evidence_used:
                if (
                    not isinstance(use, ExistingCaptureUse)
                    or use.source.run_id not in selected
                ):
                    raise ValueError(
                        "capture assessment evidence must resolve to a selected run"
                    )
        if len({item.id for item in self.assessments}) != len(self.assessments):
            raise ValueError("assessment identities must be unique")
        return self


class RecheckReport(DomainModel):
    version: Literal["assessment-v1"] = "assessment-v1"
    basis: Literal["fresh_recheck"] = "fresh_recheck"
    project_id: Identifier
    acquisitions: Annotated[tuple[RecheckAcquisition, ...], Field(min_length=1)]
    assessments: Annotated[tuple[AssessmentResult, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def references_acquisitions(self) -> Self:
        acquisition_ids = {item.id for item in self.acquisitions}
        if len(acquisition_ids) != len(self.acquisitions):
            raise ValueError("acquisition identifiers must be unique")
        for assessment in self.assessments:
            if assessment.id != assessment_id(self.project_id, assessment.claim):
                raise ValueError("assessment identity does not match its claim")
            for use in assessment.evidence_used:
                if (
                    not isinstance(use, FreshRecheckUse)
                    or use.acquisition_id not in acquisition_ids
                ):
                    raise ValueError("recheck evidence must resolve to an acquisition")
        if len({item.id for item in self.assessments}) != len(self.assessments):
            raise ValueError("assessment identities must be unique")
        return self


def assessment_id(project_id: str, claim: Claim) -> str:
    value = [
        project_id,
        claim.rule_id,
        claim.rule_version,
        claim.origin,
        claim.resource,
    ]
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
    return "assessment-v1:" + sha256(encoded).hexdigest()
