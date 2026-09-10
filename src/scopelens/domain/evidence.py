from typing import Annotated

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, StrictStr

from scopelens.domain.services import ServiceEndpoint
from scopelens.domain.targets import DomainModel, Identifier, TargetIdentity

Text = Annotated[str, Field(strict=True, min_length=1, max_length=1024, pattern=r"\S")]
ObservationValue = (
    StrictStr
    | StrictBool
    | StrictInt
    | Annotated[float, Field(strict=True, allow_inf_nan=False)]
)


class EvidenceReference(DomainModel):
    artifact_sha256: Annotated[
        str, Field(strict=True, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    ]
    record_locator: Text
    scanner: Identifier
    scanner_version: Text
    adapter_version: Text
    profile_id: Identifier
    profile_revision: Text
    captured_at: AwareDatetime


class Observation(DomainModel):
    subject: TargetIdentity | ServiceEndpoint
    key: Annotated[
        str,
        Field(
            strict=True, min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.-]*$"
        ),
    ]
    value: ObservationValue
    evidence: Annotated[tuple[EvidenceReference, ...], Field(min_length=1)]
