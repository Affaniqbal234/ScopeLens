from typing import Annotated, Literal

from pydantic import Field

from scopelens.domain.evidence import EvidenceReference
from scopelens.domain.targets import DomainModel, Identifier, Origin


class ScannerMatch(DomainModel):
    origin: Origin
    matched_location: Annotated[str, Field(strict=True, max_length=2048)]
    template_id: Identifier
    template_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    matcher: Identifier
    scanner_severity: Literal["info", "low", "medium", "high", "critical", "unknown"]
    assessment: Literal["unvalidated"] = "unvalidated"
    evidence: Annotated[
        tuple[EvidenceReference, ...], Field(min_length=1, max_length=1)
    ]
