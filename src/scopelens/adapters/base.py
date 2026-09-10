from typing import Literal, Protocol

from scopelens.domain.evidence import EvidenceReference, Observation, Text
from scopelens.domain.targets import DomainModel, Identifier


class ImportContext(DomainModel):
    profile_id: Identifier
    profile_revision: Text


class ParsedReport(DomainModel):
    evidence: EvidenceReference
    reported_exit: Literal["success", "error"] | None
    observations: tuple[Observation, ...]


class ReportParseError(ValueError):
    """A report cannot be safely interpreted by its adapter."""


class ScannerAdapter(Protocol):
    def parse(self, raw: bytes, context: ImportContext) -> ParsedReport: ...
