from typing import Literal, Protocol

from pydantic import AwareDatetime

from scopelens.domain.evidence import EvidenceReference, Observation, Text
from scopelens.domain.findings import ScannerMatch
from scopelens.domain.scope import WebTarget
from scopelens.domain.targets import DomainModel, Identifier


class ImportContext(DomainModel):
    profile_id: Identifier
    profile_revision: Text
    scanner_version: Text | None = None
    web_target: WebTarget | None = None
    template_revision: str | None = None
    captured_at: AwareDatetime | None = None


class ParsedReport(DomainModel):
    evidence: EvidenceReference
    reported_exit: Literal["success", "error"] | None
    observations: tuple[Observation, ...]
    matches: tuple[ScannerMatch, ...] = ()


class ReportParseError(ValueError):
    """A report cannot be safely interpreted by its adapter."""


class ScannerAdapter(Protocol):
    name: str
    artifact_name: str
    root_locator: str

    def parse(self, raw: bytes, context: ImportContext) -> ParsedReport: ...
