from dataclasses import dataclass

from scopelens.adapters.base import ParsedReport
from scopelens.execution.process import RawArtifacts


@dataclass(frozen=True)
class ScanResult:
    artifacts: RawArtifacts
    report: ParsedReport
