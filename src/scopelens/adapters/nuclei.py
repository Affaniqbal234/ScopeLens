import base64
import binascii
import json
from hashlib import sha256
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from scopelens.adapters.base import ImportContext, ParsedReport, ReportParseError
from scopelens.adapters.nuclei_templates import (
    NUCLEI_VERSION,
    reviewed_templates,
    template_revision,
)
from scopelens.domain.evidence import EvidenceReference
from scopelens.domain.findings import ScannerMatch


class _Match(BaseModel):
    model_config = ConfigDict(extra="ignore", hide_input_in_errors=True)
    template_id: str = Field(alias="template-id", strict=True)
    template_encoded: str = Field(
        alias="template-encoded", strict=True, max_length=32768
    )
    matcher_name: str = Field(alias="matcher-name", strict=True)
    type: Literal["http"]
    host: str = Field(strict=True)
    url: str = Field(strict=True)
    port: str = Field(strict=True)
    scheme: Literal["http", "https"]
    matched_at: str = Field(alias="matched-at", strict=True)
    ip: str = Field(strict=True)
    timestamp: AwareDatetime
    matcher_status: Literal[True] = Field(alias="matcher-status")
    info: dict[str, object]


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise ValueError("non-finite JSON value")


class NucleiAdapter:
    name = "nuclei"
    artifact_name = "stdout.jsonl"
    root_locator = "$"

    def parse(self, raw: bytes, context: ImportContext) -> ParsedReport:
        try:
            return self._parse(raw, context)
        except (
            ValueError,
            TypeError,
            RecursionError,
            ValidationError,
            binascii.Error,
            OSError,
        ):
            raise ReportParseError(
                "invalid, partial, or out-of-scope Nuclei report"
            ) from None

    def _parse(self, raw: bytes, context: ImportContext) -> ParsedReport:
        target = context.web_target
        if (
            len(raw) > 8 * 1024 * 1024
            or target is None
            or len(target.approved_addresses) != 1
            or context.scanner_version != NUCLEI_VERSION
            or context.captured_at is None
            or context.template_revision != template_revision()
        ):
            raise ValueError("missing or unsupported Nuclei context")
        origin = urlsplit(target.origin)
        address = target.approved_addresses[0]
        port = origin.port or (443 if origin.scheme == "https" else 80)
        base = f"{origin.scheme}://{address}:{port}"
        templates = {template.id: template for template in reviewed_templates()}
        root = EvidenceReference(
            artifact_sha256=sha256(raw).hexdigest(),
            record_locator="$",
            scanner="nuclei",
            scanner_version=NUCLEI_VERSION,
            adapter_version="1",
            profile_id=context.profile_id,
            profile_revision=context.profile_revision,
            captured_at=context.captured_at,
        )
        matches = []
        seen = set()
        for number, line in enumerate(raw.decode("utf-8").split("\n"), 1):
            if not line.strip():
                continue
            if len(line.encode()) > 256 * 1024:
                raise ValueError("oversized JSONL record")
            value = json.loads(
                line, object_pairs_hook=_object, parse_constant=_constant
            )
            record = _Match.model_validate(value)
            if (
                value.get("matcher-status") is not True
                or value.get("interaction")
                or value.get("global-matchers")
            ):
                raise ValueError("unsupported match semantics")
            template = templates.get(record.template_id)
            if template is None or record.matcher_name != template.matcher:
                raise ValueError("unreviewed template or matcher")
            encoded = base64.b64decode(record.template_encoded, validate=True)
            if (
                sha256(encoded).hexdigest() != template.sha256
                or record.info.get("severity") != template.severity
            ):
                raise ValueError("template revision or severity mismatch")
            if (
                record.host != address
                or record.url != base
                or record.port != str(port)
                or record.scheme != origin.scheme
                or record.matched_at != base + template.path
                or record.ip != address
            ):
                raise ValueError("match exceeds pinned origin/address/path")
            key = (record.template_id, record.matcher_name, record.matched_at)
            if key in seen:
                raise ValueError("duplicate match")
            seen.add(key)
            reference = root.model_copy(
                update={
                    "record_locator": f"line:{number}",
                    "captured_at": record.timestamp,
                }
            )
            matches.append(
                ScannerMatch.model_validate(
                    {
                        "origin": target.origin,
                        "matched_location": target.origin + template.path,
                        "template_id": template.id,
                        "template_revision": template.sha256,
                        "matcher": template.matcher,
                        "scanner_severity": template.severity,
                        "evidence": (reference,),
                    }
                )
            )
        return ParsedReport(
            evidence=root, reported_exit=None, observations=(), matches=tuple(matches)
        )


def import_nuclei(path: Path, context: ImportContext) -> ParsedReport:
    try:
        with path.open("rb") as source:
            raw = source.read(8 * 1024 * 1024 + 1)
    except OSError:
        raise ReportParseError("cannot read Nuclei JSONL") from None
    return NucleiAdapter().parse(raw, context)
