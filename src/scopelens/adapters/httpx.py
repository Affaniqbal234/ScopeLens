import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from scopelens.adapters.base import ImportContext, ParsedReport, ReportParseError
from scopelens.domain.evidence import EvidenceReference, Observation
from scopelens.domain.services import HttpEndpoint
from scopelens.domain.targets import normalize_address, normalize_origin

HTTPX_VERSION = "1.12.0"
MAX_JSONL_BYTES = 8 * 1024 * 1024
HEADERS = {
    "content_type",
    "server",
    "location",
    "strict_transport_security",
    "x_content_type_options",
    "x_frame_options",
    "content_security_policy",
    "referrer_policy",
    "cache_control",
    "www_authenticate",
}


class _Record(BaseModel):
    model_config = ConfigDict(extra="ignore", hide_input_in_errors=True)
    timestamp: AwareDatetime
    url: Annotated[str, Field(strict=True, max_length=2048)]
    failed: Annotated[bool, Field(strict=True)]
    host_ip: str | None = None
    status_code: Annotated[int, Field(strict=True, ge=0, le=599)] | None = None
    content_length: Annotated[int, Field(strict=True, ge=0)] | None = None
    title: Annotated[str, Field(strict=True, max_length=8192)] | None = None
    content_type: Annotated[str, Field(strict=True, max_length=1024)] | None = None
    webserver: Annotated[str, Field(strict=True, max_length=1024)] | None = None
    location: Annotated[str, Field(strict=True, max_length=8192)] | None = None
    error: Annotated[str, Field(strict=True, max_length=8192)] | None = None
    tech: (
        list[Annotated[str, Field(strict=True, min_length=1, max_length=256)]] | None
    ) = None
    header: dict[str, Annotated[str, Field(strict=True, max_length=8192)]] | None = None
    a: list[str] | None = None
    final_url: str | None = None


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


class HttpxAdapter:
    name = "httpx"
    artifact_name = "stdout.jsonl"
    root_locator = "$"

    def parse(self, raw: bytes, context: ImportContext) -> ParsedReport:
        if not raw or len(raw) > MAX_JSONL_BYTES:
            raise ReportParseError("httpx output is empty or exceeds 8 MiB")
        if context.scanner_version != HTTPX_VERSION or context.web_target is None:
            raise ReportParseError(
                "httpx requires its supported version and explicit web target context"
            )
        try:
            return self._normalize(raw, context)
        except ValueError, TypeError, RecursionError, ValidationError:
            raise ReportParseError(
                "malformed, partial, or unsupported httpx JSONL"
            ) from None

    def _normalize(self, raw: bytes, context: ImportContext) -> ParsedReport:
        target = context.web_target
        assert target is not None
        rows = [line for line in raw.decode("utf-8").split("\n") if line.strip()]
        if not rows or len(rows) > 256 or any(len(line) > 256 * 1024 for line in rows):
            raise ValueError("JSONL record limits")
        records = []
        for line in rows:
            value = json.loads(
                line, object_pairs_hook=_object, parse_constant=_constant
            )
            record = _Record.model_validate(value)
            if value.get("chain") or value.get("chain_status_codes"):
                raise ValueError("followed redirects are unsupported")
            records.append(record)
        evidence = EvidenceReference(
            artifact_sha256=sha256(raw).hexdigest(),
            record_locator=self.root_locator,
            scanner=self.name,
            scanner_version=HTTPX_VERSION,
            adapter_version="1",
            profile_id=context.profile_id,
            profile_revision=context.profile_revision,
            captured_at=max(record.timestamp for record in records),
        )
        endpoint = HttpEndpoint(origin=target.origin)
        observations = []
        seen: set[str] = set()
        for index, record in enumerate(records, 1):
            source = normalize_origin(record.url)
            requested = urlsplit(target.origin)
            parsed = urlsplit(source)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            expected_port = requested.port or (
                443 if requested.scheme == "https" else 80
            )
            if source != target.origin and not (
                parsed.hostname in target.approved_addresses
                and parsed.scheme == requested.scheme
                and port == expected_port
            ):
                raise ValueError("record exceeds origin scope")
            if record.final_url and normalize_origin(record.final_url) != source:
                raise ValueError("redirect was followed")
            for address in record.a or []:
                if normalize_address(address) not in target.approved_addresses:
                    raise ValueError("unapproved resolved address")
            address = (
                normalize_address(record.host_ip)
                if record.host_ip
                else (parsed.hostname or "")
            )
            if (
                parsed.hostname in target.approved_addresses
                and address != parsed.hostname
            ):
                raise ValueError("peer contradicts pinned address")
            if address not in target.approved_addresses:
                raise ValueError("missing or unapproved peer address")
            if address in seen:
                raise ValueError("duplicate endpoint evidence")
            seen.add(address)
            reference = evidence.model_copy(
                update={
                    "record_locator": f"$[{index}]",
                    "captured_at": record.timestamp,
                }
            )

            def emit(
                key: str,
                value: str | int | bool,
                reference: EvidenceReference = reference,
            ) -> None:
                observations.append(
                    Observation(
                        subject=endpoint, key=key, value=value, evidence=(reference,)
                    )
                )

            emit("http.probe_succeeded", not record.failed)
            emit("http.target_address", address)
            if record.failed:
                if record.status_code not in (None, 0):
                    raise ValueError("failed probe has a response status")
                if record.error is not None:
                    emit("http.error", record.error)
                continue
            if (
                record.host_ip is None
                or record.status_code is None
                or record.status_code < 100
            ):
                raise ValueError("successful probe lacks response metadata")
            emit("http.peer_address", record.host_ip)
            emit("http.status_code", record.status_code)
            for field in (
                "content_length",
                "title",
                "content_type",
                "webserver",
                "location",
            ):
                value = getattr(record, field)
                if value is not None:
                    emit(f"http.{field}", value)
            technologies = record.tech
            if technologies is not None:
                if len(technologies) > 128 or len(set(technologies)) != len(
                    technologies
                ):
                    raise ValueError("invalid technology list")
                for technology in technologies:
                    emit("http.technology", technology)
            seen_headers = set()
            for header, value in (record.header or {}).items():
                name = header.lower().replace("-", "_")
                if not re.fullmatch(r"[a-z0-9_]{1,96}", name) or name in seen_headers:
                    raise ValueError("ambiguous header name")
                seen_headers.add(name)
                if name in HEADERS:
                    emit(f"http.header.{name}", value)
        return ParsedReport(
            evidence=evidence, reported_exit=None, observations=tuple(observations)
        )


def import_httpx(path: Path, context: ImportContext) -> ParsedReport:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_JSONL_BYTES + 1)
    except OSError:
        raise ReportParseError("cannot read httpx JSONL") from None
    return HttpxAdapter().parse(raw, context)
