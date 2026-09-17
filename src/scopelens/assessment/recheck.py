import asyncio
import contextlib
import re
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

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
from scopelens.config import ProjectConfig
from scopelens.domain.scope import ScanProfile, WebTarget
from scopelens.execution.process import (
    ExecutionError,
    ensure_private_artifact_root,
    require_linux,
    write_private_artifact,
)

_HEADER_LIMIT = 32 * 1024
_STATUS = re.compile(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?:[ \t].*)?$")
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class _MalformedResponse(ValueError):
    pass


@dataclass(frozen=True)
class _ParsedWireResponse:
    status_code: int
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes


def _profile(config: ProjectConfig, profile_id: str) -> ScanProfile:
    for profile in config.profiles:
        if profile.id == profile_id:
            return profile
    raise ExecutionError("unknown scan profile")


def _header_values(
    headers: tuple[tuple[bytes, bytes], ...], name: bytes
) -> tuple[bytes, ...]:
    return tuple(value for key, value in headers if key == name)


def _parse_headers(
    raw: bytes,
) -> tuple[int, tuple[tuple[bytes, bytes], ...], int] | None:
    boundary = raw.find(b"\r\n\r\n")
    if boundary < 0:
        if len(raw) >= _HEADER_LIMIT:
            raise _MalformedResponse("response headers exceed limit")
        return None
    if boundary + 4 > _HEADER_LIMIT:
        raise _MalformedResponse("response headers exceed limit")
    lines = raw[:boundary].split(b"\r\n")
    if not lines or (match := _STATUS.fullmatch(lines[0])) is None:
        raise _MalformedResponse("invalid HTTP status line")
    if any(byte < 32 and byte != 9 or byte == 127 for byte in lines[0]):
        raise _MalformedResponse("invalid HTTP status line")
    headers = []
    for line in lines[1:]:
        if not line or line[:1] in (b" ", b"\t") or b":" not in line:
            raise _MalformedResponse("invalid HTTP header")
        name, value = line.split(b":", 1)
        if _HEADER_NAME.fullmatch(name) is None:
            raise _MalformedResponse("invalid HTTP header name")
        value = value.strip(b" \t")
        if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
            raise _MalformedResponse("invalid HTTP header value")
        headers.append((name.lower(), value))
    return int(match.group(1)), tuple(headers), boundary + 4


def _decode_chunked(body: bytes, *, partial: bool = False) -> tuple[bytes, int] | None:
    decoded = bytearray()
    cursor = 0
    while True:
        line_end = body.find(b"\r\n", cursor)
        if line_end < 0:
            fragment = body[cursor:]
            if fragment and re.fullmatch(rb"[0-9A-Fa-f]+\r?", fragment) is None:
                raise _MalformedResponse("invalid chunk size")
            return (bytes(decoded), len(body)) if partial else None
        token = body[cursor:line_end]
        if not token or re.fullmatch(rb"[0-9A-Fa-f]+", token) is None:
            raise _MalformedResponse("invalid chunk size")
        size = int(token, 16)
        cursor = line_end + 2
        if size == 0:
            trailer_end = body.find(b"\r\n\r\n", cursor)
            if body[cursor : cursor + 2] == b"\r\n":
                return bytes(decoded), cursor + 2
            if trailer_end < 0:
                return None
            raise _MalformedResponse("response trailers are not supported")
        end = cursor + size
        if len(body) < end + 2:
            if len(body) > end and not b"\r\n".startswith(body[end:]):
                raise _MalformedResponse("invalid chunk terminator")
            return (bytes(decoded) + body[cursor:end], len(body)) if partial else None
        if body[end : end + 2] != b"\r\n":
            raise _MalformedResponse("invalid chunk terminator")
        decoded.extend(body[cursor:end])
        cursor = end + 2


def _parse_response(raw: bytes, *, eof: bool) -> _ParsedWireResponse | None:
    parsed = _parse_headers(raw)
    if parsed is None:
        return None
    status, headers, body_start = parsed
    if _header_values(headers, b"content-range"):
        raise _MalformedResponse("partial representations are not supported")
    wire_body = raw[body_start:]
    lengths = _header_values(headers, b"content-length")
    encodings = _header_values(headers, b"transfer-encoding")
    if lengths and encodings:
        raise _MalformedResponse("ambiguous response framing")
    if len(set(lengths)) > 1 or len(lengths) > 1:
        raise _MalformedResponse("ambiguous content length")
    if encodings:
        if len(encodings) != 1 or encodings[0].lower() != b"chunked":
            raise _MalformedResponse("unsupported transfer encoding")
        decoded = _decode_chunked(wire_body)
        if decoded is None:
            return None
        body, consumed = decoded
        if len(wire_body) != consumed:
            raise _MalformedResponse("unexpected bytes after response")
        return _ParsedWireResponse(status, headers, body)
    if lengths:
        if re.fullmatch(rb"[0-9]+", lengths[0]) is None:
            raise _MalformedResponse("invalid content length")
        try:
            length = int(lengths[0])
        except ValueError:
            raise _MalformedResponse("invalid content length") from None
        if length < 0 or len(wire_body) > length:
            raise _MalformedResponse("invalid response body length")
        if len(wire_body) < length:
            return None
        return _ParsedWireResponse(status, headers, wire_body)
    if status in (204, 304) or 100 <= status < 200:
        if wire_body:
            raise _MalformedResponse("unexpected response body")
        return _ParsedWireResponse(status, headers, b"")
    if eof:
        raise _MalformedResponse("close-delimited body completeness is unknown")
    return None


def _request_bytes(origin: str, resource: str) -> bytes:
    parsed = urlsplit(origin)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    default = 443 if parsed.scheme == "https" else 80
    authority = host if port == default else f"{host}:{port}"
    return (
        f"GET {resource} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "User-Agent: ScopeLens/0.1\r\n"
        "Accept: */*\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


def _incomplete_response(raw: bytes) -> tuple[CapturedResponse, bytes] | None:
    try:
        _parse_response(raw, eof=False)
        parsed = _parse_headers(raw)
    except _MalformedResponse:
        return None
    if parsed is None:
        return None
    status, headers, body_start = parsed
    body = raw[body_start:]
    if _header_values(headers, b"transfer-encoding"):
        try:
            decoded = _decode_chunked(body, partial=True)
        except _MalformedResponse:
            return None
        if decoded is None:
            return None
        body = decoded[0]
    elif not _header_values(headers, b"content-length"):
        return None
    content_encodings = _header_values(headers, b"content-encoding")
    response = CapturedResponse(
        status_code=status,
        headers_complete=True,
        body_complete=False,
        body_sha256=sha256(body).hexdigest(),
        strict_transport_security_present=bool(
            _header_values(headers, b"strict-transport-security")
        ),
        access_challenge_present=bool(
            _header_values(headers, b"www-authenticate")
            or _header_values(headers, b"proxy-authenticate")
            or _header_values(headers, b"cf-mitigated")
        ),
        content_encoding_identity=not content_encodings
        or all(value.lower() == b"identity" for value in content_encodings),
    )
    return response, body


def _evidence(path: Path, raw: bytes) -> AcquisitionEvidence:
    return AcquisitionEvidence(
        artifact_path=str(path),
        artifact_sha256=sha256(raw).hexdigest(),
        size_bytes=len(raw),
    )


async def _acquire(
    target: WebTarget,
    address: str,
    resource: str,
    profile: ScanProfile,
    artifact_root: Path,
    timeout_seconds: float,
) -> CapturedExchange:
    require_linux()
    started = datetime.now(UTC)
    acquisition_id = uuid4()
    parsed_origin = urlsplit(target.origin)
    port = parsed_origin.port or (443 if parsed_origin.scheme == "https" else 80)
    tls = None
    server_hostname = None
    if parsed_origin.scheme == "https":
        tls = ssl.create_default_context()
        tls.check_hostname = False
        tls.verify_mode = ssl.CERT_NONE
        server_hostname = parsed_origin.hostname
    writer: asyncio.StreamWriter | None = None
    raw = bytearray()
    status: AcquisitionStatus = "transport_error"
    parsed_response: _ParsedWireResponse | None = None
    try:
        async with asyncio.timeout(timeout_seconds):
            reader, writer = await asyncio.open_connection(
                address,
                port,
                ssl=tls,
                server_hostname=server_hostname,
                limit=min(_HEADER_LIMIT, profile.max_artifact_bytes),
            )
            writer.write(_request_bytes(target.origin, resource))
            await writer.drain()
            while True:
                parsed_response = _parse_response(bytes(raw), eof=False)
                if parsed_response is not None:
                    status = "complete"
                    break
                chunk = await reader.read(
                    min(16 * 1024, profile.max_artifact_bytes + 1)
                )
                if not chunk:
                    parsed_response = _parse_response(bytes(raw), eof=True)
                    if parsed_response is None:
                        raise _MalformedResponse("incomplete HTTP response")
                    status = "complete"
                    break
                available = profile.max_artifact_bytes - len(raw)
                raw.extend(chunk[:available])
                if len(chunk) > available:
                    status = "truncated"
                    break
    except TimeoutError:
        status = "timeout"
    except OSError, ssl.SSLError:
        status = "transport_error"
    except _MalformedResponse:
        status = "malformed"
    except asyncio.CancelledError:
        if raw:
            write_private_artifact(
                artifact_root,
                prefix="recheck-",
                filename="response.http",
                content=bytes(raw),
                limit=profile.max_artifact_bytes,
            )
        raise
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError, TimeoutError):
                async with asyncio.timeout(3):
                    await writer.wait_closed()

    artifact = None
    if raw:
        path = write_private_artifact(
            artifact_root,
            prefix="recheck-",
            filename="response.http",
            content=bytes(raw),
            limit=profile.max_artifact_bytes,
        )
        artifact = _evidence(path, bytes(raw))
    response = None
    body = b""
    if parsed_response is not None:
        content_encodings = _header_values(parsed_response.headers, b"content-encoding")
        body = parsed_response.body
        response = CapturedResponse(
            status_code=parsed_response.status_code,
            headers_complete=True,
            body_complete=True,
            body_sha256=sha256(body).hexdigest(),
            strict_transport_security_present=bool(
                _header_values(parsed_response.headers, b"strict-transport-security")
            ),
            access_challenge_present=bool(
                _header_values(parsed_response.headers, b"www-authenticate")
                or _header_values(parsed_response.headers, b"proxy-authenticate")
                or _header_values(parsed_response.headers, b"cf-mitigated")
            ),
            content_encoding_identity=not content_encodings
            or all(value.lower() == b"identity" for value in content_encodings),
        )
    elif status == "truncated":
        incomplete = _incomplete_response(bytes(raw))
        if incomplete is not None:
            response, body = incomplete
    return CapturedExchange(
        RecheckAcquisition(
            id=acquisition_id,
            started_at=started,
            finished_at=datetime.now(UTC),
            origin=target.origin,
            approved_address=address,
            resource=resource,
            status=status,
            evidence=artifact,
            response=response,
        ),
        body,
    )


def _not_run(target: WebTarget, address: str, resource: str) -> CapturedExchange:
    return CapturedExchange(
        RecheckAcquisition(
            id=uuid4(),
            started_at=datetime.now(UTC),
            origin=target.origin,
            approved_address=address,
            resource=resource,
            status="not_run",
        ),
        b"",
    )


async def recheck_web(
    config: ProjectConfig,
    profile_id: str,
    artifact_root: Path,
    target: WebTarget,
) -> RecheckReport:
    profile = _profile(config, profile_id)
    if len(target.approved_addresses) != 1:
        raise ExecutionError("select exactly one approved destination address")
    address = target.approved_addresses[0]
    config.project.scope.authorize_web(target.origin, (address,))
    require_linux()
    artifact_root = ensure_private_artifact_root(artifact_root)

    exchanges = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + profile.scan_timeout_seconds
    for index, resource in enumerate(("/", "/.git/config")):
        if index:
            delay = 1 / profile.requests_per_second
            if loop.time() + delay >= deadline:
                exchanges.append(_not_run(target, address, resource))
                continue
            await asyncio.sleep(delay)
        remaining = deadline - loop.time()
        if remaining <= 0:
            exchanges.append(_not_run(target, address, resource))
            continue
        exchanges.append(
            await _acquire(
                target,
                address,
                resource,
                profile,
                artifact_root,
                min(profile.request_timeout_seconds, remaining),
            )
        )
    root, git = exchanges
    return RecheckReport(
        project_id=config.project.id,
        acquisitions=tuple(exchange.acquisition for exchange in exchanges),
        assessments=(
            assess_exposure_recheck(config.project.id, DIRECTORY_RULE, root),
            assess_exposure_recheck(config.project.id, GIT_CONFIG_RULE, git),
            assess_hsts_recheck(config.project.id, root),
        ),
    )
