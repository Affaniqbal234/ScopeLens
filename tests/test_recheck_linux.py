import asyncio
import contextlib
import socket
import ssl
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from scopelens.assessment.recheck import recheck_web
from scopelens.config import ProjectConfig
from scopelens.domain.scope import ScopeViolation, WebTarget
from scopelens.execution.process import ExecutionError

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="private recheck artifacts require Linux"
)


def config(target: WebTarget, **profile: object) -> ProjectConfig:
    return ProjectConfig.model_validate(
        {
            "project": {
                "id": "recheck-lab",
                "name": "Recheck lab",
                "scope": {"web_targets": [target.model_dump()]},
            },
            "profiles": [{"id": "web", **profile}],
        }
    )


@contextmanager
def lab(
    requests: list[tuple[str | None, str]],
    *,
    fixed: bool = False,
    redirect: str | None = None,
    status: int | None = None,
    body_size: int | None = None,
    hsts: bool = False,
    tls: ssl.SSLContext | None = None,
) -> Iterator[ThreadingHTTPServer]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append((self.headers.get("Host"), self.path))
            if self.path == "/":
                body = b"<title>Directory listing for /</title><a href='a'>a</a>"
            else:
                body = b"[core]\nrepositoryformatversion = 0\n"
            if fixed:
                body = b"Not found"
            if body_size is not None:
                body = b"x" * body_size
            response_status = status or (302 if redirect else 404 if fixed else 200)
            self.send_response(response_status)
            if redirect:
                self.send_header("Location", redirect)
            if hsts:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    ("fixed", "expected"),
    [
        (False, ("supported_positive", "supported_positive", "inconclusive")),
        (True, ("supported_negative", "supported_negative", "inconclusive")),
    ],
)
def test_controlled_vulnerable_and_fixed_rechecks(
    tmp_path: Path, fixed: bool, expected: tuple[str, str, str]
) -> None:
    requests: list[tuple[str | None, str]] = []
    with lab(requests, fixed=fixed) as server:
        target = WebTarget(
            origin=f"http://site.invalid:{server.server_port}",
            approved_addresses=("127.0.0.1",),
        )
        report = asyncio.run(recheck_web(config(target), "web", tmp_path, target))
    assert tuple(item.outcome for item in report.assessments) == expected
    assert requests == [
        (f"site.invalid:{server.server_port}", "/"),
        (f"site.invalid:{server.server_port}", "/.git/config"),
    ]
    assert len({item.id for item in report.acquisitions}) == 2
    for acquisition in report.acquisitions:
        assert acquisition.finished_at is not None
        assert acquisition.finished_at >= acquisition.started_at
        assert acquisition.evidence is not None
        artifact = Path(acquisition.evidence.artifact_path)
        assert artifact.stat().st_mode & 0o777 == 0o600
        assert artifact.parent.stat().st_mode & 0o777 == 0o700


def test_redirect_is_not_followed(tmp_path: Path) -> None:
    source_requests: list[tuple[str | None, str]] = []
    destination_requests: list[tuple[str | None, str]] = []
    with lab(destination_requests) as destination:
        with lab(
            source_requests,
            redirect=f"http://127.0.0.1:{destination.server_port}/",
        ) as source:
            target = WebTarget(
                origin=f"http://site.invalid:{source.server_port}",
                approved_addresses=("127.0.0.1",),
            )
            report = asyncio.run(recheck_web(config(target), "web", tmp_path, target))
    assert destination_requests == []
    assert len(source_requests) == 2
    assert all(item.outcome == "inconclusive" for item in report.assessments)


@pytest.mark.parametrize(
    ("hsts", "outcome"),
    [(False, "supported_positive"), (True, "supported_negative")],
)
@pytest.mark.parametrize("truncated", [False, True])
def test_https_hsts_header_presence_and_absence(
    tmp_path: Path, hsts: bool, outcome: str, truncated: bool
) -> None:
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=site.invalid",
            "-days",
            "1",
        ],
        check=True,
        capture_output=True,
        timeout=20,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    names: list[str | None] = []

    def sni(
        socket: ssl.SSLSocket | ssl.SSLObject,
        name: str | None,
        tls_socket: ssl.SSLSocket,
    ) -> None:
        names.append(name)

    context.set_servername_callback(sni)
    requests: list[tuple[str | None, str]] = []
    with lab(
        requests, hsts=hsts, tls=context, body_size=4096 if truncated else None
    ) as server:
        target = WebTarget(
            origin=f"https://site.invalid:{server.server_port}",
            approved_addresses=("127.0.0.1",),
        )
        report = asyncio.run(
            recheck_web(
                config(target, max_artifact_bytes=1024), "web", tmp_path / "raw", target
            )
        )
    assert report.assessments[2].outcome == outcome
    assert names == ["site.invalid", "site.invalid"]
    if truncated:
        assert all(item.status == "truncated" for item in report.acquisitions)
        assert all(item.outcome == "inconclusive" for item in report.assessments[:2])


def test_output_limit_is_inconclusive_and_artifact_is_bounded(tmp_path: Path) -> None:
    requests: list[tuple[str | None, str]] = []
    with lab(requests, body_size=4096) as server:
        target = WebTarget(
            origin=f"http://site.invalid:{server.server_port}",
            approved_addresses=("127.0.0.1",),
        )
        report = asyncio.run(
            recheck_web(
                config(target, max_artifact_bytes=1024), "web", tmp_path, target
            )
        )
    assert all(item.status == "truncated" for item in report.acquisitions)
    assert all(item.outcome == "inconclusive" for item in report.assessments)
    assert all(
        item.evidence is not None and item.evidence.size_bytes <= 1024
        for item in report.acquisitions
    )


def test_scope_failure_precedes_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configured = WebTarget(
        origin="http://site.invalid:8000", approved_addresses=("127.0.0.1",)
    )
    requested = WebTarget(
        origin="http://other.invalid:8000", approved_addresses=("127.0.0.1",)
    )

    async def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("scope violation reached network execution")

    monkeypatch.setattr(asyncio, "open_connection", forbidden)
    with pytest.raises(ScopeViolation):
        asyncio.run(recheck_web(config(configured), "web", tmp_path, requested))


def test_private_artifact_root_is_checked_before_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = WebTarget(
        origin="http://site.invalid:8000", approved_addresses=("127.0.0.1",)
    )
    artifact_root = tmp_path / "public"
    artifact_root.mkdir(mode=0o755)

    async def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("invalid artifact storage reached network execution")

    monkeypatch.setattr(asyncio, "open_connection", forbidden)
    with pytest.raises(ExecutionError, match="owned, private"):
        asyncio.run(recheck_web(config(target), "web", artifact_root, target))


def test_transport_failure_is_inconclusive(tmp_path: Path) -> None:
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    target = WebTarget(
        origin=f"http://site.invalid:{port}", approved_addresses=("127.0.0.1",)
    )
    report = asyncio.run(recheck_web(config(target), "web", tmp_path, target))
    assert all(item.status == "transport_error" for item in report.acquisitions)
    assert all(item.outcome == "inconclusive" for item in report.assessments)


def test_timeout_and_unrun_check_are_inconclusive(tmp_path: Path) -> None:
    async def scenario() -> tuple[str, ...]:
        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            with contextlib.suppress(asyncio.IncompleteReadError):
                await reader.readuntil(b"\r\n\r\n")
                await reader.read()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        target = WebTarget(
            origin=f"http://site.invalid:{port}",
            approved_addresses=("127.0.0.1",),
        )
        try:
            report = await recheck_web(
                config(target, request_timeout_seconds=1, scan_timeout_seconds=2),
                "web",
                tmp_path,
                target,
            )
            assert all(item.outcome == "inconclusive" for item in report.assessments)
            return tuple(item.status for item in report.acquisitions)
        finally:
            server.close()
            await server.wait_closed()

    statuses = asyncio.run(scenario())
    assert statuses[0] == "timeout"
    assert statuses[1] in ("timeout", "not_run")


def test_cancellation_closes_active_connection(tmp_path: Path) -> None:
    async def scenario() -> None:
        request_received = asyncio.Event()
        connection_closed = asyncio.Event()

        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            with contextlib.suppress(asyncio.IncompleteReadError):
                await reader.readuntil(b"\r\n\r\n")
                request_received.set()
                if await reader.read() == b"":
                    connection_closed.set()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        target = WebTarget(
            origin=f"http://site.invalid:{port}",
            approved_addresses=("127.0.0.1",),
        )
        task = asyncio.create_task(recheck_web(config(target), "web", tmp_path, target))
        try:
            await asyncio.wait_for(request_received.wait(), 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.wait_for(connection_closed.wait(), 2)
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "raw",
    [
        b"NOT HTTP\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort",
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        ),
        b"HTTP/1.1 200 OK\r\nContent-Length: +0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1_0\r\n\r\n0123456789",
        b"HTTP/1.1 200 OK\r\n\r\npossibly truncated",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: y\r\n\r\n",
    ],
    ids=[
        "malformed",
        "partial",
        "ambiguous-framing",
        "signed-length",
        "underscored-length",
        "close-delimited",
        "unassessed-trailer",
    ],
)
def test_malformed_or_partial_response_is_inconclusive(
    tmp_path: Path, raw: bytes
) -> None:
    async def scenario() -> tuple[str, ...]:
        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            with contextlib.suppress(asyncio.IncompleteReadError):
                await reader.readuntil(b"\r\n\r\n")
            writer.write(raw)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        target = WebTarget(
            origin=f"http://site.invalid:{port}",
            approved_addresses=("127.0.0.1",),
        )
        try:
            report = await recheck_web(config(target), "web", tmp_path, target)
            assert all(item.outcome == "inconclusive" for item in report.assessments)
            return tuple(item.status for item in report.acquisitions)
        finally:
            server.close()
            await server.wait_closed()

    assert asyncio.run(scenario()) == ("malformed", "malformed")


def test_complete_chunked_responses_are_evaluated(tmp_path: Path) -> None:
    async def scenario() -> tuple[str, ...]:
        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            request = await reader.readuntil(b"\r\n\r\n")
            body = (
                b"<title>Directory listing for /</title><a href='a'>a</a>"
                if request.startswith(b"GET / HTTP/")
                else b"[core]\nrepositoryformatversion = 0\n"
            )
            writer.write(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                + f"{len(body):x}\r\n".encode()
                + body
                + b"\r\n0\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        target = WebTarget(
            origin=f"http://site.invalid:{port}",
            approved_addresses=("127.0.0.1",),
        )
        try:
            report = await recheck_web(config(target), "web", tmp_path, target)
            return tuple(item.outcome for item in report.assessments)
        finally:
            server.close()
            await server.wait_closed()

    assert asyncio.run(scenario()) == (
        "supported_positive",
        "supported_positive",
        "inconclusive",
    )
