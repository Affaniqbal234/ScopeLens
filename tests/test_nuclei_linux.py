import asyncio
import os
import ssl
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from scopelens.domain.scope import WebTarget
from scopelens.execution.nuclei import scan_nuclei
from tests.test_httpx import web_config

BINARY = os.environ.get("SCOPELENS_NUCLEI_BINARY", "")
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not BINARY,
    reason="requires Linux and SCOPELENS_NUCLEI_BINARY v3.11.1",
)


@contextmanager
def lab(
    requests: list[tuple[str | None, str]],
    *,
    fixed: bool = False,
    redirect: str | None = None,
    tls: ssl.SSLContext | None = None,
) -> Iterator[ThreadingHTTPServer]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append((self.headers.get("Host"), self.path))
            body = (
                (
                    b"<title>Directory listing for /</title><a href='example.txt'>example</a>"
                    if self.path == "/"
                    else b"[core]\nrepositoryformatversion = 0\nbare = false\n"
                )
                if not fixed
                else b"Not found"
            )
            self.send_response(302 if redirect else 404 if fixed else 200)
            if redirect:
                self.send_header("Location", redirect)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if tls:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("fixed", [False, True])
def test_real_reviewed_checks_and_fixed_state(tmp_path: Path, fixed: bool) -> None:
    requests: list[tuple[str | None, str]] = []
    with lab(requests, fixed=fixed) as server:
        target = WebTarget(
            origin=f"http://site.invalid:{server.server_port}",
            approved_addresses=("127.0.0.1",),
        )
        result = asyncio.run(
            scan_nuclei(web_config(target), "web", tmp_path, target, BINARY)
        )
    assert sorted(requests) == [
        (f"site.invalid:{server.server_port}", "/"),
        (f"site.invalid:{server.server_port}", "/.git/config"),
    ]
    assert len(result.report.matches) == (0 if fixed else 2)
    assert all(match.assessment == "unvalidated" for match in result.report.matches)
    assert result.report.reported_exit is None
    assert sorted(p.name for p in result.artifacts.directory.iterdir()) == [
        "stderr.txt",
        "stdout.jsonl",
    ]
    assert result.artifacts.stdout.stat().st_mode & 0o777 == 0o600


def test_redirect_does_not_contact_destination(tmp_path: Path) -> None:
    requested: list[tuple[str | None, str]] = []
    escaped: list[tuple[str | None, str]] = []
    with lab(escaped) as destination:
        with lab(
            requested, redirect=f"http://127.0.0.1:{destination.server_port}/"
        ) as source:
            target = WebTarget(
                origin=f"http://site.invalid:{source.server_port}",
                approved_addresses=("127.0.0.1",),
            )
            result = asyncio.run(
                scan_nuclei(web_config(target), "web", tmp_path, target, BINARY)
            )
    assert escaped == [] and len(requested) == 2
    assert result.report.matches == ()


def test_tls_sni_and_origin_preserved(tmp_path: Path) -> None:
    import subprocess

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
        socket: ssl.SSLSocket | ssl.SSLObject, name: str | None, tls_context: object
    ) -> None:
        names.append(name)

    context.set_servername_callback(sni)
    requested: list[tuple[str | None, str]] = []
    with lab(requested, tls=context) as source:
        target = WebTarget(
            origin=f"https://site.invalid:{source.server_port}",
            approved_addresses=("127.0.0.1",),
        )
        result = asyncio.run(
            scan_nuclei(web_config(target), "web", tmp_path / "raw", target, BINARY)
        )
    assert names and set(names) == {"site.invalid"}
    assert len(result.report.matches) == 2
    assert {host for host, _ in requested} == {f"site.invalid:{source.server_port}"}
