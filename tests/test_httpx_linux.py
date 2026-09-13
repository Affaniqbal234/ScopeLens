import asyncio
import os
import ssl
import stat
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from scopelens.domain.scope import WebTarget
from scopelens.execution.httpx import scan_httpx
from tests.test_httpx import web_config

BINARY = os.environ.get("SCOPELENS_HTTPX_BINARY", "")
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not BINARY,
    reason="requires Linux and SCOPELENS_HTTPX_BINARY pointing to httpx v1.12.0",
)


@contextmanager
def server(
    requests: list[tuple[str | None, str]],
    location: str | None = None,
    tls: ssl.SSLContext | None = None,
) -> Iterator[ThreadingHTTPServer]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append((self.headers.get("Host"), self.path))
            body = b"<html><title>Local service</title></html>"
            self.send_response(302 if location else 200)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    instance = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if tls:
        instance.socket = tls.wrap_socket(instance.socket, server_side=True)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=5)


def test_real_http_host_redirect_and_private_jsonl(tmp_path: Path) -> None:
    requests: list[tuple[str | None, str]] = []
    redirected: list[tuple[str | None, str]] = []
    with server(redirected) as destination:
        location = f"http://127.0.0.1:{destination.server_port}/outside"
        with server(requests, location) as source:
            target = WebTarget(
                origin=f"http://site.invalid:{source.server_port}",
                approved_addresses=("127.0.0.1",),
            )
            result = asyncio.run(
                scan_httpx(web_config(target), "web", tmp_path, target, BINARY)
            )
    assert requests == [(f"site.invalid:{source.server_port}", "/")]
    assert redirected == []
    values = {item.key: item.value for item in result.report.observations}
    assert values["http.status_code"] == 302
    assert values["http.location"] == location
    assert values["http.title"] == "Local service"
    assert result.artifacts.stdout.name == "stdout.jsonl"
    assert stat.S_IMODE(result.artifacts.directory.stat().st_mode) == 0o700
    for path in (result.artifacts.stdout, result.artifacts.stderr):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_real_https_keeps_host_and_sni(tmp_path: Path) -> None:
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
        socket: ssl.SSLSocket | ssl.SSLObject, name: str | None, ssl_context: object
    ) -> None:
        names.append(name)

    context.set_servername_callback(sni)
    requests: list[tuple[str | None, str]] = []
    with server(requests, tls=context) as source:
        target = WebTarget(
            origin=f"https://site.invalid:{source.server_port}",
            approved_addresses=("127.0.0.1",),
        )
        result = asyncio.run(
            scan_httpx(web_config(target), "web", tmp_path / "raw", target, BINARY)
        )
    assert names == ["site.invalid"]
    assert requests == [(f"site.invalid:{source.server_port}", "/")]
    assert any(
        item.key == "http.status_code" and item.value == 200
        for item in result.report.observations
    )


def test_real_https_does_not_fall_back_to_http(tmp_path: Path) -> None:
    requests: list[tuple[str | None, str]] = []
    with server(requests) as source:
        target = WebTarget(
            origin=f"https://site.invalid:{source.server_port}",
            approved_addresses=("127.0.0.1",),
        )
        result = asyncio.run(
            scan_httpx(web_config(target), "web", tmp_path, target, BINARY)
        )
    assert requests == []
    assert any(
        item.key == "http.probe_succeeded" and item.value is False
        for item in result.report.observations
    )
    assert not any(
        item.key == "http.status_code" for item in result.report.observations
    )
