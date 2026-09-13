import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from scopelens.adapters.base import ImportContext, ParsedReport, ReportParseError
from scopelens.adapters.httpx import HTTPX_VERSION, HttpxAdapter
from scopelens.adapters.registry import adapter_for
from scopelens.cli import main
from scopelens.config import ProjectConfig
from scopelens.domain.scope import ScopeViolation, WebTarget
from scopelens.domain.services import HttpEndpoint, ServiceEndpoint
from scopelens.execution import httpx
from scopelens.execution.process import ExecutionError, RawArtifacts

FIXTURES = Path(__file__).parent / "fixtures"
TARGET = WebTarget(
    origin="https://site.invalid:8443", approved_addresses=("127.0.0.1",)
)
CONTEXT = ImportContext(
    profile_id="web",
    profile_revision="test",
    scanner_version=HTTPX_VERSION,
    web_target=TARGET,
)
RAW = (FIXTURES / "httpx/metadata.jsonl").read_bytes()


def web_config(target: WebTarget = TARGET) -> ProjectConfig:
    return ProjectConfig.model_validate(
        {
            "project": {
                "id": "web-lab",
                "name": "Web lab",
                "scope": {"web_targets": [target.model_dump()]},
            },
            "profiles": [{"id": "web"}],
        }
    )


def test_metadata_origin_identity_and_provenance() -> None:
    report = HttpxAdapter().parse(RAW, CONTEXT)
    values = {item.key: item.value for item in report.observations}
    assert values["http.title"] == "Café 東京"
    assert values["http.status_code"] == 302
    assert values["http.location"] == "https://outside.invalid/login"
    assert values["http.header.x_frame_options"] == "DENY"
    assert "http.header.set_cookie" not in values
    assert values["http.technology"] == "ExampleTech"
    assert all(
        item.subject == HttpEndpoint(origin=TARGET.origin)
        for item in report.observations
    )
    assert all(
        item.evidence[0].record_locator == "$[1]" for item in report.observations
    )
    assert report.reported_exit is None
    assert ParsedReport.model_validate_json(report.model_dump_json()) == report
    assert (
        HttpEndpoint(origin="http://site.invalid:8443")
        != report.observations[0].subject
    )
    assert report.observations[0].subject != ServiceEndpoint(
        address="127.0.0.1", transport="tcp", port=8443
    )


def test_failed_probe_is_not_a_negative_http_response() -> None:
    report = HttpxAdapter().parse(
        (FIXTURES / "httpx/failed.jsonl").read_bytes(), CONTEXT
    )
    values = {item.key: item.value for item in report.observations}
    assert values["http.probe_succeeded"] is False
    assert "http.status_code" not in values
    assert "http.peer_address" not in values


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{}",
        b"[]",
        b'{"timestamp":',
        RAW + b'{"partial":',
        RAW + RAW,
        b'{"failed":true,"failed":false}',
        b'{"x":NaN}',
        b"\xff",
        b"[" * 2000,
        b" " * (8 * 1024 * 1024 + 1),
    ],
    ids=[
        "empty",
        "object",
        "array",
        "truncated",
        "partial",
        "duplicate",
        "duplicate-key",
        "nan",
        "encoding",
        "nesting",
        "oversized",
    ],
)
def test_bad_or_duplicate_records_fail_atomically(raw: bytes) -> None:
    with pytest.raises(ReportParseError):
        HttpxAdapter().parse(raw, CONTEXT)


@pytest.mark.parametrize(
    "change",
    [
        {"host_ip": "192.0.2.1"},
        {"a": ["127.0.0.1", "192.0.2.1"]},
        {"url": "http://127.0.0.1:8443"},
        {"url": "https://127.0.0.1:443"},
        {"url": "https://outside.invalid:8443"},
        {"url": "https://127.0.0.1:8443/path"},
        {"final_url": "https://outside.invalid"},
        {"chain_status_codes": [302, 200]},
        {"status_code": True},
        {"status_code": "200"},
        {"status_code": 0},
        {"failed": True},
        {"timestamp": "2026-09-13T12:00:00"},
        {"header": {"x-frame-options": "DENY", "x_frame_options": "SAMEORIGIN"}},
        {"tech": ["ExampleTech", "ExampleTech"]},
        {"title": "x" * 8193},
    ],
)
def test_invalid_fields_or_expanded_scope_rejected(change: dict[str, object]) -> None:
    record = json.loads(RAW)
    record.update(change)
    with pytest.raises(ReportParseError):
        HttpxAdapter().parse(json.dumps(record).encode(), CONTEXT)


def test_missing_optional_metadata_and_unicode_separator() -> None:
    record = json.loads(RAW)
    for key in (
        "title",
        "tech",
        "header",
        "location",
        "content_type",
        "webserver",
        "content_length",
    ):
        record.pop(key, None)
    values = {
        item.key: item.value
        for item in HttpxAdapter()
        .parse(json.dumps(record).encode(), CONTEXT)
        .observations
    }
    assert "http.title" not in values
    record["title"] = "one\u2028two"
    report = HttpxAdapter().parse(
        json.dumps(record, ensure_ascii=False).encode(), CONTEXT
    )
    assert any(item.value == "one\u2028two" for item in report.observations)


@pytest.mark.parametrize("scanner", ["nmap", "httpx"])
def test_shared_adapter_contract(scanner: str) -> None:
    adapter = adapter_for(scanner)
    raw = (FIXTURES / "nmap/minimal.xml").read_bytes() if scanner == "nmap" else RAW
    report = adapter.parse(raw, CONTEXT)
    assert report.evidence.scanner == adapter.name
    assert report.evidence.record_locator == adapter.root_locator
    assert report.observations
    assert (
        report.evidence.artifact_sha256
        == report.observations[0].evidence[0].artifact_sha256
    )


def test_command_pins_address_preserves_host_and_sni() -> None:
    argv = httpx.build_command(web_config(), "web", TARGET, "/trusted/httpx")
    assert argv[argv.index("-u") + 1] == "https://127.0.0.1:8443"
    assert argv[argv.index("-H") + 1] == "Host: site.invalid:8443"
    assert argv[argv.index("-sni") + 1] == "site.invalid"
    for flag in (
        "-no-fallback-scheme",
        "-follow-redirects=false",
        "-follow-host-redirects=false",
        "-omit-body",
    ):
        assert flag in argv
    assert not {
        "-no-fallback",
        "-tls-probe",
        "-csp-probe",
        "-screenshot",
        "-unsafe",
    }.intersection(argv)


@pytest.mark.parametrize(
    "target",
    [
        WebTarget(origin="http://site.invalid:8443", approved_addresses=("127.0.0.1",)),
        WebTarget(origin=TARGET.origin, approved_addresses=("192.0.2.1",)),
        WebTarget(origin=TARGET.origin, approved_addresses=("127.0.0.1", "192.0.2.1")),
    ],
)
def test_scope_failure_precedes_process_start(
    target: WebTarget, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = AsyncMock()
    monkeypatch.setattr(httpx, "run_process", runner)
    with pytest.raises((ScopeViolation, ExecutionError)):
        asyncio.run(httpx.scan_httpx(web_config(), "web", tmp_path, target))
    runner.assert_not_called()


def test_network_authorization_does_not_grant_web_access() -> None:
    config = ProjectConfig.model_validate(
        {
            "project": {
                "id": "network",
                "name": "Network",
                "scope": {
                    "network_targets": [{"address": "127.0.0.1", "ports": [8443]}]
                },
            },
            "profiles": [{"id": "web", "tcp_ports": [8443]}],
        }
    )
    with pytest.raises(ScopeViolation):
        httpx.build_command(config, "web", TARGET)
    with pytest.raises(ValidationError):
        WebTarget(
            origin="https://site.invalid;echo injected",
            approved_addresses=("127.0.0.1",),
        )


@pytest.mark.parametrize(
    "failure", ["identity", "version-prefix", "process", "partial"]
)
def test_execution_failure_retains_diagnostics(
    failure: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def artifact(name: str, raw: bytes, error: bytes = b"") -> RawArtifacts:
        root = tmp_path / name
        root.mkdir()
        stdout, stderr = root / "stdout.jsonl", root / "stderr.txt"
        stdout.write_bytes(raw)
        stderr.write_bytes(error)
        return RawArtifacts(root, stdout, stderr)

    identity = artifact(
        "identity",
        b"",
        b"projectdiscovery.io\n[INF] Current Version: v1.12.0\n"
        if failure not in ("identity", "version-prefix")
        else b"Python httpx"
        if failure == "identity"
        else b"projectdiscovery.io\n[INF] Current Version: v1.12.01\n",
    )
    result = artifact("scan", b'{"partial":' if failure == "partial" else RAW)
    runner = AsyncMock(
        side_effect=[
            identity,
            ExecutionError("failed", result.directory)
            if failure == "process"
            else result,
        ]
    )
    monkeypatch.setattr(httpx, "run_process", runner)
    with pytest.raises(ExecutionError):
        asyncio.run(httpx.scan_httpx(web_config(), "web", tmp_path, TARGET))
    assert runner.await_count == (1 if failure in ("identity", "version-prefix") else 2)


def test_import_cli(capsys: pytest.CaptureFixture[str]) -> None:
    main(
        [
            "import-httpx",
            str(FIXTURES / "httpx/metadata.jsonl"),
            "--origin",
            TARGET.origin,
            "--address",
            "127.0.0.1",
            "--profile-id",
            "web",
            "--profile-revision",
            "test",
            "--scanner-version",
            HTTPX_VERSION,
        ]
    )
    assert (
        ParsedReport.model_validate_json(capsys.readouterr().out).evidence.scanner
        == "httpx"
    )


def test_import_is_offline_and_context_is_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket

    def blocked(*args: object, **kwargs: object) -> None:
        pytest.fail("offline parsing attempted network or DNS access")

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    assert HttpxAdapter().parse(RAW, CONTEXT).observations
    for context in (
        ImportContext(profile_id="web", profile_revision="test"),
        CONTEXT.model_copy(update={"scanner_version": "0.28.1"}),
    ):
        with pytest.raises(ReportParseError):
            HttpxAdapter().parse(RAW, context)


def test_peer_cannot_contradict_pinned_address() -> None:
    context = CONTEXT.model_copy(
        update={
            "web_target": WebTarget(
                origin=TARGET.origin, approved_addresses=("127.0.0.1", "127.0.0.2")
            )
        }
    )
    record = json.loads(RAW)
    record["host_ip"] = "127.0.0.2"
    with pytest.raises(ReportParseError):
        HttpxAdapter().parse(json.dumps(record).encode(), context)


def test_scan_cli_reports_retained_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from scopelens import cli

    monkeypatch.setattr(cli, "load_config", lambda _: web_config())
    monkeypatch.setattr(
        cli,
        "scan_httpx",
        AsyncMock(side_effect=ExecutionError("scanner failed", tmp_path)),
    )
    with pytest.raises(SystemExit) as error:
        main(
            [
                "scan-httpx",
                "scope.toml",
                "--profile",
                "web",
                "--origin",
                TARGET.origin,
                "--address",
                "127.0.0.1",
            ]
        )
    assert error.value.code == 2
    assert "private artifacts:" in capsys.readouterr().err


@pytest.mark.parametrize("binary", ["httpx", "/tmp/httpx\x00-extra"])
def test_invalid_binary_path_rejected(binary: str) -> None:
    with pytest.raises(ExecutionError):
        httpx.build_command(web_config(), "web", TARGET, binary)
