import asyncio
import base64
import json
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import yaml

from scopelens.adapters.base import ImportContext, ParsedReport, ReportParseError
from scopelens.adapters.nuclei import NucleiAdapter
from scopelens.adapters.nuclei_templates import (
    NUCLEI_VERSION,
    reviewed_templates,
    template_revision,
)
from scopelens.cli import main
from scopelens.domain.scope import ScopeViolation, WebTarget
from scopelens.execution import nuclei
from scopelens.execution.process import ExecutionError, RawArtifacts
from tests.test_httpx import web_config

RAW = (Path(__file__).parent / "fixtures/nuclei/matches.jsonl").read_bytes()
TARGET = WebTarget(origin="http://site.invalid:8000", approved_addresses=("127.0.0.1",))
CONTEXT = ImportContext(
    profile_id="web",
    profile_revision="test",
    scanner_version=NUCLEI_VERSION,
    web_target=TARGET,
    template_revision=template_revision(),
    captured_at=datetime(2026, 9, 14, tzinfo=UTC),
)


def test_normalized_matches_and_no_false_certainty() -> None:
    report = NucleiAdapter().parse(RAW, CONTEXT)
    assert len(report.matches) == 2
    assert {item.scanner_severity for item in report.matches} == {"low", "medium"}
    assert {item.assessment for item in report.matches} == {"unvalidated"}
    assert {item.origin for item in report.matches} == {TARGET.origin}
    assert all(
        item.matched_location.startswith(TARGET.origin) for item in report.matches
    )
    assert report.matches[0].evidence[0].record_locator == "line:1"
    assert (
        report.matches[0].evidence[0].artifact_sha256 == report.evidence.artifact_sha256
    )
    assert ParsedReport.model_validate_json(report.model_dump_json()) == report


def test_empty_output_has_no_negative_findings() -> None:
    report = NucleiAdapter().parse(b"", CONTEXT)
    assert (
        report.matches == ()
        and report.observations == ()
        and report.reported_exit is None
    )
    assert report.evidence.captured_at == CONTEXT.captured_at


@pytest.mark.parametrize(
    "raw",
    [
        b'{"partial":',
        RAW + b"{",
        RAW + RAW,
        b"[]",
        b"{}",
        b"\xff",
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b"[" * 2000,
        b" " * (8 * 1024 * 1024 + 1),
    ],
    ids=[
        "partial",
        "trailing",
        "duplicate",
        "array",
        "missing",
        "encoding",
        "duplicate-key",
        "nan",
        "nested",
        "large",
    ],
)
def test_malformed_or_duplicate_output_rejected(raw: bytes) -> None:
    with pytest.raises(ReportParseError):
        NucleiAdapter().parse(raw, CONTEXT)


@pytest.mark.parametrize(
    "change",
    [
        {"template-id": "unreviewed"},
        {"template-encoded": base64.b64encode(b"changed").decode()},
        {"matcher-name": "different"},
        {"info": {"severity": "critical"}},
        {"type": "dns"},
        {"ip": "192.0.2.1"},
        {"host": "elsewhere.invalid"},
        {"url": "http://127.0.0.2:8000"},
        {"port": "8001"},
        {"scheme": "https"},
        {"matched-at": "https://elsewhere.invalid/"},
        {"matched-at": "http://127.0.0.1:8000/other"},
        {"matcher-status": False},
        {"matcher-status": 1},
        {"interaction": {"protocol": "dns"}},
        {"global-matchers": True},
        {"timestamp": "2026-09-14T00:00:00"},
    ],
)
def test_template_scope_and_semantic_mismatches(change: dict[str, object]) -> None:
    record = json.loads(RAW.splitlines()[0])
    record.update(change)
    with pytest.raises(ReportParseError):
        NucleiAdapter().parse(json.dumps(record).encode(), CONTEXT)


def test_missing_context_and_template_revision_rejected() -> None:
    for field in ("web_target", "scanner_version", "template_revision", "captured_at"):
        with pytest.raises(ReportParseError):
            NucleiAdapter().parse(RAW, CONTEXT.model_copy(update={field: None}))


def test_reviewed_templates_only_use_fixed_read_only_http() -> None:
    for template in reviewed_templates():
        document = yaml.safe_load(
            files("scopelens").joinpath("templates", template.filename).read_text()
        )
        assert set(document) == {"id", "info", "http"}
        assert len(document["http"]) == 1
        request = document["http"][0]
        assert set(request) == {"method", "path", "redirects", "matchers"}
        assert request["method"] == "GET" and request["redirects"] is False
        assert request["path"] == ["{{BaseURL}}" + template.path]


def test_command_is_pinned_and_has_no_expansion_flags() -> None:
    command = nuclei.build_command(web_config(TARGET), "web", TARGET)
    assert command[command.index("-u") + 1] == "http://127.0.0.1:8000"
    assert command[command.index("-H") + 1] == "Host: site.invalid:8000"
    assert command[command.index("-sni") + 1] == "site.invalid"
    assert command.count("-t") == 2
    assert {
        "-disable-update-check",
        "-no-interactsh",
        "-disable-redirects",
        "-no-httpx",
        "-no-stdin",
    } <= set(command)
    assert not {
        "-headless",
        "-code",
        "-dast",
        "-follow-redirects",
        "-update-templates",
    } & set(command)


@pytest.mark.parametrize(
    "target",
    [
        WebTarget(
            origin="https://site.invalid:8000", approved_addresses=("127.0.0.1",)
        ),
        WebTarget(origin=TARGET.origin, approved_addresses=("192.0.2.1",)),
        WebTarget(origin=TARGET.origin, approved_addresses=("127.0.0.1", "192.0.2.1")),
    ],
)
def test_scope_rejected_before_execution(
    target: WebTarget, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = AsyncMock()
    monkeypatch.setattr(nuclei, "run_process", runner)
    with pytest.raises((ScopeViolation, ExecutionError)):
        asyncio.run(nuclei.scan_nuclei(web_config(TARGET), "web", tmp_path, target))
    runner.assert_not_called()


@pytest.mark.parametrize("mode", ["identity", "failure", "partial", "empty"])
def test_execution_failures_and_empty_results(
    mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def artifact(name: str, raw: bytes) -> RawArtifacts:
        root = tmp_path / name
        root.mkdir()
        stdout = root / "stdout.jsonl"
        stderr = root / "stderr.txt"
        stdout.write_bytes(raw)
        stderr.write_bytes(b"")
        return RawArtifacts(root, stdout, stderr)

    identity = artifact(
        "identity",
        b"wrong version"
        if mode == "identity"
        else b"[INF] Nuclei Engine Version: v3.11.1\n",
    )
    capture = artifact("scan", b"{" if mode == "partial" else b"")
    runner = AsyncMock(
        side_effect=[
            identity,
            ExecutionError("failed", capture.directory)
            if mode == "failure"
            else capture,
        ]
    )
    monkeypatch.setattr(nuclei, "run_process", runner)
    if mode == "empty":
        result = asyncio.run(
            nuclei.scan_nuclei(web_config(TARGET), "web", tmp_path, TARGET)
        )
        assert result.report.matches == ()
    else:
        with pytest.raises(ExecutionError):
            asyncio.run(nuclei.scan_nuclei(web_config(TARGET), "web", tmp_path, TARGET))


def test_manifest_cli(capsys: pytest.CaptureFixture[str]) -> None:
    main(["nuclei-templates"])
    assert json.loads(capsys.readouterr().out)["revision"] == template_revision()


def test_unavailable_templates_fail_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing() -> None:
        raise OSError("missing template")

    runner = AsyncMock()
    monkeypatch.setattr(nuclei, "reviewed_templates", missing)
    monkeypatch.setattr(nuclei, "run_process", runner)
    with pytest.raises(ExecutionError, match="unavailable"):
        asyncio.run(nuclei.scan_nuclei(web_config(TARGET), "web", tmp_path, TARGET))
    runner.assert_not_called()


def test_template_changes_fail_digest_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scopelens.adapters import nuclei_templates

    root = tmp_path / "templates"
    root.mkdir()
    for name in ("manifest.json", "directory-listing.yaml", "exposed-git-config.yaml"):
        (root / name).write_bytes(
            files("scopelens").joinpath("templates", name).read_bytes()
        )
    (root / "directory-listing.yaml").write_text("changed")
    monkeypatch.setattr(nuclei_templates, "files", lambda _: tmp_path)
    with pytest.raises(ValueError, match="digest mismatch"):
        reviewed_templates()


def test_import_cli_and_no_arbitrary_flags(capsys: pytest.CaptureFixture[str]) -> None:
    args = [
        "import-nuclei",
        str(Path(__file__).parent / "fixtures/nuclei/matches.jsonl"),
        "--profile-id",
        "web",
        "--profile-revision",
        "test",
        "--origin",
        TARGET.origin,
        "--address",
        "127.0.0.1",
        "--scanner-version",
        NUCLEI_VERSION,
        "--template-revision",
        template_revision(),
        "--captured-at",
        "2026-09-14T00:00:00Z",
    ]
    main(args)
    assert len(ParsedReport.model_validate_json(capsys.readouterr().out).matches) == 2
    with pytest.raises(SystemExit):
        main([*args, "--templates", "/unreviewed.yaml"])


def test_execution_uses_private_template_copies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def runner(
        argv: tuple[str, ...], root: Path, **limits: object
    ) -> RawArtifacts:
        directory = root / ("identity" if "-version" in argv else "capture")
        directory.mkdir()
        stdout, stderr = directory / "stdout.jsonl", directory / "stderr.txt"
        stderr.write_bytes(b"")
        if "-version" in argv:
            stdout.write_bytes(b"[INF] Nuclei Engine Version: v3.11.1\n")
        else:
            paths = [
                Path(argv[index + 1])
                for index, value in enumerate(argv)
                if value == "-t"
            ]
            assert len(paths) == 2
            assert all(
                path.is_relative_to(tmp_path) and path.read_bytes() for path in paths
            )
            assert all(
                path.parent.name.startswith("nuclei-templates-") for path in paths
            )
            stdout.write_bytes(b"")
        return RawArtifacts(directory, stdout, stderr)

    monkeypatch.setattr(nuclei, "run_process", runner)
    asyncio.run(nuclei.scan_nuclei(web_config(TARGET), "web", tmp_path, TARGET))
    assert not list(tmp_path.glob("nuclei-templates-*"))
