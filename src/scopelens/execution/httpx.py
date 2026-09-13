from hashlib import sha256
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from scopelens.adapters.base import ImportContext, ReportParseError
from scopelens.adapters.httpx import HTTPX_VERSION, HttpxAdapter
from scopelens.config import ProjectConfig
from scopelens.domain.scope import ScopeViolation, WebTarget
from scopelens.execution.base import ScanResult
from scopelens.execution.process import ExecutionError, RawArtifacts, run_process

HTTPX_EXECUTABLE = "/usr/local/bin/httpx"


def build_command(
    config: ProjectConfig,
    profile_id: str,
    target: WebTarget,
    binary: str = HTTPX_EXECUTABLE,
) -> tuple[str, ...]:
    config = ProjectConfig.model_validate(config.model_dump())
    target = WebTarget.model_validate(target.model_dump())
    if (
        not PurePosixPath(binary).is_absolute()
        or "\x00" in binary
        or len(target.approved_addresses) != 1
    ):
        raise ExecutionError(
            "httpx requires an absolute binary path and one pinned address"
        )
    config.project.scope.authorize_web(target.origin, target.approved_addresses)
    profile = next((p for p in config.profiles if p.id == profile_id), None)
    if profile is None:
        raise ExecutionError("unknown scan profile")
    origin = urlsplit(target.origin)
    port = origin.port or (443 if origin.scheme == "https" else 80)
    address = target.approved_addresses[0]
    return (
        binary,
        "-u",
        f"{origin.scheme}://{address}:{port}",
        "-H",
        f"Host: {origin.netloc}",
        "-sni",
        origin.hostname or "",
        "-json",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-no-stdin",
        "-auth=false",
        "-no-fallback-scheme",
        "-follow-redirects=false",
        "-follow-host-redirects=false",
        "-respect-hsts=false",
        "-random-agent=false",
        "-cdn=false",
        "-probe",
        "-status-code",
        "-title",
        "-tech-detect",
        "-include-response-header",
        "-omit-body",
        "-threads",
        "1",
        "-rate-limit",
        str(profile.requests_per_second),
        "-timeout",
        str(profile.request_timeout_seconds),
        "-retries",
        "0",
        "-response-size-to-read",
        "65536",
        "-allow",
        address,
    )


async def scan_httpx(
    config: ProjectConfig,
    profile_id: str,
    artifact_root: Path,
    target: WebTarget,
    binary: str = HTTPX_EXECUTABLE,
) -> ScanResult:
    config = ProjectConfig.model_validate(config.model_dump())
    target = WebTarget.model_validate(target.model_dump())
    argv = build_command(config, profile_id, target, binary)
    profile = next(p for p in config.profiles if p.id == profile_id)
    identity = await run_process(
        (binary, "-version", "-disable-update-check", "-no-color"),
        artifact_root,
        timeout=5,
        output_limit=4096,
        scanner="httpx",
    )
    version_lines = {
        line.strip()
        for line in (
            identity.stdout.read_bytes() + identity.stderr.read_bytes()
        ).splitlines()
    }
    if (
        f"[INF] Current Version: v{HTTPX_VERSION}".encode() not in version_lines
        or b"projectdiscovery.io" not in version_lines
    ):
        raise ExecutionError(
            "expected ProjectDiscovery httpx v1.12.0", identity.directory
        )
    _remove_generated_config(identity)
    identity.stdout.unlink()
    identity.stderr.unlink()
    identity.directory.rmdir()
    artifacts = await run_process(
        argv,
        artifact_root,
        timeout=profile.scan_timeout_seconds,
        output_limit=profile.max_artifact_bytes,
        scanner="httpx",
    )
    _remove_generated_config(artifacts)
    try:
        report = HttpxAdapter().parse(
            artifacts.stdout.read_bytes(),
            ImportContext(
                profile_id=profile.id,
                profile_revision=sha256(profile.model_dump_json().encode()).hexdigest(),
                scanner_version=HTTPX_VERSION,
                web_target=target,
            ),
        )
        addresses = [
            item.value
            for item in report.observations
            if item.key == "http.target_address"
        ]
        if addresses != list(target.approved_addresses):
            raise ScopeViolation("httpx report does not cover the pinned target")
    except ReportParseError, ScopeViolation:
        raise ExecutionError(
            "httpx output was invalid, incomplete, or outside scope",
            artifacts.directory,
        ) from None
    return ScanResult(artifacts, report)


def _remove_generated_config(artifacts: RawArtifacts) -> None:
    # httpx creates this default file even for -version; HOME is a fresh private directory.
    config = artifacts.directory / ".config" / "httpx" / "config.yaml"
    try:
        if config.exists():
            config.unlink()
            config.parent.rmdir()
            config.parent.parent.rmdir()
    except OSError:
        raise ExecutionError(
            "cannot clean generated httpx configuration", artifacts.directory
        ) from None
