import re
import shutil
from datetime import UTC, datetime
from hashlib import sha256
from importlib.resources import files
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

from scopelens.adapters.base import ImportContext, ReportParseError
from scopelens.adapters.nuclei import NucleiAdapter
from scopelens.adapters.nuclei_templates import (
    NUCLEI_VERSION,
    reviewed_templates,
    template_revision,
)
from scopelens.config import ProjectConfig
from scopelens.domain.scope import WebTarget
from scopelens.execution.base import ScanResult
from scopelens.execution.process import ExecutionError, RawArtifacts, run_process

NUCLEI_EXECUTABLE = "/usr/local/bin/nuclei"


def build_command(
    config: ProjectConfig,
    profile_id: str,
    target: WebTarget,
    binary: str = NUCLEI_EXECUTABLE,
) -> tuple[str, ...]:
    config = ProjectConfig.model_validate(config.model_dump())
    target = WebTarget.model_validate(target.model_dump())
    if (
        not PurePosixPath(binary).is_absolute()
        or "\x00" in binary
        or len(target.approved_addresses) != 1
    ):
        raise ExecutionError(
            "Nuclei requires an absolute binary path and one pinned address"
        )
    config.project.scope.authorize_web(target.origin, target.approved_addresses)
    profile = next((p for p in config.profiles if p.id == profile_id), None)
    if profile is None:
        raise ExecutionError("unknown scan profile")
    try:
        templates = reviewed_templates()
    except OSError, ValueError:
        raise ExecutionError(
            "reviewed Nuclei templates are unavailable or changed"
        ) from None
    origin = urlsplit(target.origin)
    port = origin.port or (443 if origin.scheme == "https" else 80)
    template_args = tuple(
        arg
        for template in templates
        for arg in (
            "-t",
            str(files("scopelens").joinpath("templates", template.filename)),
        )
    )
    return (
        binary,
        "-u",
        f"{origin.scheme}://{target.approved_addresses[0]}:{port}",
        *template_args,
        "-H",
        f"Host: {origin.netloc}",
        "-sni",
        origin.hostname or "",
        "-jsonl",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-no-interactsh",
        "-disable-redirects",
        "-no-httpx",
        "-no-stdin",
        "-disable-clustering",
        "-type",
        "http",
        "-concurrency",
        "1",
        "-bulk-size",
        "1",
        "-rate-limit",
        str(profile.requests_per_second),
        "-timeout",
        str(profile.request_timeout_seconds),
        "-retries",
        "0",
        "-response-size-read",
        "65536",
    )


def _clean_configuration(artifacts: RawArtifacts) -> None:
    # Only scanner-created configuration inside this fresh private HOME is removed.
    for name in (".config", ".cache", ".pdcp"):
        path = artifacts.directory / name
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)


async def scan_nuclei(
    config: ProjectConfig,
    profile_id: str,
    artifact_root: Path,
    target: WebTarget,
    binary: str = NUCLEI_EXECUTABLE,
    *,
    captured_at: datetime | None = None,
) -> ScanResult:
    config = ProjectConfig.model_validate(config.model_dump())
    target = WebTarget.model_validate(target.model_dump())
    argv = build_command(config, profile_id, target, binary)
    profile = next(p for p in config.profiles if p.id == profile_id)
    templates = reviewed_templates()
    captured_at = captured_at or datetime.now(UTC)
    identity = await run_process(
        (binary, "-version", "-disable-update-check", "-no-color"),
        artifact_root,
        timeout=5,
        output_limit=4096,
        scanner="nuclei",
    )
    lines = {
        re.sub(rb"\x1b\[[0-9;]*m", b"", line).strip()
        for line in (
            identity.stdout.read_bytes() + identity.stderr.read_bytes()
        ).splitlines()
    }
    if f"[INF] Nuclei Engine Version: v{NUCLEI_VERSION}".encode() not in lines:
        raise ExecutionError(
            "expected ProjectDiscovery Nuclei v3.11.1", identity.directory
        )
    _clean_configuration(identity)
    identity.stdout.unlink()
    identity.stderr.unlink()
    identity.directory.rmdir()
    with TemporaryDirectory(prefix="nuclei-templates-", dir=artifact_root) as temporary:
        command = list(argv)
        for template in templates:
            source = files("scopelens").joinpath("templates", template.filename)
            raw = source.read_bytes()
            if sha256(raw).hexdigest() != template.sha256:
                raise ExecutionError(
                    "reviewed Nuclei template changed before execution"
                )
            path = Path(temporary) / template.filename
            path.write_bytes(raw)
            path.chmod(0o600)
            command[command.index(str(source))] = str(path.absolute())
        artifacts = await run_process(
            tuple(command),
            artifact_root,
            timeout=profile.scan_timeout_seconds,
            output_limit=profile.max_artifact_bytes,
            scanner="nuclei",
        )
    _clean_configuration(artifacts)
    try:
        report = NucleiAdapter().parse(
            artifacts.stdout.read_bytes(),
            ImportContext(
                profile_id=profile_id,
                profile_revision=sha256(profile.model_dump_json().encode()).hexdigest(),
                scanner_version=NUCLEI_VERSION,
                web_target=target,
                template_revision=template_revision(),
                captured_at=captured_at,
            ),
        )
    except ReportParseError:
        raise ExecutionError(
            "invalid Nuclei output; private artifacts retained", artifacts.directory
        ) from None
    return ScanResult(artifacts, report)
