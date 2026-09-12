from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from scopelens.adapters.base import ImportContext, ParsedReport, ReportParseError
from scopelens.adapters.nmap import import_nmap
from scopelens.config import ProjectConfig
from scopelens.domain.scope import NetworkTarget, ScopeViolation
from scopelens.domain.services import ServiceEndpoint
from scopelens.execution.process import ExecutionError, RawArtifacts, run_process

NMAP_EXECUTABLE = "/usr/bin/nmap"


@dataclass(frozen=True)
class ScanResult:
    artifacts: RawArtifacts
    report: ParsedReport


def build_command(config: ProjectConfig, profile_id: str) -> tuple[str, ...]:
    # Revalidate at the execution boundary, including profiles and all targets.
    config = ProjectConfig.model_validate(config.model_dump())
    profile = next((p for p in config.profiles if p.id == profile_id), None)
    if profile is None:
        raise ExecutionError("unknown scan profile")
    targets = config.project.scope.network_targets
    if not targets:
        raise ScopeViolation("Nmap requires explicit network authorization")
    for target in targets:
        config.project.scope.authorize_network(
            NetworkTarget(address=target.address, ports=profile.tcp_ports)
        )
    return (
        NMAP_EXECUTABLE,
        "--unprivileged",
        "-sT",
        "-Pn",
        "-n",
        "--disable-arp-ping",
        "--max-retries",
        "1",
        "--max-parallelism",
        "1",
        "--max-rate",
        str(profile.probes_per_second),
        "--host-timeout",
        f"{profile.scan_timeout_seconds}s",
        "-p",
        ",".join(str(port) for port in profile.tcp_ports),
        "-oX",
        "-",
        *(target.address for target in targets),
    )


async def scan_nmap(
    config: ProjectConfig, profile_id: str, artifact_root: Path
) -> ScanResult:
    config = ProjectConfig.model_validate(config.model_dump())
    argv = build_command(config, profile_id)
    profile = next(p for p in config.profiles if p.id == profile_id)
    artifacts = await run_process(
        argv,
        artifact_root,
        timeout=profile.scan_timeout_seconds,
        output_limit=profile.max_artifact_bytes,
    )
    try:
        report = import_nmap(
            artifacts.stdout,
            ImportContext(
                profile_id=profile.id,
                profile_revision=sha256(profile.model_dump_json().encode()).hexdigest(),
            ),
        )
        if report.reported_exit != "success":
            raise ExecutionError(
                "Nmap did not report successful completion", artifacts.directory
            )
        permitted = {target.address for target in config.project.scope.network_targets}
        coverage = dict.fromkeys(permitted, 0)
        for observation in report.observations:
            subject = observation.subject
            if isinstance(subject, ServiceEndpoint):
                if subject.transport != "tcp" or subject.port not in profile.tcp_ports:
                    raise ScopeViolation(
                        "scanner reported a service outside the requested scope"
                    )
                config.project.scope.authorize_network(
                    NetworkTarget(address=subject.address, ports=(subject.port,))
                )
                if observation.key == "service.state":
                    coverage[subject.address] += 1
            elif subject not in permitted:
                raise ScopeViolation(
                    "scanner reported a host outside the requested scope"
                )
            elif observation.key.startswith("ports.") and observation.key.endswith(
                ".count"
            ):
                if type(observation.value) is not int:
                    raise ScopeViolation("invalid reported port count")
                coverage[subject] += observation.value
            if observation.key == "host.timed_out" and observation.value is True:
                raise ExecutionError(
                    "Nmap reported a host timeout", artifacts.directory
                )
        if any(count != len(profile.tcp_ports) for count in coverage.values()):
            raise ExecutionError(
                "Nmap report does not cover every requested host and port",
                artifacts.directory,
            )
    except ReportParseError, ScopeViolation:
        raise ExecutionError(
            "Nmap output was invalid or outside the requested scope",
            artifacts.directory,
        ) from None
    return ScanResult(artifacts, report)
