import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest
import yaml

from scopelens.adapters.base import ParsedReport
from scopelens.config import load_config
from scopelens.domain.services import ServiceEndpoint

ROOT = Path(__file__).resolve().parents[1]


def test_lab_configuration_is_contained() -> None:
    compose = yaml.safe_load((ROOT / "lab/compose.yaml").read_text())
    assert compose["networks"]["lab"]["internal"] is True
    assert set(compose["services"]) == {"target", "scanner"}
    for service in compose["services"].values():
        assert not service.get("ports")
        assert not service.get("privileged")
        assert not service.get("network_mode")
        assert service["user"] == "10001:10001"
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert set(service["networks"]) == {"lab"}
        assert service["pids_limit"] <= 64
        assert "mem_limit" in service
        assert service["logging"]["options"] == {
            "max-size": "1m",
            "max-file": "1",
            "compress": "false",
        }
    assert compose["services"]["scanner"]["volumes"] == ["artifacts:/artifacts"]
    assert compose["services"]["target"]["tmpfs"] == ["/tmp:size=16m,mode=1777"]
    assert compose["services"]["scanner"]["tmpfs"] == ["/tmp:size=64m,mode=1777"]
    scope = load_config(ROOT / "lab/scope.toml")
    target = scope.project.scope.network_targets[0]
    assert (
        target.address
        == compose["services"]["target"]["networks"]["lab"]["ipv4_address"]
    )
    assert target.ports == (8000, 8001)
    assert not scope.project.scope.web_targets


@pytest.mark.skipif(
    os.environ.get("SCOPELENS_LAB_TEST") != "1",
    reason="opt-in Docker lab integration: set SCOPELENS_LAB_TEST=1",
)
def test_docker_lab_scan_and_exposure() -> None:
    assert shutil.which("docker"), "Docker is required for opted-in lab tests"
    command = [
        "docker",
        "compose",
        "-p",
        f"scopelens-test-{uuid.uuid4().hex[:12]}",
        "-f",
        str(ROOT / "lab/compose.yaml"),
    ]

    def run(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [*command, *args],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        assert result.returncode == 0, result.stderr
        return result

    try:
        run("--profile", "scan", "config", "--quiet")
        run("--profile", "scan", "build", timeout=600)
        run("up", "-d", "--wait", "target")
        response = run(
            "exec",
            "-T",
            "target",
            "python",
            "-c",
            "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/sample-backup.txt').read().decode())",
        )
        assert "no credentials or real data" in response.stdout
        report = ParsedReport.model_validate_json(run("run", "--rm", "scanner").stdout)
        states = {
            item.subject.port: item.value
            for item in report.observations
            if isinstance(item.subject, ServiceEndpoint) and item.key == "service.state"
        }
        assert states.get(8000) == "open"
        assert states.get(8001) == "closed" or any(
            item.key == "ports.closed.count" and item.value == 1
            for item in report.observations
        )
        assert report.reported_exit == "success"
        artifact_check = run(
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "python",
            "scanner",
            "-c",
            """
import os, stat
from pathlib import Path
from scopelens.adapters.base import ImportContext
from scopelens.adapters.nmap import import_nmap
from scopelens.config import load_config
from hashlib import sha256

root = Path('/artifacts')
runs = list(root.glob('nmap-*'))
assert len(runs) == 1
directory = runs[0]
for path in (root, directory):
    assert stat.S_IMODE(path.stat().st_mode) == 0o700
    assert path.stat().st_uid == os.geteuid()
for path in directory.iterdir():
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_uid == os.geteuid()
profile = load_config(Path('/app/lab/scope.toml')).profiles[0]
assert sum(path.stat().st_size for path in directory.iterdir()) <= profile.max_artifact_bytes
assert (directory / 'stderr.txt').stat().st_size <= 65536
context = ImportContext(profile_id=profile.id, profile_revision=sha256(profile.model_dump_json().encode()).hexdigest())
parsed = import_nmap(directory / 'stdout.xml', context)
assert parsed.evidence.artifact_sha256 == sha256((directory / 'stdout.xml').read_bytes()).hexdigest()
assert all(line.split()[1] != '00000000' for line in Path('/proc/net/route').read_text().splitlines()[1:])
print(parsed.model_dump_json())
""",
        )
        assert ParsedReport.model_validate_json(artifact_check.stdout) == report
        container = run("ps", "-q", "target").stdout.strip()
        inspect = subprocess.run(
            ["docker", "inspect", container],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        info = json.loads(inspect.stdout)[0]
        assert not info["HostConfig"]["PortBindings"]
        network_name = next(iter(info["NetworkSettings"]["Networks"]))
        network = subprocess.run(
            ["docker", "network", "inspect", network_name],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert json.loads(network.stdout)[0]["Internal"] is True
    finally:
        # This unique project and its volumes belong only to this test invocation.
        run("--profile", "scan", "down", "--volumes", "--remove-orphans")
