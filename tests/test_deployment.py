import json
import os
import re
import shutil
import socket
import subprocess
import uuid
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import pytest
import yaml

from scopelens.config import load_config
from scopelens.deployment import recorded_demo_report
from scopelens.reporting.models import PublicSnapshot
from scopelens.reporting.render import render_json
from scopelens.reporting.snapshot import build_public_snapshot

ROOT = Path(__file__).resolve().parents[1]


def test_compose_keeps_operational_ports_local_and_demo_separate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SCOPELENS_POSTGRES_PASSWORD", "deployment-test-password")
    monkeypatch.setenv("SCOPELENS_API_TOKEN", "deployment-test-token-0123456789abcdef")
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert set(services) == {
        "postgres",
        "lab-target",
        "api",
        "dashboard",
    }
    assert "ports" not in services["postgres"]
    assert services["postgres"]["volumes"] == ["postgres-data:/var/lib/postgresql"]
    assert services["api"]["ports"][0].startswith("127.0.0.1:")
    assert services["dashboard"]["ports"][0].startswith("127.0.0.1:")
    assert set(services["api"]["networks"]) == {"data", "assessment"}
    for name in ("lab-target", "api", "dashboard"):
        service = services[name]
        assert service["user"] == "10001:10001"
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert not service.get("privileged")
        assert not service.get("network_mode")

    demo = yaml.safe_load(
        (ROOT / "deploy/compose.demo.yaml").read_text(encoding="utf-8")
    )
    public_demo = demo["services"]["public-demo"]
    assert public_demo["ports"][0].startswith("127.0.0.1:")
    assert set(public_demo["networks"]) == {"demo"}
    assert "environment" not in public_demo
    assert "volumes" not in public_demo
    assert "depends_on" not in public_demo
    assert "internal" not in demo["networks"]["demo"]
    assert public_demo["user"] == "10001:10001"
    assert public_demo["read_only"] is True
    assert public_demo["cap_drop"] == ["ALL"]


def test_deployment_scope_is_only_the_controlled_lab() -> None:
    config = load_config(ROOT / "deploy/scope.lab.toml")
    scope = config.project.scope
    assert [(item.address, item.ports) for item in scope.network_targets] == [
        ("172.31.255.2", (8000,))
    ]
    assert {item.origin for item in scope.web_targets} == {
        "http://lab-one.example.invalid:8000",
        "http://lab-two.example.invalid:8000",
    }
    assert {item.approved_addresses for item in scope.web_targets} == {
        ("172.31.255.2",)
    }
    assert scope.web_targets[0].origin != scope.network_targets[0].address


def test_example_environment_contains_no_working_secret() -> None:
    values = {}
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", 1)
        values[key] = value
    assert values["SCOPELENS_POSTGRES_PASSWORD"] == ""
    assert values["SCOPELENS_API_TOKEN"] == ""
    assert values["SCOPELENS_API_URL"] == "http://127.0.0.1:8000"
    assert values["SCOPELENS_CORS_ORIGIN"] == "http://127.0.0.1:8080"


def test_bundled_demo_is_deterministic_sanitized_and_offline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket, "create_connection", lambda *args, **kwargs: pytest.fail("network used")
    )
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args, **kwargs: pytest.fail("DNS used")
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: pytest.fail("process used")
    )
    report = recorded_demo_report()
    comparison = report.comparison
    resolved = next(item for item in comparison.results if item.state == "resolved")
    assert resolved.baseline is not None and resolved.baseline.evidence_used
    assert resolved.current is not None and resolved.current.evidence_used
    assert resolved.claim.rule_id == "scopelens.hsts-header-missing"
    hsts_by_origin = {
        item.claim.origin: item.state
        for item in comparison.results
        if item.claim.rule_id == "scopelens.hsts-header-missing"
    }
    assert hsts_by_origin == {
        "https://lab-one.example.invalid": "resolved",
        "https://lab-two.example.invalid": "new",
    }
    snapshot = build_public_snapshot(report, display_name="ScopeLens controlled demo")
    bundled = (ROOT / "frontend/demo-data/public-snapshot.json").read_bytes()
    assert bundled == render_json(snapshot)
    parsed = PublicSnapshot.model_validate_json(bundled)
    assert {item.state for item in parsed.lifecycle} == {
        "resolved",
        "unknown",
        "not_observed",
        "new",
    }
    assert len({item.origin for item in parsed.contexts}) == 2
    assert len({item.address for item in parsed.contexts}) == 1
    documentation_networks = (
        ip_network("192.0.2.0/24"),
        ip_network("198.51.100.0/24"),
        ip_network("203.0.113.0/24"),
    )
    for context in parsed.contexts:
        assert context.address is not None
        assert any(
            ip_address(context.address) in network for network in documentation_networks
        )
        assert context.origin is not None
        hostname = urlsplit(context.origin).hostname
        assert hostname is not None
        assert hostname.endswith(".example.invalid")
    encoded = bundled.decode()
    for forbidden in (
        "Authorization",
        "Cookie",
        "SCOPELENS_API_TOKEN",
        "postgresql://",
        "/var/lib/scopelens",
        "C:\\Users\\",
        "/home/",
    ):
        assert forbidden not in encoded


def test_public_demo_source_has_no_operational_api_path() -> None:
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "frontend/src/demo").glob("*"))
        if path.is_file()
    )
    for forbidden in (
        "/api/v1/",
        "Authorization",
        "Bearer ",
        "createApiClient",
        "executeAssessment",
        "createRetest",
        "reconcile",
        "fetch(",
    ):
        assert forbidden not in sources
    assert "<button" not in sources
    assert "<input" not in sources


def test_recovery_instructions_fail_closed() -> None:
    operations = (ROOT / "docs/operations.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```powershell\n(.*?)```", operations, flags=re.DOTALL)
    backup = next(block for block in blocks if "pg_dump" in block)
    restore = next(block for block in blocks if "pg_restore" in block)

    for block in (backup, restore):
        docker_lines = [
            line.strip() for line in block.splitlines() if "docker " in line
        ]
        assert docker_lines
        assert all("Invoke-CheckedNative { docker " in line for line in docker_lines)
        assert '$ErrorActionPreference = "Stop"' in block
        assert "$LASTEXITCODE" in block

    assert "Backup destination already exists" in backup
    assert "Backup root is not a directory" in backup
    assert backup.index("Test-Path -LiteralPath $BackupRoot") < backup.index(
        "$BackupDir = Join-Path $BackupRoot"
    )
    assert backup.index("Test-Path -LiteralPath $BackupDir") < backup.index(
        "New-Item -ItemType Directory -Path $BackupDir"
    )
    assert backup.index("docker compose cp api:") < backup.index(
        "[IO.File]::WriteAllText"
    )
    assert '"scopelens-paired-backup-v1"' in backup

    stop_source = restore.index("docker compose down")
    assert restore.index("$DumpBackup") < stop_source
    assert restore.index("$ArtifactsBackup") < stop_source
    assert restore.index("$CompleteMarker") < stop_source
    assert restore.index("$ExistingContainers") < stop_source
    assert restore.index("$ExistingVolumes") < stop_source
    assert "$SourceProject" in restore

    restore_database = restore.index("pg_restore --exit-on-error")
    copy_artifacts = restore.index('cp "$ArtifactsBackup/."')
    repair_permissions = restore.index("--cap-add CHOWN")
    start_stack = restore.index("docker compose -p $RestoreProject up -d --wait }")
    assert restore_database < copy_artifacts < repair_permissions < start_stack


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


@pytest.mark.skipif(
    os.environ.get("SCOPELENS_DEPLOYMENT_TEST") != "1",
    reason="opt-in Compose deployment integration",
)
def test_local_stack_start_restart_reconcile_and_static_demo(tmp_path: Path) -> None:
    assert shutil.which("docker"), "Docker is required for opted-in deployment tests"
    project = f"scopelens-deploy-{uuid.uuid4().hex[:12]}"
    api_port, dashboard_port, demo_port = (_free_port() for _ in range(3))
    token = f"deployment-{uuid.uuid4().hex}-{uuid.uuid4().hex}"
    password = f"db{uuid.uuid4().hex}"
    env_file = tmp_path / "deployment.env"
    env_file.write_text(
        "\n".join(
            (
                f"SCOPELENS_POSTGRES_PASSWORD={password}",
                f"SCOPELENS_API_TOKEN={token}",
                f"SCOPELENS_API_PORT={api_port}",
                f"SCOPELENS_DASHBOARD_PORT={dashboard_port}",
                f"SCOPELENS_DEMO_PORT={demo_port}",
                f"SCOPELENS_CORS_ORIGIN=http://127.0.0.1:{dashboard_port}",
                f"SCOPELENS_API_URL=http://127.0.0.1:{api_port}",
                "SCOPELENS_CONFIG_PATH=./deploy/scope.lab.toml",
            )
        ),
        encoding="ascii",
    )
    command = [
        "docker",
        "compose",
        "-p",
        project,
        "--env-file",
        str(env_file),
        "-f",
        str(ROOT / "compose.yaml"),
    ]
    fixed_command = [*command, "-f", str(ROOT / "deploy/compose.fixed.yaml")]
    demo_command = [
        "docker",
        "compose",
        "-p",
        f"{project}-demo",
        "--env-file",
        str(env_file),
        "-f",
        str(ROOT / "deploy/compose.demo.yaml"),
    ]

    def compose(*args: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [*command, *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result

    def demo_compose(
        *args: str, timeout: int = 180
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [*demo_command, *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result

    def fixed_compose(
        *args: str, timeout: int = 180
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [*fixed_command, *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result

    def api(
        path: str,
        *,
        method: str = "GET",
        body: dict[str, object] | None = None,
        authenticated: bool = True,
    ) -> tuple[int, dict[str, Any]]:
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = f"Bearer {token}"
        request = Request(
            f"http://127.0.0.1:{api_port}{path}",
            method=method,
            headers=headers,
            data=json.dumps(body).encode() if body is not None else None,
        )
        try:
            with urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    assessment_id = str(uuid.uuid4())
    stale_id = str(uuid.uuid4())
    try:
        compose("config", "--quiet")
        compose("build", timeout=900)
        compose("up", "-d", "--wait", timeout=300)
        with urlopen(f"http://127.0.0.1:{dashboard_port}/", timeout=10) as response:
            assert response.status == 200
            assert b'<div id="root"></div>' in response.read()
        assert api("/api/v1/project", authenticated=False)[0] == 401
        status, project_response = api("/api/v1/project")
        assert status == 200
        assert project_response["project"]["id"] == "controlled-lab"
        assert (
            api(
                "/api/v1/retests",
                method="POST",
                body={
                    "assessment_id": str(uuid.uuid4()),
                    "project_id": "controlled-lab",
                    "profile_id": "conservative",
                    "origin": "http://lab-one.example.invalid:8000",
                    "approved_address": "172.31.255.3",
                },
            )[0]
            == 403
        )
        status, created = api(
            "/api/v1/assessments",
            method="POST",
            body={
                "assessment_id": assessment_id,
                "project_id": "controlled-lab",
                "profile_id": "conservative",
                "stages": ["web_recheck"],
            },
        )
        assert status == 201
        assert created["status"] == "pending"
        status, completed = api(
            f"/api/v1/assessments/{assessment_id}/execute", method="POST"
        )
        assert status == 200
        assert completed["status"] == "completed"
        stage_id = completed["stages"][0]["id"]
        status, recheck = api(
            f"/api/v1/assessments/{assessment_id}/stages/{stage_id}/recheck"
        )
        assert status == 200
        assert all(
            item["evidence"]["health"] == "ready"
            for item in recheck["acquisitions"]
            if item["evidence"] is not None
        )
        compose("restart", "api", timeout=180)
        compose("up", "-d", "--wait", "api", timeout=180)
        assert api(f"/api/v1/assessments/{assessment_id}")[1]["status"] == "completed"
        assert (
            api(f"/api/v1/assessments/{assessment_id}/stages/{stage_id}/recheck")[0]
            == 200
        )

        fixed_compose(
            "up",
            "-d",
            "--build",
            "--force-recreate",
            "--wait",
            "lab-target",
            timeout=300,
        )
        current_id = str(uuid.uuid4())
        status, current = api(
            "/api/v1/retests",
            method="POST",
            body={
                "assessment_id": current_id,
                "project_id": "controlled-lab",
                "profile_id": "conservative",
                "origin": "http://lab-one.example.invalid:8000",
                "approved_address": "172.31.255.2",
            },
        )
        assert status == 201
        status, current = api(
            f"/api/v1/assessments/{current_id}/execute", method="POST"
        )
        assert status == 200
        assert current["status"] == "completed"
        current_stage = current["stages"][0]["id"]
        status, comparison = api(
            "/api/v1/analysis/comparison",
            method="POST",
            body={
                "project_id": "controlled-lab",
                "baseline": {
                    "basis": "persisted_recheck",
                    "assessment_id": assessment_id,
                    "stage_id": stage_id,
                },
                "current": {
                    "basis": "persisted_recheck",
                    "assessment_id": current_id,
                    "stage_id": current_stage,
                },
            },
        )
        assert status == 200
        directory_listing = next(
            item
            for item in comparison["results"]
            if item["claim"]["rule_id"] == "scopelens.directory-listing"
        )
        assert directory_listing["state"] == "resolved"
        assert directory_listing["baseline"]["outcome"] == "supported_positive"
        assert directory_listing["current"]["outcome"] == "supported_negative"

        status, stale = api(
            "/api/v1/assessments",
            method="POST",
            body={
                "assessment_id": stale_id,
                "project_id": "controlled-lab",
                "profile_id": "conservative",
                "stages": ["web_recheck"],
            },
        )
        assert status == 201
        stale_stage = stale["stages"][0]["id"]
        python = (
            "import os; from pathlib import Path; from uuid import UUID,uuid4; "
            "from scopelens.storage.database import database; "
            "from scopelens.storage.artifacts import ArtifactStore; "
            "from scopelens.orchestration.store import OrchestrationStore; "
            "store=OrchestrationStore(database(os.environ['SCOPELENS_DATABASE_URL']),"
            "ArtifactStore(Path(os.environ['SCOPELENS_ARTIFACTS']))); "
            f"aid=UUID('{stale_id}'); token=uuid4(); store.claim(token,aid); "
            f"store.start_stage(aid,UUID('{stale_stage}'),token)"
        )
        compose("exec", "-T", "api", "python", "-c", python)
        compose("restart", "api", timeout=180)
        compose("up", "-d", "--wait", "api", timeout=180)
        assert api(f"/api/v1/assessments/{stale_id}")[1]["status"] == "running"
        status, reconciled = api("/api/v1/worker/reconcile", method="POST")
        assert status == 200
        assert stale_id in reconciled["interrupted_assessment_ids"]
        assert api(f"/api/v1/assessments/{stale_id}")[1]["status"] == "interrupted"

        permissions = compose(
            "exec",
            "-T",
            "api",
            "python",
            "-c",
            "import os,stat; print(oct(stat.S_IMODE(os.stat('/var/lib/scopelens').st_mode)))",
        ).stdout.strip()
        assert permissions == "0o700"
        compose("exec", "-T", "api", "httpx", "-version")
        compose("exec", "-T", "api", "nuclei", "-version")
        compose("exec", "-T", "api", "nmap", "--version")

        demo_compose("up", "-d", "--wait", "public-demo", timeout=300)
        with urlopen(f"http://127.0.0.1:{demo_port}/demo.html", timeout=10) as response:
            html = response.read()
        assert b"ScopeLens recorded demo" in html
    finally:
        demo_compose("down", "--volumes", timeout=180)
        compose("down", "--volumes", timeout=180)
