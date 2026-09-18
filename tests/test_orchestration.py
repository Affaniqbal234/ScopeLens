from uuid import UUID

import pytest

from scopelens.cli import main
from scopelens.config import ProjectConfig
from scopelens.domain.scope import ScopeViolation
from scopelens.orchestration.store import build_plan


def config(*, network: bool = False) -> ProjectConfig:
    scope: dict[str, object] = {
        "web_targets": [
            {
                "origin": "https://app.local",
                "approved_addresses": ["127.0.0.1"],
            }
        ]
    }
    ports: list[int] = []
    if network:
        scope["network_targets"] = [{"address": "127.0.0.1", "ports": [443]}]
        ports = [443]
    return ProjectConfig.model_validate(
        {
            "project": {"id": "lab", "name": "Lab", "scope": scope},
            "profiles": [{"id": "safe", "tcp_ports": ports}],
        }
    )


def test_plan_snapshots_exact_targets_resources_and_order() -> None:
    plan = build_plan(
        config(network=True), "safe", ("nmap", "httpx", "nuclei", "web_recheck")
    )
    assert [item.kind for item in plan] == ["nmap", "httpx", "nuclei", "web_recheck"]
    assert plan[0].network_targets[0].ports == (443,)
    assert plan[1].web_target is not None
    assert plan[1].web_target.approved_addresses == ("127.0.0.1",)
    assert plan[1].resources == ("/",)
    assert plan[2].resources == ("/", "/.git/config")
    assert plan[3].resources == ("/", "/.git/config")
    assert isinstance(plan[0].planned_run_id, UUID)
    assert plan[3].planned_run_id is None


def test_web_authorization_cannot_create_network_stage() -> None:
    with pytest.raises(ScopeViolation, match="network authorization"):
        build_plan(config(), "safe", ("nmap",))


def test_plan_rejects_duplicate_or_empty_stage_selection() -> None:
    with pytest.raises(ValueError, match="at least one"):
        build_plan(config(), "safe", ())
    with pytest.raises(ValueError, match="each assessment stage"):
        build_plan(config(), "safe", ("httpx", "httpx"))


def test_assessment_cli_exposes_only_fixed_stage_choices(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["assessment-create", "--help"])
    assert stopped.value.code == 0
    output = capsys.readouterr().out
    assert "{nmap,httpx,nuclei,web_recheck}" in output
    assert "--flags" not in output
    assert "--template" not in output
