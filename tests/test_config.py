import socket
import subprocess
import tomllib
from pathlib import Path

import pytest
from pydantic import ValidationError

from scopelens.config import (
    MAX_CONFIG_BYTES,
    ConfigurationError,
    ProjectConfig,
    load_config,
)
from scopelens.domain.scope import NetworkTarget


def test_loads_and_checks_config_without_network_or_processes(
    config_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("configuration and scope validation must remain offline")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    config = load_config(config_path)
    assert config.project.id == "local-lab"
    config.project.scope.authorize_network(
        NetworkTarget(address="127.0.0.1", ports=(8000,))
    )
    config.project.scope.authorize_web("http://localhost:8000/", ("127.0.0.1",))
    assert config.profiles[0].requests_per_second == 5
    assert ProjectConfig.model_validate_json(config.model_dump_json()) == config


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("ports = [8000]", "ports = [8000, 8000]"),
        ("tcp_ports = [8000]", "tcp_ports = [22]"),
        ("tcp_ports = [8000]", "tcp_ports = []"),
        ("tcp_ports = [8000]", "tcp_ports = [8000]\nmax_targets = 1"),
        ('name = "Local lab"', 'name = "Local lab"\ncommand = "nmap"'),
    ],
)
def test_invalid_configs_do_not_expand_scope(
    config_path: Path, config_text: str, old: str, new: str
) -> None:
    config_path.write_text(config_text.replace(old, new), encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(config_path)


def test_web_only_config_requires_no_network_permissions(config_text: str) -> None:
    data = tomllib.loads(config_text)
    del data["project"]["scope"]["network_targets"]
    data["profiles"][0]["tcp_ports"] = []
    config = ProjectConfig.model_validate(data)
    assert config.project.scope.network_targets == ()
    data["profiles"][0]["tcp_ports"] = [443]
    with pytest.raises(ValidationError):
        ProjectConfig.model_validate(data)


def test_duplicate_profile_ids_are_rejected(config_text: str) -> None:
    data = tomllib.loads(config_text)
    data["profiles"].append(data["profiles"][0].copy())
    with pytest.raises(ValidationError, match="duplicate profile"):
        ProjectConfig.model_validate(data)


def test_address_expansion_counts_against_profile_limit(config_text: str) -> None:
    data = tomllib.loads(config_text)
    data["project"]["scope"]["web_targets"][0]["approved_addresses"] = [
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.3",
    ]
    data["profiles"][0]["max_targets"] = 2
    with pytest.raises(ValidationError, match="target limit"):
        ProjectConfig.model_validate(data)


@pytest.mark.parametrize("content", [b"[[broken", b"\xff\xfe", b""])
def test_bad_toml_or_missing_fields_are_rejected(
    tmp_path: Path, content: bytes
) -> None:
    path = tmp_path / "invalid.toml"
    path.write_bytes(content)
    with pytest.raises(ConfigurationError):
        load_config(path)


def test_missing_or_unreadable_file_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ConfigurationError, match="cannot read"):
        load_config(tmp_path / "missing.toml")

    def denied(*args: object, **kwargs: object) -> None:
        raise PermissionError

    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(ConfigurationError, match="cannot read"):
        load_config(tmp_path / "denied.toml")


def test_configuration_size_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "oversized.toml"
    path.write_bytes(b" " * (MAX_CONFIG_BYTES + 1))
    with pytest.raises(ConfigurationError, match="1 MiB"):
        load_config(path)


def test_error_does_not_echo_rejected_credentials(
    config_path: Path, config_text: str
) -> None:
    config_path.write_text(
        config_text.replace(
            "http://localhost:8000", "http://user:private-token@localhost:8000"
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError) as exc:
        load_config(config_path)
    assert "private-token" not in str(exc.value)
    assert "credentials" in str(exc.value)
