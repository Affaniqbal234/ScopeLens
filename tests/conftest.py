from pathlib import Path

import pytest


@pytest.fixture
def config_text() -> str:
    return """
[project]
id = "local-lab"
name = "Local lab"

[[project.scope.network_targets]]
address = "127.0.0.1"
ports = [8000]

[[project.scope.web_targets]]
origin = "http://localhost:8000"
approved_addresses = ["127.0.0.1"]

[[profiles]]
id = "conservative"
tcp_ports = [8000]
"""


@pytest.fixture
def config_path(tmp_path: Path, config_text: str) -> Path:
    path = tmp_path / "scope.toml"
    path.write_text(config_text, encoding="utf-8")
    return path
