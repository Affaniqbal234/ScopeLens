import json
import subprocess
from typing import Any

import pytest

from tests.postgres import LABEL, DisposablePostgres


class FakePostgres(DisposablePostgres):
    def __init__(self) -> None:
        super().__init__()
        self.commands: list[tuple[str, ...]] = []
        self.details: dict[str, Any] = {
            "Id": "a" * 64,
            "Name": f"/{self.name}",
            "Config": {"Labels": {LABEL: self.token}},
            "NetworkSettings": {
                "Ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "15432"}]}
            },
        }
        self.ready_error = False

    def _docker(self, *args: str, timeout: int = 60) -> str:
        self.commands.append(args)
        if args[0] == "create":
            return "a" * 64
        if args[0] == "inspect":
            return json.dumps([self.details])
        return ""

    def _wait_ready(self) -> None:
        if self.ready_error:
            raise RuntimeError("readiness failed")


def test_disposable_database_ignores_operator_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://production/important")
    monkeypatch.setenv("SCOPELENS_DATABASE_URL", "postgresql://production/important")
    monkeypatch.setenv("PGHOSTADDR", "192.0.2.99")
    with FakePostgres() as database:
        assert database.url.endswith(
            "@127.0.0.1:15432/scopelens_test?hostaddr=127.0.0.1"
        )
        assert "production" not in database.url
        create = next(
            command for command in database.commands if command[0] == "create"
        )
        assert "127.0.0.1::5432" in create
        assert "type=volume,destination=/var/lib/postgresql" in create
        assert database.password not in " ".join(create)
        database.restart()
        assert ("restart", "--time", "5", "a" * 64) in database.commands
    assert database.commands[-1] == ("rm", "--force", "--volumes", "a" * 64)


@pytest.mark.parametrize("field", ["name", "label", "identity"])
@pytest.mark.parametrize("operation", ["restart", "close"])
def test_foreign_container_is_never_modified(field: str, operation: str) -> None:
    database = FakePostgres()
    database.container_id = "a" * 64
    if field == "name":
        database.details["Name"] = "/operator-database"
    elif field == "label":
        database.details["Config"]["Labels"][LABEL] = "foreign"
    else:
        database.details["Id"] = "b" * 64
    with pytest.raises(RuntimeError, match="unowned"):
        getattr(database, operation)()
    assert all(command[0] == "inspect" for command in database.commands)


def test_readiness_failure_removes_owned_container_and_volume() -> None:
    database = FakePostgres()
    database.ready_error = True
    with pytest.raises(RuntimeError, match="readiness failed"), database:
        pytest.fail("unready database was yielded")
    assert database.commands[-1] == ("rm", "--force", "--volumes", "a" * 64)


def test_exception_in_test_removes_owned_container_and_volume() -> None:
    database = FakePostgres()
    with pytest.raises(ValueError, match="test failed"), database:
        raise ValueError("test failed")
    assert database.commands[-1] == ("rm", "--force", "--volumes", "a" * 64)


def test_non_loopback_binding_rejected_and_cleaned() -> None:
    database = FakePostgres()
    database.details["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostIp"] = "0.0.0.0"
    with pytest.raises(RuntimeError, match="loopback"), database:
        pytest.fail("public database was yielded")
    assert database.commands[-1] == ("rm", "--force", "--volumes", "a" * 64)


def test_docker_errors_do_not_expose_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = DisposablePostgres()
    calls: list[list[str]] = []

    def fail(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        assert args[:3] == ["docker", "--host", "unix:///var/run/docker.sock"]
        assert kwargs["env"]["POSTGRES_PASSWORD"] == database.password
        return subprocess.CompletedProcess(
            args, 1, database.password, database.password
        )

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="Docker create failed") as error:
        database._docker("create", "--env", "POSTGRES_PASSWORD", "postgres:18-bookworm")
    assert database.password not in str(error.value)
    assert database.password not in " ".join(calls[0])


def test_docker_timeout_does_not_expose_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = DisposablePostgres()

    def timeout(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(args, 60, output=database.password)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(RuntimeError, match="could not complete") as error:
        database._docker("inspect", database.name)
    assert database.password not in str(error.value)


@pytest.mark.parametrize("foreign", [False, True])
def test_create_timeout_checks_identity_before_cleanup(foreign: bool) -> None:
    class TimedOutPostgres(FakePostgres):
        def _docker(self, *args: str, timeout: int = 60) -> str:
            if args[0] == "create":
                self.commands.append(args)
                raise RuntimeError("Docker create could not complete")
            return super()._docker(*args, timeout=timeout)

    database = TimedOutPostgres()
    if foreign:
        database.details["Config"]["Labels"][LABEL] = "foreign"
    with pytest.raises(RuntimeError, match="Docker create could not complete"):
        with database:
            pytest.fail("failed creation was yielded")
    removed = [command for command in database.commands if command[0] == "rm"]
    assert removed == ([] if foreign else [("rm", "--force", "--volumes", "a" * 64)])
