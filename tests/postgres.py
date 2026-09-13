"""A PostgreSQL instance owned exclusively by the integration test session."""

import json
import os
import re
import secrets
import subprocess
import time
import uuid
from types import TracebackType
from typing import Any, Self

import psycopg

LABEL = "scopelens.test-instance"


class DisposablePostgres:
    def __init__(self) -> None:
        self.token = uuid.uuid4().hex
        self.name = f"scopelens-postgres-test-{self.token}"
        self.password = secrets.token_hex(24)
        self.container_id: str | None = None
        self.url = ""
        self.port = 0

    def _docker(self, *args: str, timeout: int = 60) -> str:
        env = dict(os.environ, POSTGRES_PASSWORD=self.password)
        try:
            result = subprocess.run(
                ["docker", "--host", "unix:///var/run/docker.sock", *args],
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
                env=env,
            )
        except OSError, subprocess.TimeoutExpired:
            raise RuntimeError(f"Docker {args[0]} could not complete") from None
        if result.returncode:
            # Docker inspect and environment diagnostics can contain credentials.
            raise RuntimeError(f"Docker {args[0]} failed (exit {result.returncode})")
        return result.stdout.strip()

    def _owned_container(self) -> dict[str, Any]:
        details: Any = json.loads(self._docker("inspect", self.name))
        if not isinstance(details, list) or len(details) != 1:
            raise RuntimeError("Unexpected test container inspection")
        container: dict[str, Any] = details[0]
        identifier = container.get("Id", "")
        if (
            not isinstance(identifier, str)
            or re.fullmatch(r"[0-9a-f]{64}", identifier) is None
            or container.get("Name") != f"/{self.name}"
            or container.get("Config", {}).get("Labels", {}).get(LABEL) != self.token
            or (self.container_id is not None and identifier != self.container_id)
        ):
            raise RuntimeError("Refusing to operate on an unowned test container")
        return container

    def __enter__(self) -> Self:
        self._docker("pull", "postgres:18-bookworm", timeout=600)
        try:
            identifier = self._docker(
                "create",
                "--name",
                self.name,
                "--label",
                f"{LABEL}={self.token}",
                "--publish",
                "127.0.0.1::5432",
                "--env",
                "POSTGRES_PASSWORD",
                "--env",
                "POSTGRES_DB=scopelens_test",
                "--mount",
                "type=volume,destination=/var/lib/postgresql",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "--pids-limit",
                "128",
                "postgres:18-bookworm",
            )
            if re.fullmatch(r"[0-9a-f]{64}", identifier) is None:
                raise RuntimeError("Docker returned an invalid test container identity")
            self.container_id = identifier
            self._owned_container()
            self._docker("start", identifier)
            self._connect_address()
            self._wait_ready()
            return self
        except BaseException as error:
            try:
                # Creation can succeed even when the Docker client times out.
                self._remove_owned()
            except Exception:
                error.add_note(
                    f"Could not confirm cleanup of test container {self.name}"
                )
            raise

    def _remove_owned(self) -> None:
        container = self._owned_container()
        self._docker("rm", "--force", "--volumes", container["Id"])
        self.container_id = None

    def _connect_address(self) -> None:
        container = self._owned_container()
        bindings = container["NetworkSettings"]["Ports"]["5432/tcp"]
        if len(bindings) != 1 or bindings[0]["HostIp"] != "127.0.0.1":
            raise RuntimeError("Test PostgreSQL must publish only on loopback")
        self.port = int(bindings[0]["HostPort"])
        if not 1 <= self.port <= 65535:
            raise RuntimeError("Invalid test PostgreSQL port")
        self.url = (
            f"postgresql+psycopg://postgres:{self.password}"
            f"@127.0.0.1:{self.port}/scopelens_test?hostaddr=127.0.0.1"
        )

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                with psycopg.connect(
                    host="127.0.0.1",
                    hostaddr="127.0.0.1",
                    port=self.port,
                    dbname="scopelens_test",
                    user="postgres",
                    password=self.password,
                    connect_timeout=2,
                ) as connection:
                    connection.execute("SELECT 1")
                return
            except psycopg.OperationalError:
                time.sleep(0.25)
        raise RuntimeError(
            "Disposable PostgreSQL did not become ready within 60 seconds"
        )

    def restart(self) -> None:
        container = self._owned_container()
        self._docker("restart", "--time", "5", container["Id"])
        self._connect_address()
        self._wait_ready()

    def close(self) -> None:
        if self.container_id is not None:
            self._remove_owned()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
