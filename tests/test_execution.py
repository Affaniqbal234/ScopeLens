import asyncio
import sys
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from scopelens.config import ProjectConfig, load_config
from scopelens.domain.scope import ScanProfile, ScopeViolation
from scopelens.execution import nmap, process
from scopelens.execution.process import ExecutionError, RawArtifacts


@pytest.fixture
def config(config_path: Path) -> ProjectConfig:
    return load_config(config_path)


def test_command_contains_only_authorized_targets_and_controls(
    config: ProjectConfig,
) -> None:
    argv = nmap.build_command(config, "conservative")
    assert argv[0] == "/usr/bin/nmap"
    assert argv[-1] == "127.0.0.1"
    assert argv[argv.index("-p") + 1] == "8000"
    assert argv[argv.index("-oX") + 1] == "-"
    for flag in ("-sT", "-Pn", "-n", "--unprivileged", "--disable-arp-ping"):
        assert flag in argv
    assert not {"-sV", "-sC", "--script", "-O", "-A", "-iL", "-sS"}.intersection(argv)
    assert argv[argv.index("--max-rate") + 1] == "5"
    assert argv[argv.index("--max-retries") + 1] == "1"


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1;echo injected",
        "--script=all",
        "localhost",
        "127.0.0.0/8",
        "127.0.0.1\n192.0.2.1",
    ],
)
def test_injection_and_target_expansion_are_rejected(
    config: ProjectConfig, address: str
) -> None:
    data = config.model_dump()
    data["project"]["scope"]["network_targets"][0]["address"] = address
    with pytest.raises(ValidationError):
        ProjectConfig.model_validate(data)


def test_web_authorization_does_not_enable_nmap(config: ProjectConfig) -> None:
    data = config.model_dump()
    data["project"]["scope"]["network_targets"] = []
    data["profiles"][0]["tcp_ports"] = []
    with pytest.raises(ScopeViolation):
        nmap.build_command(ProjectConfig.model_validate(data), "conservative")


def test_revalidation_rejects_bypassed_profile_port_scope(
    config: ProjectConfig,
) -> None:
    profile = config.profiles[0].model_copy(update={"tcp_ports": (22,)})
    bypassed = config.model_copy(update={"profiles": (profile,)})
    with pytest.raises(ValidationError):
        nmap.build_command(bypassed, "conservative")


@pytest.mark.parametrize(
    "field,value",
    [
        ("scan_timeout_seconds", 0),
        ("scan_timeout_seconds", 121),
        ("scan_timeout_seconds", "30"),
        ("probes_per_second", 6),
        ("probes_per_second", True),
        ("max_artifact_bytes", 1023),
        ("max_artifact_bytes", 8388609),
    ],
)
def test_execution_profile_bounds(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        ScanProfile.model_validate({"id": "lab", field: value})


REPORT = b"""<nmaprun scanner="nmap" version="7.95">
<host><status state="up" reason="user-set"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8000"><state state="open"/></port></ports></host>
<runstats><finished time="1700000010" exit="success"/></runstats></nmaprun>"""


@pytest.mark.parametrize(
    "change",
    [
        "valid",
        "wrong-address",
        "mixed-addresses",
        "wrong-port",
        "extra-port",
        "udp",
        "truncated",
        "error",
        "empty",
        "missing-port",
        "timed-out",
    ],
)
def test_scan_checks_output_before_returning(
    config: ProjectConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    raw = REPORT
    replacements = {
        "wrong-address": (b"127.0.0.1", b"192.0.2.1"),
        "mixed-addresses": (
            b"</host>",
            b'</host><host><status state="up"/><address addr="192.0.2.1"/></host>',
        ),
        "wrong-port": (b"8000", b"22"),
        "extra-port": (
            b"</ports>",
            b'<port protocol="tcp" portid="22"><state state="open"/></port></ports>',
        ),
        "udp": (b'protocol="tcp"', b'protocol="udp"'),
        "truncated": (b"</nmaprun>", b""),
        "error": (b'exit="success"', b'exit="error"'),
        "missing-port": (b"<ports>", b"<ignored>"),
        "timed-out": (b"<host>", b'<host timedout="true">'),
    }
    if change in replacements:
        raw = raw.replace(*replacements[change])
    if change == "missing-port":
        raw = raw.replace(b"</ports>", b"</ignored>")
    if change == "empty":
        raw = (Path(__file__).parent / "fixtures/nmap/empty.xml").read_bytes()
    stdout = tmp_path / "stdout.xml"
    stdout.write_bytes(raw)
    stderr = tmp_path / "stderr.txt"
    stderr.write_bytes(b"")
    runner = AsyncMock(return_value=RawArtifacts(tmp_path, stdout, stderr))
    monkeypatch.setattr(nmap, "run_process", runner)
    if change == "valid":
        result = asyncio.run(nmap.scan_nmap(config, "conservative", tmp_path))
        assert result.report.observations
        assert len(result.report.evidence.profile_revision) == 64
    else:
        with pytest.raises(ExecutionError):
            asyncio.run(nmap.scan_nmap(config, "conservative", tmp_path))
    assert runner.call_args.args[0] == nmap.build_command(config, "conservative")


def test_invalid_profile_never_starts_process(
    config: ProjectConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = AsyncMock()
    monkeypatch.setattr(nmap, "run_process", runner)
    with pytest.raises(ExecutionError, match="unknown"):
        asyncio.run(nmap.scan_nmap(config, "--script=all", tmp_path))
    runner.assert_not_called()


class FakeProcess:
    def __init__(
        self, stdout: bytes = b"", stderr: bytes = b"", code: int | None = 0
    ) -> None:
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_data(stdout)
        self.stderr.feed_data(stderr)
        self.returncode = code
        self.exited = asyncio.Event()
        if code is not None:
            self.stdout.feed_eof()
            self.stderr.feed_eof()
            self.exited.set()

    async def wait(self) -> int:
        await self.exited.wait()
        assert self.returncode is not None
        return self.returncode


@pytest.fixture
def portable_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    # Test execution control flow on Windows; POSIX behavior has separate tests.
    monkeypatch.setattr(process, "require_linux", lambda: None)

    def directory(root: Path) -> Path:
        root.mkdir()
        return root

    monkeypatch.setattr(process, "_private_directory", directory)
    monkeypatch.setattr(process, "_private_file", lambda path: path.open("xb"))


@pytest.mark.usefixtures("portable_runner")
@pytest.mark.parametrize(
    "mode",
    [
        "success",
        "exit",
        "missing",
        "stdout-limit",
        "stderr-limit",
        "combined-limit",
        "timeout",
        "cancel",
        "cancel-spawn",
        "repeat-cancel",
    ],
)
def test_process_failure_and_cleanup_paths(
    mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        live = mode in ("timeout", "cancel", "cancel-spawn", "repeat-cancel")
        child = FakeProcess(
            b"x"
            * (
                1100
                if mode == "stdout-limit"
                else 600
                if mode == "combined-limit"
                else 2
            ),
            b"x"
            * (
                70000
                if mode == "stderr-limit"
                else 600
                if mode == "combined-limit"
                else 2
            ),
            None if live else 2 if mode == "exit" else 0,
        )

        async def spawn(*args: object, **kwargs: object) -> asyncio.subprocess.Process:
            assert kwargs["start_new_session"] is True
            assert kwargs["stdin"] == asyncio.subprocess.DEVNULL
            assert kwargs["env"] == {
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "HOME": str(tmp_path / "artifacts"),
            }
            if mode == "missing":
                raise FileNotFoundError
            if mode == "cancel-spawn":
                await asyncio.sleep(0.04)
            return cast(asyncio.subprocess.Process, child)

        stopped = asyncio.Event()

        async def stop(proc: asyncio.subprocess.Process) -> None:
            assert proc is cast(asyncio.subprocess.Process, child)
            if mode == "repeat-cancel":
                await asyncio.sleep(0.05)
            child.returncode = -9
            child.exited.set()
            if live:
                child.stdout.feed_eof()
                child.stderr.feed_eof()
            stopped.set()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        monkeypatch.setattr(process, "_stop", stop)
        task = asyncio.create_task(
            process.run_process(
                (sys.executable, "-V"),
                tmp_path / "artifacts",
                timeout=0.02 if mode == "timeout" else 1,
                output_limit=100000 if mode == "stderr-limit" else 1024,
            )
        )
        if mode in ("cancel", "cancel-spawn", "repeat-cancel"):
            await asyncio.sleep(0.01)
            task.cancel()
            if mode == "repeat-cancel":
                await asyncio.sleep(0.01)
                task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        elif mode == "success":
            result = await task
            assert result.stdout.read_bytes() == b"xx"
        else:
            with pytest.raises(ExecutionError):
                await task
        assert stopped.is_set() == (mode != "missing")
        total = sum(path.stat().st_size for path in (tmp_path / "artifacts").iterdir())
        assert total <= (100000 if mode == "stderr-limit" else 1024)
        assert (tmp_path / "artifacts/stderr.txt").stat().st_size <= 65536

    asyncio.run(scenario())


def test_windows_execution_fails_without_creating_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(ExecutionError, match="requires Linux"):
        asyncio.run(
            process.run_process(
                (sys.executable,), tmp_path / "absent", timeout=1, output_limit=1024
            )
        )
    assert not (tmp_path / "absent").exists()


@pytest.mark.usefixtures("portable_runner")
def test_artifact_write_failure_still_stops_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typing import IO

    class FailingFile:
        def write(self, data: bytes) -> int:
            raise OSError("disk full")

        def __enter__(self) -> IO[bytes]:
            return cast(IO[bytes], self)

        def __exit__(self, *args: object) -> None:
            pass

    async def scenario() -> None:
        child = FakeProcess(b"data")
        starter = AsyncMock(return_value=child)
        stopper = AsyncMock()
        monkeypatch.setattr(asyncio, "create_subprocess_exec", starter)
        monkeypatch.setattr(process, "_stop", stopper)
        monkeypatch.setattr(process, "_private_file", lambda path: FailingFile())
        with pytest.raises(ExecutionError, match="write artifacts"):
            await process.run_process(
                (sys.executable,), tmp_path / "private", timeout=1, output_limit=1024
            )
        stopper.assert_awaited_once()

    asyncio.run(scenario())
