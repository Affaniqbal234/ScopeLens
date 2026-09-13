import asyncio
import stat
import sys
from pathlib import Path

import pytest

from scopelens.execution.process import ExecutionError, run_process

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="requires real Linux process groups and permissions"
)


def test_real_process_and_private_artifacts(tmp_path: Path) -> None:
    root = tmp_path / "private"
    result = asyncio.run(
        run_process(
            (
                sys.executable,
                "-c",
                "import sys; print(sys.argv[1]); print('diagnostic', file=sys.stderr)",
                "; touch forbidden",
            ),
            root,
            timeout=3,
            output_limit=1024,
        )
    )
    assert result.stdout.read_text().strip() == "; touch forbidden"
    assert result.stderr.read_text().strip() == "diagnostic"
    assert not (result.directory / "forbidden").exists()
    for path in (root, result.directory):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    for path in (result.stdout, result.stderr):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("scanner", ["nmap", "httpx"])
@pytest.mark.parametrize("mode", ["timeout", "overflow", "cancel", "descendant"])
def test_real_cleanup_is_bounded_under_pipe_pressure(
    tmp_path: Path, mode: str, scanner: str
) -> None:
    filename = "stdout.xml" if scanner == "nmap" else "stdout.jsonl"

    async def scenario() -> None:
        code = """
import os, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
print(os.getpid(), flush=True)
if sys.argv[1] == 'descendant':
    child = os.fork()
    if child:
        print(child, flush=True)
        sys.exit(0)
if sys.argv[1] in ('overflow', 'cancel'):
    while True:
        os.write(1, b'x' * 65536)
        time.sleep(0.001)
else:
    time.sleep(60)
"""
        task = asyncio.create_task(
            run_process(
                (sys.executable, "-c", code, mode),
                tmp_path / "private",
                scanner=scanner,
                timeout=2 if mode == "cancel" else 0.3,
                output_limit=1024 if mode == "overflow" else 8 * 1024 * 1024,
            )
        )
        if mode == "cancel":
            # Wait for launch, then cancel with output still arriving.
            for _ in range(100):
                paths = list((tmp_path / "private").glob(f"*/{filename}"))
                if paths and paths[0].stat().st_size:
                    break
                await asyncio.sleep(0.001)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 5)
        else:
            with pytest.raises(ExecutionError):
                await asyncio.wait_for(task, 5)
        raw = next((tmp_path / "private").glob(f"*/{filename}")).read_bytes()
        files = list((tmp_path / "private").glob("*/*"))
        assert sum(path.stat().st_size for path in files) <= (
            1024 if mode == "overflow" else 8 * 1024 * 1024
        )
        assert (
            next(path for path in files if path.name == "stderr.txt").stat().st_size
            <= 65536
        )
        pids = [int(line) for line in raw.splitlines()[:2] if line.isdigit()]
        assert pids
        for pid in pids:
            status = Path(f"/proc/{pid}/stat")
            # An orphan can remain a zombie until the system reaps it, but cannot run.
            assert not status.exists() or status.read_text().split()[2] == "Z"

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["public-root", "symlink"])
def test_refuses_unsafe_artifact_root(tmp_path: Path, mode: str) -> None:
    root = tmp_path / "artifacts"
    if mode == "public-root":
        root.mkdir(mode=0o755)
        root.chmod(0o755)
    else:
        destination = tmp_path / "destination"
        destination.mkdir(mode=0o700)
        root.symlink_to(destination, target_is_directory=True)
    with pytest.raises(ExecutionError, match="private"):
        asyncio.run(
            run_process((sys.executable, "-V"), root, timeout=1, output_limit=1024)
        )


def test_real_missing_executable(tmp_path: Path) -> None:
    with pytest.raises(ExecutionError, match="could not start"):
        asyncio.run(
            run_process(
                (str(tmp_path / "missing"),),
                tmp_path / "private",
                timeout=1,
                output_limit=1024,
            )
        )


def test_real_nonzero_exit_keeps_diagnostics(tmp_path: Path) -> None:
    with pytest.raises(ExecutionError, match="unsuccessfully") as exc:
        asyncio.run(
            run_process(
                (
                    sys.executable,
                    "-c",
                    "import sys; print('failure', file=sys.stderr); sys.exit(2)",
                ),
                tmp_path / "private",
                timeout=2,
                output_limit=1024,
            )
        )
    assert exc.value.artifacts is not None
    assert (exc.value.artifacts / "stderr.txt").read_text().strip() == "failure"
