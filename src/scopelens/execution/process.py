import asyncio
import os
import signal
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO


class ExecutionError(RuntimeError):
    def __init__(self, message: str, artifacts: Path | None = None) -> None:
        super().__init__(message)
        self.artifacts = artifacts


@dataclass(frozen=True)
class RawArtifacts:
    directory: Path
    stdout: Path
    stderr: Path


def require_linux() -> None:
    if sys.platform != "linux":
        raise ExecutionError(
            "live execution requires Linux; use WSL2 or the Compose lab"
        )


def ensure_private_artifact_root(root: Path) -> Path:
    root = root.absolute()
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = root.lstat()
    except OSError:
        raise ExecutionError("cannot create the private artifact directory") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise ExecutionError(
            "artifact root must be an owned, private directory (mode 0700)"
        )
    return root


def _private_directory(root: Path, prefix: str = "nmap-") -> Path:
    root = ensure_private_artifact_root(root)
    try:
        return Path(tempfile.mkdtemp(prefix=prefix, dir=root))
    except OSError:
        raise ExecutionError("cannot allocate a private run directory") from None


def _private_file(path: Path) -> IO[bytes]:
    try:
        return os.fdopen(
            os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600),
            "wb",
            buffering=0,
        )
    except OSError:
        raise ExecutionError(
            "cannot create a private artifact file", path.parent
        ) from None


def write_private_artifact(
    root: Path, *, prefix: str, filename: str, content: bytes, limit: int
) -> Path:
    require_linux()
    if (
        not filename
        or Path(filename).name != filename
        or not 0 <= len(content) <= limit <= 8 * 1024 * 1024
    ):
        raise ExecutionError("invalid private artifact")
    directory = _private_directory(root.absolute(), prefix)
    path = directory / filename
    with _private_file(path) as destination:
        if destination.write(content) != len(content):
            raise ExecutionError("incomplete artifact write", directory)
    return path


async def _stop(process: asyncio.subprocess.Process) -> None:
    # Kill the session's process group even if the leader has already exited.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    else:
        await asyncio.sleep(0.2)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    await process.wait()


async def run_process(
    argv: tuple[str, ...],
    artifact_root: Path,
    *,
    timeout: float,
    output_limit: int,
    scanner: str = "nmap",
) -> RawArtifacts:
    require_linux()
    if not argv or not Path(argv[0]).is_absolute():
        raise ExecutionError("scanner executable must use an absolute path")
    if not 0 < timeout <= 120 or not 0 < output_limit <= 8 * 1024 * 1024:
        raise ExecutionError("invalid process limits")
    if scanner not in ("nmap", "httpx", "nuclei"):
        raise ExecutionError("unsupported scanner process")
    directory = (
        _private_directory(artifact_root.absolute())
        if scanner == "nmap"
        else _private_directory(artifact_root.absolute(), f"{scanner}-")
    )
    artifacts = RawArtifacts(
        directory,
        directory / ("stdout.xml" if scanner == "nmap" else "stdout.jsonl"),
        directory / "stderr.txt",
    )
    used = 0
    stderr_used = 0

    async def drain(
        stream: asyncio.StreamReader, destination: IO[bytes], *, stderr: bool
    ) -> None:
        nonlocal used, stderr_used
        while chunk := await stream.read(16 * 1024):
            available = output_limit - used
            if stderr:
                available = min(available, 64 * 1024 - stderr_used)
            saved = chunk[:available]
            if destination.write(saved) != len(saved):
                raise OSError("incomplete artifact write")
            used += len(saved)
            if stderr:
                stderr_used += len(saved)
            if len(saved) != len(chunk):
                raise ExecutionError(
                    "scanner output exceeded its artifact limit", directory
                )

    with (
        _private_file(artifacts.stdout) as stdout,
        _private_file(artifacts.stderr) as stderr,
    ):
        spawn = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
                cwd=directory,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "HOME": str(directory),
                    **(
                        {
                            f"DISABLE_NUCLEI_TEMPLATES_{source}_DOWNLOAD": "true"
                            for source in ("PUBLIC", "GITHUB", "GITLAB", "AWS", "AZURE")
                        }
                        if scanner == "nuclei"
                        else {}
                    ),
                },
                limit=16 * 1024,
            )
        )
        readers: list[asyncio.Task[None]] = []
        try:
            async with asyncio.timeout(timeout):
                process = await asyncio.shield(spawn)
                assert process.stdout is not None and process.stderr is not None
                readers = [
                    asyncio.create_task(drain(process.stdout, stdout, stderr=False)),
                    asyncio.create_task(drain(process.stderr, stderr, stderr=True)),
                ]
                await asyncio.gather(*readers, process.wait())
                if process.returncode != 0:
                    raise ExecutionError("scanner exited unsuccessfully", directory)
        except TimeoutError:
            raise ExecutionError(
                "scanner timed out; partial artifacts retained", directory
            ) from None
        except OSError:
            raise ExecutionError(
                "scanner could not start or write artifacts", directory
            ) from None
        finally:

            async def cleanup() -> None:
                try:
                    process = await spawn
                except OSError:
                    return
                for reader in readers:
                    reader.cancel()
                await asyncio.gather(*readers, return_exceptions=True)

                async def discard(stream: asyncio.StreamReader) -> None:
                    while await stream.read(16 * 1024):
                        pass

                assert process.stdout is not None and process.stderr is not None
                drains = [
                    asyncio.create_task(discard(stream))
                    for stream in (process.stdout, process.stderr)
                ]
                try:
                    async with asyncio.timeout(3):
                        await _stop(process)
                        await asyncio.gather(*drains)
                except TimeoutError:
                    raise ExecutionError(
                        "scanner cleanup did not complete", directory
                    ) from None
                finally:
                    for drain_task in drains:
                        drain_task.cancel()
                    await asyncio.gather(*drains, return_exceptions=True)

            cleanup_task = asyncio.create_task(cleanup())
            cancelled = False
            while not cleanup_task.done():
                try:
                    await asyncio.shield(cleanup_task)
                except asyncio.CancelledError:
                    cancelled = True
            cleanup_task.result()
            if cancelled:
                raise asyncio.CancelledError
    return artifacts
