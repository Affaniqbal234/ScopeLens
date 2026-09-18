import os
import stat
import sys
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

MAX_ARTIFACT_BYTES = 8 * 1024 * 1024


class ArtifactError(ValueError):
    """Private artifact bytes could not be safely stored or verified."""


class ArtifactStore:
    def __init__(self, root: Path, *, create: bool = True) -> None:
        if sys.platform != "linux":
            raise ArtifactError(
                "persistent artifacts require a Linux private filesystem"
            )
        self.root = root.absolute()
        if create:
            self._directory(self.root)

    @staticmethod
    def _directory(path: Path) -> None:
        if path.resolve() != path:
            raise ArtifactError("linked artifact directory")
        missing = []
        ancestor = path
        while not ancestor.exists():
            missing.append(ancestor)
            ancestor = ancestor.parent
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        for created in reversed(missing):
            descriptor = os.open(
                created.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or path.resolve() != path
        ):
            raise ArtifactError(
                "artifact directories must be owned, private and not linked"
            )

    def directory(self, run_id: UUID) -> Path:
        self._directory(self.root)
        directory = self.root / str(run_id)
        self._directory(directory)
        return directory

    def path(self, relative: str) -> Path:
        parts = relative.split("/")
        try:
            valid = (
                len(parts) == 2
                and str(UUID(parts[0])) == parts[0]
                and parts[1]
                in ("stdout.xml", "stdout.jsonl", "stderr.txt", "response.http")
            )
        except ValueError:
            valid = False
        if not valid:
            raise ArtifactError("invalid artifact reference")
        return self.root / parts[0] / parts[1]

    def read(self, relative: str) -> bytes:
        path = self.path(relative)
        if self.root.resolve() != self.root:
            raise ArtifactError("linked artifact directory")
        with ExitStack() as directories:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            parent = os.open(self.root.anchor, flags)
            directories.callback(os.close, parent)
            # Resolve each directory through its open parent, never through a replaced link.
            components = (*self.root.parts[1:], path.parent.name)
            for index, component in enumerate(components):
                parent = os.open(component, flags, dir_fd=parent)
                directories.callback(os.close, parent)
                if index >= len(components) - 2:
                    info = os.fstat(parent)
                    if (
                        info.st_uid != os.geteuid()
                        or info.st_mode & 0o077
                        or (
                            index == len(components) - 2
                            and stat.S_IMODE(info.st_mode) != 0o700
                        )
                    ):
                        raise ArtifactError("unsafe artifact directory")
            descriptor = os.open(
                path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
            )
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_size > MAX_ARTIFACT_BYTES
            ):
                raise ArtifactError("unsafe artifact file")
            raw = source.read(MAX_ARTIFACT_BYTES + 1)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise ArtifactError("artifact exceeds size limit")
        return raw

    def publish(self, run_id: UUID, filename: str, raw: bytes) -> tuple[str, str, int]:
        relative = f"{run_id}/{filename}"
        destination = self.path(relative)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise ArtifactError("artifact exceeds size limit")
        directory = self.directory(run_id)
        if destination.exists() or destination.is_symlink():
            if self.read(relative) != raw:
                raise ArtifactError("existing artifact differs; refusing overwrite")
        else:
            temporary = directory / f".pending-{uuid4()}"
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as target:
                    target.write(raw)
                    target.flush()
                    os.fsync(target.fileno())
                # Atomic no-overwrite publication on the same filesystem.
                os.link(temporary, destination, follow_symlinks=False)
            finally:
                temporary.unlink(missing_ok=True)
        for path in (directory, self.root):
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return relative, sha256(raw).hexdigest(), len(raw)
