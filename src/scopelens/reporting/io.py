import os
from pathlib import Path
from uuid import uuid4

MAX_REPORT_BYTES = 8 * 1024 * 1024


class ReportOutputError(ValueError):
    """A derived report could not be written safely."""


def write_new(path: Path, content: bytes) -> None:
    if not content or len(content) > MAX_REPORT_BYTES:
        raise ReportOutputError("report output must be between 1 byte and 8 MiB")
    destination = path.absolute()
    parent = destination.parent
    if not parent.is_dir():
        raise ReportOutputError("report output directory does not exist")
    if destination.exists() or destination.is_symlink():
        raise ReportOutputError("report output already exists; refusing overwrite")
    temporary = parent / f".{destination.name}.pending-{uuid4()}"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.link(temporary, destination, follow_symlinks=False)
    except FileExistsError:
        raise ReportOutputError(
            "report output already exists; refusing overwrite"
        ) from None
    except OSError as exc:
        raise ReportOutputError("report output could not be written") from exc
    finally:
        temporary.unlink(missing_ok=True)
