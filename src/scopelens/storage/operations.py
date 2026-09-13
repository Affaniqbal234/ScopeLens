import asyncio
import os
import stat
import warnings
from pathlib import Path
from uuid import UUID

from sqlalchemy import Connection, select

from scopelens.adapters.base import ParsedReport, ReportParseError
from scopelens.config import ProjectConfig
from scopelens.domain.scope import ScopeViolation
from scopelens.execution.nmap import build_command, scan_nmap
from scopelens.execution.process import ExecutionError
from scopelens.storage import schema as s
from scopelens.storage.artifacts import MAX_ARTIFACT_BYTES, ArtifactError
from scopelens.storage.database import HistoryError, locked_run
from scopelens.storage.history import History


def read_input(path: Path, limit: int = MAX_ARTIFACT_BYTES) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ArtifactError("artifact input must be a regular file")
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ArtifactError("artifact input exceeds its limit")
    return raw


def import_history(
    history: History, config: ProjectConfig, profile: str, run_id: UUID, path: Path
) -> ParsedReport:
    raw = read_input(path)
    with locked_run(history.engine, run_id) as connection:
        history.begin(connection, run_id, config, profile, kind="import")
        try:
            return history.ingest(connection, run_id, raw)
        except ReportParseError, ScopeViolation:
            _failure(history, connection, run_id, "failed", "invalid_report")
            raise


def _failure(
    history: History, connection: Connection, run_id: UUID, status: str, code: str
) -> None:
    with connection.begin():
        history._finish(connection, run_id, status, code)


def scan_history(
    history: History, config: ProjectConfig, profile: str, run_id: UUID
) -> ParsedReport:
    build_command(config, profile)
    with locked_run(history.engine, run_id) as connection:
        # A scan attempt is never restarted by reusing its ID.
        exists = connection.scalar(select(s.runs.c.id).where(s.runs.c.id == run_id))
        connection.commit()
        if exists is not None:
            raise HistoryError(
                "scan identifier already exists; use history-show or a new ID"
            )
        history.begin(connection, run_id, config, profile, kind="scan")
        directory = history.artifacts.directory(run_id)
        try:
            result = asyncio.run(scan_nmap(config, profile, directory))
        except KeyboardInterrupt:
            _failure(history, connection, run_id, "interrupted", "cancelled")
            raise
        except ExecutionError:
            _failure(history, connection, run_id, "failed", "execution_failed")
            raise
        report = history.ingest(
            connection,
            run_id,
            read_input(result.artifacts.stdout),
            read_input(result.artifacts.stderr, 65536),
        )
        # Published copies are durable before removing this run's capture files.
        try:
            result.artifacts.stdout.unlink()
            result.artifacts.stderr.unlink()
            result.artifacts.directory.rmdir()
        except OSError:
            warnings.warn(
                "report committed; capture cleanup incomplete, run reconciliation",
                stacklevel=2,
            )
        return report
