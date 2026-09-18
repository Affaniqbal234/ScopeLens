from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.engine import make_url


class HistoryError(ValueError):
    """A history operation conflicts with stored state or provenance."""


def database(url: str) -> Engine:
    parsed = make_url(url)
    if parsed.drivername not in ("postgresql", "postgresql+psycopg"):
        raise HistoryError("history requires PostgreSQL with Psycopg")
    return create_engine(
        parsed.set(drivername="postgresql+psycopg"),
        hide_parameters=True,
        connect_args={
            "connect_timeout": 5,
            "options": "-c statement_timeout=30000 -c lock_timeout=5000",
        },
    )


def migrate(engine: Engine, revision: str = "head") -> None:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    with engine.begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(1935896430)"))
        config.attributes["connection"] = connection
        command.upgrade(config, revision)


@contextmanager
def locked_run(engine: Engine, run_id: UUID) -> Iterator[Connection]:
    key = int.from_bytes(run_id.bytes[:8], "big", signed=True)
    with engine.connect() as connection:
        try:
            acquired = connection.scalar(
                text("SELECT pg_try_advisory_lock(:key)"), {"key": key}
            )
            connection.commit()
        except BaseException:
            connection.invalidate()
            raise
        if not acquired:
            raise HistoryError("run is busy; retry after its owner finishes")
        try:
            yield connection
        finally:
            if not connection.invalidated:
                try:
                    connection.rollback()
                    connection.execute(
                        text("SELECT pg_advisory_unlock(:key)"), {"key": key}
                    )
                    connection.commit()
                except BaseException:
                    connection.invalidate()
                    raise


@contextmanager
def single_assessment_worker(engine: Engine) -> Iterator[Connection]:
    with engine.connect() as connection:
        acquired = connection.scalar(text("SELECT pg_try_advisory_lock(1935896431)"))
        connection.commit()
        if not acquired:
            raise HistoryError("assessment worker is already running")
        try:
            yield connection
        finally:
            if not connection.invalidated:
                connection.rollback()
                connection.execute(text("SELECT pg_advisory_unlock(1935896431)"))
                connection.commit()
