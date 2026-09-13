"""Run packaged migrations using a supplied SQLAlchemy connection."""

import os

import sqlalchemy as sa
from alembic import context

from scopelens.storage.schema import metadata

config = context.config


def migrate(connection: sa.Connection) -> None:
    if connection.dialect.name != "postgresql":
        raise ValueError("ScopeLens storage requires PostgreSQL")
    context.configure(connection=connection, target_metadata=metadata)
    with context.begin_transaction():
        context.run_migrations()


connection = config.attributes.get("connection")
if connection is not None:
    migrate(connection)
else:
    database_url = os.environ.get("SCOPELENS_DATABASE_URL")
    if not database_url:
        raise ValueError("SCOPELENS_DATABASE_URL is required")
    engine = sa.create_engine(
        database_url, hide_parameters=True, poolclass=sa.pool.NullPool
    )
    try:
        with engine.connect() as owned_connection:
            migrate(owned_connection)
    finally:
        engine.dispose()
