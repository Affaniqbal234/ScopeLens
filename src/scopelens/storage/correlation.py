from collections.abc import Sequence
from uuid import UUID

from pydantic import TypeAdapter
from sqlalchemy import Engine, select, text

from scopelens.adapters.base import ImportContext
from scopelens.analysis.correlation import CorrelationError, correlate
from scopelens.analysis.models import CorrelationResult, RunSource, StoredArtifact
from scopelens.domain.scope import ScanProfile
from scopelens.domain.targets import Identifier
from scopelens.storage import schema as s
from scopelens.storage.reports import read_report


def correlate_history(
    engine: Engine, project_id: str, run_ids: Sequence[UUID]
) -> CorrelationResult:
    project_id = TypeAdapter(Identifier).validate_python(project_id)
    if not run_ids:
        raise CorrelationError("select at least one completed run")
    if len(set(run_ids)) != len(run_ids):
        raise CorrelationError("select each run only once")

    sources = []
    with engine.connect() as connection, connection.begin():
        connection.execute(
            text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        )
        runs = (
            connection.execute(
                select(s.runs)
                .where(s.runs.c.project_id == project_id, s.runs.c.id.in_(run_ids))
                .order_by(s.runs.c.id)
            )
            .mappings()
            .all()
        )
        if len(runs) != len(run_ids):
            raise CorrelationError(
                "selected run is missing or belongs to another project"
            )
        for run in runs:
            stage = (
                connection.execute(
                    select(s.stages).where(s.stages.c.run_id == run["id"])
                )
                .mappings()
                .one()
            )
            if run["status"] != "succeeded" or stage["status"] != "succeeded":
                raise CorrelationError(
                    "every selected run must have a completed report"
                )
            profile = ScanProfile.model_validate(run["profile"])
            sources.append(
                RunSource(
                    run_id=run["id"],
                    project_id=project_id,
                    kind=run["kind"],
                    created_at=run["created_at"],
                    scope_snapshot_id=run["scope_snapshot_id"],
                    profile=profile,
                    context=ImportContext(
                        profile_id=profile.id,
                        profile_revision=run["profile_revision"],
                        **stage["input_context"],
                    ),
                    report=read_report(connection, stage["id"]),
                    artifacts=tuple(
                        StoredArtifact(
                            role=row.role,
                            relative_path=row.relative_path,
                            sha256=row.sha256,
                            size_bytes=row.size_bytes,
                            recorded_health=row.health,
                        )
                        for row in connection.execute(
                            select(s.artifacts)
                            .where(s.artifacts.c.stage_id == stage["id"])
                            .order_by(s.artifacts.c.role)
                        )
                    ),
                )
            )
    return correlate(project_id, sources)
