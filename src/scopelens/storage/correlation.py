from collections.abc import Sequence
from hashlib import sha256
from uuid import UUID

from pydantic import TypeAdapter
from sqlalchemy import Engine, select, text

from scopelens.adapters.base import ImportContext
from scopelens.analysis.correlation import CorrelationError, correlate
from scopelens.analysis.models import CorrelationResult, RunSource, StoredArtifact
from scopelens.assessment.capture import assess_correlation
from scopelens.comparison.compare import ArtifactHealth, compare_assessments
from scopelens.comparison.models import HistoricalComparisonReport
from scopelens.domain.scope import ScanProfile
from scopelens.domain.targets import Identifier
from scopelens.storage import schema as s
from scopelens.storage.artifacts import ArtifactError, ArtifactStore
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
                    finished_at=run["finished_at"],
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


def compare_history(
    engine: Engine,
    artifacts: ArtifactStore,
    project_id: str,
    baseline_run_ids: Sequence[UUID],
    current_run_ids: Sequence[UUID],
) -> HistoricalComparisonReport:
    if not baseline_run_ids or not current_run_ids:
        raise CorrelationError("select baseline and current runs explicitly")
    if len(set(baseline_run_ids)) != len(baseline_run_ids) or len(
        set(current_run_ids)
    ) != len(current_run_ids):
        raise CorrelationError("select each run once per comparison side")
    selected = tuple(sorted(set(baseline_run_ids) | set(current_run_ids)))
    combined = correlate_history(engine, project_id, selected)
    verified_sources = []
    verified_health: dict[tuple[UUID, str], ArtifactHealth] = {}
    for source in combined.sources:
        verified_artifacts = []
        for artifact in source.artifacts:
            health: ArtifactHealth = "ready"
            try:
                raw = artifacts.read(artifact.relative_path)
                if (
                    len(raw) != artifact.size_bytes
                    or sha256(raw).hexdigest() != artifact.sha256
                ):
                    health = "corrupt"
            except FileNotFoundError:
                health = "missing"
            except OSError, ArtifactError:
                health = "corrupt"
            if artifact.role == "stdout":
                verified_health[(source.run_id, artifact.sha256)] = health
            verified_artifacts.append(
                artifact.model_copy(update={"recorded_health": health})
            )
        verified_sources.append(
            source.model_copy(update={"artifacts": tuple(verified_artifacts)})
        )
    combined = combined.model_copy(update={"sources": tuple(verified_sources)})
    baseline_ids = set(baseline_run_ids)
    current_ids = set(current_run_ids)
    baseline = correlate(
        project_id,
        (source for source in combined.sources if source.run_id in baseline_ids),
    )
    current = correlate(
        project_id,
        (source for source in combined.sources if source.run_id in current_ids),
    )
    return compare_assessments(
        assess_correlation(baseline),
        assess_correlation(current),
        baseline_correlation=baseline,
        current_correlation=current,
        baseline_capture_health=verified_health,
        current_capture_health=verified_health,
    )
