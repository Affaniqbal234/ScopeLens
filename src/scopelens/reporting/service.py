from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select

from scopelens.analysis.models import CorrelationResult
from scopelens.assessment.models import CaptureAssessmentReport, RecheckReport
from scopelens.comparison.compare import (
    ArtifactHealth,
    CaptureHealth,
    compare_assessments,
)
from scopelens.orchestration.store import OrchestrationStore
from scopelens.storage import schema as s
from scopelens.storage.correlation import load_capture_assessment
from scopelens.storage.database import HistoryError

from .models import (
    AssessmentReport,
    ComparisonReport,
    ReportSelection,
    StoredRunSelection,
)
from .projection import build_assessment_report, build_comparison_report


@dataclass(frozen=True)
class _LoadedSide:
    report: CaptureAssessmentReport | RecheckReport
    correlation: CorrelationResult | None
    acquisition_health: dict[UUID, ArtifactHealth] | None
    capture_health: CaptureHealth | None


def load_assessment_report(
    store: OrchestrationStore, assessment_id: UUID
) -> AssessmentReport:
    manifest = store.get(assessment_id)
    config = store.config(assessment_id)
    run_ids = tuple(
        stage.result_run_id
        for stage in manifest.stages
        if stage.result_run_id is not None
    )
    capture = None
    correlation = None
    if run_ids:
        capture, correlation, _ = load_capture_assessment(
            store.engine, store.artifacts, manifest.project_id, run_ids
        )
    rechecks: dict[UUID, tuple[RecheckReport, dict[UUID, ArtifactHealth]]] = {}
    for stage in manifest.stages:
        if stage.request.kind != "web_recheck" or stage.status in (
            "pending",
            "running",
            "skipped",
        ):
            continue
        try:
            rechecks[stage.id] = store.load_recheck(stage.id)
        except HistoryError as exc:
            if str(exc) != "recheck result does not exist":
                raise
    return build_assessment_report(
        config,
        manifest,
        capture=capture,
        correlation=correlation,
        rechecks=rechecks,
    )


def _load_side(
    store: OrchestrationStore, project_id: str, selection: ReportSelection
) -> _LoadedSide:
    if isinstance(selection, StoredRunSelection):
        capture_report, correlation, capture_health = load_capture_assessment(
            store.engine, store.artifacts, project_id, selection.run_ids
        )
        return _LoadedSide(capture_report, correlation, None, capture_health)
    manifest = store.get(selection.assessment_id)
    if manifest.project_id != project_id:
        raise HistoryError("selected recheck belongs to another project")
    stage = next(
        (item for item in manifest.stages if item.id == selection.stage_id), None
    )
    if stage is None or stage.request.kind != "web_recheck":
        raise HistoryError("recheck stage does not exist")
    recheck_report, acquisition_health = store.load_recheck(stage.id)
    return _LoadedSide(recheck_report, None, acquisition_health, None)


def load_comparison_report(
    store: OrchestrationStore,
    project_id: str,
    baseline: ReportSelection,
    current: ReportSelection,
) -> ComparisonReport:
    baseline_side = _load_side(store, project_id, baseline)
    current_side = _load_side(store, project_id, current)
    comparison = compare_assessments(
        baseline_side.report,
        current_side.report,
        baseline_correlation=baseline_side.correlation,
        current_correlation=current_side.correlation,
        baseline_acquisition_health=baseline_side.acquisition_health,
        current_acquisition_health=current_side.acquisition_health,
        baseline_capture_health=baseline_side.capture_health,
        current_capture_health=current_side.capture_health,
    )
    with store.engine.connect() as connection:
        project_name = connection.scalar(
            select(s.projects.c.name).where(s.projects.c.id == project_id)
        )
    if not isinstance(project_name, str):
        raise HistoryError("project does not exist")
    return build_comparison_report(project_id, project_name, comparison)
