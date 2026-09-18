import hmac
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from scopelens.analysis.correlation import CorrelationError
from scopelens.analysis.models import CorrelationResult
from scopelens.assessment.capture import assess_correlation
from scopelens.assessment.models import CaptureAssessmentReport, RecheckReport
from scopelens.comparison.compare import (
    ArtifactHealth,
    CaptureHealth,
    ComparisonError,
    compare_assessments,
)
from scopelens.comparison.models import HistoricalComparisonReport
from scopelens.config import ProjectConfig
from scopelens.domain.scope import ScopeViolation
from scopelens.domain.targets import normalize_origin
from scopelens.orchestration.models import AssessmentManifest
from scopelens.orchestration.store import OrchestrationStore, build_plan
from scopelens.orchestration.worker import AssessmentWorker
from scopelens.storage.artifacts import ArtifactError
from scopelens.storage.correlation import (
    correlate_history,
    load_capture_assessment,
)
from scopelens.storage.database import HistoryError

from .models import (
    AssessmentCreateRequest,
    AssessmentResponse,
    ComparisonRequest,
    CorrelationResponse,
    ErrorDetail,
    ErrorResponse,
    FocusedRetestRequest,
    HealthResponse,
    PersistedRecheckSelection,
    ProjectSummary,
    RecheckAcquisitionResponse,
    RecheckEvidenceResponse,
    RecheckReportResponse,
    ReconcileResponse,
    RunAnalysisRequest,
    RunSelection,
    StageResponse,
    assessment_response,
    correlation_response,
    stage_response,
)


@dataclass(frozen=True)
class ApiContext:
    config: ProjectConfig
    store: OrchestrationStore
    worker: AssessmentWorker


@dataclass(frozen=True)
class _LoadedSide:
    report: CaptureAssessmentReport | RecheckReport
    correlation: CorrelationResult | None
    acquisition_health: dict[UUID, ArtifactHealth] | None
    capture_health: CaptureHealth | None


class ApiProblem(Exception):
    def __init__(self, http_status: int, code: str, message: str) -> None:
        self.http_status = http_status
        self.code = code
        self.message = message


def _error(code: str, message: str, http_status: int) -> JSONResponse:
    payload = ErrorResponse(error=ErrorDetail(code=code, message=message))
    return JSONResponse(
        status_code=http_status, content=payload.model_dump(mode="json")
    )


def _validate_token(token: str) -> None:
    if (
        len(token) < 32
        or len(token) > 512
        or not token.isascii()
        or any(ord(character) < 33 or ord(character) == 127 for character in token)
    ):
        raise ValueError(
            "local API token must contain 32 to 512 visible ASCII characters"
        )


def _cors_origin(value: str) -> str:
    normalized = normalize_origin(value)
    parsed = urlsplit(normalized)
    if parsed.hostname not in ("localhost", "127.0.0.1"):
        raise ValueError("CORS origins must use localhost or 127.0.0.1")
    return normalized


def create_app(
    config: ProjectConfig,
    store: OrchestrationStore,
    worker: AssessmentWorker,
    *,
    token: str,
    allowed_origins: tuple[str, ...] = (),
) -> FastAPI:
    _validate_token(token)
    origins = tuple(_cors_origin(value) for value in allowed_origins)
    if len(set(origins)) != len(origins):
        raise ValueError("duplicate CORS origins are not allowed")
    context = ApiContext(config=config, store=store, worker=worker)
    security = HTTPBearer(auto_error=False)
    app = FastAPI(
        title="ScopeLens local API",
        version="1",
        description="Local authenticated access to configured ScopeLens assessments.",
    )
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(origins),
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
        )

    def authenticate(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    ) -> None:
        supplied = credentials.credentials if credentials is not None else ""
        scheme = credentials.scheme if credentials is not None else ""
        if scheme.lower() != "bearer" or not hmac.compare_digest(supplied, token):
            raise ApiProblem(401, "authentication_required", "authentication required")

    def require_project(project_id: str) -> None:
        if project_id != context.config.project.id:
            raise ApiProblem(404, "not_found", "project does not exist")

    def require_profile(profile_id: str) -> None:
        if not any(item.id == profile_id for item in context.config.profiles):
            raise ApiProblem(404, "not_found", "profile does not exist")

    def manifest(assessment_id: UUID) -> AssessmentManifest:
        try:
            result = context.store.get(assessment_id)
        except HistoryError as exc:
            if str(exc) == "assessment does not exist":
                raise ApiProblem(
                    404, "not_found", "assessment does not exist"
                ) from None
            raise
        if result.project_id != context.config.project.id:
            raise ApiProblem(404, "not_found", "assessment does not exist")
        return result

    def recheck_side(selection: PersistedRecheckSelection) -> _LoadedSide:
        selected = manifest(selection.assessment_id)
        stage = next(
            (item for item in selected.stages if item.id == selection.stage_id), None
        )
        if stage is None or stage.request.kind != "web_recheck":
            raise ApiProblem(404, "not_found", "recheck stage does not exist")
        try:
            report, health = context.store.load_recheck(selection.stage_id)
        except HistoryError as exc:
            if str(exc) == "recheck result does not exist":
                raise ApiProblem(
                    404, "not_found", "recheck result does not exist"
                ) from None
            raise
        return _LoadedSide(report, None, health, None)

    def load_side(selection: RunSelection | PersistedRecheckSelection) -> _LoadedSide:
        if isinstance(selection, PersistedRecheckSelection):
            return recheck_side(selection)
        report, correlation, health = load_capture_assessment(
            context.store.engine,
            context.store.artifacts,
            context.config.project.id,
            selection.run_ids,
        )
        return _LoadedSide(report, correlation, None, health)

    @app.exception_handler(ApiProblem)
    async def api_problem_handler(_: Request, exc: ApiProblem) -> JSONResponse:
        return _error(exc.code, exc.message, exc.http_status)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(
        _: Request, __: RequestValidationError
    ) -> JSONResponse:
        return _error("validation_error", "request validation failed", 422)

    @app.exception_handler(ScopeViolation)
    async def scope_handler(_: Request, __: ScopeViolation) -> JSONResponse:
        return _error("scope_violation", "request is outside configured scope", 403)

    @app.exception_handler(HistoryError)
    async def history_handler(_: Request, exc: HistoryError) -> JSONResponse:
        message = str(exc)
        if "already running" in message:
            return _error("worker_busy", "assessment worker is already running", 409)
        return _error(
            "lifecycle_conflict",
            "request conflicts with durable assessment state",
            409,
        )

    @app.exception_handler(CorrelationError)
    @app.exception_handler(ComparisonError)
    async def analysis_handler(_: Request, __: Exception) -> JSONResponse:
        return _error("invalid_selection", "selected evidence cannot be analyzed", 422)

    @app.exception_handler(ArtifactError)
    @app.exception_handler(SQLAlchemyError)
    async def unavailable_handler(_: Request, __: Exception) -> JSONResponse:
        return _error("service_unavailable", "local data service is unavailable", 503)

    @app.exception_handler(ValidationError)
    async def stored_validation_handler(
        _: Request, __: ValidationError
    ) -> JSONResponse:
        return _error("invalid_stored_data", "stored data failed validation", 500)

    @app.exception_handler(Exception)
    async def internal_handler(_: Request, __: Exception) -> JSONResponse:
        return _error("internal_error", "internal server error", 500)

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse()

    protected = [Depends(authenticate)]

    @app.get(
        "/api/v1/project",
        response_model=ProjectSummary,
        dependencies=protected,
    )
    def project() -> ProjectSummary:
        return ProjectSummary(
            project=context.config.project, profiles=context.config.profiles
        )

    @app.post(
        "/api/v1/assessments",
        response_model=AssessmentResponse,
        status_code=201,
        dependencies=protected,
    )
    def create_assessment(request: AssessmentCreateRequest) -> AssessmentResponse:
        require_project(request.project_id)
        require_profile(request.profile_id)
        planned = build_plan(context.config, request.profile_id, request.stages)
        return assessment_response(
            context.store.enqueue(request.assessment_id, context.config, planned)
        )

    @app.post(
        "/api/v1/retests",
        response_model=AssessmentResponse,
        status_code=201,
        dependencies=protected,
    )
    def create_retest(request: FocusedRetestRequest) -> AssessmentResponse:
        require_project(request.project_id)
        require_profile(request.profile_id)
        selected = tuple(
            item
            for item in build_plan(context.config, request.profile_id, ("web_recheck",))
            if item.web_target is not None
            and item.web_target.origin == request.origin
            and item.web_target.approved_addresses == (request.approved_address,)
        )
        if len(selected) != 1:
            raise ScopeViolation("focused recheck target is outside configured scope")
        return assessment_response(
            context.store.enqueue(request.assessment_id, context.config, selected)
        )

    @app.get(
        "/api/v1/assessments",
        response_model=list[AssessmentResponse],
        dependencies=protected,
    )
    def list_assessments(
        project_id: str = Query(min_length=1, max_length=64),
    ) -> list[AssessmentResponse]:
        require_project(project_id)
        return [
            assessment_response(item)
            for item in context.store.list_manifests(project_id)
        ]

    @app.get(
        "/api/v1/assessments/{assessment_id}",
        response_model=AssessmentResponse,
        dependencies=protected,
    )
    def get_assessment(assessment_id: UUID) -> AssessmentResponse:
        return assessment_response(manifest(assessment_id))

    @app.get(
        "/api/v1/assessments/{assessment_id}/stages/{stage_id}",
        response_model=StageResponse,
        dependencies=protected,
    )
    def get_stage(assessment_id: UUID, stage_id: UUID) -> StageResponse:
        selected = manifest(assessment_id)
        stage = next((item for item in selected.stages if item.id == stage_id), None)
        if stage is None:
            raise ApiProblem(404, "not_found", "assessment stage does not exist")
        return stage_response(stage)

    @app.post(
        "/api/v1/assessments/{assessment_id}/execute",
        response_model=AssessmentResponse,
        dependencies=protected,
    )
    def execute_assessment(assessment_id: UUID) -> AssessmentResponse:
        selected = manifest(assessment_id)
        if selected.status != "pending":
            raise ApiProblem(
                409,
                "lifecycle_conflict",
                "only a pending assessment can be executed",
            )
        result = context.worker.run_one(assessment_id)
        if result is None:
            raise ApiProblem(
                409, "lifecycle_conflict", "assessment is no longer pending"
            )
        return assessment_response(result)

    @app.post(
        "/api/v1/worker/reconcile",
        response_model=ReconcileResponse,
        dependencies=protected,
    )
    def reconcile_worker() -> ReconcileResponse:
        return ReconcileResponse(
            interrupted_assessment_ids=tuple(context.worker.reconcile())
        )

    @app.post(
        "/api/v1/analysis/correlation",
        response_model=CorrelationResponse,
        dependencies=protected,
    )
    def correlation(request: RunAnalysisRequest) -> CorrelationResponse:
        require_project(request.project_id)
        return correlation_response(
            correlate_history(context.store.engine, request.project_id, request.run_ids)
        )

    @app.post(
        "/api/v1/analysis/assessment",
        response_model=CaptureAssessmentReport,
        dependencies=protected,
    )
    def assessment(request: RunAnalysisRequest) -> CaptureAssessmentReport:
        require_project(request.project_id)
        return assess_correlation(
            correlate_history(context.store.engine, request.project_id, request.run_ids)
        )

    @app.post(
        "/api/v1/analysis/comparison",
        response_model=HistoricalComparisonReport,
        dependencies=protected,
    )
    def comparison(request: ComparisonRequest) -> HistoricalComparisonReport:
        require_project(request.project_id)
        baseline = load_side(request.baseline)
        current = load_side(request.current)
        return compare_assessments(
            baseline.report,
            current.report,
            baseline_correlation=baseline.correlation,
            current_correlation=current.correlation,
            baseline_acquisition_health=baseline.acquisition_health,
            current_acquisition_health=current.acquisition_health,
            baseline_capture_health=baseline.capture_health,
            current_capture_health=current.capture_health,
        )

    @app.get(
        "/api/v1/assessments/{assessment_id}/stages/{stage_id}/recheck",
        response_model=RecheckReportResponse,
        dependencies=protected,
    )
    def get_recheck(assessment_id: UUID, stage_id: UUID) -> RecheckReportResponse:
        side = recheck_side(
            PersistedRecheckSelection(assessment_id=assessment_id, stage_id=stage_id)
        )
        assert isinstance(side.report, RecheckReport)
        health = side.acquisition_health or {}
        acquisitions = []
        for acquisition in side.report.acquisitions:
            evidence = acquisition.evidence
            safe_evidence = (
                RecheckEvidenceResponse(
                    acquisition_id=acquisition.id,
                    sha256=evidence.artifact_sha256,
                    size_bytes=evidence.size_bytes,
                    health=health.get(acquisition.id, "corrupt"),
                )
                if evidence is not None
                else None
            )
            acquisitions.append(
                RecheckAcquisitionResponse(
                    id=acquisition.id,
                    started_at=acquisition.started_at,
                    finished_at=acquisition.finished_at,
                    origin=acquisition.origin,
                    approved_address=acquisition.approved_address,
                    method=acquisition.method,
                    resource=acquisition.resource,
                    status=acquisition.status,
                    response=acquisition.response,
                    evidence=safe_evidence,
                )
            )
        return RecheckReportResponse(
            project_id=side.report.project_id,
            assessment_id=assessment_id,
            stage_id=stage_id,
            acquisitions=tuple(acquisitions),
            assessments=side.report.assessments,
        )

    return app
