import asyncio
import shutil
import warnings
from pathlib import Path
from tempfile import mkdtemp
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import select

from scopelens.assessment.recheck import recheck_web
from scopelens.domain.scope import ScopeViolation
from scopelens.execution.process import ExecutionError
from scopelens.orchestration.models import AssessmentManifest, PlannedStage
from scopelens.orchestration.store import OrchestrationStore
from scopelens.storage import schema as s
from scopelens.storage.artifacts import ArtifactError
from scopelens.storage.database import HistoryError, single_assessment_worker
from scopelens.storage.history import History
from scopelens.storage.operations import scan_history


class AssessmentWorker:
    def __init__(
        self,
        store: OrchestrationStore,
        *,
        httpx_binary: str | None = None,
        nuclei_binary: str | None = None,
    ) -> None:
        self.store = store
        self.history = History(store.engine, store.artifacts)
        self.httpx_binary = httpx_binary
        self.nuclei_binary = nuclei_binary

    def _run_exists(self, run_id: UUID) -> bool:
        with self.store.engine.connect() as connection:
            return (
                connection.scalar(select(s.runs.c.id).where(s.runs.c.id == run_id))
                is not None
            )

    def _scanner_stage(
        self, manifest: AssessmentManifest, stage: PlannedStage, token: UUID
    ) -> None:
        request = stage.request
        run_id = request.planned_run_id
        assert run_id is not None
        config = self.store.config(manifest.id)
        binary = (
            self.nuclei_binary
            if request.kind == "nuclei"
            else self.httpx_binary
            if request.kind == "httpx"
            else None
        )
        try:
            scan_history(
                self.history,
                config,
                request.profile_id,
                run_id,
                scanner=request.kind,
                web_target=request.web_target,
                binary=binary,
                orchestration_stage_id=stage.id,
            )
        except KeyboardInterrupt:
            self.store.finish_stage(
                manifest.id,
                stage.id,
                token,
                "interrupted",
                reason="operator_cancelled",
                result_run_id=run_id if self._run_exists(run_id) else None,
            )
            raise
        except ExecutionError, HistoryError, ScopeViolation, ArtifactError, OSError:
            self.store.finish_stage(
                manifest.id,
                stage.id,
                token,
                "failed",
                reason="execution_failed",
                result_run_id=run_id if self._run_exists(run_id) else None,
            )
        else:
            self.store.finish_stage(
                manifest.id,
                stage.id,
                token,
                "completed",
                result_run_id=run_id,
            )

    def _recheck_stage(
        self, manifest: AssessmentManifest, stage: PlannedStage, token: UUID
    ) -> None:
        request = stage.request
        assert request.web_target is not None
        config = self.store.config(manifest.id)
        staging = Path(
            mkdtemp(prefix=".pending-recheck-", dir=self.store.artifacts.root)
        )
        try:
            report = asyncio.run(
                recheck_web(
                    config,
                    request.profile_id,
                    staging,
                    request.web_target,
                )
            )
            failed = any(
                acquisition.status != "complete" for acquisition in report.acquisitions
            )
            self.store.persist_recheck(
                manifest.id, stage.id, token, report, failed=failed
            )
        except KeyboardInterrupt:
            self.store.finish_stage(
                manifest.id,
                stage.id,
                token,
                "interrupted",
                reason="operator_cancelled",
            )
            raise
        except (
            ExecutionError,
            HistoryError,
            ScopeViolation,
            ArtifactError,
            ValidationError,
            OSError,
        ):
            self.store.finish_stage(
                manifest.id,
                stage.id,
                token,
                "failed",
                reason="execution_failed",
            )
        else:
            try:
                if (
                    staging.parent != self.store.artifacts.root
                    or not staging.name.startswith(".pending-recheck-")
                    or staging.is_symlink()
                ):
                    raise OSError("unsafe recheck staging path")
                shutil.rmtree(staging)
            except OSError:
                warnings.warn(
                    "recheck result committed; staging cleanup incomplete",
                    stacklevel=2,
                )

    def run_one(self, assessment_id: UUID | None = None) -> AssessmentManifest | None:
        token = uuid4()
        with single_assessment_worker(self.store.engine):
            self.store.reconcile_stale()
            claimed = self.store.claim(token, assessment_id)
            if claimed is None:
                return None
            manifest = self.store.get(claimed)
            config = self.store.config(manifest.id)
            try:
                for stage in manifest.stages:
                    self.store.validate_stage(config, stage.request)
                    if stage.request.skip_reason is not None:
                        self.store.skip_stage(
                            manifest.id,
                            stage.id,
                            token,
                            stage.request.skip_reason,
                        )
                        continue
                    self.store.start_stage(manifest.id, stage.id, token)
                    if stage.request.kind == "web_recheck":
                        self._recheck_stage(manifest, stage, token)
                    else:
                        self._scanner_stage(manifest, stage, token)
            except KeyboardInterrupt:
                self.store.finalize(manifest.id, token)
                raise
            return self.store.finalize(manifest.id, token)

    def reconcile(self) -> list[UUID]:
        with single_assessment_worker(self.store.engine):
            return self.store.reconcile_stale()
