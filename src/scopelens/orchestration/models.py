from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from scopelens.domain.scope import NetworkTarget, WebTarget
from scopelens.domain.targets import DomainModel, Identifier

AssessmentStatus = Literal["pending", "running", "completed", "failed", "interrupted"]
StageStatus = Literal[
    "pending", "running", "completed", "failed", "skipped", "interrupted"
]
StageKind = Literal["nmap", "httpx", "nuclei", "web_recheck"]


class StageRequest(DomainModel):
    kind: StageKind
    profile_id: Identifier
    network_targets: tuple[NetworkTarget, ...] = ()
    web_target: WebTarget | None = None
    resources: Annotated[tuple[str, ...], Field(min_length=1)]
    rule_revision: str | None = None
    planned_run_id: UUID | None = None
    skip_reason: Annotated[
        str | None,
        Field(pattern=r"^[a-z][a-z0-9_]*$", min_length=1, max_length=64),
    ] = None

    @model_validator(mode="after")
    def validate_kind(self) -> Self:
        if self.kind == "nmap":
            if (
                not self.network_targets
                or self.web_target is not None
                or self.resources != ("network-services",)
                or self.rule_revision is not None
                or self.planned_run_id is None
            ):
                raise ValueError("invalid Nmap stage request")
        elif self.kind in ("httpx", "nuclei"):
            if (
                self.network_targets
                or self.web_target is None
                or len(self.web_target.approved_addresses) != 1
                or self.planned_run_id is None
            ):
                raise ValueError("invalid web scanner stage request")
        elif (
            self.network_targets
            or self.web_target is None
            or len(self.web_target.approved_addresses) != 1
            or self.planned_run_id is not None
            or self.rule_revision is None
        ):
            raise ValueError("invalid web recheck stage request")
        return self


class PlannedStage(DomainModel):
    id: UUID
    ordinal: Annotated[int, Field(ge=0)]
    request: StageRequest
    status: StageStatus
    result_run_id: UUID | None = None
    started_at: AwareDatetime | None = None
    finished_at: AwareDatetime | None = None
    reason: str | None = None

    @model_validator(mode="after")
    def consistent_lifecycle(self) -> Self:
        if self.finished_at is not None and self.started_at is not None:
            if self.finished_at < self.started_at:
                raise ValueError("stage completion precedes its start")
        if self.status == "pending":
            valid = (
                self.started_at is None
                and self.finished_at is None
                and self.reason is None
                and self.result_run_id is None
            )
        elif self.status == "running":
            valid = (
                self.started_at is not None
                and self.finished_at is None
                and self.reason is None
                and self.result_run_id is None
            )
        elif self.status == "completed":
            valid = (
                self.started_at is not None
                and self.finished_at is not None
                and self.reason is None
                and (
                    (self.request.kind == "web_recheck" and self.result_run_id is None)
                    or self.result_run_id == self.request.planned_run_id
                )
            )
        elif self.status == "skipped":
            valid = (
                self.started_at is None
                and self.finished_at is not None
                and self.reason is not None
                and self.result_run_id is None
            )
        else:
            valid = (
                self.started_at is not None
                and self.finished_at is not None
                and self.reason is not None
                and (
                    self.result_run_id is None
                    or self.result_run_id == self.request.planned_run_id
                )
            )
        if not valid:
            raise ValueError("stage lifecycle fields do not match its status")
        return self


class AssessmentManifest(DomainModel):
    id: UUID
    project_id: Identifier
    scope_snapshot_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    status: AssessmentStatus
    created_at: AwareDatetime
    started_at: AwareDatetime | None = None
    finished_at: AwareDatetime | None = None
    worker_token: UUID | None = None
    reason: str | None = None
    stages: tuple[PlannedStage, ...]

    @model_validator(mode="after")
    def ordered_stages(self) -> Self:
        if not self.stages:
            raise ValueError("assessment requires at least one stage")
        if tuple(stage.ordinal for stage in self.stages) != tuple(
            range(len(self.stages))
        ):
            raise ValueError("assessment stages must use consecutive order")
        if len({stage.id for stage in self.stages}) != len(self.stages):
            raise ValueError("assessment stage identifiers must be unique")
        if self.finished_at is not None and self.started_at is not None:
            if self.finished_at < self.started_at:
                raise ValueError("assessment completion precedes its start")
        if self.status == "pending":
            valid = (
                self.started_at is None
                and self.finished_at is None
                and self.worker_token is None
                and self.reason is None
                and all(stage.status == "pending" for stage in self.stages)
            )
        elif self.status == "running":
            valid = (
                self.started_at is not None
                and self.finished_at is None
                and self.worker_token is not None
                and self.reason is None
            )
        elif self.status == "completed":
            valid = (
                self.started_at is not None
                and self.finished_at is not None
                and self.worker_token is None
                and self.reason is None
                and all(
                    stage.status in ("completed", "skipped") for stage in self.stages
                )
            )
        elif self.status == "failed":
            valid = (
                self.started_at is not None
                and self.finished_at is not None
                and self.worker_token is None
                and self.reason is not None
                and any(stage.status == "failed" for stage in self.stages)
                and all(
                    stage.status in ("completed", "failed", "skipped")
                    for stage in self.stages
                )
            )
        else:
            valid = (
                self.started_at is not None
                and self.finished_at is not None
                and self.worker_token is None
                and self.reason is not None
                and any(stage.status == "interrupted" for stage in self.stages)
                and all(stage.status != "running" for stage in self.stages)
            )
        if not valid:
            raise ValueError("assessment lifecycle fields do not match its status")
        return self
