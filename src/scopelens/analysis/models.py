from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from scopelens.adapters.base import ImportContext, ParsedReport
from scopelens.domain.evidence import ObservationValue
from scopelens.domain.scope import ScanProfile
from scopelens.domain.services import ServiceEndpoint
from scopelens.domain.targets import DomainModel, Identifier, IPv4, Origin

Digest = Annotated[
    str, Field(strict=True, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
]
ProjectionId = Annotated[
    str,
    Field(
        strict=True,
        min_length=75,
        max_length=77,
        pattern=r"^(inventory|finding)-v1:[0-9a-f]{64}$",
    ),
]
Resource = Annotated[
    str, Field(strict=True, min_length=1, max_length=2048, pattern=r"^/")
]


class StoredArtifact(DomainModel):
    role: Literal["stdout", "stderr"]
    relative_path: str
    sha256: Digest
    size_bytes: Annotated[int, Field(strict=True, ge=0, le=8 * 1024 * 1024)]
    recorded_health: Literal["ready", "missing", "corrupt"]


class RunSource(DomainModel):
    run_id: UUID
    project_id: Identifier
    kind: Literal["scan", "import"]
    created_at: AwareDatetime
    scope_snapshot_id: Digest
    profile: ScanProfile
    context: ImportContext
    report: ParsedReport
    artifacts: tuple[StoredArtifact, ...]


class SourceReference(DomainModel):
    run_id: UUID
    section: Literal["context", "observations", "matches"]
    ordinal: Annotated[int, Field(strict=True, ge=0)] | None = None

    @model_validator(mode="after")
    def ordinal_matches_section(self) -> Self:
        if (self.section == "context") != (self.ordinal is None):
            raise ValueError("observations and matches require an occurrence ordinal")
        return self


class Host(DomainModel):
    kind: Literal["host"] = "host"
    address: IPv4


class NetworkService(DomainModel):
    kind: Literal["network_service"] = "network_service"
    endpoint: ServiceEndpoint


class HttpOrigin(DomainModel):
    kind: Literal["http_origin"] = "http_origin"
    origin: Origin


class HttpResource(DomainModel):
    kind: Literal["http_resource"] = "http_resource"
    origin: Origin
    resource: Resource


InventoryIdentity = Annotated[
    Host | NetworkService | HttpOrigin | HttpResource, Field(discriminator="kind")
]


class InventoryItem(DomainModel):
    id: ProjectionId
    identity: InventoryIdentity
    sources: Annotated[tuple[SourceReference, ...], Field(min_length=1)]


RelationshipKind = Literal[
    "service_on_host",
    "resource_on_origin",
    "configured_address",
    "reported_target_address",
    "reported_peer_address",
    "reported_peer_service",
]


class Relationship(DomainModel):
    kind: RelationshipKind
    source_id: ProjectionId
    target_id: ProjectionId
    sources: Annotated[tuple[SourceReference, ...], Field(min_length=1)]


class AssertionGroup(DomainModel):
    subject_id: ProjectionId
    key: str
    value: ObservationValue
    occurrences: Annotated[tuple[SourceReference, ...], Field(min_length=1)]


class FindingIdentity(DomainModel):
    rule: Literal["finding-v1"] = "finding-v1"
    project_id: Identifier
    origin: Origin
    resource: Resource
    template_id: Identifier
    matcher: Identifier


class FindingGroup(DomainModel):
    id: ProjectionId
    identity: FindingIdentity
    resource_id: ProjectionId
    occurrences: Annotated[tuple[SourceReference, ...], Field(min_length=1)]


class ArtifactCopies(DomainModel):
    scanner: Identifier
    artifact_sha256: Digest
    run_ids: Annotated[tuple[UUID, ...], Field(min_length=1)]


class CorrelationResult(DomainModel):
    version: Literal["correlation-v1"] = "correlation-v1"
    project_id: Identifier
    sources: Annotated[tuple[RunSource, ...], Field(min_length=1)]
    inventory: tuple[InventoryItem, ...]
    relationships: tuple[Relationship, ...]
    assertions: tuple[AssertionGroup, ...]
    findings: tuple[FindingGroup, ...]
    artifact_copies: tuple[ArtifactCopies, ...]
