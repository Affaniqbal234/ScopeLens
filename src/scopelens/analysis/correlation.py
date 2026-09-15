import json
from collections.abc import Iterable
from hashlib import sha256
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import TypeAdapter

from scopelens.analysis.models import (
    ArtifactCopies,
    AssertionGroup,
    CorrelationResult,
    FindingGroup,
    FindingIdentity,
    Host,
    HttpOrigin,
    HttpResource,
    InventoryIdentity,
    InventoryItem,
    NetworkService,
    Relationship,
    RelationshipKind,
    RunSource,
    SourceReference,
)
from scopelens.domain.evidence import ObservationValue
from scopelens.domain.services import HttpEndpoint, ServiceEndpoint
from scopelens.domain.targets import Identifier, normalize_origin


class CorrelationError(ValueError):
    """Selected history cannot form a consistent correlation input."""


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _id(rule: str, value: object) -> str:
    return rule + ":" + sha256(_json(value).encode()).hexdigest()


def _references(values: Iterable[SourceReference]) -> tuple[SourceReference, ...]:
    return tuple(sorted(set(values), key=lambda ref: ref.model_dump_json()))


def matched_resource(origin: str, location: str) -> str:
    if any(ord(char) <= 32 or ord(char) == 127 for char in location) or any(
        char in location for char in ("\\", "#")
    ):
        raise CorrelationError("unsafe matched resource")
    try:
        parsed = urlsplit(location)
        actual_origin = normalize_origin(f"{parsed.scheme}://{parsed.netloc}")
    except ValueError:
        raise CorrelationError("invalid matched resource") from None
    if actual_origin != origin:
        raise CorrelationError("matched resource belongs to a different origin")
    # Path case, percent encoding, and query order are evidence, not aliases.
    return (parsed.path or "/") + ("?" + parsed.query if "?" in location else "")


def correlate(project_id: str, sources: Iterable[RunSource]) -> CorrelationResult:
    project_id = TypeAdapter(Identifier).validate_python(project_id)
    selected = tuple(sorted(sources, key=lambda source: source.run_id))
    if not selected:
        raise CorrelationError("select at least one completed run")
    if any(source.project_id != project_id for source in selected):
        raise CorrelationError("all selected runs must belong to the requested project")
    if len({source.run_id for source in selected}) != len(selected):
        raise CorrelationError("select each run only once")

    identities: dict[str, InventoryIdentity] = {}
    inventory_refs: dict[str, list[SourceReference]] = {}
    relationships: set[tuple[RelationshipKind, str, str]] = set()
    relationship_refs: dict[tuple[str, str, str], list[SourceReference]] = {}
    assertions: dict[str, tuple[str, str, ObservationValue]] = {}
    assertion_refs: dict[str, list[SourceReference]] = {}
    findings: dict[str, tuple[FindingIdentity, str]] = {}
    finding_refs: dict[str, list[SourceReference]] = {}
    copies: dict[tuple[str, str], list[UUID]] = {}

    def item(identity: InventoryIdentity, ref: SourceReference) -> str:
        key = _id("inventory-v1", [project_id, identity.model_dump(mode="json")])
        identities[key] = identity
        inventory_refs.setdefault(key, []).append(ref)
        return key

    def relate(
        kind: RelationshipKind,
        source_id: str,
        target_id: str,
        ref: SourceReference,
    ) -> None:
        key = (kind, source_id, target_id)
        relationships.add(key)
        relationship_refs.setdefault(key, []).append(ref)

    def resource(origin: str, path: str, ref: SourceReference) -> str:
        origin_id = item(HttpOrigin(origin=origin), ref)
        resource_id = item(HttpResource(origin=origin, resource=path), ref)
        relate("resource_on_origin", resource_id, origin_id, ref)
        return resource_id

    def service(endpoint: ServiceEndpoint, ref: SourceReference) -> str:
        service_id = item(NetworkService(endpoint=endpoint), ref)
        host_id = item(Host(address=endpoint.address), ref)
        relate("service_on_host", service_id, host_id, ref)
        return service_id

    for source in selected:
        copies.setdefault(
            (source.report.evidence.scanner, source.report.evidence.artifact_sha256),
            [],
        ).append(source.run_id)
        if source.context.web_target is not None:
            ref = SourceReference(run_id=source.run_id, section="context")
            origin_id = item(HttpOrigin(origin=source.context.web_target.origin), ref)
            for address in source.context.web_target.approved_addresses:
                host_id = item(Host(address=address), ref)
                relate("configured_address", origin_id, host_id, ref)

        for ordinal, observation in enumerate(source.report.observations):
            ref = SourceReference(
                run_id=source.run_id, section="observations", ordinal=ordinal
            )
            subject = observation.subject
            if isinstance(subject, ServiceEndpoint):
                subject_id = service(subject, ref)
            elif isinstance(subject, HttpEndpoint):
                subject_id = resource(subject.origin, subject.path, ref)
            elif "://" in subject:
                subject_id = item(HttpOrigin(origin=subject), ref)
            else:
                subject_id = item(Host(address=subject), ref)
            assertion = (subject_id, observation.key, observation.value)
            key = _json(assertion)
            assertions[key] = assertion
            assertion_refs.setdefault(key, []).append(ref)

            if isinstance(subject, HttpEndpoint) and observation.key in (
                "http.target_address",
                "http.peer_address",
            ):
                if not isinstance(observation.value, str):
                    raise CorrelationError("HTTP address observation is not an address")
                host_id = item(Host(address=observation.value), ref)
                origin_id = item(HttpOrigin(origin=subject.origin), ref)
                if observation.key == "http.target_address":
                    relate("reported_target_address", origin_id, host_id, ref)
                else:
                    relate("reported_peer_address", origin_id, host_id, ref)
                    parsed = urlsplit(subject.origin)
                    endpoint = ServiceEndpoint(
                        address=observation.value,
                        transport="tcp",
                        port=parsed.port or (443 if parsed.scheme == "https" else 80),
                    )
                    relate(
                        "reported_peer_service", origin_id, service(endpoint, ref), ref
                    )

        for ordinal, match in enumerate(source.report.matches):
            ref = SourceReference(
                run_id=source.run_id, section="matches", ordinal=ordinal
            )
            path = matched_resource(match.origin, match.matched_location)
            identity = FindingIdentity(
                project_id=project_id,
                origin=match.origin,
                resource=path,
                template_id=match.template_id,
                matcher=match.matcher,
            )
            key = _id(
                identity.rule,
                identity.model_dump(mode="json", exclude={"rule"}),
            )
            findings[key] = (identity, resource(match.origin, path, ref))
            finding_refs.setdefault(key, []).append(ref)

    return CorrelationResult(
        project_id=project_id,
        sources=selected,
        inventory=tuple(
            InventoryItem(
                id=key,
                identity=identities[key],
                sources=_references(inventory_refs[key]),
            )
            for key in sorted(identities)
        ),
        relationships=tuple(
            Relationship(
                kind=key[0],
                source_id=key[1],
                target_id=key[2],
                sources=_references(relationship_refs[key]),
            )
            for key in sorted(relationships)
        ),
        assertions=tuple(
            AssertionGroup(
                subject_id=assertions[key][0],
                key=assertions[key][1],
                value=assertions[key][2],
                occurrences=_references(assertion_refs[key]),
            )
            for key in sorted(assertions)
        ),
        findings=tuple(
            FindingGroup(
                id=key,
                identity=findings[key][0],
                resource_id=findings[key][1],
                occurrences=_references(finding_refs[key]),
            )
            for key in sorted(findings)
        ),
        artifact_copies=tuple(
            ArtifactCopies(
                scanner=scanner, artifact_sha256=digest, run_ids=tuple(run_ids)
            )
            for (scanner, digest), run_ids in sorted(copies.items())
            if len(run_ids) > 1
        ),
    )
