import socket
import subprocess
from datetime import UTC, datetime, timedelta
from itertools import permutations
from uuid import UUID

import pytest
from pydantic import ValidationError

from scopelens.adapters.base import ImportContext, ParsedReport
from scopelens.analysis.correlation import CorrelationError, correlate, matched_resource
from scopelens.analysis.models import (
    CorrelationResult,
    Host,
    HttpOrigin,
    HttpResource,
    NetworkService,
    RunSource,
    SourceReference,
)
from scopelens.domain.evidence import EvidenceReference, Observation
from scopelens.domain.findings import ScannerMatch
from scopelens.domain.scope import (
    AuthorizedScope,
    NetworkTarget,
    ScanProfile,
    ScopeViolation,
    WebTarget,
)
from scopelens.domain.services import HttpEndpoint, ServiceEndpoint

ORIGIN = "http://site.invalid:8000"
NOW = datetime(2026, 9, 14, tzinfo=UTC)
ENDPOINT = HttpEndpoint(origin=ORIGIN)


def evidence(scanner: str = "nuclei", locator: str = "line:1") -> EvidenceReference:
    return EvidenceReference(
        scanner=scanner,
        scanner_version="test",
        adapter_version="test",
        artifact_sha256="a" * 64,
        record_locator=locator,
        profile_id="web",
        profile_revision="test",
        captured_at=NOW,
    )


def match(
    origin: str = ORIGIN,
    path: str = "/",
    template: str = "directory-listing",
    matcher: str = "listing",
) -> ScannerMatch:
    return ScannerMatch(
        origin=origin,
        matched_location=origin + path,
        template_id=template,
        template_revision="b" * 64,
        matcher=matcher,
        scanner_severity="low",
        evidence=(evidence(),),
    )


def observation(
    key: str,
    value: str | bool | int | float,
    subject: str | HttpEndpoint | ServiceEndpoint = ENDPOINT,
    scanner: str = "httpx",
) -> Observation:
    return Observation(
        subject=subject, key=key, value=value, evidence=(evidence(scanner),)
    )


def source(
    number: int = 1,
    *,
    matches: tuple[ScannerMatch, ...] = (),
    observations: tuple[Observation, ...] = (),
    target: WebTarget | None = None,
    scanner: str = "nuclei",
    project: str = "lab",
) -> RunSource:
    return RunSource(
        run_id=UUID(int=number),
        project_id=project,
        kind="import",
        created_at=NOW,
        scope_snapshot_id="c" * 64,
        profile=ScanProfile(id="web"),
        context=ImportContext(
            profile_id="web",
            profile_revision="test",
            web_target=target,
        ),
        report=ParsedReport(
            evidence=evidence(scanner, "$"),
            reported_exit=None,
            observations=observations,
            matches=matches,
        ),
        artifacts=(),
    )


def test_input_order_and_repeated_analysis_are_identical() -> None:
    sources = (
        source(3, matches=(match(),)),
        source(1, matches=(match(path="/.git/config", template="git-config"),)),
        source(
            2, observations=(observation("http.status_code", 200),), scanner="httpx"
        ),
    )
    original = tuple(item.model_dump_json() for item in sources)
    expected = correlate("lab", sources).model_dump_json()
    for ordered in permutations(sources):
        assert correlate("lab", ordered).model_dump_json() == expected
    assert tuple(item.model_dump_json() for item in sources) == original
    assert CorrelationResult.model_validate_json(expected).model_dump_json() == expected


def test_occurrences_and_artifact_copies_are_preserved_without_confirmation() -> None:
    first = source(matches=(match(),))
    imported_again = first.model_copy(update={"run_id": UUID(int=2)})
    later_scan = first.model_copy(update={"run_id": UUID(int=3), "kind": "scan"})
    result = correlate("lab", (later_scan, imported_again, first))
    assert len(result.findings) == 1
    assert result.findings[0].occurrences == tuple(
        SourceReference(run_id=UUID(int=i), section="matches", ordinal=0)
        for i in (1, 2, 3)
    )
    assert result.artifact_copies[0].run_ids == tuple(UUID(int=i) for i in (1, 2, 3))
    assert result.sources == (first, imported_again, later_scan)
    assert all(s.report.matches[0].assessment == "unvalidated" for s in result.sources)
    assert "confidence" not in result.model_dump_json()
    assert "corroboration" not in result.model_dump_json()


@pytest.mark.parametrize(
    ("origin", "path", "template", "matcher"),
    [
        ("https://site.invalid:8000", "/", "directory-listing", "listing"),
        ("http://site.invalid:8001", "/", "directory-listing", "listing"),
        ("http://other.invalid:8000", "/", "directory-listing", "listing"),
        (ORIGIN, "/other", "directory-listing", "listing"),
        (ORIGIN, "/", "other-template", "listing"),
        (ORIGIN, "/", "directory-listing", "other-matcher"),
        (ORIGIN, "/?x=1", "directory-listing", "listing"),
        (ORIGIN, "/?", "directory-listing", "listing"),
    ],
)
def test_each_identity_dimension_separates_findings(
    origin: str,
    path: str,
    template: str,
    matcher: str,
) -> None:
    result = correlate(
        "lab",
        (
            source(1, matches=(match(),)),
            source(2, matches=(match(origin, path, template, matcher),)),
        ),
    )
    assert len(result.findings) == 2
    assert len({finding.id for finding in result.findings}) == 2


def test_project_is_part_of_identity() -> None:
    first = correlate("lab", (source(matches=(match(),)),))
    second = correlate("other", (source(matches=(match(),), project="other"),))
    assert first.findings[0].id != second.findings[0].id


def test_mutable_metadata_does_not_change_finding_identity() -> None:
    original = match()
    changed_ref = evidence().model_copy(
        update={
            "profile_id": "other",
            "profile_revision": "changed",
            "captured_at": NOW + timedelta(days=1),
            "artifact_sha256": "d" * 64,
        }
    )
    changed = original.model_copy(
        update={
            "template_revision": "e" * 64,
            "scanner_severity": "high",
            "evidence": (changed_ref,),
        }
    )
    first = source(
        1, matches=(original,), observations=(observation("http.title", "Same"),)
    )
    second = source(
        2, matches=(changed,), observations=(observation("http.title", "Similar"),)
    )
    result = correlate("lab", (first, second))
    assert len(result.findings) == 1
    assert result.findings[0].identity.rule == "finding-v1"
    assert result.sources[0].report.matches == (original,)
    assert result.sources[1].report.matches == (changed,)
    assert {item.value for item in result.assertions} == {"Same", "Similar"}


def test_titles_do_not_merge_distinct_findings() -> None:
    result = correlate(
        "lab",
        (
            source(
                1,
                matches=(match(),),
                observations=(observation("http.title", "Index"),),
            ),
            source(
                2,
                matches=(match(template="other"),),
                observations=(observation("http.title", "Index"),),
            ),
            source(
                3,
                matches=(match(matcher="other"),),
                observations=(observation("http.title", "Index of /"),),
            ),
        ),
    )
    assert len(result.findings) == 3
    assert sorted(len(item.occurrences) for item in result.assertions) == [1, 2]


def test_shared_ip_keeps_virtual_hosts_and_network_identity_separate() -> None:
    origins = (ORIGIN, "http://other.invalid:8000")
    web = tuple(
        source(
            i,
            scanner="httpx",
            observations=(
                observation(
                    "http.peer_address", "127.0.0.1", HttpEndpoint(origin=origin)
                ),
            ),
            target=WebTarget(origin=origin, approved_addresses=("127.0.0.1",)),
        )
        for i, origin in enumerate(origins, 1)
    )
    endpoint = ServiceEndpoint(address="127.0.0.1", transport="tcp", port=8000)
    nmap = source(
        3,
        scanner="nmap",
        observations=(observation("service.state", "open", endpoint, "nmap"),),
    )
    result = correlate("lab", (*web, nmap))
    assert (
        len([item for item in result.inventory if isinstance(item.identity, Host)]) == 1
    )
    assert {
        item.identity.origin
        for item in result.inventory
        if isinstance(item.identity, HttpOrigin)
    } == set(origins)
    services = [
        item for item in result.inventory if isinstance(item.identity, NetworkService)
    ]
    assert len(services) == 1
    assert isinstance(services[0].identity, NetworkService)
    assert services[0].identity.endpoint == endpoint
    assert {ref.run_id for ref in services[0].sources} == {
        UUID(int=i) for i in (1, 2, 3)
    }
    peers = [rel for rel in result.relationships if rel.kind == "reported_peer_service"]
    assert len(peers) == 2 and peers[0].source_id != peers[1].source_id
    scope = AuthorizedScope(
        web_targets=tuple(s.context.web_target for s in web if s.context.web_target)
    )
    with pytest.raises(ScopeViolation):
        scope.authorize_network(NetworkTarget(address="127.0.0.1", ports=(8000,)))


def test_configuration_and_failed_target_are_not_observed_peers() -> None:
    target = WebTarget(origin=ORIGIN, approved_addresses=("127.0.0.1", "127.0.0.2"))
    result = correlate(
        "lab",
        (
            source(
                target=target,
                scanner="httpx",
                observations=(
                    observation("http.target_address", "127.0.0.1"),
                    observation("http.probe_succeeded", False),
                    observation("http.location", "https://outside.invalid/"),
                ),
            ),
        ),
    )
    kinds = [rel.kind for rel in result.relationships]
    assert kinds.count("configured_address") == 2
    assert kinds.count("reported_target_address") == 1
    assert not any(kind.startswith("reported_peer") for kind in kinds)
    assert not any(
        isinstance(item.identity, NetworkService) for item in result.inventory
    )
    assert {
        item.identity.origin
        for item in result.inventory
        if isinstance(item.identity, HttpOrigin)
    } == {ORIGIN}


def test_missing_peer_does_not_borrow_context_from_another_record() -> None:
    result = correlate(
        "lab",
        (
            source(
                1, target=WebTarget(origin=ORIGIN, approved_addresses=("127.0.0.1",))
            ),
            source(
                2, observations=(observation("http.status_code", 200),), scanner="httpx"
            ),
        ),
    )
    assert {rel.kind for rel in result.relationships} == {
        "configured_address",
        "resource_on_origin",
    }
    assert not any(
        isinstance(item.identity, NetworkService) for item in result.inventory
    )


def test_nuclei_only_inputs_preserve_resources_without_inventing_peers() -> None:
    result = correlate(
        "lab",
        (source(matches=(match(), match(path="/.git/config", template="git-config"))),),
    )
    assert len(result.findings) == 2 and result.assertions == ()
    assert {item.identity.kind for item in result.inventory} == {
        "http_origin",
        "http_resource",
    }
    assert {rel.kind for rel in result.relationships} == {"resource_on_origin"}
    assert {
        item.identity.resource
        for item in result.inventory
        if isinstance(item.identity, HttpResource)
    } == {"/", "/.git/config"}


def test_canonical_origin_and_exact_resource_spelling() -> None:
    result = correlate(
        "lab",
        (
            source(
                matches=(
                    match("HTTP://SITE.INVALID:80", "/"),
                    match("http://site.invalid", "/"),
                )
            ),
        ),
    )
    assert len(result.findings) == 1
    for left, right in (
        ("/A", "/a"),
        ("/%61", "/a"),
        ("/?a=1&b=2", "/?b=2&a=1"),
        ("/a/../", "/"),
    ):
        result = correlate(
            "lab", (source(matches=(match(path=left), match(path=right))),)
        )
        assert len(result.findings) == 2


@pytest.mark.parametrize(
    "location",
    [
        "http://site.invalid:8000.evil/",
        "http://site.invalid:8000@evil.invalid/",
        "https://site.invalid:8000/",
        "//site.invalid:8000/",
        ORIGIN + "/#fragment",
        ORIGIN + "/bad\npath",
        ORIGIN + "/bad\\path",
        "http://[invalid/",
    ],
)
def test_invalid_or_foreign_resource_rejected(location: str) -> None:
    with pytest.raises(CorrelationError):
        matched_resource(ORIGIN, location)


def test_differing_and_typed_values_preserve_every_source() -> None:
    observations = tuple(
        observation("http.example", value)
        for value in (True, 1, 1.0, "1", False, "closed", "filtered", "open")
    )
    result = correlate("lab", (source(observations=observations, scanner="httpx"),))
    assert len(result.assertions) == len(observations)
    for assertion in result.assertions:
        ref = assertion.occurrences[0]
        assert ref.ordinal is not None
        original = result.sources[0].report.observations[ref.ordinal]
        assert type(original.value) is type(assertion.value)
        assert original.value == assertion.value and original.evidence == (
            evidence("httpx"),
        )
    assert source().report.observations == ()


def test_every_projection_reference_resolves_to_preserved_input() -> None:
    originals = (
        source(
            matches=(match(),),
            observations=(
                observation("http.peer_address", "127.0.0.1"),
                observation("http.title", "Index"),
            ),
            target=WebTarget(origin=ORIGIN, approved_addresses=("127.0.0.1",)),
        ),
    )
    result = correlate("lab", originals)
    assert result.sources == originals
    refs = [ref for item in result.inventory for ref in item.sources]
    refs += [ref for rel in result.relationships for ref in rel.sources]
    refs += [ref for group in result.assertions for ref in group.occurrences]
    refs += [ref for group in result.findings for ref in group.occurrences]
    for ref in refs:
        original = next(item for item in originals if item.run_id == ref.run_id)
        if ref.section == "context":
            assert original.context.web_target is not None
        else:
            assert ref.ordinal is not None
            assert getattr(original.report, ref.section)[ref.ordinal].evidence
    ids = {item.id for item in result.inventory}
    assert all(
        rel.source_id in ids and rel.target_id in ids for rel in result.relationships
    )


def test_empty_completed_report_does_not_invent_negative_facts() -> None:
    result = correlate("lab", (source(),))
    assert result.inventory == ()
    assert result.assertions == ()
    assert result.findings == ()
    assert len(result.sources) == 1


def test_analysis_never_resolves_connects_or_executes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = (
        source(
            matches=(match(),),
            observations=(observation("http.peer_address", "127.0.0.1"),),
            target=WebTarget(origin=ORIGIN, approved_addresses=("127.0.0.1",)),
        ),
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("analysis attempted network or process activity")

    for name in (
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "gethostbyaddr",
        "create_connection",
        "socket",
    ):
        monkeypatch.setattr(socket, name, forbidden)
    for name in ("Popen", "run"):
        monkeypatch.setattr(subprocess, name, forbidden)
    assert correlate("lab", inputs).findings


@pytest.mark.parametrize(
    "inputs", [(), (source(), source()), (source(project="other"),)]
)
def test_invalid_selection_is_not_silently_adjusted(
    inputs: tuple[RunSource, ...],
) -> None:
    with pytest.raises(CorrelationError):
        correlate("lab", inputs)


@pytest.mark.parametrize(
    ("section", "ordinal"), [("matches", None), ("context", 0), ("observations", -1)]
)
def test_invalid_source_reference_rejected(section: str, ordinal: int | None) -> None:
    with pytest.raises(ValidationError):
        SourceReference.model_validate(
            {"run_id": UUID(int=1), "section": section, "ordinal": ordinal}
        )


def test_version_one_identity_is_stable() -> None:
    result = correlate("lab", (source(matches=(match(),)),))
    assert result.findings[0].id == (
        "finding-v1:4a119d43fd882c9bb5829cb6b243b5e098d37fa67d86dc7611049638675c03fd"
    )


def test_projection_contract_rejects_missing_provenance() -> None:
    result = correlate("lab", (source(matches=(match(),)),))
    inventory = result.inventory[0].model_dump()
    inventory["sources"] = []
    with pytest.raises(ValidationError):
        type(result.inventory[0]).model_validate(inventory)

    finding = result.findings[0].model_dump()
    finding["occurrences"] = []
    with pytest.raises(ValidationError):
        type(result.findings[0]).model_validate(finding)


def test_record_order_changes_references_without_changing_identity() -> None:
    matches = (match(), match(path="/.git/config", template="git-config"))
    observations = (
        observation("http.title", "Index"),
        observation("http.status_code", 200),
    )
    first = correlate("lab", (source(matches=matches, observations=observations),))
    second = correlate(
        "lab", (source(matches=matches[::-1], observations=observations[::-1]),)
    )
    assert [finding.identity for finding in first.findings] == [
        finding.identity for finding in second.findings
    ]
    assert [finding.id for finding in first.findings] == [
        finding.id for finding in second.findings
    ]
    for result in (first, second):
        for finding in result.findings:
            ordinal = finding.occurrences[0].ordinal
            assert ordinal is not None
            assert (
                result.sources[0].report.matches[ordinal].template_id
                == finding.identity.template_id
            )
        for assertion in result.assertions:
            ordinal = assertion.occurrences[0].ordinal
            assert ordinal is not None
            original = result.sources[0].report.observations[ordinal]
            assert (original.key, original.value) == (assertion.key, assertion.value)


@pytest.mark.parametrize(
    "titles",
    [
        ("Exposed resource", "Exposed resource"),
        ("Exposed resource", "Exposed resources"),
    ],
)
def test_nuclei_display_titles_do_not_define_groups(titles: tuple[str, str]) -> None:
    import json

    from scopelens.adapters.nuclei import NucleiAdapter
    from tests.test_nuclei import CONTEXT, RAW

    records = [json.loads(line) for line in RAW.splitlines()]
    for record, title in zip(records, titles, strict=True):
        record["info"]["name"] = title
    raw = "\n".join(json.dumps(record) for record in records).encode()
    report = NucleiAdapter().parse(raw, CONTEXT)
    result = correlate("lab", (source().model_copy(update={"report": report}),))
    assert len(result.findings) == 2
    assert result.sources[0].report == report
