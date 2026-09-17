import socket
import subprocess
from datetime import UTC, datetime
from hashlib import sha256
from unittest.mock import AsyncMock
from uuid import UUID

import pytest

from scopelens.adapters.base import ImportContext, ParsedReport
from scopelens.adapters.nuclei_templates import reviewed_templates
from scopelens.analysis.correlation import correlate
from scopelens.analysis.models import RunSource
from scopelens.assessment.capture import assess_correlation
from scopelens.assessment.models import (
    AcquisitionEvidence,
    AcquisitionStatus,
    CapturedResponse,
    FreshRecheckUse,
    RecheckAcquisition,
    RecheckReport,
    assessment_id,
)
from scopelens.assessment.rules import (
    DIRECTORY_RULE,
    GIT_CONFIG_RULE,
    HSTS_RULE,
    CapturedExchange,
    assess_exposure_recheck,
    assess_hsts_recheck,
    exposure_claim,
)
from scopelens.cli import main
from scopelens.domain.evidence import EvidenceReference, Observation
from scopelens.domain.findings import ScannerMatch
from scopelens.domain.scope import ScanProfile, WebTarget
from scopelens.domain.services import HttpEndpoint

NOW = datetime(2026, 9, 16, tzinfo=UTC)
ORIGIN = "http://site.invalid:8000"


def acquisition(
    *,
    number: int = 1,
    origin: str = ORIGIN,
    resource: str = "/",
    status: AcquisitionStatus = "complete",
    status_code: int = 200,
    body: bytes = b"",
    headers_complete: bool = True,
    body_complete: bool = True,
    hsts: bool = False,
    encoded: bool = False,
    access_challenge: bool = False,
) -> CapturedExchange:
    raw_hash = sha256(b"raw" + bytes([number])).hexdigest()
    response = (
        CapturedResponse(
            status_code=status_code,
            headers_complete=headers_complete,
            body_complete=body_complete,
            body_sha256=sha256(body).hexdigest(),
            strict_transport_security_present=hsts,
            access_challenge_present=access_challenge,
            content_encoding_identity=not encoded,
        )
        if status in ("complete", "truncated")
        else None
    )
    return CapturedExchange(
        RecheckAcquisition(
            id=UUID(int=number),
            started_at=NOW,
            origin=origin,
            approved_address="127.0.0.1",
            resource=resource,
            status=status,
            evidence=(
                AcquisitionEvidence(
                    artifact_path=f"private/{number}/response.http",
                    artifact_sha256=raw_hash,
                    size_bytes=len(body),
                )
                if status in ("complete", "truncated")
                else None
            ),
            response=response,
        ),
        body,
    )


@pytest.mark.parametrize(
    ("rule_id", "resource", "vulnerable", "fixed", "lookalike"),
    [
        (
            DIRECTORY_RULE,
            "/",
            b"<title>Directory listing for /</title><a href='a'>a</a>",
            b"Not found",
            b"<title>Directory listing for /</title><p>No links here</p>",
        ),
        (
            GIT_CONFIG_RULE,
            "/.git/config",
            b"[core]\nrepositoryformatversion = 0\n",
            b"Not found",
            b"Documentation mentions repositoryformatversion but is not a Git config.",
        ),
    ],
)
def test_vulnerable_fixed_and_lookalike_semantics(
    rule_id: str,
    resource: str,
    vulnerable: bytes,
    fixed: bytes,
    lookalike: bytes,
) -> None:
    positive = assess_exposure_recheck(
        "lab", rule_id, acquisition(resource=resource, body=vulnerable)
    )
    negative = assess_exposure_recheck(
        "lab",
        rule_id,
        acquisition(number=2, resource=resource, status_code=404, body=fixed),
    )
    harmless = assess_exposure_recheck(
        "lab", rule_id, acquisition(number=3, resource=resource, body=lookalike)
    )
    assert positive.outcome == "supported_positive"
    assert negative.outcome == "supported_negative"
    assert harmless.outcome == "supported_negative"


@pytest.mark.parametrize(
    ("status", "code", "body_complete", "expected_reason"),
    [
        ("timeout", 200, True, "recheck_timed_out"),
        ("transport_error", 200, True, "transport_failed"),
        ("cancelled", 200, True, "recheck_cancelled"),
        ("not_run", 200, True, "check_not_run"),
        ("malformed", 200, True, "response_malformed"),
        ("truncated", 200, False, "response_truncated"),
        ("complete", 302, True, "redirect_prevented_evaluation"),
        ("complete", 403, True, "response_blocked_or_ambiguous"),
        ("complete", 503, True, "response_blocked_or_ambiguous"),
        ("complete", 400, True, "response_status_ambiguous"),
    ],
)
def test_failed_incomplete_redirected_or_blocked_is_inconclusive(
    status: AcquisitionStatus,
    code: int,
    body_complete: bool,
    expected_reason: str,
) -> None:
    result = assess_exposure_recheck(
        "lab",
        DIRECTORY_RULE,
        acquisition(status=status, status_code=code, body_complete=body_complete),
    )
    assert result.outcome == "inconclusive"
    assert result.reason == expected_reason
    assert isinstance(result.evidence_used[0], FreshRecheckUse)


def test_missing_prerequisite_is_not_supported_negative() -> None:
    result = assess_exposure_recheck(
        "lab", DIRECTORY_RULE, acquisition(resource="/.git/config")
    )
    assert result.outcome == "inconclusive"
    assert result.reason == "wrong_resource"


def test_explicit_access_challenge_is_not_a_false_negative() -> None:
    exposure = assess_exposure_recheck(
        "lab", DIRECTORY_RULE, acquisition(access_challenge=True)
    )
    hsts = assess_hsts_recheck(
        "lab",
        acquisition(origin="https://site.invalid", access_challenge=True),
    )
    assert exposure.outcome == "inconclusive"
    assert hsts.outcome == "inconclusive"
    assert exposure.reason == hsts.reason == "response_blocked_or_ambiguous"


def test_fresh_acquisitions_have_distinct_provenance() -> None:
    first = assess_exposure_recheck(
        "lab", DIRECTORY_RULE, acquisition(number=1, body=b"Not a listing")
    )
    second = assess_exposure_recheck(
        "lab", DIRECTORY_RULE, acquisition(number=2, body=b"Not a listing")
    )
    assert first.id == second.id
    first_use, second_use = first.evidence_used[0], second.evidence_used[0]
    assert isinstance(first_use, FreshRecheckUse)
    assert isinstance(second_use, FreshRecheckUse)
    assert first_use.acquisition_id != second_use.acquisition_id


def test_rule_version_is_part_of_assessment_identity() -> None:
    claim = exposure_claim(DIRECTORY_RULE, ORIGIN)
    changed = claim.model_copy(update={"rule_version": "2"})
    assert assessment_id("lab", claim) != assessment_id("lab", changed)
    reworded = claim.model_copy(update={"statement": "Different display wording."})
    assert assessment_id("lab", claim) == assessment_id("lab", reworded)


def test_response_body_must_match_its_evidence_digest() -> None:
    exchange = acquisition(body=b"captured")
    with pytest.raises(ValueError, match="body bytes do not match"):
        CapturedExchange(exchange.acquisition, b"different")


@pytest.mark.parametrize(
    ("origin", "hsts", "headers_complete", "status_code", "outcome"),
    [
        ("https://site.invalid", False, True, 200, "supported_negative"),
        ("https://site.invalid", True, True, 200, "supported_positive"),
        ("https://127.0.0.1", False, True, 200, "inconclusive"),
        ("http://site.invalid", False, True, 200, "inconclusive"),
        ("https://site.invalid", False, False, 200, "inconclusive"),
        ("https://site.invalid", False, True, 302, "inconclusive"),
        ("https://site.invalid", False, True, 403, "inconclusive"),
        ("https://site.invalid", False, True, 500, "inconclusive"),
    ],
)
def test_hsts_prerequisites_and_outcomes(
    origin: str,
    hsts: bool,
    headers_complete: bool,
    status_code: int,
    outcome: str,
) -> None:
    status: AcquisitionStatus = "complete" if headers_complete else "truncated"
    result = assess_hsts_recheck(
        "lab",
        acquisition(
            origin=origin,
            status=status,
            status_code=status_code,
            hsts=hsts,
            headers_complete=headers_complete,
            body_complete=status == "complete",
        ),
    )
    assert result.outcome == outcome


def _evidence(scanner: str, digest: str = "a" * 64) -> EvidenceReference:
    return EvidenceReference(
        artifact_sha256=digest,
        record_locator="$",
        scanner=scanner,
        scanner_version="test",
        adapter_version="test",
        profile_id="web",
        profile_revision="1",
        captured_at=NOW,
    )


def _source(
    number: int,
    *,
    scanner: str,
    matches: tuple[ScannerMatch, ...] = (),
    observations: tuple[Observation, ...] = (),
    digest: str = "a" * 64,
    origin: str = ORIGIN,
) -> RunSource:
    target = WebTarget(origin=origin, approved_addresses=("127.0.0.1",))
    return RunSource(
        run_id=UUID(int=number),
        project_id="lab",
        kind="import",
        created_at=NOW,
        scope_snapshot_id="c" * 64,
        profile=ScanProfile(id="web"),
        context=ImportContext(
            profile_id="web", profile_revision="1", web_target=target
        ),
        report=ParsedReport(
            evidence=_evidence(scanner, digest),
            reported_exit=None,
            observations=observations,
            matches=matches,
        ),
        artifacts=(),
    )


def test_existing_nuclei_match_is_positive_but_empty_output_is_inconclusive() -> None:
    match = ScannerMatch(
        origin=ORIGIN,
        matched_location=ORIGIN + "/",
        template_id="scopelens-directory-listing",
        template_revision=reviewed_templates()[0].sha256,
        matcher="listing",
        scanner_severity="low",
        evidence=(_evidence("nuclei"),),
    )
    report = assess_correlation(
        correlate(
            "lab",
            (
                _source(1, scanner="nuclei", matches=(match,)),
                _source(2, scanner="nuclei"),
            ),
        )
    )
    by_rule = {item.claim.rule_id: item for item in report.assessments}
    assert by_rule[DIRECTORY_RULE].outcome == "supported_positive"
    assert by_rule[GIT_CONFIG_RULE].outcome == "inconclusive"
    assert len(by_rule[DIRECTORY_RULE].evidence_used) == 1


def test_repeated_import_is_preserved_without_independent_confirmation() -> None:
    match = ScannerMatch(
        origin=ORIGIN,
        matched_location=ORIGIN + "/",
        template_id="scopelens-directory-listing",
        template_revision=reviewed_templates()[0].sha256,
        matcher="listing",
        scanner_severity="low",
        evidence=(_evidence("nuclei"),),
    )
    sources = (
        _source(1, scanner="nuclei", matches=(match,)),
        _source(2, scanner="nuclei", matches=(match,)),
    )
    result = assess_correlation(correlate("lab", sources))
    repeated = assess_correlation(correlate("lab", reversed(sources)))
    assert result.model_dump_json() == repeated.model_dump_json()
    assert type(result).model_validate_json(result.model_dump_json()) == result
    assessment = next(
        item for item in result.assessments if item.claim.rule_id == DIRECTORY_RULE
    )
    assert len(assessment.evidence_used) == 2
    assert any(
        "not independent confirmation" in item for item in assessment.limitations
    )
    assert "confidence" not in result.model_dump_json()


def test_existing_httpx_can_support_header_presence_but_not_absence() -> None:
    origin = "https://site.invalid"
    endpoint = HttpEndpoint(origin=origin)
    evidence = _evidence("httpx")
    observations = tuple(
        Observation(subject=endpoint, key=key, value=value, evidence=(evidence,))
        for key, value in (
            ("http.probe_succeeded", True),
            ("http.status_code", 200),
            ("http.header.strict_transport_security", "max-age=31536000"),
        )
    )
    report = assess_correlation(
        correlate(
            "lab",
            (_source(1, scanner="httpx", observations=observations, origin=origin),),
        )
    )
    hsts = next(item for item in report.assessments if item.claim.rule_id == HSTS_RULE)
    assert hsts.outcome == "supported_positive"
    without_header = assess_correlation(
        correlate(
            "lab",
            (
                _source(
                    2, scanner="httpx", observations=observations[:2], origin=origin
                ),
            ),
        )
    )
    missing = next(
        item for item in without_header.assessments if item.claim.rule_id == HSTS_RULE
    )
    assert missing.outcome == "inconclusive"


def test_capture_assessment_performs_no_network_dns_or_process_activity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = correlate("lab", (_source(1, scanner="nuclei"),))

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("capture assessment attempted external activity")

    for name in ("getaddrinfo", "gethostbyname", "create_connection", "socket"):
        monkeypatch.setattr(socket, name, forbidden)
    for name in ("Popen", "run"):
        monkeypatch.setattr(subprocess, name, forbidden)
    assert assess_correlation(result).basis == "existing_capture"


def test_recheck_cli_has_no_rule_path_or_flag_escape(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from scopelens import cli

    target = WebTarget(origin=ORIGIN, approved_addresses=("127.0.0.1",))
    exchange = acquisition(body=b"Not a listing")
    result = RecheckReport(
        project_id="lab",
        acquisitions=(exchange.acquisition,),
        assessments=(assess_exposure_recheck("lab", DIRECTORY_RULE, exchange),),
    )
    assert RecheckReport.model_validate_json(result.model_dump_json()) == result
    runner = AsyncMock(return_value=result)
    monkeypatch.setattr(cli, "load_config", lambda _: object())
    monkeypatch.setattr(cli, "recheck_web", runner)
    arguments = [
        "recheck-web",
        "scope.toml",
        "--profile",
        "web",
        "--origin",
        ORIGIN,
        "--address",
        "127.0.0.1",
    ]
    main(arguments)
    assert capsys.readouterr().out == result.model_dump_json(indent=2) + "\n"
    assert runner.await_args is not None
    called_target = runner.await_args.args[3]
    assert called_target == target
    for extra in (("--path", "/other"), ("--rule", "arbitrary"), ("--flag", "x")):
        with pytest.raises(SystemExit):
            main([*arguments, *extra])
        assert "unrecognized arguments" in capsys.readouterr().err


@pytest.mark.parametrize("hsts", [False, True])
def test_hsts_complete_headers_can_be_assessed_despite_body_truncation(
    hsts: bool,
) -> None:
    result = assess_hsts_recheck(
        "lab",
        acquisition(
            origin="https://site.invalid",
            status="truncated",
            body_complete=False,
            headers_complete=True,
            hsts=hsts,
        ),
    )
    assert result.outcome == ("supported_positive" if hsts else "supported_negative")


@pytest.mark.parametrize("status_code", [200, 404, 410])
def test_explicit_block_page_is_not_an_absence_check(status_code: int) -> None:
    blocked = acquisition(
        origin="https://site.invalid",
        status_code=status_code,
        body=b"<html><title>Access denied</title><p>Request blocked by policy</p></html>",
    )
    assert (
        assess_exposure_recheck("lab", DIRECTORY_RULE, blocked).outcome
        == "inconclusive"
    )
    assert assess_hsts_recheck("lab", blocked).outcome == "inconclusive"


def test_partial_content_is_not_complete_resource_evidence() -> None:
    partial = acquisition(
        origin="https://site.invalid", status_code=206, body=b"fragment"
    )
    assert (
        assess_exposure_recheck("lab", DIRECTORY_RULE, partial).outcome
        == "inconclusive"
    )
    assert assess_hsts_recheck("lab", partial).outcome == "inconclusive"


@pytest.mark.parametrize("status_code", [200, 404, 410])
def test_generic_usable_response_only_disproves_exact_exposure_markers(
    status_code: int,
) -> None:
    for rule_id, resource in ((DIRECTORY_RULE, "/"), (GIT_CONFIG_RULE, "/.git/config")):
        exchange = acquisition(
            resource=resource, status_code=status_code, body=b"Welcome"
        )
        result = assess_exposure_recheck("lab", rule_id, exchange)
        assert result.outcome == "supported_negative"
        assert result.claim.resource == resource
        assert isinstance(result.evidence_used[0], FreshRecheckUse)
        assert result.evidence_used[0].acquisition_id == exchange.acquisition.id


def test_stored_hsts_does_not_combine_different_response_records() -> None:
    import json

    from scopelens.adapters.httpx import HTTPX_VERSION, HttpxAdapter

    origin = "https://site.invalid"
    records = [
        {
            "timestamp": NOW.isoformat(),
            "url": "https://127.0.0.1",
            "host_ip": "127.0.0.1",
            "failed": False,
            "status_code": 403,
            "header": {"strict_transport_security": "max-age=1"},
        },
        {
            "timestamp": NOW.isoformat(),
            "url": "https://127.0.0.2",
            "host_ip": "127.0.0.2",
            "failed": False,
            "status_code": 200,
        },
    ]
    target = WebTarget(origin=origin, approved_addresses=("127.0.0.1", "127.0.0.2"))
    for ordered in (records, list(reversed(records))):
        context = ImportContext(
            profile_id="web",
            profile_revision="1",
            scanner_version=HTTPX_VERSION,
            web_target=target,
        )
        report = HttpxAdapter().parse(
            "\n".join(json.dumps(row) for row in ordered).encode(), context
        )
        source = _source(1, scanner="httpx", origin=origin).model_copy(
            update={"report": report, "context": context}
        )
        result = assess_correlation(correlate("lab", (source,)))
        assert result.assessments[0].outcome == "inconclusive"


def test_stored_hsts_auth_challenge_cannot_support_a_conclusion() -> None:
    origin = "https://site.invalid"
    observations = tuple(
        Observation(
            subject=HttpEndpoint(origin=origin),
            key=key,
            value=value,
            evidence=(_evidence("httpx"),),
        )
        for key, value in (
            ("http.probe_succeeded", True),
            ("http.status_code", 200),
            ("http.header.strict_transport_security", "max-age=1"),
            ("http.header.www_authenticate", "Basic realm=private"),
        )
    )
    result = assess_correlation(
        correlate(
            "lab",
            (_source(1, scanner="httpx", origin=origin, observations=observations),),
        )
    )
    assert (
        next(
            item for item in result.assessments if item.claim.rule_id == HSTS_RULE
        ).outcome
        == "inconclusive"
    )


@pytest.mark.parametrize(
    "body",
    [b"Access denied", b"Please complete the CAPTCHA", b"<input type='password'>"],
)
def test_ambiguous_access_page_is_inconclusive(body: bytes) -> None:
    exchange = acquisition(origin="https://site.invalid", body=body)
    assert (
        assess_exposure_recheck("lab", DIRECTORY_RULE, exchange).outcome
        == "inconclusive"
    )
    assert assess_hsts_recheck("lab", exchange).outcome == "inconclusive"


@pytest.mark.parametrize("code", [200, 404, 410])
def test_encoded_body_cannot_establish_exposure_absence(code: int) -> None:
    result = assess_exposure_recheck(
        "lab", DIRECTORY_RULE, acquisition(status_code=code, encoded=True)
    )
    assert result.outcome == "inconclusive"


@pytest.mark.parametrize(
    "status", ["timeout", "cancelled", "not_run", "transport_error", "malformed"]
)
def test_hsts_failed_acquisitions_are_inconclusive(status: AcquisitionStatus) -> None:
    assert (
        assess_hsts_recheck(
            "lab", acquisition(origin="https://site.invalid", status=status)
        ).outcome
        == "inconclusive"
    )


@pytest.mark.parametrize("resource", ["/", "/other"])
def test_unreviewed_nuclei_revision_or_resource_is_not_validated(resource: str) -> None:
    match = ScannerMatch(
        origin=ORIGIN,
        matched_location=ORIGIN + resource,
        template_id="scopelens-directory-listing",
        template_revision="b" * 64
        if resource == "/"
        else reviewed_templates()[0].sha256,
        matcher="listing",
        scanner_severity="low",
        evidence=(_evidence("nuclei"),),
    )
    report = assess_correlation(
        correlate("lab", (_source(1, scanner="nuclei", matches=(match,)),))
    )
    assert all(item.outcome == "inconclusive" for item in report.assessments)
    checked = next(
        item for item in report.assessments if item.claim.resource == resource
    )
    assert checked.reason == "unreviewed_match_context"


def test_nuclei_severity_does_not_change_assessment_identity() -> None:
    match = ScannerMatch(
        origin=ORIGIN,
        matched_location=ORIGIN + "/",
        template_id="scopelens-directory-listing",
        template_revision=reviewed_templates()[0].sha256,
        matcher="listing",
        scanner_severity="low",
        evidence=(_evidence("nuclei"),),
    )
    changed = match.model_copy(update={"scanner_severity": "high"})
    first = assess_correlation(
        correlate("lab", (_source(1, scanner="nuclei", matches=(match,)),))
    )
    second = assess_correlation(
        correlate("lab", (_source(2, scanner="nuclei", matches=(changed,)),))
    )
    assert [item.id for item in first.assessments] == [
        item.id for item in second.assessments
    ]
    assert [item.outcome for item in first.assessments] == [
        item.outcome for item in second.assessments
    ]


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 200 OK\r\nX: " + b"x" * 32768 + b"\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 O\x00K\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Range: bytes 0-1/10\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0;\x00\r\n\r\n",
    ],
    ids=["header-limit", "status-control", "partial-representation", "chunk-extension"],
)
def test_uncertain_wire_response_is_rejected(raw: bytes) -> None:
    from scopelens.assessment.recheck import _MalformedResponse, _parse_response

    with pytest.raises(_MalformedResponse):
        _parse_response(raw, eof=True)


@pytest.mark.parametrize("framing", ["length", "chunked"])
def test_truncated_hsts_keeps_captured_block_indicators(framing: str) -> None:
    from scopelens.assessment.recheck import _incomplete_response

    body = b"<title>Access denied</title>"
    raw = b"HTTP/1.1 200 OK\r\n" + (
        b"Content-Length: 1000\r\n\r\n" + body
        if framing == "length"
        else b"Transfer-Encoding: chunked\r\n\r\n11\r\n<title>Access den\r\n100\r\nied</title>"
    )
    incomplete = _incomplete_response(raw)
    assert incomplete is not None
    response, captured_body = incomplete
    assert captured_body == body
    recorded = acquisition(
        origin="https://site.invalid",
        status="truncated",
        body_complete=False,
        body=body,
    )
    exchange = CapturedExchange(
        recorded.acquisition.model_copy(update={"response": response}), captured_body
    )
    assert assess_hsts_recheck("lab", exchange).outcome == "inconclusive"


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: +1000\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nXYZ\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nXYZ",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxZ",
    ],
)
def test_truncation_cannot_hide_invalid_or_incomplete_headers(raw: bytes) -> None:
    from scopelens.assessment.recheck import _incomplete_response

    assert _incomplete_response(raw) is None


@pytest.mark.parametrize(
    "key,value",
    [
        ("http.header.strict_transport_security", "max-age=1"),
        ("http.status_code", 200),
        ("http.peer_address", "127.0.0.1"),
    ],
)
def test_origin_without_qualifying_response_cannot_inherit_hsts_presence(
    key: str, value: str | int
) -> None:
    first, second = "https://first.invalid", "https://second.invalid"
    first_observations = tuple(
        Observation(
            subject=HttpEndpoint(origin=first),
            key=key,
            value=value,
            evidence=(_evidence("httpx"),),
        )
        for key, value in (
            ("http.probe_succeeded", True),
            ("http.status_code", 200),
            ("http.header.strict_transport_security", "max-age=1"),
        )
    )
    second_observations = (
        Observation(
            subject=HttpEndpoint(origin=second),
            key=key,
            value=value,
            evidence=(_evidence("httpx"),),
        ),
    )
    report = assess_correlation(
        correlate(
            "lab",
            (
                _source(
                    1, scanner="httpx", origin=first, observations=first_observations
                ),
                _source(
                    2, scanner="httpx", origin=second, observations=second_observations
                ),
            ),
        )
    )
    assert any(
        item.claim.origin == first and item.outcome == "supported_positive"
        for item in report.assessments
    )
    assert all(
        item.outcome == "inconclusive"
        for item in report.assessments
        if item.claim.origin == second
    )


def test_unknown_nuclei_templates_and_matchers_are_explicitly_inconclusive() -> None:
    matches = tuple(
        ScannerMatch(
            origin=ORIGIN,
            matched_location=ORIGIN + "/",
            template_id=template_id,
            template_revision=reviewed_templates()[0].sha256,
            matcher=matcher,
            scanner_severity="low",
            evidence=(_evidence("nuclei"),),
        )
        for template_id, matcher in (
            ("unknown-one", "listing"),
            ("unknown-two", "listing"),
            ("scopelens-directory-listing", "unknown-matcher"),
        )
    )
    result = assess_correlation(
        correlate("lab", (_source(1, scanner="nuclei", matches=matches),))
    )
    unknown = [
        item for item in result.assessments if item.reason == "unreviewed_match_context"
    ]
    assert len(unknown) == 3
    assert len({item.id for item in unknown}) == 3
    assert all(
        item.outcome == "inconclusive" and item.evidence_used for item in unknown
    )
