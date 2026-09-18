import re
from dataclasses import dataclass
from hashlib import sha256
from ipaddress import IPv4Address
from typing import Literal
from urllib.parse import urlsplit

from scopelens.assessment.models import (
    AssessmentResult,
    Claim,
    EvidenceFact,
    FreshRecheckUse,
    Outcome,
    Prerequisite,
    RecheckAcquisition,
    assessment_id,
)

DIRECTORY_RULE = "scopelens.directory-listing"
GIT_CONFIG_RULE = "scopelens.git-config-exposure"
HSTS_RULE = "scopelens.hsts-header-missing"
RULE_VERSION = "1"

_ACCESS_PAGE = re.compile(
    rb"<title\b[^>]*>\s*(?:access denied|request blocked|forbidden|"
    rb"just a moment|attention required|verify (?:you are|you're) human|"
    rb"sign in|log[ -]?in)\b",
    re.IGNORECASE,
)
_PASSWORD_INPUT = re.compile(
    rb"<input\b[^>]*\btype\s*=\s*['\"]?password\b", re.IGNORECASE
)
_BLOCK_NOTICE = re.compile(
    rb"\b(?:access denied|request (?:was )?blocked|authentication required|"
    rb"verify (?:that )?(?:you are|you're) human|captcha)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CapturedExchange:
    acquisition: RecheckAcquisition
    body: bytes

    def __post_init__(self) -> None:
        response = self.acquisition.response
        if response is None:
            if self.body:
                raise ValueError("body bytes require captured response evidence")
        elif sha256(self.body).hexdigest() != response.body_sha256:
            raise ValueError("body bytes do not match captured response evidence")


def access_page(body: bytes) -> bool:
    return bool(
        _ACCESS_PAGE.search(body)
        or _PASSWORD_INPUT.search(body)
        or _BLOCK_NOTICE.search(body)
    )


def exposure_claim(rule_id: str, origin: str) -> Claim:
    if rule_id == DIRECTORY_RULE:
        return Claim(
            rule_id=rule_id,
            rule_version=RULE_VERSION,
            origin=origin,
            resource="/",
            statement=(
                "The checked directory resource returned HTTP 200 and the reviewed "
                "directory-listing body markers."
            ),
        )
    if rule_id == GIT_CONFIG_RULE:
        return Claim(
            rule_id=rule_id,
            rule_version=RULE_VERSION,
            origin=origin,
            resource="/.git/config",
            statement=(
                "The checked Git configuration resource returned HTTP 200 and "
                "contained the reviewed Git configuration body markers."
            ),
        )
    raise ValueError("unsupported exposure assessment rule")


def hsts_claim(origin: str) -> Claim:
    return Claim(
        rule_id=HSTS_RULE,
        rule_version=RULE_VERSION,
        origin=origin,
        resource="/",
        statement=(
            "The checked HTTPS hostname response lacked a "
            "Strict-Transport-Security header."
        ),
    )


def _prerequisite(id: str, met: bool | None, explanation: str) -> Prerequisite:
    state: Literal["met", "not_met", "unknown"]
    state = "unknown" if met is None else "met" if met else "not_met"
    return Prerequisite(id=id, state=state, explanation=explanation)


def _failure_reason(acquisition: RecheckAcquisition) -> tuple[str, str]:
    reasons = {
        "timeout": (
            "recheck_timed_out",
            "The targeted request timed out before usable evidence was captured.",
        ),
        "transport_error": (
            "transport_failed",
            "The targeted request failed at the transport layer.",
        ),
        "cancelled": (
            "recheck_cancelled",
            "The targeted request was cancelled before evaluation completed.",
        ),
        "malformed": (
            "response_malformed",
            "The response could not be interpreted as complete HTTP evidence.",
        ),
        "truncated": (
            "response_truncated",
            "The captured response was truncated before required evidence completed.",
        ),
        "not_run": (
            "check_not_run",
            "The scan deadline was reached before this targeted request ran.",
        ),
    }
    return reasons.get(
        acquisition.status,
        ("response_unusable", "The targeted request did not yield usable evidence."),
    )


def _fresh_use(
    acquisition: RecheckAcquisition, *facts: EvidenceFact
) -> tuple[FreshRecheckUse, ...]:
    return (FreshRecheckUse(acquisition_id=acquisition.id, facts=tuple(facts)),)


def assess_exposure_recheck(
    project_id: str, rule_id: str, exchange: CapturedExchange
) -> AssessmentResult:
    acquisition = exchange.acquisition
    claim = exposure_claim(rule_id, acquisition.origin)
    correct_resource = acquisition.resource == claim.resource
    response = acquisition.response
    complete = (
        acquisition.status == "complete"
        and response is not None
        and response.headers_complete
        and response.body_complete
    )
    prerequisites = (
        _prerequisite(
            "authorized_target",
            True,
            "The acquisition used the approved origin and destination address.",
        ),
        _prerequisite(
            "intended_resource",
            correct_resource,
            "The acquisition path matches the resource defined by this rule.",
        ),
        _prerequisite(
            "complete_response",
            complete,
            "A complete status, header block, and response body are required.",
        ),
    )
    if not correct_resource:
        return AssessmentResult(
            id=assessment_id(project_id, claim),
            claim=claim,
            prerequisites=prerequisites,
            outcome="inconclusive",
            reason="wrong_resource",
            explanation="The acquisition did not evaluate the rule's exact resource.",
            evidence_used=_fresh_use(
                acquisition,
                EvidenceFact(key="acquisition.status", value=acquisition.status),
            ),
            limitations=("No conclusion is drawn for another path or origin.",),
        )
    if not complete or response is None:
        reason, explanation = _failure_reason(acquisition)
        return AssessmentResult(
            id=assessment_id(project_id, claim),
            claim=claim,
            prerequisites=prerequisites,
            outcome="inconclusive",
            reason=reason,
            explanation=explanation,
            evidence_used=_fresh_use(
                acquisition,
                EvidenceFact(key="acquisition.status", value=acquisition.status),
            ),
            limitations=(
                "Missing or incomplete response bytes cannot establish absence.",
            ),
        )

    facts = (
        EvidenceFact(key="http.status_code", value=response.status_code),
        EvidenceFact(key="http.body_sha256", value=response.body_sha256),
        EvidenceFact(key="http.body_complete", value=response.body_complete),
    )
    if 300 <= response.status_code < 400:
        return AssessmentResult(
            id=assessment_id(project_id, claim),
            claim=claim,
            prerequisites=prerequisites,
            outcome="inconclusive",
            reason="redirect_prevented_evaluation",
            explanation="The intended resource returned a redirect, which was not followed.",
            evidence_used=_fresh_use(acquisition, *facts),
            limitations=("The redirect destination was not authorized or evaluated.",),
        )
    if (
        response.access_challenge_present
        or access_page(exchange.body)
        or response.status_code in (401, 403, 407, 429)
        or response.status_code >= 500
    ):
        return AssessmentResult(
            id=assessment_id(project_id, claim),
            claim=claim,
            prerequisites=prerequisites,
            outcome="inconclusive",
            reason="response_blocked_or_ambiguous",
            explanation="The response could represent authentication, blocking, or a server failure.",
            evidence_used=_fresh_use(acquisition, *facts),
            limitations=(
                "The response does not establish whether the condition is absent.",
            ),
        )
    if response.status_code not in (200, 404, 410):
        return AssessmentResult(
            id=assessment_id(project_id, claim),
            claim=claim,
            prerequisites=prerequisites,
            outcome="inconclusive",
            reason="response_status_ambiguous",
            explanation="The response status does not support a reliable evaluation.",
            evidence_used=_fresh_use(acquisition, *facts),
            limitations=(
                "Only a usable success response or an explicit not-found response can "
                "support a negative for this condition.",
            ),
        )
    if not response.content_encoding_identity:
        return AssessmentResult(
            id=assessment_id(project_id, claim),
            claim=claim,
            prerequisites=prerequisites,
            outcome="inconclusive",
            reason="unsupported_content_encoding",
            explanation="The response body was encoded and was not decoded for this rule.",
            evidence_used=_fresh_use(acquisition, *facts),
            limitations=("Encoded body bytes cannot be treated as a negative match.",),
        )

    body = exchange.body
    matched = response.status_code == 200 and (
        (
            rule_id == DIRECTORY_RULE
            and (
                b"<title>Directory listing for /" in body
                or b"<title>Index of /" in body
            )
            and b"href=" in body
        )
        or (
            rule_id == GIT_CONFIG_RULE
            and b"[core]" in body
            and b"repositoryformatversion" in body
        )
    )
    outcome: Outcome = "supported_positive" if matched else "supported_negative"
    reason = "reviewed_markers_present" if matched else "reviewed_condition_absent"
    explanation = (
        "The complete response satisfied the reviewed status and body conditions."
        if matched
        else "The complete usable response did not satisfy the reviewed condition."
    )
    return AssessmentResult(
        id=assessment_id(project_id, claim),
        claim=claim,
        prerequisites=prerequisites,
        outcome=outcome,
        reason=reason,
        explanation=explanation,
        evidence_used=_fresh_use(
            acquisition,
            *facts,
            EvidenceFact(key="rule.markers_present", value=matched),
        ),
        limitations=(
            "This result evaluates only the exact resource and reviewed markers.",
            "It does not establish compromise, secret exposure, or exploitability.",
            "Matching markers do not authenticate the resource's content or type.",
            "An unmarked intermediary response cannot be distinguished from the origin response.",
        ),
    )


def assess_hsts_recheck(
    project_id: str, exchange: CapturedExchange
) -> AssessmentResult:
    acquisition = exchange.acquisition
    claim = hsts_claim(acquisition.origin)
    parsed = urlsplit(acquisition.origin)
    https = parsed.scheme == "https"
    try:
        IPv4Address(parsed.hostname or "")
    except ValueError:
        hostname = True
    else:
        hostname = False
    response = acquisition.response
    correct_resource = acquisition.resource == "/"
    usable = (
        correct_resource
        and acquisition.status in ("complete", "truncated")
        and response is not None
        and response.headers_complete
        and response.status_code == 200
        and response.content_encoding_identity
        and not response.access_challenge_present
        and not access_page(exchange.body)
    )
    prerequisites = (
        _prerequisite("https_origin", https, "HSTS applies only to an HTTPS origin."),
        _prerequisite(
            "hostname_origin",
            hostname,
            "This rule is limited to hostname origins, not IP literals.",
        ),
        _prerequisite(
            "intended_resource",
            correct_resource,
            "The acquisition must evaluate the origin root for this rule.",
        ),
        _prerequisite(
            "complete_headers",
            response.headers_complete if response is not None else None,
            "A complete response header block is required to assess header absence.",
        ),
        _prerequisite(
            "usable_response",
            usable,
            "The intended resource must return a usable non-redirect response.",
        ),
    )
    if not https or not hostname:
        return AssessmentResult(
            id=assessment_id(project_id, claim),
            claim=claim,
            prerequisites=prerequisites,
            outcome="inconclusive",
            reason="hsts_not_applicable",
            explanation="The target is outside this rule's hostname-based HTTPS context.",
            evidence_used=_fresh_use(
                acquisition,
                EvidenceFact(key="acquisition.status", value=acquisition.status),
            ),
            limitations=("No HSTS conclusion is made for HTTP or IP-literal origins.",),
        )
    if not correct_resource:
        return AssessmentResult(
            id=assessment_id(project_id, claim),
            claim=claim,
            prerequisites=prerequisites,
            outcome="inconclusive",
            reason="wrong_resource",
            explanation="The acquisition did not evaluate the rule's exact resource.",
            evidence_used=_fresh_use(
                acquisition,
                EvidenceFact(key="acquisition.status", value=acquisition.status),
            ),
            limitations=("No HSTS conclusion is drawn for another resource.",),
        )
    if not usable or response is None:
        reason, explanation = _failure_reason(acquisition)
        if response is not None and 300 <= response.status_code < 400:
            reason = "redirect_prevented_evaluation"
            explanation = (
                "The intended resource returned a redirect, which was not followed."
            )
        elif response is not None and (
            response.access_challenge_present
            or access_page(exchange.body)
            or response.status_code >= 400
        ):
            reason = "response_blocked_or_ambiguous"
            explanation = (
                "Authentication or blocking prevented a usable HSTS assessment."
            )
        return AssessmentResult(
            id=assessment_id(project_id, claim),
            claim=claim,
            prerequisites=prerequisites,
            outcome="inconclusive",
            reason=reason,
            explanation=explanation,
            evidence_used=_fresh_use(
                acquisition,
                EvidenceFact(key="acquisition.status", value=acquisition.status),
                *(
                    (EvidenceFact(key="http.status_code", value=response.status_code),)
                    if response is not None
                    else ()
                ),
            ),
            limitations=(
                "Failure or incomplete headers cannot establish that the header was absent.",
            ),
        )

    missing = not response.strict_transport_security_present
    return AssessmentResult(
        id=assessment_id(project_id, claim),
        claim=claim,
        prerequisites=prerequisites,
        outcome="supported_positive" if missing else "supported_negative",
        reason="hsts_header_absent" if missing else "hsts_header_present",
        explanation=(
            "The complete captured header block did not contain Strict-Transport-Security."
            if missing
            else "The complete captured header block contained Strict-Transport-Security."
        ),
        evidence_used=_fresh_use(
            acquisition,
            EvidenceFact(key="http.status_code", value=response.status_code),
            EvidenceFact(key="http.headers_complete", value=response.headers_complete),
            EvidenceFact(key="http.body_complete", value=response.body_complete),
            EvidenceFact(
                key="http.header.strict_transport_security_present",
                value=response.strict_transport_security_present,
            ),
        ),
        limitations=(
            "The rule checks header presence only, not directive syntax or policy strength.",
            "TLS certificate validity and browser-effective HSTS behavior are not assessed.",
            "The claim is limited to the captured header block; an uncaptured body suffix may contain access-page indicators.",
        ),
    )
