import json
from collections import defaultdict
from hashlib import sha256
from ipaddress import IPv4Address
from urllib.parse import urlsplit
from uuid import UUID

from scopelens.adapters.nuclei_templates import reviewed_templates
from scopelens.analysis.models import CorrelationResult, SourceReference
from scopelens.assessment.models import (
    AssessmentResult,
    CaptureAssessmentReport,
    Claim,
    EvidenceFact,
    ExistingCaptureUse,
    Outcome,
    Prerequisite,
    assessment_id,
)
from scopelens.assessment.rules import (
    DIRECTORY_RULE,
    GIT_CONFIG_RULE,
    RULE_VERSION,
    access_page,
    exposure_claim,
    hsts_claim,
)
from scopelens.domain.evidence import EvidenceReference
from scopelens.domain.services import HttpEndpoint

_TEMPLATE_RULES = {
    ("scopelens-directory-listing", "listing"): DIRECTORY_RULE,
    ("scopelens-exposed-git-config", "git-config"): GIT_CONFIG_RULE,
}


def _met(id: str, explanation: str) -> Prerequisite:
    return Prerequisite(id=id, state="met", explanation=explanation)


def _copy_limitation(result: CorrelationResult, run_ids: set[UUID]) -> tuple[str, ...]:
    if any(
        len(run_ids.intersection(item.run_ids)) > 1 for item in result.artifact_copies
    ):
        return (
            "Identical artifact bytes from repeated runs are retained as occurrences, "
            "not independent confirmation.",
        )
    return ()


def _exposure_assessments(result: CorrelationResult) -> list[AssessmentResult]:
    sources = {source.run_id: source for source in result.sources}
    templates = {template.id: template for template in reviewed_templates()}
    assessments = []
    assessed: set[tuple[str, str]] = set()
    for finding in result.findings:
        rule_id = _TEMPLATE_RULES.get(
            (finding.identity.template_id, finding.identity.matcher)
        )
        if rule_id is None:
            identity = json.dumps(
                [finding.identity.template_id, finding.identity.matcher],
                separators=(",", ":"),
            ).encode()
            claim = Claim(
                rule_id="scopelens.unreviewed-nuclei." + sha256(identity).hexdigest(),
                rule_version=RULE_VERSION,
                origin=finding.identity.origin,
                resource=finding.identity.resource,
                statement="The stored Nuclei assertion can be interpreted under a reviewed ScopeLens rule.",
            )
        else:
            claim = exposure_claim(rule_id, finding.identity.origin)
        correct_resource = (
            rule_id is not None and finding.identity.resource == claim.resource
        )
        claim = claim.model_copy(update={"resource": finding.identity.resource})
        template = templates.get(finding.identity.template_id)
        reviewed = correct_resource and template is not None
        uses: list[ExistingCaptureUse] = []
        for occurrence in finding.occurrences:
            if occurrence.ordinal is None:
                continue
            match = sources[occurrence.run_id].report.matches[occurrence.ordinal]
            reviewed &= (
                template is not None
                and match.template_revision == template.sha256
                and all(ref.scanner == "nuclei" for ref in match.evidence)
            )
            uses.extend(
                ExistingCaptureUse(
                    source=occurrence,
                    evidence=reference,
                    facts=(
                        EvidenceFact(
                            key="scanner.template_id", value=match.template_id
                        ),
                        EvidenceFact(key="scanner.matcher", value=match.matcher),
                        EvidenceFact(
                            key="scanner.template_revision",
                            value=match.template_revision,
                        ),
                        EvidenceFact(
                            key="scanner.matched_location", value=match.matched_location
                        ),
                    ),
                )
                for reference in match.evidence
            )
        occurrence_run_ids = {use.source.run_id for use in uses}
        reviewed &= bool(uses)
        assessments.append(
            AssessmentResult(
                id=assessment_id(result.project_id, claim),
                claim=claim,
                prerequisites=(
                    Prerequisite(
                        id="reviewed_template",
                        state="met" if reviewed else "not_met",
                        explanation="The template revision, matcher, and exact resource must match the reviewed rule.",
                    ),
                    _met(
                        "positive_match_evidence",
                        "The scanner emitted a positive structured match for this resource.",
                    ),
                ),
                outcome="supported_positive" if reviewed else "inconclusive",
                reason="reviewed_scanner_match"
                if reviewed
                else "unreviewed_match_context",
                explanation=(
                    "Nuclei reported that its reviewed status and body matcher succeeded."
                    if reviewed
                    else "The stored match cannot be interpreted under this reviewed rule."
                ),
                evidence_used=tuple(uses),
                limitations=(
                    "The match supports only the narrow reviewed condition.",
                    "This accepts the scanner's matcher report; response bytes were not independently validated.",
                    "It does not establish compromise, secret exposure, or exploitability.",
                    *_copy_limitation(result, occurrence_run_ids),
                ),
            )
        )
        if correct_resource and rule_id is not None:
            assessed.add((finding.identity.origin, rule_id))

    nuclei_origins: dict[str, list[UUID]] = defaultdict(list)
    for source in result.sources:
        target = source.context.web_target
        if source.report.evidence.scanner == "nuclei" and target is not None:
            nuclei_origins[target.origin].append(source.run_id)
    for origin, origin_run_ids in nuclei_origins.items():
        for rule_id in (DIRECTORY_RULE, GIT_CONFIG_RULE):
            if (origin, rule_id) in assessed:
                continue
            claim = exposure_claim(rule_id, origin)
            missing_uses = tuple(
                ExistingCaptureUse(
                    source=SourceReference(run_id=run_id, section="context"),
                    evidence=sources[run_id].report.evidence,
                    facts=(
                        EvidenceFact(
                            key="scanner.match_count",
                            value=len(sources[run_id].report.matches),
                        ),
                    ),
                )
                for run_id in sorted(origin_run_ids)
            )
            assessments.append(
                AssessmentResult(
                    id=assessment_id(result.project_id, claim),
                    claim=claim,
                    prerequisites=(
                        _met(
                            "reviewed_template",
                            "The stored report is from the restricted Nuclei integration.",
                        ),
                        Prerequisite(
                            id="complete_negative_evidence",
                            state="unknown",
                            explanation=(
                                "Nuclei match output does not record a complete failed-match response."
                            ),
                        ),
                    ),
                    outcome="inconclusive",
                    reason="no_supported_negative_evidence",
                    explanation=(
                        "No positive match was captured, but this output cannot establish "
                        "that the condition was absent."
                    ),
                    evidence_used=missing_uses,
                    limitations=(
                        "Empty match output can also result from request or evaluation failure.",
                        *_copy_limitation(result, set(origin_run_ids)),
                    ),
                )
            )
    return assessments


def _hsts_assessments(result: CorrelationResult) -> list[AssessmentResult]:
    by_origin: dict[str, list[ExistingCaptureUse]] = defaultdict(list)
    records: dict[tuple[UUID, str, EvidenceReference], list[ExistingCaptureUse]] = (
        defaultdict(list)
    )
    for source in result.sources:
        if source.report.evidence.scanner != "httpx":
            continue
        for ordinal, observation in enumerate(source.report.observations):
            if not isinstance(observation.subject, HttpEndpoint):
                continue
            origin = observation.subject.origin
            if observation.key in (
                "http.probe_succeeded",
                "http.status_code",
                "http.location",
                "http.header.location",
                "http.header.www_authenticate",
                "http.title",
                "http.header.strict_transport_security",
            ):
                for reference in observation.evidence:
                    use = ExistingCaptureUse(
                        source=SourceReference(
                            run_id=source.run_id,
                            section="observations",
                            ordinal=ordinal,
                        ),
                        evidence=reference,
                        facts=(
                            EvidenceFact(key=observation.key, value=observation.value),
                        ),
                    )
                    by_origin[origin].append(use)
                    records[(source.run_id, origin, reference)].append(use)

    assessments = []
    for origin, uses in by_origin.items():
        claim = hsts_claim(origin)
        parsed = urlsplit(origin)
        try:
            IPv4Address(parsed.hostname or "")
        except ValueError:
            hostname = True
        else:
            hostname = False
        https = parsed.scheme == "https"
        qualifying_records = []
        for (_run_id, item_origin, _reference), record_uses in records.items():
            if item_origin != origin:
                continue
            values = {use.facts[0].key: use.facts[0].value for use in record_uses}
            unambiguous = len(values) == len(record_uses)
            title = values.get("http.title", "")
            blocked_title = access_page(f"<title>{title}</title>".encode())
            qualifying_records.append(
                unambiguous
                and not blocked_title
                and "http.header.www_authenticate" not in values
                and "http.header.location" not in values
                and values.get("http.probe_succeeded") is True
                and values.get("http.status_code") == 200
                and "http.location" not in values
                and "http.header.strict_transport_security" in values
            )
        prerequisites = (
            Prerequisite(
                id="https_origin",
                state="met" if https else "not_met",
                explanation="HSTS applies only to an HTTPS origin.",
            ),
            Prerequisite(
                id="hostname_origin",
                state="met" if hostname else "not_met",
                explanation="This rule is limited to hostname origins, not IP literals.",
            ),
            Prerequisite(
                id="complete_headers",
                state="unknown",
                explanation=(
                    "Stored httpx observations do not certify a complete response header block."
                ),
            ),
        )
        if not https or not hostname:
            outcome: Outcome = "inconclusive"
            reason = "hsts_not_applicable"
            explanation = "The origin is outside this hostname-based HTTPS rule."
        elif qualifying_records and all(qualifying_records):
            outcome = "supported_positive"
            reason = "hsts_header_observed"
            explanation = "Each evaluated stored response explicitly captured Strict-Transport-Security in a usable context."
        else:
            outcome = "inconclusive"
            reason = "header_capture_incomplete"
            explanation = "The stored observations cannot establish that an omitted header was absent."
        run_ids = {use.source.run_id for use in uses}
        assessments.append(
            AssessmentResult(
                id=assessment_id(result.project_id, claim),
                claim=claim,
                prerequisites=prerequisites,
                outcome=outcome,
                reason=reason,
                explanation=explanation,
                evidence_used=tuple(uses),
                limitations=(
                    "Header presence is assessed without validating directive syntax or policy strength.",
                    "TLS certificate validity and browser-effective HSTS behavior are not assessed.",
                    "Stored metadata cannot exclude unreported blocking or body truncation; it never establishes header absence.",
                    *_copy_limitation(result, run_ids),
                ),
            )
        )
    return assessments


def assess_correlation(result: CorrelationResult) -> CaptureAssessmentReport:
    assessments = _exposure_assessments(result) + _hsts_assessments(result)
    return CaptureAssessmentReport(
        project_id=result.project_id,
        run_ids=tuple(source.run_id for source in result.sources),
        assessments=tuple(sorted(assessments, key=lambda item: item.id)),
    )
