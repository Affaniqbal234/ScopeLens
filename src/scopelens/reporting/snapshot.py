from hashlib import sha256
from typing import cast
from urllib.parse import urlsplit

from scopelens.assessment.models import ExistingCaptureUse, FreshRecheckUse
from scopelens.assessment.rules import DIRECTORY_RULE, GIT_CONFIG_RULE, HSTS_RULE
from scopelens.comparison.models import AssessmentReference

from .models import (
    AssessmentReport,
    ComparisonReport,
    EvidenceHealth,
    PublicClaim,
    PublicContext,
    PublicLifecycleResult,
    PublicSnapshot,
    PublicStage,
    Report,
)

_RULES = {
    DIRECTORY_RULE: (
        "/",
        "The checked directory resource returned the reviewed directory-listing evidence.",
        "The conclusion applies only to the recorded route and backend context.",
    ),
    GIT_CONFIG_RULE: (
        "/.git/config",
        "The checked Git configuration resource returned the reviewed configuration evidence.",
        "The conclusion does not establish repository compromise or secret exposure.",
    ),
    HSTS_RULE: (
        "/",
        "The checked HTTPS hostname response lacked a Strict-Transport-Security header.",
        "Header presence or absence does not assess policy strength, certificate validity, or browser behavior.",
    ),
}

_STATE_EXPLANATIONS = {
    "new": "The adverse condition is supported in the current selection without comparable baseline support. The snapshot does not claim when it began.",
    "changed": "Comparable recorded evidence materially differs. The snapshot does not classify the difference as an improvement or regression.",
    "unchanged": "Comparable evidence supports the same conclusion in both selections.",
    "resolved": "The previously supported condition was not supported by a later comparable recheck of the same recorded route and backend context.",
    "not_observed": "The later selection did not establish the condition again, but no usable comparable negative established absence.",
    "unknown": "A failure, interruption, incompatible context, or evidence problem prevented a conclusion.",
}


def _public_ref(prefix: str, value: object) -> str:
    digest = sha256(f"public-snapshot-v1:{prefix}:{value}".encode()).hexdigest()[:16]
    return f"{prefix}-{digest}"


def _comparison_refs(
    side_name: str, reference: AssessmentReference | None
) -> tuple[str, ...]:
    if reference is None:
        return ()
    values = []
    for use in reference.evidence_used:
        if isinstance(use, ExistingCaptureUse):
            values.append(_public_ref(f"{side_name}-run", use.source.run_id))
        elif isinstance(use, FreshRecheckUse):
            values.append(_public_ref(f"{side_name}-acquisition", use.acquisition_id))
    if not values:
        values.append(_public_ref(f"{side_name}-assessment", reference.assessment_id))
    return tuple(sorted(set(values)))


class _Aliases:
    def __init__(self, origins: set[str], addresses: set[str]) -> None:
        self.origins = {
            value: self._origin(index, value)
            for index, value in enumerate(sorted(origins), 1)
        }
        self.addresses = {
            value: f"192.0.2.{index}"
            for index, value in enumerate(sorted(addresses), 1)
        }

    @staticmethod
    def _origin(index: int, value: str) -> str:
        parsed = urlsplit(value)
        default = 443 if parsed.scheme == "https" else 80
        suffix = f":{parsed.port}" if parsed.port and parsed.port != default else ""
        return f"{parsed.scheme}://host-{index}.example.invalid{suffix}"

    def origin(self, value: str) -> str:
        return self.origins[value]

    def address(self, value: str | None) -> str | None:
        return self.addresses.get(value) if value is not None else None


def _assessment_aliases(report: AssessmentReport) -> _Aliases:
    origins = {item.origin for item in report.authorized_scope.web_targets}
    origins.update(
        item.result.claim.origin
        for item in report.claims
        if item.result.claim.rule_id in _RULES
    )
    addresses = {item.address for item in report.authorized_scope.network_targets}
    addresses.update(
        address
        for target in report.authorized_scope.web_targets
        for address in target.approved_addresses
    )
    return _Aliases(origins, addresses)


def _comparison_aliases(report: ComparisonReport) -> _Aliases:
    results = report.comparison.results
    return _Aliases(
        {item.claim.origin for item in results if item.claim.rule_id in _RULES},
        {
            item.claim.address
            for item in results
            if item.claim.rule_id in _RULES and item.claim.address is not None
        },
    )


def _assessment_contexts(
    report: AssessmentReport, aliases: _Aliases
) -> tuple[PublicContext, ...]:
    contexts = []
    for network_target in sorted(
        report.authorized_scope.network_targets, key=lambda item: item.address
    ):
        address = aliases.address(network_target.address)
        contexts.append(PublicContext(kind="host", address=address))
        for port in network_target.ports:
            contexts.append(
                PublicContext(
                    kind="network_service",
                    address=address,
                    protocol="tcp",
                    port=port,
                )
            )
    for web_target in sorted(
        report.authorized_scope.web_targets, key=lambda item: item.origin
    ):
        for address in web_target.approved_addresses:
            contexts.append(
                PublicContext(
                    kind="http_origin",
                    origin=aliases.origin(web_target.origin),
                    address=aliases.address(address),
                )
            )
    return tuple(contexts)


def _health_for_claim(
    report: AssessmentReport,
    source_ids: tuple[object, ...],
    artifact_sha256s: tuple[str, ...],
) -> EvidenceHealth:
    selected = [
        item.health
        for item in report.evidence_health
        if item.source_id in source_ids
        and (
            item.source_kind == "fresh_recheck"
            or not artifact_sha256s
            or item.artifact_sha256 in artifact_sha256s
        )
    ]
    if not selected:
        return "unavailable"
    for state in ("corrupt", "missing", "unavailable"):
        if state in selected:
            return cast(EvidenceHealth, state)
    return "ready"


def _assessment_snapshot(report: AssessmentReport, display_name: str) -> PublicSnapshot:
    aliases = _assessment_aliases(report)
    stages = []
    for stage in report.stages:
        target = stage.request.web_target
        context = None
        if target is not None:
            context = PublicContext(
                kind="http_origin",
                origin=aliases.origin(target.origin),
                address=aliases.address(target.approved_addresses[0]),
            )
        capabilities = {
            "nmap": ("network service discovery",),
            "httpx": ("HTTP service metadata",),
            "nuclei": ("reviewed exposure templates",),
            "web_recheck": (
                "directory listing",
                "Git configuration",
                "missing HSTS header",
            ),
        }[stage.kind]
        stages.append(
            PublicStage(
                ordinal=stage.ordinal,
                kind=stage.kind,
                status=stage.status,
                capabilities=capabilities,
                context=context,
            )
        )
    claims = []
    for claim in report.claims:
        rule = _RULES.get(claim.result.claim.rule_id)
        if rule is None or claim.result.claim.resource != rule[0]:
            continue
        source_ids: tuple[object, ...] = (*claim.run_ids, *claim.acquisition_ids)
        claims.append(
            PublicClaim(
                rule_id=claim.result.claim.rule_id,
                rule_version=claim.result.claim.rule_version,
                statement=rule[1],
                origin=aliases.origin(claim.result.claim.origin),
                resource=rule[0],
                outcome=claim.display_outcome,
                evidence_health=_health_for_claim(
                    report, source_ids, claim.artifact_sha256s
                ),
                provenance_refs=tuple(
                    _public_ref("evidence", value)
                    for value in sorted(source_ids, key=str)
                ),
                limitation=rule[2],
            )
        )
    coverage = report.coverage
    note = (
        f"{coverage.completed} of {coverage.requested} planned stages completed; "
        f"{coverage.skipped} skipped, {coverage.failed} failed, and "
        f"{coverage.interrupted} interrupted; {coverage.inconclusive_claims} "
        "assessment claims were inconclusive."
    )
    return PublicSnapshot(
        source_kind="assessment",
        display_name=display_name,
        source_ref=_public_ref("assessment", report.assessment_id),
        contexts=_assessment_contexts(report, aliases),
        stages=tuple(stages),
        claims=tuple(sorted(claims, key=lambda item: (item.rule_id, item.origin))),
        lifecycle=(),
        coverage_note=note,
    )


def _comparison_snapshot(report: ComparisonReport, display_name: str) -> PublicSnapshot:
    aliases = _comparison_aliases(report)
    lifecycle = []
    contexts = set()
    for item in report.comparison.results:
        rule = _RULES.get(item.claim.rule_id)
        if rule is None or item.claim.resource != rule[0]:
            continue
        origin = aliases.origin(item.claim.origin)
        address = aliases.address(item.claim.address)
        contexts.add((origin, address))
        refs = (
            *_comparison_refs("baseline", item.baseline),
            *_comparison_refs("current", item.current),
        )
        lifecycle.append(
            PublicLifecycleResult(
                rule_id=item.claim.rule_id,
                rule_version=(
                    item.current.rule_version
                    if item.current is not None
                    else item.baseline.rule_version
                    if item.baseline is not None
                    else "unavailable"
                ),
                origin=origin,
                resource=rule[0],
                address=address,
                state=item.state,
                coverage=item.coverage.status,
                baseline_health=(
                    item.baseline.evidence_health if item.baseline else None
                ),
                current_health=(item.current.evidence_health if item.current else None),
                provenance_refs=refs,
                explanation=_STATE_EXPLANATIONS[item.state],
                limitation=(
                    rule[2]
                    if item.state != "resolved"
                    else "Resolution is limited to the recorded route, backend, and comparable recheck evidence. It does not prove an underlying code fix."
                ),
            )
        )
    public_contexts = tuple(
        PublicContext(kind="http_origin", origin=origin, address=address)
        for origin, address in sorted(contexts)
    )
    membership = (
        f"project:{report.project.id}",
        "baseline:" + "|".join(sorted(report.comparison.baseline.identifiers)),
        "current:" + "|".join(sorted(report.comparison.current.identifiers)),
    )
    return PublicSnapshot(
        source_kind="comparison",
        display_name=display_name,
        source_ref=_public_ref("comparison", "|".join(membership)),
        contexts=public_contexts,
        stages=(),
        claims=(),
        lifecycle=tuple(
            sorted(
                lifecycle,
                key=lambda item: (
                    item.rule_id,
                    item.origin,
                    item.resource,
                    item.address or "",
                ),
            )
        ),
        coverage_note="Each lifecycle state comes from the explicit baseline and current selections recorded in this snapshot.",
    )


def build_public_snapshot(
    report: Report, *, display_name: str = "ScopeLens recorded demo"
) -> PublicSnapshot:
    if (
        not display_name
        or len(display_name) > 80
        or any(ord(char) < 32 for char in display_name)
    ):
        raise ValueError("public display name must be 1 to 80 printable characters")
    if isinstance(report, AssessmentReport):
        return _assessment_snapshot(report, display_name)
    if isinstance(report, ComparisonReport):
        return _comparison_snapshot(report, display_name)
    raise TypeError("unsupported report type")
