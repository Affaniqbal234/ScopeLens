import json
from html import escape

from scopelens.assessment.models import ExistingCaptureUse, FreshRecheckUse
from scopelens.comparison.models import AssessmentReference
from scopelens.domain.targets import DomainModel
from scopelens.orchestration.models import StageRequest

from .models import AssessmentReport, ComparisonReport, PublicSnapshot, Report


def render_json(document: DomainModel) -> bytes:
    payload = document.model_dump(
        mode="json", exclude_none=isinstance(document, PublicSnapshot)
    )
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()


def _text(value: object) -> str:
    return escape(str(value), quote=True)


def _time(value: object | None) -> str:
    return _text(value) if value is not None else "Not recorded"


def _badge(value: str) -> str:
    return f'<span class="badge badge-{_text(value)}">{_text(value.replace("_", " "))}</span>'


def _evidence_refs(reference: AssessmentReference | None) -> str:
    if reference is None:
        return "No comparable assessment"
    values = []
    for use in reference.evidence_used:
        if isinstance(use, ExistingCaptureUse):
            values.append(f"run {use.source.run_id}")
        elif isinstance(use, FreshRecheckUse):
            values.append(f"acquisition {use.acquisition_id}")
    return ", ".join(values) or "No evidence reference"


def _stage_context(request: StageRequest) -> str:
    if request.web_target is not None:
        return (
            f"{request.web_target.origin} at "
            f"{', '.join(request.web_target.approved_addresses)}"
        )
    return "; ".join(
        f"{target.address} ports {','.join(str(port) for port in target.ports)}"
        for target in request.network_targets
    )


def _layout(title: str, project: str, body: str) -> bytes:
    css = """
    :root { color: #182534; background: #eef2f4; font-family: Arial, sans-serif; line-height: 1.45; }
    * { box-sizing: border-box; }
    body { margin: 0; }
    main { max-width: 1080px; margin: 0 auto; padding: 42px 28px 72px; }
    header { border-top: 5px solid #17677a; background: #102030; color: white; padding: 28px; }
    header p { color: #b8c7d2; margin: 6px 0 0; }
    h1, h2, h3 { line-height: 1.2; }
    h1 { margin: 0; font-size: 30px; }
    h2 { margin-top: 30px; font-size: 21px; }
    h3 { font-size: 16px; }
    section, article { break-inside: avoid; }
    .panel { background: white; border: 1px solid #ccd6dd; margin-top: 16px; padding: 20px; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px 24px; }
    .metric-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; background: #ccd6dd; border: 1px solid #ccd6dd; }
    .metric { background: white; padding: 14px; }
    .metric strong, .metric span { display: block; }
    .metric strong { font-size: 22px; }
    .metric span, dt { color: #5e6d7b; font-size: 11px; font-weight: bold; letter-spacing: .05em; text-transform: uppercase; }
    dl { margin: 0; }
    dd { margin: 3px 0 0; overflow-wrap: anywhere; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { border-bottom: 1px solid #dce3e8; padding: 9px 7px; text-align: left; vertical-align: top; }
    th { color: #566575; font-size: 10px; letter-spacing: .06em; text-transform: uppercase; }
    code { font-family: Consolas, monospace; font-size: .9em; overflow-wrap: anywhere; }
    .badge { display: inline-block; border: 1px solid #aab7c0; border-radius: 999px; padding: 3px 8px; font-size: 11px; font-weight: bold; }
    .badge-supported_positive, .badge-condition_supported, .badge-new, .badge-failed, .badge-corrupt { background: #fff0ee; border-color: #d79a92; color: #81342c; }
    .badge-inconclusive, .badge-unknown, .badge-not_observed, .badge-interrupted, .badge-missing, .badge-unavailable { background: #fff7e7; border-color: #d5b16c; color: #73500f; }
    .badge-supported_negative, .badge-resolved, .badge-completed, .badge-ready { background: #edf8f5; border-color: #8fc4ba; color: #245e55; }
    .qualification, .limits { border-left: 4px solid #bf8424; background: #fff8eb; padding: 12px 14px; }
    .result { border-left: 5px solid #80909d; }
    .result-new { border-left-color: #b94d40; }
    .result-unknown, .result-not_observed { border-left-color: #bf8424; }
    .result-resolved { border-left-color: #2d796f; }
    .subtle { color: #5f6d7b; }
    .eyebrow { color: #607080; font-size: 11px; font-weight: bold; letter-spacing: .08em; text-transform: uppercase; }
    ul { padding-left: 20px; }
    @media (max-width: 700px) { .grid, .metric-grid { grid-template-columns: 1fr; } main { padding: 20px 12px 40px; } }
    @media print { :root { background: white; } main { max-width: none; padding: 0; } .panel { box-shadow: none; } header { print-color-adjust: exact; } }
    """
    document = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{_text(title)}</title><style>{css}</style></head>
<body><main><header><h1>{_text(title)}</h1><p>{_text(project)} · ScopeLens report-v1</p></header>{body}</main></body>
</html>
"""
    return document.encode()


def _assessment_html(report: AssessmentReport) -> bytes:
    coverage = report.coverage
    metrics = "".join(
        f'<div class="metric"><strong>{value}</strong><span>{_text(label)}</span></div>'
        for label, value in (
            ("requested", coverage.requested),
            ("completed", coverage.completed),
            ("skipped", coverage.skipped),
            ("failed", coverage.failed),
            ("interrupted", coverage.interrupted),
            ("inconclusive claims", coverage.inconclusive_claims),
        )
    )
    stage_rows = "".join(
        "<tr>"
        f"<td>{stage.ordinal + 1}</td><td>{_text(stage.kind)}</td><td>{_badge(stage.status)}</td>"
        f"<td>{_text(_stage_context(stage.request))}</td>"
        f"<td>{_text(', '.join(stage.request.resources))}</td>"
        f"<td>{_text(stage.reason or 'None')}</td>"
        f"<td><code>{_text(stage.result_run_id or 'None')}</code></td></tr>"
        for stage in report.stages
    )
    claim_sections = (
        "".join(
            f"""<article class="panel">
<p class="eyebrow">{_text(claim.result.claim.rule_id)} · version {_text(claim.result.claim.rule_version)}</p>
<h3>{_text(claim.result.claim.statement)}</h3>
<p>{_badge(claim.display_outcome)}</p>
<div class="grid"><dl><dt>Origin</dt><dd>{_text(claim.result.claim.origin)}</dd></dl><dl><dt>Resource</dt><dd><code>{_text(claim.result.claim.resource)}</code></dd></dl><dl><dt>Reason</dt><dd>{_text(claim.result.reason)}</dd></dl><dl><dt>Source</dt><dd>{_text(claim.source_basis)}</dd></dl><dl><dt>Run provenance</dt><dd><code>{_text(", ".join(str(value) for value in claim.run_ids) or "None")}</code></dd></dl><dl><dt>Acquisition provenance</dt><dd><code>{_text(", ".join(str(value) for value in claim.acquisition_ids) or "None")}</code></dd></dl></div>
<p>{_text(claim.result.explanation)}</p>
<div class="limits"><strong>Limitations</strong><ul>{"".join(f"<li>{_text(item)}</li>" for item in claim.result.limitations) or "<li>No additional limitation was recorded.</li>"}</ul></div>
</article>"""
            for claim in report.claims
        )
        or '<div class="panel"><p>No deterministic assessment claims were produced by the selected evidence.</p></div>'
    )
    health_rows = (
        "".join(
            f"<tr><td>{_text(item.source_kind)}</td><td><code>{_text(item.source_id)}</code></td><td>{_text(item.role)}</td><td>{_badge(item.health)}</td><td><code>{_text(item.artifact_sha256 or 'No captured artifact')}</code></td></tr>"
            for item in report.evidence_health
        )
        or '<tr><td colspan="5">No evidence artifact was linked to completed work.</td></tr>'
    )
    inventory_rows = (
        "".join(
            f"<tr><td>{_text(item.identity.kind)}</td><td><code>{_text(item.identity.model_dump(mode='json'))}</code></td><td>{len(item.sources)}</td></tr>"
            for item in report.inventory
        )
        or '<tr><td colspan="3">No normalized inventory was produced.</td></tr>'
    )
    findings = (
        "".join(
            f"<tr><td>{_text(item.identity.template_id)}</td><td>{_text(item.identity.matcher)}</td><td>{_text(item.identity.origin)}<code>{_text(item.identity.resource)}</code></td><td>{_text(', '.join(str(value.run_id) for value in item.occurrences))}</td></tr>"
            for item in report.findings
        )
        or '<tr><td colspan="4">No scanner matches were grouped. This is not negative evidence.</td></tr>'
    )
    assertion_rows = (
        "".join(
            f"<tr><td><code>{_text(item.subject_id)}</code></td><td>{_text(item.key)}</td><td>{_text(item.value)}</td><td>{_text(', '.join(str(value.run_id) for value in item.occurrences))}</td></tr>"
            for item in report.assertions
        )
        or '<tr><td colspan="4">No grouped scanner assertions were recorded.</td></tr>'
    )
    relationship_rows = (
        "".join(
            f"<tr><td><code>{_text(item.source_id)}</code></td><td>{_text(item.kind)}</td><td><code>{_text(item.target_id)}</code></td><td>{_text(', '.join(str(value.run_id) for value in item.sources))}</td></tr>"
            for item in report.relationships
        )
        or '<tr><td colspan="4">No inventory relationships were recorded.</td></tr>'
    )
    qualifications = "".join(
        f"<li>{_text(item)}</li>" for item in report.qualifications
    )
    body = f"""
<section class="panel"><div class="grid"><dl><dt>Assessment</dt><dd><code>{_text(report.assessment_id)}</code></dd></dl><dl><dt>Lifecycle</dt><dd>{_badge(report.status)}</dd></dl><dl><dt>Created</dt><dd>{_time(report.created_at)}</dd></dl><dl><dt>Started / finished</dt><dd>{_time(report.started_at)} / {_time(report.finished_at)}</dd></dl><dl><dt>Profile</dt><dd>{_text(report.profile.id)}</dd></dl><dl><dt>Scope snapshot</dt><dd><code>{_text(report.scope_snapshot_id)}</code></dd></dl><dl><dt>Assessment reason</dt><dd>{_text(report.reason or "None")}</dd></dl></div></section>
<h2>Coverage</h2><div class="metric-grid">{metrics}</div><div class="qualification"><ul>{qualifications}</ul></div>
<h2>Authorized scope</h2><section class="panel"><p><strong>Network targets:</strong> {_text(len(report.authorized_scope.network_targets))} &nbsp; <strong>Web origins:</strong> {_text(len(report.authorized_scope.web_targets))}</p>{"".join(f"<p><code>{_text(item.origin)}</code> at {_text(', '.join(item.approved_addresses))}</p>" for item in report.authorized_scope.web_targets)}</section>
<h2>Planned stages and actual outcomes</h2><section class="panel"><table><thead><tr><th>Order</th><th>Stage</th><th>Outcome</th><th>Target context</th><th>Capabilities</th><th>Reason</th><th>Run</th></tr></thead><tbody>{stage_rows}</tbody></table></section>
<h2>Evidence health</h2><section class="panel"><table><thead><tr><th>Source</th><th>Identifier</th><th>Role</th><th>Health</th><th>Digest</th></tr></thead><tbody>{health_rows}</tbody></table></section>
<h2>Assessment claims</h2>{claim_sections}
<h2>Inventory</h2><section class="panel"><table><thead><tr><th>Type</th><th>Identity</th><th>Sources</th></tr></thead><tbody>{inventory_rows}</tbody></table></section>
<h2>Relationships</h2><section class="panel"><table><thead><tr><th>Source</th><th>Relationship</th><th>Target</th><th>Runs</th></tr></thead><tbody>{relationship_rows}</tbody></table></section>
<h2>Scanner assertions</h2><section class="panel"><table><thead><tr><th>Subject</th><th>Key</th><th>Value</th><th>Runs</th></tr></thead><tbody>{assertion_rows}</tbody></table></section>
<h2>Scanner findings</h2><section class="panel"><table><thead><tr><th>Template</th><th>Matcher</th><th>Context</th><th>Run provenance</th></tr></thead><tbody>{findings}</tbody></table></section>
"""
    return _layout("Assessment report", report.project.name, body)


def _comparison_html(report: ComparisonReport) -> bytes:
    selection = report.comparison
    items = []
    for item in selection.results:
        qualification = (
            f'<p class="qualification">{_text(report.resolved_qualification)}</p>'
            if item.state == "resolved"
            else ""
        )
        limits = "".join(f"<li>{_text(value)}</li>" for value in item.limitations)
        items.append(
            f"""<article class="panel result result-{_text(item.state)}">
<p class="eyebrow">{_text(item.claim.rule_id)}</p><h3>{_text(item.claim.origin)} <code>{_text(item.claim.resource)}</code></h3><p>{_badge(item.state)}</p>
<p>{_text(item.explanation)}</p>{qualification}
<div class="grid"><dl><dt>Backend</dt><dd>{_text(item.claim.address or "No address context")}</dd></dl><dl><dt>Coverage</dt><dd>{_text(item.coverage.status)}: {_text(item.coverage.explanation)}</dd></dl><dl><dt>Baseline</dt><dd>{_text(item.baseline.outcome if item.baseline else "No comparable baseline")} · {_text(item.baseline.evidence_health if item.baseline else "not available")}<br><code>{_text(item.baseline.assessment_id if item.baseline else "None")}</code><br>{_text(_evidence_refs(item.baseline))}</dd></dl><dl><dt>Current</dt><dd>{_text(item.current.outcome if item.current else "No comparable current assessment")} · {_text(item.current.evidence_health if item.current else "not available")}<br><code>{_text(item.current.assessment_id if item.current else "None")}</code><br>{_text(_evidence_refs(item.current))}</dd></dl></div>
<div class="limits"><strong>Limitations</strong><ul>{limits or "<li>No additional limitation was recorded.</li>"}</ul></div></article>"""
        )
    body = f"""
<section class="panel"><div class="grid"><dl><dt>Baseline basis</dt><dd>{_text(selection.baseline.basis)}</dd></dl><dl><dt>Current basis</dt><dd>{_text(selection.current.basis)}</dd></dl><dl><dt>Baseline membership</dt><dd>{_text(", ".join(selection.baseline.identifiers))}</dd></dl><dl><dt>Current membership</dt><dd>{_text(", ".join(selection.current.identifiers))}</dd></dl></div></section>
<h2>State meanings</h2><section class="panel"><dl>{"".join(f"<dt>{_text(key)}</dt><dd>{_text(value)}</dd>" for key, value in sorted(report.state_definitions.items()))}</dl></section>
<h2>Condition history</h2>{"".join(items) or '<div class="panel"><p>The selected evidence produced no historical condition entries.</p></div>'}
"""
    return _layout("Historical comparison report", report.project.name, body)


def render_html(report: Report) -> bytes:
    if isinstance(report, AssessmentReport):
        return _assessment_html(report)
    if isinstance(report, ComparisonReport):
        return _comparison_html(report)
    raise TypeError("unsupported report type")
