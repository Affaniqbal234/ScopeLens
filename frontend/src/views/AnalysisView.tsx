import { useMemo, useState } from "react";
import type { ApiClient } from "../api/client";
import type {
  AssessmentReport,
  AssessmentResponse,
  CorrelationResponse,
  InventoryIdentity,
} from "../api/types";
import { AssessmentResultCard } from "../components/AssessmentResultCard";
import { StatePanel } from "../components/StatePanel";

const identityText = (identity: InventoryIdentity) => {
  if (identity.kind === "host") return identity.address;
  if (identity.kind === "network_service")
    return `${identity.endpoint.protocol}://${identity.endpoint.address}:${identity.endpoint.port}`;
  if (identity.kind === "http_origin") return identity.origin;
  return `${identity.origin}${identity.resource}`;
};
const kindLabel: Record<InventoryIdentity["kind"], string> = {
  host: "Host",
  network_service: "Network service",
  http_origin: "HTTP origin",
  http_resource: "HTTP resource",
};

export function AnalysisView({
  projectId,
  assessments,
  api,
}: {
  projectId: string;
  assessments: AssessmentResponse[];
  api: ApiClient;
}) {
  const runs = useMemo(
    () =>
      assessments.flatMap((assessment) =>
        assessment.stages
          .filter((stage) => stage.result_run_id)
          .map((stage) => ({
            id: stage.result_run_id!,
            label: `${stage.request.kind} · ${stage.result_run_id!.slice(0, 8)} · ${assessment.id.slice(0, 8)}`,
          })),
      ),
    [assessments],
  );
  const [selected, setSelected] = useState<string[]>([]);
  const [correlation, setCorrelation] = useState<CorrelationResponse | null>(
    null,
  );
  const [assessment, setAssessment] = useState<AssessmentReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const [nextCorrelation, nextAssessment] = await Promise.all([
        api.correlate(projectId, selected),
        api.assess(projectId, selected),
      ]);
      setCorrelation(nextCorrelation);
      setAssessment(nextAssessment);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "The selected evidence could not be analyzed.",
      );
    } finally {
      setLoading(false);
    }
  };
  return (
    <section aria-labelledby="evidence-title">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Explicit stored-run selection</p>
          <h2 id="evidence-title">Evidence and inventory</h2>
          <p>
            Correlation preserves host, service, origin, and resource identity.
            Shared addresses do not merge virtual hosts.
          </p>
        </div>
      </div>
      <article className="panel selection-panel">
        <h3>Select captured runs</h3>
        {runs.length === 0 ? (
          <p className="muted">
            No completed scanner runs are referenced by current assessments.
          </p>
        ) : (
          <div className="selection-list">
            {runs.map((run) => (
              <label className="check-label" key={run.id}>
                <input
                  type="checkbox"
                  checked={selected.includes(run.id)}
                  onChange={() =>
                    setSelected((current) =>
                      current.includes(run.id)
                        ? current.filter((id) => id !== run.id)
                        : [...current, run.id],
                    )
                  }
                />
                {run.label}
              </label>
            ))}
          </div>
        )}
        <button
          onClick={() => void load()}
          disabled={selected.length === 0 || loading}
        >
          {loading ? "Analyzing…" : "Analyze selected runs"}
        </button>
      </article>
      {error && (
        <StatePanel tone="error" title="Analysis unavailable" detail={error} />
      )}
      {correlation && (
        <>
          <div className="metric-strip">
            <div>
              <strong>{correlation.inventory.length}</strong>
              <span>inventory identities</span>
            </div>
            <div>
              <strong>{correlation.findings.length}</strong>
              <span>grouped scanner findings</span>
            </div>
            <div>
              <strong>{correlation.assertions.length}</strong>
              <span>evidence assertions</span>
            </div>
          </div>
          <article className="panel">
            <h3>Typed inventory</h3>
            {correlation.inventory.length === 0 ? (
              <p className="muted">
                The selected evidence contains no inventory observations.
              </p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Identity</th>
                    <th>Sources</th>
                  </tr>
                </thead>
                <tbody>
                  {correlation.inventory.map((item) => (
                    <tr key={item.id}>
                      <td>{kindLabel[item.identity.kind]}</td>
                      <td>
                        <code>{identityText(item.identity)}</code>
                      </td>
                      <td>{item.sources.length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </article>
          <article className="panel">
            <h3>Grouped scanner findings</h3>
            {correlation.findings.length === 0 ? (
              <p className="muted">
                No scanner matches are present in this projection. This is not
                negative evidence.
              </p>
            ) : (
              correlation.findings.map((finding) => {
                const occurrenceDetails = finding.occurrences.map(
                  (occurrence) => {
                    const source = correlation.sources.find(
                      (item) => item.run_id === occurrence.run_id,
                    );
                    const match =
                      occurrence.ordinal === null
                        ? undefined
                        : source?.report.matches[occurrence.ordinal];
                    return { ...occurrence, match };
                  },
                );
                const severities = [
                  ...new Set(
                    occurrenceDetails
                      .map((item) => item.match?.scanner_severity)
                      .filter(Boolean),
                  ),
                ];
                return (
                  <div className="finding-block" key={finding.id}>
                    <div className="finding-row">
                      <div>
                        <strong>{finding.identity.template_id}</strong>
                        <span>Matcher: {finding.identity.matcher}</span>
                      </div>
                      <code>
                        {finding.identity.origin}
                        {finding.identity.resource}
                      </code>
                      <span>
                        Scanner severity: {severities.join(", ") || "unknown"}
                      </span>
                    </div>
                    <ul className="occurrence-list">
                      {occurrenceDetails.map((item) => (
                        <li key={`${item.run_id}:${item.ordinal}`}>
                          <code>{item.run_id.slice(0, 8)}</code> · match{" "}
                          {item.ordinal ?? "context"}
                          {item.match && (
                            <>
                              {" "}
                              · revision{" "}
                              <code>
                                {item.match.template_revision.slice(0, 10)}…
                              </code>{" "}
                              · {item.match.assessment}
                            </>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                );
              })
            )}
          </article>
        </>
      )}
      {assessment && (
        <article className="panel">
          <h3>Deterministic assessment</h3>
          {assessment.assessments.length === 0 ? (
            <p className="muted">
              No supported assessment rules apply to this capture.
            </p>
          ) : (
            assessment.assessments.map((result) => (
              <AssessmentResultCard key={result.id} result={result} />
            ))
          )}
        </article>
      )}
    </section>
  );
}
