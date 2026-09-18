import { useMemo, useState } from "react";
import type { ApiClient } from "../api/client";
import type {
  AssessmentResponse,
  ComparisonReport,
  ComparisonSide,
  HistoricalState,
} from "../api/types";
import { StatePanel } from "../components/StatePanel";
import { StatusBadge } from "../components/StatusBadge";

type Option = { key: string; label: string; side: ComparisonSide };
const priority: Record<HistoricalState, number> = {
  new: 0,
  changed: 1,
  unknown: 2,
  not_observed: 3,
  resolved: 4,
  unchanged: 5,
};

export function ComparisonView({
  projectId,
  assessments,
  api,
}: {
  projectId: string;
  assessments: AssessmentResponse[];
  api: ApiClient;
}) {
  const options = useMemo<Option[]>(
    () =>
      assessments.flatMap((assessment): Option[] =>
        assessment.stages.flatMap((stage): Option[] => {
          if (stage.result_run_id)
            return [
              {
                key: `run:${stage.result_run_id}`,
                label: `${stage.request.kind} run · ${stage.result_run_id.slice(0, 8)}`,
                side: {
                  basis: "stored_runs" as const,
                  run_ids: [stage.result_run_id],
                },
              },
            ];
          if (
            stage.request.kind === "web_recheck" &&
            ["completed", "failed", "interrupted"].includes(stage.status)
          )
            return [
              {
                key: `recheck:${assessment.id}:${stage.id}`,
                label: `web recheck · ${assessment.id.slice(0, 8)} · stage ${stage.ordinal + 1} · ${stage.status}`,
                side: {
                  basis: "persisted_recheck" as const,
                  assessment_id: assessment.id,
                  stage_id: stage.id,
                },
              },
            ];
          return [];
        }),
      ),
    [assessments],
  );
  const [baselineKey, setBaselineKey] = useState("");
  const [currentKey, setCurrentKey] = useState("");
  const [report, setReport] = useState<ComparisonReport | null>(null);
  const [error, setError] = useState("");
  const compare = async () => {
    const baseline = options.find((item) => item.key === baselineKey)?.side;
    const current = options.find((item) => item.key === currentKey)?.side;
    if (!baseline || !current) return;
    setError("");
    try {
      setReport(await api.compare(projectId, baseline, current));
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "The selected evidence could not be compared.",
      );
    }
  };
  return (
    <section aria-labelledby="history-title">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Coverage-aware history</p>
          <h2 id="history-title">Historical comparison</h2>
          <p>
            Select both sides explicitly. A missing later occurrence is never
            treated as resolved.
          </p>
        </div>
      </div>
      <article className="panel comparison-select">
        <div className="form-row">
          <label>
            Baseline
            <select
              aria-label="Baseline evidence"
              value={baselineKey}
              onChange={(event) => setBaselineKey(event.target.value)}
            >
              <option value="">Choose baseline…</option>
              {options.map((item) => (
                <option key={`b-${item.key}`} value={item.key}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Current
            <select
              aria-label="Current evidence"
              value={currentKey}
              onChange={(event) => setCurrentKey(event.target.value)}
            >
              <option value="">Choose current…</option>
              {options.map((item) => (
                <option key={`c-${item.key}`} value={item.key}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>
          <button
            disabled={!baselineKey || !currentKey || baselineKey === currentKey}
            onClick={() => void compare()}
          >
            Compare selections
          </button>
        </div>
        {options.length < 2 && (
          <p className="muted">
            At least two explicit evidence selections are required.
          </p>
        )}
      </article>
      {error && (
        <StatePanel
          tone="error"
          title="Comparison unavailable"
          detail={error}
        />
      )}
      {!report && !error && (
        <StatePanel
          title="No comparison selected"
          detail="Choose a baseline and current evidence set. ScopeLens will not select the latest records for you."
        />
      )}
      {report && (
        <div className="comparison-results">
          {report.results.length === 0 ? (
            <StatePanel
              title="No comparable conditions"
              detail="The selected evidence produced no lifecycle entries."
            />
          ) : (
            [...report.results]
              .sort((a, b) => priority[a.state] - priority[b.state])
              .map((result) => (
                <article
                  className={`comparison-card comparison-card--${result.state}`}
                  key={result.id}
                >
                  <div className="comparison-card__head">
                    <div>
                      <p className="eyebrow">{result.claim.rule_id}</p>
                      <h3>
                        {result.claim.origin}
                        <code>{result.claim.resource}</code>
                      </h3>
                    </div>
                    <StatusBadge value={result.state} />
                  </div>
                  <p>{result.explanation}</p>
                  <dl className="fact-grid">
                    <div>
                      <dt>Backend</dt>
                      <dd>{result.claim.address ?? "No address context"}</dd>
                    </div>
                    <div>
                      <dt>Coverage</dt>
                      <dd>
                        {result.coverage.status}: {result.coverage.explanation}
                      </dd>
                    </div>
                    <div>
                      <dt>Baseline evidence</dt>
                      <dd>
                        {result.baseline
                          ? `${result.baseline.outcome} · ${result.baseline.evidence_health}`
                          : "No comparable baseline assessment"}
                      </dd>
                    </div>
                    <div>
                      <dt>Current evidence</dt>
                      <dd>
                        {result.current
                          ? `${result.current.outcome} · ${result.current.evidence_health}`
                          : "No comparable current assessment"}
                      </dd>
                    </div>
                  </dl>
                  {result.state === "resolved" && (
                    <p className="qualification">
                      Resolved means the condition was absent in a later
                      comparable check of this route and backend. It does not
                      prove a code fix or safety elsewhere.
                    </p>
                  )}
                  {result.limitations.length > 0 && (
                    <div className="limitations">
                      <strong>Limits</strong>
                      <ul>
                        {result.limitations.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </article>
              ))
          )}
        </div>
      )}
    </section>
  );
}
