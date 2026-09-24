import snapshotData from "../../demo-data/public-snapshot.json";
import type { LifecycleState, PublicSnapshot } from "./types";
import "./demo.css";

const snapshot = snapshotData as unknown as PublicSnapshot;

const labels: Record<LifecycleState, string> = {
  new: "New to this comparison",
  changed: "Changed",
  unchanged: "Unchanged",
  resolved: "Resolved in checked context",
  not_observed: "Not observed; absence unproven",
  unknown: "Unknown",
};

export default function DemoApp() {
  return (
    <main className="demo-shell">
      <header className="demo-header">
        <p className="eyebrow">Static public demo</p>
        <h1>{snapshot.display_name}</h1>
        <p>
          Deterministic synthetic acquisitions evaluated and sanitized by
          ScopeLens. No live target or operational API is used.
        </p>
      </header>

      <section aria-labelledby="coverage-heading" className="demo-panel">
        <h2 id="coverage-heading">Coverage</h2>
        <p>{snapshot.coverage_note}</p>
        <div className="context-grid">
          {snapshot.contexts.map((context) => (
            <article
              className="context"
              key={`${context.kind}:${context.origin}:${context.address}`}
            >
              <strong>{context.origin ?? context.address}</strong>
              <span>{context.kind.replaceAll("_", " ")}</span>
              {context.address && <code>{context.address}</code>}
            </article>
          ))}
        </div>
      </section>

      <section aria-labelledby="results-heading" className="demo-panel">
        <h2 id="results-heading">Historical comparison</h2>
        <div className="result-list">
          {snapshot.lifecycle.map((result) => (
            <article
              className="result"
              key={`${result.rule_id}:${result.origin}:${result.resource}`}
            >
              <div className="result-heading">
                <div>
                  <p className="rule">{result.rule_id}</p>
                  <h3>{result.origin}</h3>
                </div>
                <span className={`state state--${result.state}`}>
                  {labels[result.state]}
                </span>
              </div>
              <dl>
                <div>
                  <dt>Resource</dt>
                  <dd>
                    <code>{result.resource}</code>
                  </dd>
                </div>
                <div>
                  <dt>Backend</dt>
                  <dd>
                    <code>{result.address ?? "not recorded"}</code>
                  </dd>
                </div>
                <div>
                  <dt>Coverage</dt>
                  <dd>{result.coverage.replaceAll("_", " ")}</dd>
                </div>
              </dl>
              <p>{result.explanation}</p>
              <p className="limitation">
                <strong>Limit:</strong> {result.limitation}
              </p>
              <p className="provenance">
                Evidence references:{" "}
                {result.provenance_refs.join(", ") || "none"}
              </p>
            </article>
          ))}
        </div>
      </section>

      <footer>
        This static demo cannot start assessments or contact assessment targets.
      </footer>
    </main>
  );
}
