import type { AssessmentResult } from "../api/types";
import { StatusBadge } from "./StatusBadge";

export function AssessmentResultCard({ result }: { result: AssessmentResult }) {
  return (
    <article className="evidence-card">
      <div className="evidence-card__head">
        <div>
          <p className="eyebrow">
            {result.claim.rule_id} · v{result.claim.rule_version}
          </p>
          <h4>{result.claim.statement}</h4>
        </div>
        <StatusBadge value={result.outcome} />
      </div>
      <dl className="fact-grid">
        <div>
          <dt>Origin</dt>
          <dd>{result.claim.origin}</dd>
        </div>
        <div>
          <dt>Resource</dt>
          <dd>
            <code>{result.claim.resource}</code>
          </dd>
        </div>
        <div>
          <dt>Reason</dt>
          <dd>{result.reason}</dd>
        </div>
        <div>
          <dt>Evidence uses</dt>
          <dd>{result.evidence_used.length}</dd>
        </div>
      </dl>
      <p>{result.explanation}</p>
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
  );
}
