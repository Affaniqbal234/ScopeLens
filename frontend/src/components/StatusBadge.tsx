import type {
  AssessmentOutcome,
  HistoricalState,
  StageStatus,
} from "../api/types";

const labels: Record<string, string> = {
  pending: "Pending",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  interrupted: "Interrupted",
  skipped: "Skipped",
  supported_positive: "Supported",
  supported_negative: "Not supported by this evidence",
  inconclusive: "Inconclusive",
  new: "New to this comparison",
  changed: "Changed",
  unchanged: "Unchanged",
  resolved: "Resolved in checked context",
  not_observed: "Not observed; absence unproven",
  unknown: "Unknown",
  ready: "Evidence available",
  missing: "Evidence missing",
  corrupt: "Evidence corrupt",
  unavailable: "Evidence unavailable",
};

export function StatusBadge({
  value,
}: {
  value:
    | StageStatus
    | AssessmentOutcome
    | HistoricalState
    | "ready"
    | "missing"
    | "corrupt"
    | "unavailable";
}) {
  return (
    <span className={`status status--${value}`}>{labels[value] ?? value}</span>
  );
}
