export type LifecycleState =
  "new" | "changed" | "unchanged" | "resolved" | "not_observed" | "unknown";

export interface PublicContext {
  kind: "host" | "network_service" | "http_origin" | "http_resource";
  address?: string | null;
  protocol?: string | null;
  port?: number | null;
  origin?: string | null;
  resource?: string | null;
}

export interface PublicLifecycleResult {
  rule_id: string;
  rule_version: string;
  origin: string;
  resource: string;
  address: string | null;
  state: LifecycleState;
  coverage: "comparable" | "insufficient" | "unusable" | "not_assessed";
  baseline_health: "ready" | "unavailable" | null;
  current_health: "ready" | "unavailable" | null;
  provenance_refs: string[];
  explanation: string;
  limitation: string;
}

export interface PublicSnapshot {
  version: "public-snapshot-v1";
  source_report_version: "report-v1";
  source_kind: "assessment" | "comparison";
  display_name: string;
  source_ref: string;
  contexts: PublicContext[];
  lifecycle: PublicLifecycleResult[];
  coverage_note: string;
  recorded_data_notice: string;
}
