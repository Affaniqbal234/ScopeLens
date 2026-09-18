export type AssessmentStatus =
  "pending" | "running" | "completed" | "failed" | "interrupted";
export type StageStatus = AssessmentStatus | "skipped";
export type StageKind = "nmap" | "httpx" | "nuclei" | "web_recheck";
export type AssessmentOutcome =
  "supported_positive" | "supported_negative" | "inconclusive";
export type HistoricalState =
  "new" | "changed" | "unchanged" | "resolved" | "not_observed" | "unknown";
export type ArtifactHealth = "ready" | "missing" | "corrupt";

export interface NetworkTarget {
  address: string;
  ports: number[];
}
export interface WebTarget {
  origin: string;
  approved_addresses: string[];
}
export interface ScanProfile {
  id: string;
  tcp_ports: number[];
  max_targets: number;
  requests_per_second: number;
  request_timeout_seconds: number;
  scan_timeout_seconds: number;
  probes_per_second: number;
  max_artifact_bytes: number;
}
export interface ProjectSummary {
  project: {
    id: string;
    name: string;
    scope: { network_targets: NetworkTarget[]; web_targets: WebTarget[] };
  };
  profiles: ScanProfile[];
}

export interface StageRequest {
  kind: StageKind;
  profile_id: string;
  network_targets: NetworkTarget[];
  web_target: WebTarget | null;
  resources: string[];
  rule_revision: string | null;
  planned_run_id: string | null;
  skip_reason: string | null;
}
export interface StageResponse {
  id: string;
  ordinal: number;
  request: StageRequest;
  status: StageStatus;
  result_run_id: string | null;
  started_at: string | null;
  finished_at: string | null;
  reason: string | null;
}
export interface AssessmentResponse {
  id: string;
  project_id: string;
  scope_snapshot_id: string;
  status: AssessmentStatus;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  reason: string | null;
  stages: StageResponse[];
}

export interface SourceReference {
  run_id: string;
  section: "context" | "observations" | "matches";
  ordinal: number | null;
}
export type InventoryIdentity =
  | { kind: "host"; address: string }
  | {
      kind: "network_service";
      endpoint: { address: string; protocol: string; port: number };
    }
  | { kind: "http_origin"; origin: string }
  | { kind: "http_resource"; origin: string; resource: string };
export interface InventoryItem {
  id: string;
  identity: InventoryIdentity;
  sources: SourceReference[];
}
export interface Relationship {
  kind: string;
  source_id: string;
  target_id: string;
  sources: SourceReference[];
}
export interface FindingGroup {
  id: string;
  identity: {
    rule: "finding-v1";
    project_id: string;
    origin: string;
    resource: string;
    template_id: string;
    matcher: string;
  };
  resource_id: string;
  occurrences: SourceReference[];
}
export interface CorrelationResponse {
  version: "correlation-v1";
  project_id: string;
  sources: Array<{
    run_id: string;
    report: {
      matches: Array<{
        scanner_severity: string;
        template_revision: string;
        matched_location: string;
        assessment: "unvalidated";
      }>;
    };
    artifacts: Array<{ role: string; recorded_health: ArtifactHealth }>;
  }>;
  inventory: InventoryItem[];
  relationships: Relationship[];
  assertions: Array<{
    subject_id: string;
    key: string;
    value: unknown;
    occurrences: SourceReference[];
  }>;
  findings: FindingGroup[];
  artifact_copies: Array<{
    scanner: string;
    artifact_sha256: string;
    run_ids: string[];
  }>;
}

export interface AssessmentResult {
  id: string;
  claim: {
    rule_id: string;
    rule_version: string;
    origin: string;
    resource: string;
    statement: string;
  };
  prerequisites: Array<{
    id: string;
    state: "met" | "not_met" | "unknown";
    explanation: string;
  }>;
  outcome: AssessmentOutcome;
  reason: string;
  explanation: string;
  evidence_used: Array<{
    kind: "existing_capture" | "fresh_recheck";
    [key: string]: unknown;
  }>;
  limitations: string[];
}
export interface AssessmentReport {
  version: "assessment-v1";
  basis: "existing_capture" | "fresh_recheck";
  project_id: string;
  assessments: AssessmentResult[];
  run_ids?: string[];
  correlation_version?: "correlation-v1";
}

export interface RecheckAcquisition {
  id: string;
  started_at: string;
  finished_at: string | null;
  origin: string;
  approved_address: string;
  method: "GET";
  resource: string;
  status:
    | "complete"
    | "timeout"
    | "transport_error"
    | "cancelled"
    | "malformed"
    | "truncated"
    | "not_run";
  response: {
    status_code: number;
    headers_complete: boolean;
    body_complete: boolean;
    strict_transport_security_present: boolean;
    access_challenge_present: boolean;
    content_encoding_identity: boolean;
  } | null;
  evidence: {
    acquisition_id: string;
    sha256: string;
    size_bytes: number;
    health: ArtifactHealth;
  } | null;
}
export interface RecheckReport {
  version: "assessment-v1";
  basis: "fresh_recheck";
  project_id: string;
  assessment_id: string;
  stage_id: string;
  acquisitions: RecheckAcquisition[];
  assessments: AssessmentResult[];
}

export type ComparisonSide =
  | { basis: "stored_runs"; run_ids: string[] }
  | { basis: "persisted_recheck"; assessment_id: string; stage_id: string };
export interface AssessmentReference {
  assessment_id: string;
  rule_version: string;
  outcome: AssessmentOutcome;
  reason: string;
  evidence_health: "ready" | "unavailable";
  observed_at: string[];
  acquisition_started_at: string | null;
  acquisition_finished_at: string | null;
  evidence_used: unknown[];
}
export interface ComparisonResult {
  id: string;
  claim: {
    rule_id: string;
    origin: string;
    resource: string;
    address: string | null;
  };
  state: HistoricalState;
  reason: string;
  explanation: string;
  coverage: {
    status: "comparable" | "insufficient" | "unusable" | "not_assessed";
    reason: string;
    explanation: string;
  };
  baseline: AssessmentReference | null;
  current: AssessmentReference | null;
  limitations: string[];
}
export interface ComparisonReport {
  version: "comparison-v1";
  project_id: string;
  baseline: {
    basis: "existing_capture" | "fresh_recheck";
    identifiers: string[];
  };
  current: {
    basis: "existing_capture" | "fresh_recheck";
    identifiers: string[];
  };
  results: ComparisonResult[];
}

export interface ApiProblem {
  error: { code: string; message: string };
}
