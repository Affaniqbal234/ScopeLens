import type {
  AssessmentResponse,
  ComparisonReport,
  ProjectSummary,
} from "../api/types";

export const project: ProjectSummary = {
  project: {
    id: "local_lab",
    name: "Local lab",
    scope: {
      network_targets: [{ address: "127.0.0.1", ports: [8000] }],
      web_targets: [
        { origin: "https://app.scope.test", approved_addresses: ["127.0.0.1"] },
        {
          origin: "https://admin.scope.test",
          approved_addresses: ["127.0.0.1"],
        },
      ],
    },
  },
  profiles: [
    {
      id: "conservative",
      tcp_ports: [8000],
      max_targets: 4,
      requests_per_second: 2,
      request_timeout_seconds: 5,
      scan_timeout_seconds: 30,
      probes_per_second: 2,
      max_artifact_bytes: 1048576,
    },
  ],
};

const request = {
  kind: "web_recheck" as const,
  profile_id: "conservative",
  network_targets: [],
  web_target: project.project.scope.web_targets[0],
  resources: ["/", "/.git/config"],
  rule_revision: "assessment-v1",
  planned_run_id: null,
  skip_reason: null,
};
export const partialAssessment: AssessmentResponse = {
  id: "10000000-0000-4000-8000-000000000001",
  project_id: "local_lab",
  scope_snapshot_id: "a".repeat(64),
  status: "failed",
  created_at: "2026-09-18T10:00:00Z",
  started_at: "2026-09-18T10:01:00Z",
  finished_at: "2026-09-18T10:02:00Z",
  reason: "stage_failed",
  stages: [
    {
      id: "20000000-0000-4000-8000-000000000001",
      ordinal: 0,
      request,
      status: "completed",
      result_run_id: null,
      started_at: "2026-09-18T10:01:00Z",
      finished_at: "2026-09-18T10:01:30Z",
      reason: null,
    },
    {
      id: "20000000-0000-4000-8000-000000000002",
      ordinal: 1,
      request: {
        ...request,
        kind: "nuclei",
        planned_run_id: "30000000-0000-4000-8000-000000000001",
        rule_revision: null,
      },
      status: "failed",
      result_run_id: null,
      started_at: "2026-09-18T10:01:30Z",
      finished_at: "2026-09-18T10:02:00Z",
      reason: "scanner_failed",
    },
  ],
};
export const interruptedAssessment: AssessmentResponse = {
  ...partialAssessment,
  id: "10000000-0000-4000-8000-000000000002",
  status: "interrupted",
  reason: "worker_restarted",
  stages: [
    {
      ...partialAssessment.stages[0],
      id: "20000000-0000-4000-8000-000000000003",
      status: "interrupted",
      reason: "worker_restarted",
    },
  ],
};

const ref = (
  outcome: "supported_positive" | "supported_negative" | "inconclusive",
  health: "ready" | "unavailable" = "ready",
) => ({
  assessment_id: `assessment-v1:${"b".repeat(64)}`,
  rule_version: "1",
  outcome,
  reason: "fixture",
  evidence_health: health,
  observed_at: ["2026-09-18T10:00:00Z"],
  acquisition_started_at: "2026-09-18T10:00:00Z",
  acquisition_finished_at: "2026-09-18T10:00:01Z",
  evidence_used: [],
});
export const comparisonFixture: ComparisonReport = {
  version: "comparison-v1",
  project_id: "local_lab",
  baseline: { basis: "fresh_recheck", identifiers: ["baseline"] },
  current: { basis: "fresh_recheck", identifiers: ["current"] },
  results: [
    {
      id: `comparison-v1:${"1".repeat(64)}`,
      claim: {
        rule_id: "scopelens.directory-listing",
        origin: "https://app.scope.test",
        resource: "/",
        address: "127.0.0.1",
      },
      state: "resolved",
      reason: "supported_negative",
      explanation:
        "The previously supported directory listing was absent in a later comparable check.",
      coverage: {
        status: "comparable",
        reason: "same_context",
        explanation: "Same rule, route, and backend.",
      },
      baseline: ref("supported_positive"),
      current: ref("supported_negative"),
      limitations: ["This does not prove an application-wide fix."],
    },
    {
      id: `comparison-v1:${"2".repeat(64)}`,
      claim: {
        rule_id: "scopelens.git-config-exposed",
        origin: "https://app.scope.test",
        resource: "/.git/config",
        address: "127.0.0.1",
      },
      state: "unknown",
      reason: "current_timeout",
      explanation:
        "The current check timed out, so absence cannot be established.",
      coverage: {
        status: "unusable",
        reason: "current_timeout",
        explanation: "The attempted check produced no usable response.",
      },
      baseline: ref("supported_positive"),
      current: ref("inconclusive", "unavailable"),
      limitations: [],
    },
    {
      id: `comparison-v1:${"3".repeat(64)}`,
      claim: {
        rule_id: "scopelens.git-config-exposed",
        origin: "https://admin.scope.test",
        resource: "/.git/config",
        address: "127.0.0.1",
      },
      state: "not_observed",
      reason: "check_omitted",
      explanation: "The current selection did not assess this condition.",
      coverage: {
        status: "not_assessed",
        reason: "check_omitted",
        explanation: "No comparable negative was selected.",
      },
      baseline: ref("supported_positive"),
      current: null,
      limitations: [],
    },
    {
      id: `comparison-v1:${"4".repeat(64)}`,
      claim: {
        rule_id: "scopelens.hsts-header-missing",
        origin: "https://app.scope.test",
        resource: "/",
        address: "127.0.0.1",
      },
      state: "resolved",
      reason: "supported_negative",
      explanation:
        "The previously missing header was present in the later response.",
      coverage: {
        status: "comparable",
        reason: "same_context",
        explanation: "Same HTTPS route and backend.",
      },
      baseline: ref("supported_positive"),
      current: ref("supported_negative"),
      limitations: ["Header presence does not validate policy strength."],
    },
    {
      id: `comparison-v1:${"5".repeat(64)}`,
      claim: {
        rule_id: "scopelens.hsts-header-missing",
        origin: "https://admin.scope.test",
        resource: "/",
        address: "127.0.0.1",
      },
      state: "new",
      reason: "current_supported",
      explanation:
        "The missing-HSTS condition is supported in current evidence without comparable baseline support.",
      coverage: {
        status: "not_assessed",
        reason: "baseline_negative",
        explanation: "The baseline response contained the header.",
      },
      baseline: ref("supported_negative"),
      current: ref("supported_positive"),
      limitations: ["This does not establish when the condition began."],
    },
  ],
};
