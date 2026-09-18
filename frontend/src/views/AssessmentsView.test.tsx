import { render, screen } from "@testing-library/react";
import type { ApiClient } from "../api/client";
import {
  interruptedAssessment,
  partialAssessment,
  project,
} from "../test/fixtures";
import { AssessmentsView } from "./AssessmentsView";

const assessmentResult = {
  id: `assessment-v1:${"f".repeat(64)}`,
  claim: {
    rule_id: "scopelens.directory-listing",
    rule_version: "1",
    origin: "https://app.scope.test",
    resource: "/",
    statement: "Directory listing is exposed",
  },
  prerequisites: [
    {
      id: "usable_response",
      state: "met",
      explanation: "Response was usable.",
    },
  ],
  outcome: "supported_negative" as const,
  reason: "marker_absent",
  explanation:
    "The complete checked resource did not contain directory-listing evidence.",
  evidence_used: [{ kind: "fresh_recheck" as const, acquisition_id: "a" }],
  limitations: [
    "This conclusion applies only to the checked route and backend.",
  ],
};
const api = {
  getRecheck: vi.fn().mockResolvedValue({
    version: "assessment-v1",
    basis: "fresh_recheck",
    project_id: "local_lab",
    assessment_id: partialAssessment.id,
    stage_id: partialAssessment.stages[0].id,
    acquisitions: [
      {
        id: "40000000-0000-4000-8000-000000000001",
        started_at: "2026-09-18T10:01:00Z",
        finished_at: "2026-09-18T10:01:30Z",
        origin: "https://app.scope.test",
        approved_address: "127.0.0.1",
        method: "GET",
        resource: "/",
        status: "complete",
        response: null,
        evidence: {
          acquisition_id: "40000000-0000-4000-8000-000000000001",
          sha256: "f".repeat(64),
          size_bytes: 200,
          health: "ready",
        },
      },
      {
        id: "40000000-0000-4000-8000-000000000002",
        started_at: "2026-09-18T10:01:31Z",
        finished_at: "2026-09-18T10:01:32Z",
        origin: "https://app.scope.test",
        approved_address: "127.0.0.1",
        method: "GET",
        resource: "/.git/config",
        status: "truncated",
        response: null,
        evidence: {
          acquisition_id: "40000000-0000-4000-8000-000000000002",
          sha256: "e".repeat(64),
          size_bytes: 200,
          health: "corrupt",
        },
      },
    ],
    assessments: [assessmentResult],
  }),
} as unknown as ApiClient;

test("keeps failed and interrupted assessments distinct", () => {
  render(
    <AssessmentsView
      project={project}
      assessments={[partialAssessment, interruptedAssessment]}
      api={api}
      onRefresh={vi.fn()}
    />,
  );
  expect(screen.getAllByText("Failed").length).toBeGreaterThan(0);
  expect(screen.getAllByText("Interrupted").length).toBeGreaterThan(0);
});

test("shows completed evidence inside a failed partial assessment", async () => {
  render(
    <AssessmentsView
      project={project}
      assessments={[partialAssessment]}
      api={api}
      onRefresh={vi.fn()}
    />,
  );
  expect(screen.getByText("stage_failed")).toBeVisible();
  expect(await screen.findByText("Persisted recheck evidence")).toBeVisible();
  expect(screen.getByText("Not supported by this evidence")).toBeVisible();
  expect(screen.getByText("Evidence corrupt")).toBeVisible();
  expect(screen.getByText(/applies only to the checked route/i)).toBeVisible();
});
