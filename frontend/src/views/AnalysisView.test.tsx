import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ApiClient } from "../api/client";
import { partialAssessment } from "../test/fixtures";
import { AnalysisView } from "./AnalysisView";

const withRuns = {
  ...partialAssessment,
  stages: partialAssessment.stages.map((stage, index) => ({
    ...stage,
    result_run_id: `30000000-0000-4000-8000-00000000000${index + 1}`,
  })),
};
const correlation = {
  version: "correlation-v1" as const,
  project_id: "local_lab",
  sources: [
    {
      run_id: withRuns.stages[0].result_run_id!,
      report: {
        matches: [
          {
            scanner_severity: "medium",
            template_revision: "c".repeat(64),
            matched_location: "https://app.scope.test/.git/config",
            assessment: "unvalidated" as const,
          },
        ],
      },
      artifacts: [],
    },
  ],
  inventory: [
    {
      id: `inventory-v1:${"1".repeat(64)}`,
      identity: {
        kind: "http_origin" as const,
        origin: "https://app.scope.test",
      },
      sources: [
        {
          run_id: withRuns.stages[0].result_run_id!,
          section: "context" as const,
          ordinal: null,
        },
      ],
    },
    {
      id: `inventory-v1:${"2".repeat(64)}`,
      identity: {
        kind: "http_origin" as const,
        origin: "https://admin.scope.test",
      },
      sources: [
        {
          run_id: withRuns.stages[0].result_run_id!,
          section: "context" as const,
          ordinal: null,
        },
      ],
    },
  ],
  relationships: [],
  assertions: [],
  findings: [
    {
      id: `finding-v1:${"3".repeat(64)}`,
      identity: {
        rule: "finding-v1" as const,
        project_id: "local_lab",
        origin: "https://app.scope.test",
        resource: "/.git/config",
        template_id: "git-config-exposure",
        matcher: "git-config",
      },
      resource_id: `inventory-v1:${"4".repeat(64)}`,
      occurrences: [
        {
          run_id: withRuns.stages[0].result_run_id!,
          section: "matches" as const,
          ordinal: 0,
        },
      ],
    },
  ],
  artifact_copies: [],
};
const api = {
  correlate: vi.fn().mockResolvedValue(correlation),
  assess: vi.fn().mockResolvedValue({
    version: "assessment-v1",
    basis: "existing_capture",
    project_id: "local_lab",
    assessments: [],
  }),
} as unknown as ApiClient;

test("keeps two virtual hosts on one address visibly separate", async () => {
  const user = userEvent.setup();
  render(
    <AnalysisView projectId="local_lab" assessments={[withRuns]} api={api} />,
  );
  await user.click(screen.getAllByRole("checkbox")[0]);
  await user.click(
    screen.getByRole("button", { name: "Analyze selected runs" }),
  );
  expect(await screen.findByText("https://app.scope.test")).toBeVisible();
  expect(screen.getByText("https://admin.scope.test")).toBeVisible();
  expect(screen.getByText("Scanner severity: medium")).toBeVisible();
  expect(screen.getByText(/unvalidated/)).toBeVisible();
});
