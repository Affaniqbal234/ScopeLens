import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ApiClient } from "../api/client";
import { comparisonFixture, partialAssessment } from "../test/fixtures";
import { ComparisonView } from "./ComparisonView";

const second = {
  ...partialAssessment,
  id: "10000000-0000-4000-8000-000000000099",
  stages: [
    {
      ...partialAssessment.stages[0],
      id: "20000000-0000-4000-8000-000000000099",
      status: "completed" as const,
    },
  ],
};
const api = {
  compare: vi.fn().mockResolvedValue(comparisonFixture),
} as unknown as ApiClient;

test("requires explicit baseline and current selections", () => {
  render(
    <ComparisonView
      projectId="local_lab"
      assessments={[partialAssessment, second]}
      api={api}
    />,
  );
  expect(
    screen.getByRole("button", { name: "Compare selections" }),
  ).toBeDisabled();
  expect(screen.getByText(/will not select the latest/i)).toBeVisible();
});

test("communicates resolved, unknown, not observed, and HSTS polarity", async () => {
  const user = userEvent.setup();
  render(
    <ComparisonView
      projectId="local_lab"
      assessments={[partialAssessment, second]}
      api={api}
    />,
  );
  await user.selectOptions(
    screen.getByLabelText("Baseline evidence"),
    screen.getAllByRole("option")[1].getAttribute("value")!,
  );
  const currentOptions = screen
    .getByLabelText("Current evidence")
    .querySelectorAll("option");
  await user.selectOptions(
    screen.getByLabelText("Current evidence"),
    currentOptions[currentOptions.length - 1].value,
  );
  await user.click(screen.getByRole("button", { name: "Compare selections" }));
  expect(
    await screen.findAllByText("Resolved in checked context"),
  ).toHaveLength(2);
  expect(screen.getByText("Unknown")).toBeVisible();
  expect(screen.getByText("Not observed; absence unproven")).toBeVisible();
  expect(
    screen.getByText(/missing-HSTS condition is supported/i),
  ).toBeVisible();
  expect(screen.getAllByText(/does not prove a code fix/i)).toHaveLength(2);
});
