import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App";
import { project } from "./test/fixtures";

test("handles unauthorized access without echoing the token", async () => {
  const token = "not-a-valid-local-api-token-value";
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(
      JSON.stringify({
        error: {
          code: "authentication_required",
          message: "authentication required",
        },
      }),
      { status: 401, headers: { "Content-Type": "application/json" } },
    ),
  );
  const user = userEvent.setup();
  render(<App />);
  await user.type(screen.getByLabelText("Local API token"), token);
  await user.click(screen.getByRole("button", { name: "Open dashboard" }));
  expect(
    await screen.findByText("The local API token was not accepted."),
  ).toBeVisible();
  expect(screen.queryByText(token)).not.toBeInTheDocument();
});

test("opens the dashboard with a valid in-memory token", async () => {
  vi.spyOn(globalThis, "fetch").mockImplementation(
    async (input) =>
      new Response(
        JSON.stringify(String(input).includes("assessments?") ? [] : project),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
  );
  const user = userEvent.setup();
  render(<App />);
  await user.type(screen.getByLabelText("Local API token"), "x".repeat(32));
  await user.click(screen.getByRole("button", { name: "Open dashboard" }));
  expect(
    await screen.findByRole("heading", { name: "Assessments" }),
  ).toBeVisible();
  expect(screen.getByText("No assessments yet")).toBeVisible();
});
