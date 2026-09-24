import { render, screen } from "@testing-library/react";
import DemoApp from "./DemoApp";

test("renders qualified synthetic states without operational controls", () => {
  render(<DemoApp />);

  expect(
    screen.getByText(/deterministic synthetic acquisitions/i),
  ).toBeInTheDocument();
  expect(screen.getByText("Resolved in checked context")).toBeInTheDocument();
  expect(screen.getByText("Unknown")).toBeInTheDocument();
  expect(
    screen.getByText("Not observed; absence unproven"),
  ).toBeInTheDocument();
  expect(screen.getByText("New to this comparison")).toBeInTheDocument();
  expect(screen.getAllByText("192.0.2.1")).toHaveLength(6);
  expect(screen.queryByRole("button")).not.toBeInTheDocument();
  expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  expect(
    screen.getByText(/cannot start assessments or contact assessment targets/i),
  ).toBeInTheDocument();
});
