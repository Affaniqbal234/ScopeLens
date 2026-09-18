import { render, screen } from "@testing-library/react";
import { StatusBadge } from "./StatusBadge";

test.each([
  ["supported_positive", "Supported"],
  ["supported_negative", "Not supported by this evidence"],
  ["inconclusive", "Inconclusive"],
  ["resolved", "Resolved in checked context"],
  ["not_observed", "Not observed; absence unproven"],
  ["unknown", "Unknown"],
] as const)("renders %s without changing its meaning", (value, label) => {
  render(<StatusBadge value={value} />);
  expect(screen.getByText(label)).toBeVisible();
});
