import { render, screen } from "@testing-library/react";
import type { ApiClient } from "../api/client";
import { project } from "../test/fixtures";
import { ScopeView } from "./ScopeView";

test("offers only server-approved focused recheck contexts", () => {
  render(
    <ScopeView project={project} api={{} as ApiClient} onCreated={vi.fn()} />,
  );
  const options = screen
    .getByLabelText("Authorized context")
    .querySelectorAll("option");
  expect(options).toHaveLength(2);
  expect([...options].map((item) => item.textContent)).toEqual([
    "https://app.scope.test · 127.0.0.1",
    "https://admin.scope.test · 127.0.0.1",
  ]);
  expect(
    screen.queryByLabelText(/path|method|flags|template/i),
  ).not.toBeInTheDocument();
  expect(
    screen.getByText(/Web approval and network approval remain separate/i),
  ).toBeVisible();
});
