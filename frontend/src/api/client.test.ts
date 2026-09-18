import { createApiClient } from "./client";
import { project } from "../test/fixtures";

test("sends the token only in the Authorization header", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(JSON.stringify(project), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
  await createApiClient("x".repeat(32), "http://127.0.0.1:8000").getProject();
  const [url, init] = fetchMock.mock.calls[0];
  expect(String(url)).not.toContain("x".repeat(32));
  expect(new Headers(init?.headers).get("Authorization")).toBe(
    `Bearer ${"x".repeat(32)}`,
  );
});

test("does not expose unstructured backend traces", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response("Traceback C:\\private\\secret.py token=abc", { status: 500 }),
  );
  await expect(
    createApiClient("x".repeat(32)).getProject(),
  ).rejects.toMatchObject({
    message: "The local API could not complete the request.",
  });
});
