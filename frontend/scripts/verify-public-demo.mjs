import { readdir, readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../dist-demo/", import.meta.url));
const forbidden = [
  "/api/v1/",
  "Authorization",
  "Bearer ",
  "SCOPELENS_API_TOKEN",
  "SCOPELENS_DATABASE_URL",
  "postgresql://",
  "worker/reconcile",
  "/execute",
  "/retests",
  "Cookie",
  "Set-Cookie",
  "/var/lib/scopelens",
  "C:\\Users\\",
  "/home/",
];

async function files(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map((entry) => {
      const path = join(directory, entry.name);
      return entry.isDirectory() ? files(path) : [path];
    }),
  );
  return nested.flat();
}

const paths = await files(root);
if (!paths.some((path) => extname(path) === ".html")) {
  throw new Error("public demo build has no HTML entry point");
}
for (const path of paths) {
  const content = await readFile(path, "utf8");
  for (const value of forbidden) {
    if (content.includes(value)) {
      throw new Error(
        `public demo contains forbidden operational data: ${value}`,
      );
    }
  }
}
