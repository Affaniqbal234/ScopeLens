import { useMemo, useState } from "react";
import type { ApiClient } from "../api/client";
import type { ProjectSummary } from "../api/types";

export function ScopeView({
  project,
  api,
  onCreated,
}: {
  project: ProjectSummary;
  api: ApiClient;
  onCreated: () => Promise<void>;
}) {
  const contexts = useMemo(
    () =>
      project.project.scope.web_targets.flatMap((target) =>
        target.approved_addresses.map((address) => ({
          origin: target.origin,
          address,
          key: `${target.origin}|${address}`,
        })),
      ),
    [project],
  );
  const [contextKey, setContextKey] = useState(contexts[0]?.key ?? "");
  const [profileId, setProfileId] = useState(project.profiles[0]?.id ?? "");
  const [message, setMessage] = useState("");
  const createRetest = async () => {
    const selected = contexts.find((item) => item.key === contextKey);
    if (!selected) return;
    setMessage("Creating focused recheck…");
    try {
      await api.createRetest(
        crypto.randomUUID(),
        project.project.id,
        profileId,
        selected.origin,
        selected.address,
      );
      setMessage(
        "Focused recheck queued. It will not run until explicitly executed.",
      );
      await onCreated();
    } catch (error) {
      setMessage(
        error instanceof Error
          ? error.message
          : "Focused recheck could not be created.",
      );
    }
  };
  return (
    <section aria-labelledby="scope-title">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Server-owned authorization</p>
          <h2 id="scope-title">{project.project.name}</h2>
          <p>
            Web approval and network approval remain separate. Discovered
            addresses, peers, and redirects never become authorized targets.
          </p>
        </div>
      </div>
      <div className="split-grid">
        <article className="panel">
          <h3>Network scope</h3>
          {project.project.scope.network_targets.length ? (
            <table>
              <thead>
                <tr>
                  <th>Address</th>
                  <th>TCP ports</th>
                </tr>
              </thead>
              <tbody>
                {project.project.scope.network_targets.map((target) => (
                  <tr key={target.address}>
                    <td>
                      <code>{target.address}</code>
                    </td>
                    <td>{target.ports.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="muted">No network targets are authorized.</p>
          )}
        </article>
        <article className="panel">
          <h3>Web scope</h3>
          {project.project.scope.web_targets.map((target) => (
            <div className="scope-row" key={target.origin}>
              <strong>{target.origin}</strong>
              <span>{target.approved_addresses.join(", ")}</span>
            </div>
          ))}
        </article>
      </div>
      <article className="panel action-panel">
        <div>
          <p className="eyebrow">Bounded action</p>
          <h3>Queue a focused web recheck</h3>
          <p>
            Choose one existing origin and approved backend. ScopeLens uses only
            its fixed read-only resources.
          </p>
        </div>
        <div className="form-row">
          <label>
            Authorized context
            <select
              value={contextKey}
              onChange={(event) => setContextKey(event.target.value)}
            >
              {contexts.map((item) => (
                <option key={item.key} value={item.key}>
                  {item.origin} · {item.address}
                </option>
              ))}
            </select>
          </label>
          <label>
            Profile
            <select
              value={profileId}
              onChange={(event) => setProfileId(event.target.value)}
            >
              {project.profiles.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.id}
                </option>
              ))}
            </select>
          </label>
          <button
            onClick={() => void createRetest()}
            disabled={!contextKey || !profileId}
          >
            Queue recheck
          </button>
        </div>
        {message && (
          <p className="form-message" role="status">
            {message}
          </p>
        )}
      </article>
    </section>
  );
}
