import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, createApiClient, type ApiClient } from "./api/client";
import type { AssessmentResponse, ProjectSummary } from "./api/types";
import { StatePanel } from "./components/StatePanel";
import { AnalysisView } from "./views/AnalysisView";
import { AssessmentsView } from "./views/AssessmentsView";
import { ComparisonView } from "./views/ComparisonView";
import { ScopeView } from "./views/ScopeView";

type View = "assessments" | "evidence" | "history" | "scope";

function Login({ onConnect }: { onConnect: (token: string) => Promise<void> }) {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onConnect(token);
      setToken("");
    } catch (reason) {
      setError(
        reason instanceof ApiError && reason.status === 401
          ? "The local API token was not accepted."
          : reason instanceof Error
            ? reason.message
            : "The local API is unavailable.",
      );
    } finally {
      setBusy(false);
    }
  };
  return (
    <main className="login-shell">
      <section className="login-panel" aria-labelledby="login-title">
        <div className="brand-mark" aria-hidden="true">
          SL
        </div>
        <p className="eyebrow">Local assessment workspace</p>
        <h1 id="login-title">Connect to ScopeLens</h1>
        <p>
          Enter the server-owned API token for this browser session. It stays in
          memory and is cleared when you sign out or close the tab.
        </p>
        <form onSubmit={(event) => void submit(event)}>
          <label>
            Local API token
            <input
              type="password"
              autoComplete="off"
              minLength={32}
              required
              value={token}
              onChange={(event) => setToken(event.target.value)}
            />
          </label>
          <button disabled={busy || token.length < 32}>
            {busy ? "Connecting…" : "Open dashboard"}
          </button>
        </form>
        {error && (
          <StatePanel tone="error" title="Connection failed" detail={error} />
        )}
      </section>
    </main>
  );
}

function Dashboard({
  api,
  project,
  onSignOut,
}: {
  api: ApiClient;
  project: ProjectSummary;
  onSignOut: () => void;
}) {
  const [view, setView] = useState<View>("assessments");
  const [assessments, setAssessments] = useState<AssessmentResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setAssessments(await api.listAssessments(project.project.id));
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Assessment history is unavailable.",
      );
    } finally {
      setLoading(false);
    }
  }, [api, project.project.id]);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  const content = useMemo(() => {
    if (loading)
      return <StatePanel title="Loading durable assessment history" />;
    if (error)
      return (
        <StatePanel
          tone="error"
          title="Assessment history unavailable"
          detail={error}
        />
      );
    if (view === "assessments")
      return (
        <AssessmentsView
          project={project}
          assessments={assessments}
          api={api}
          onRefresh={refresh}
        />
      );
    if (view === "evidence")
      return (
        <AnalysisView
          projectId={project.project.id}
          assessments={assessments}
          api={api}
        />
      );
    if (view === "history")
      return (
        <ComparisonView
          projectId={project.project.id}
          assessments={assessments}
          api={api}
        />
      );
    return <ScopeView project={project} api={api} onCreated={refresh} />;
  }, [api, assessments, error, loading, project, refresh, view]);
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <aside className="sidebar">
        <div>
          <div className="sidebar-brand">
            <span className="brand-mark" aria-hidden="true">
              SL
            </span>
            <div>
              <strong>ScopeLens</strong>
              <small>{project.project.name}</small>
            </div>
          </div>
          <nav aria-label="Primary navigation">
            {(
              [
                ["assessments", "Assessments"],
                ["evidence", "Evidence"],
                ["history", "History"],
                ["scope", "Authorized scope"],
              ] as [View, string][]
            ).map(([id, label]) => (
              <button
                key={id}
                className={view === id ? "is-active" : ""}
                aria-current={view === id ? "page" : undefined}
                onClick={() => setView(id)}
              >
                {label}
              </button>
            ))}
          </nav>
        </div>
        <div className="sidebar-foot">
          <p>
            <span className="connection-dot" />
            Local API connected
          </p>
          <button className="button--quiet" onClick={onSignOut}>
            Clear token and sign out
          </button>
        </div>
      </aside>
      <main id="main-content" className="workspace" tabIndex={-1}>
        {content}
      </main>
    </div>
  );
}

export default function App() {
  const [session, setSession] = useState<{
    api: ApiClient;
    project: ProjectSummary;
  } | null>(null);
  const connect = async (token: string) => {
    const api = createApiClient(token);
    const project = await api.getProject();
    setSession({ api, project });
  };
  if (!session) return <Login onConnect={connect} />;
  return (
    <Dashboard
      api={session.api}
      project={session.project}
      onSignOut={() => setSession(null)}
    />
  );
}
