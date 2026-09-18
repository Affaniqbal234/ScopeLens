import { useEffect, useState } from "react";
import type { ApiClient } from "../api/client";
import type {
  AssessmentResponse,
  ProjectSummary,
  RecheckReport,
  StageKind,
} from "../api/types";
import { AssessmentResultCard } from "../components/AssessmentResultCard";
import { StatePanel } from "../components/StatePanel";
import { StatusBadge } from "../components/StatusBadge";

const formatTime = (value: string | null) =>
  value
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(new Date(value))
    : "Not recorded";
const shortId = (value: string) => value.slice(0, 8);
const stageOrder: StageKind[] = ["nmap", "httpx", "nuclei", "web_recheck"];

function RecheckDetail({
  api,
  assessmentId,
  stageId,
}: {
  api: ApiClient;
  assessmentId: string;
  stageId: string;
}) {
  const [report, setReport] = useState<RecheckReport | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    void api
      .getRecheck(assessmentId, stageId)
      .then(setReport)
      .catch((reason: unknown) =>
        setError(
          reason instanceof Error
            ? reason.message
            : "Recheck evidence is unavailable.",
        ),
      );
  }, [api, assessmentId, stageId]);
  if (error)
    return (
      <StatePanel
        tone="error"
        title="Recheck evidence unavailable"
        detail={error}
      />
    );
  if (!report) return <StatePanel title="Loading recheck evidence" />;
  return (
    <div className="recheck-detail">
      <h4>Persisted recheck evidence</h4>
      {report.acquisitions.map((item) => (
        <article className="acquisition" key={item.id}>
          <div>
            <strong>{item.resource}</strong>
            <span>
              {item.origin} · {item.approved_address}
            </span>
          </div>
          <dl className="fact-grid">
            <div>
              <dt>Acquisition</dt>
              <dd>{item.status}</dd>
            </div>
            <div>
              <dt>Started</dt>
              <dd>{formatTime(item.started_at)}</dd>
            </div>
            <div>
              <dt>Finished</dt>
              <dd>{formatTime(item.finished_at)}</dd>
            </div>
            <div>
              <dt>Evidence</dt>
              <dd>
                {item.evidence ? (
                  <StatusBadge value={item.evidence.health} />
                ) : (
                  "No artifact"
                )}
              </dd>
            </div>
          </dl>
        </article>
      ))}
      {report.assessments.map((result) => (
        <AssessmentResultCard key={result.id} result={result} />
      ))}
    </div>
  );
}

export function AssessmentsView({
  project,
  assessments,
  api,
  onRefresh,
}: {
  project: ProjectSummary;
  assessments: AssessmentResponse[];
  api: ApiClient;
  onRefresh: () => Promise<void>;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(
    assessments[0]?.id ?? null,
  );
  const [stages, setStages] = useState<StageKind[]>([
    "httpx",
    "nuclei",
    "web_recheck",
  ]);
  const [profileId, setProfileId] = useState(project.profiles[0]?.id ?? "");
  const [message, setMessage] = useState("");
  const selected = assessments.find((item) => item.id === selectedId) ?? null;
  const toggleStage = (kind: StageKind) =>
    setStages((current) =>
      current.includes(kind)
        ? current.filter((item) => item !== kind)
        : [...current, kind],
    );
  const create = async () => {
    setMessage("Creating assessment…");
    try {
      const result = await api.createAssessment(
        crypto.randomUUID(),
        project.project.id,
        profileId,
        stageOrder.filter((kind) => stages.includes(kind)),
      );
      await onRefresh();
      setSelectedId(result.id);
      setMessage("Assessment created. No work has run yet.");
    } catch (error) {
      setMessage(
        error instanceof Error
          ? error.message
          : "Assessment could not be created.",
      );
    }
  };
  const execute = async () => {
    if (!selected) return;
    setMessage("Running the selected assessment synchronously…");
    try {
      await api.executeAssessment(selected.id);
      await onRefresh();
      setMessage("Worker returned. Durable stage outcomes are shown below.");
    } catch (error) {
      await onRefresh();
      setMessage(
        error instanceof Error
          ? error.message
          : "The worker could not run the assessment.",
      );
    }
  };
  return (
    <section aria-labelledby="assessments-title">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Plan · execution · result</p>
          <h2 id="assessments-title">Assessments</h2>
          <p>
            Assessment status summarizes the manifest. Stage outcomes show what
            was actually attempted.
          </p>
        </div>
        <button className="button--secondary" onClick={() => void onRefresh()}>
          Refresh
        </button>
      </div>
      <article className="panel create-panel">
        <h3>Create a bounded assessment</h3>
        <div className="form-row">
          <label>
            Profile
            <select
              value={profileId}
              onChange={(event) => setProfileId(event.target.value)}
            >
              {project.profiles.map((profile) => (
                <option key={profile.id}>{profile.id}</option>
              ))}
            </select>
          </label>
          <fieldset>
            <legend>Stages run in the order shown</legend>
            {stageOrder.map((kind) => (
              <label className="check-label" key={kind}>
                <input
                  type="checkbox"
                  checked={stages.includes(kind)}
                  onChange={() => toggleStage(kind)}
                />
                {kind}
              </label>
            ))}
          </fieldset>
          <button
            disabled={!profileId || stages.length === 0}
            onClick={() => void create()}
          >
            Create only
          </button>
        </div>
        {message && (
          <p className="form-message" role="status">
            {message}
          </p>
        )}
      </article>
      {assessments.length === 0 ? (
        <StatePanel
          title="No assessments yet"
          detail="Create an explicit stage plan to begin."
        />
      ) : (
        <div className="master-detail">
          <div className="assessment-list" aria-label="Assessment list">
            {assessments.map((item) => {
              const caveats = item.stages.filter((stage) =>
                ["failed", "interrupted", "skipped"].includes(stage.status),
              ).length;
              return (
                <button
                  className={`assessment-row ${item.id === selectedId ? "is-selected" : ""}`}
                  key={item.id}
                  onClick={() => setSelectedId(item.id)}
                >
                  <span>
                    <strong>{shortId(item.id)}</strong>
                    <small>{formatTime(item.created_at)}</small>
                  </span>
                  <StatusBadge value={item.status} />
                  {caveats > 0 && (
                    <small>
                      {caveats} coverage caveat{caveats === 1 ? "" : "s"}
                    </small>
                  )}
                </button>
              );
            })}
          </div>
          {selected && (
            <article className="panel detail-panel">
              <div className="detail-head">
                <div>
                  <p className="eyebrow">Manifest {selected.id}</p>
                  <h3>Assessment detail</h3>
                </div>
                <StatusBadge value={selected.status} />
              </div>
              <dl className="fact-grid">
                <div>
                  <dt>Created</dt>
                  <dd>{formatTime(selected.created_at)}</dd>
                </div>
                <div>
                  <dt>Started</dt>
                  <dd>{formatTime(selected.started_at)}</dd>
                </div>
                <div>
                  <dt>Finished</dt>
                  <dd>{formatTime(selected.finished_at)}</dd>
                </div>
                <div>
                  <dt>Scope snapshot</dt>
                  <dd>
                    <code>{selected.scope_snapshot_id.slice(0, 12)}…</code>
                  </dd>
                </div>
              </dl>
              {selected.reason && (
                <p className="failure-reason">{selected.reason}</p>
              )}
              {selected.status === "pending" && (
                <button onClick={() => void execute()}>
                  Run pending assessment
                </button>
              )}
              <h4 className="section-label">Stored stage order</h4>
              <ol className="stage-list">
                {selected.stages.map((stage) => (
                  <li key={stage.id}>
                    <div className="stage-line">
                      <span className="stage-index">{stage.ordinal + 1}</span>
                      <div>
                        <strong>{stage.request.kind}</strong>
                        <small>{stage.request.resources.join(", ")}</small>
                      </div>
                      <StatusBadge value={stage.status} />
                    </div>
                    <dl className="stage-meta">
                      <div>
                        <dt>Planned target</dt>
                        <dd>
                          {stage.request.web_target
                            ? `${stage.request.web_target.origin} · ${stage.request.web_target.approved_addresses.join(", ")}`
                            : stage.request.network_targets
                                .map((item) => item.address)
                                .join(", ") || "None"}
                        </dd>
                      </div>
                      <div>
                        <dt>Timing</dt>
                        <dd>
                          {formatTime(stage.started_at)} →{" "}
                          {formatTime(stage.finished_at)}
                        </dd>
                      </div>
                      <div>
                        <dt>Result</dt>
                        <dd>
                          {stage.result_run_id
                            ? `Run ${shortId(stage.result_run_id)}`
                            : (stage.reason ?? "No durable result reference")}
                        </dd>
                      </div>
                    </dl>
                    {stage.request.kind === "web_recheck" &&
                      ["completed", "failed", "interrupted"].includes(
                        stage.status,
                      ) && (
                        <RecheckDetail
                          api={api}
                          assessmentId={selected.id}
                          stageId={stage.id}
                        />
                      )}
                  </li>
                ))}
              </ol>
            </article>
          )}
        </div>
      )}
    </section>
  );
}
