import type {
  AssessmentReport,
  AssessmentResponse,
  ComparisonReport,
  ComparisonSide,
  CorrelationResponse,
  ProjectSummary,
  RecheckReport,
  StageKind,
} from "./types";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const fallbackMessage = (status: number) => {
  if (status === 401) return "The API token was not accepted.";
  if (status === 403) return "This operation is outside the configured scope.";
  if (status === 404) return "The selected record was not found.";
  if (status === 409)
    return "The durable lifecycle does not allow this operation.";
  if (status === 422) return "The selected inputs could not be processed.";
  if (status === 503) return "The local data service is unavailable.";
  return "The local API could not complete the request.";
};

export const createApiClient = (
  token: string,
  baseUrl = import.meta.env.VITE_SCOPELENS_API_URL ?? "http://127.0.0.1:8000",
) => {
  const request = async <T>(
    path: string,
    init: RequestInit = {},
  ): Promise<T> => {
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${token}`);
    if (init.body) headers.set("Content-Type", "application/json");
    let response: Response;
    try {
      response = await fetch(`${baseUrl}${path}`, { ...init, headers });
    } catch {
      throw new ApiError(
        0,
        "network_error",
        "The local ScopeLens API is unavailable.",
      );
    }
    if (!response.ok) {
      let code = "request_failed";
      let message = fallbackMessage(response.status);
      try {
        const body = (await response.json()) as unknown;
        if (body && typeof body === "object" && "error" in body) {
          const error = (body as { error?: unknown }).error;
          if (error && typeof error === "object") {
            const candidate = error as { code?: unknown; message?: unknown };
            if (typeof candidate.code === "string") code = candidate.code;
            if (
              typeof candidate.message === "string" &&
              candidate.message.length <= 240
            )
              message = candidate.message;
          }
        }
      } catch {
        /* Use the bounded status message. */
      }
      throw new ApiError(response.status, code, message);
    }
    return response.json() as Promise<T>;
  };

  return {
    getProject: () => request<ProjectSummary>("/api/v1/project"),
    listAssessments: (projectId: string) =>
      request<AssessmentResponse[]>(
        `/api/v1/assessments?project_id=${encodeURIComponent(projectId)}`,
      ),
    getAssessment: (id: string) =>
      request<AssessmentResponse>(
        `/api/v1/assessments/${encodeURIComponent(id)}`,
      ),
    createAssessment: (
      assessmentId: string,
      projectId: string,
      profileId: string,
      stages: StageKind[],
    ) =>
      request<AssessmentResponse>("/api/v1/assessments", {
        method: "POST",
        body: JSON.stringify({
          assessment_id: assessmentId,
          project_id: projectId,
          profile_id: profileId,
          stages,
        }),
      }),
    executeAssessment: (id: string) =>
      request<AssessmentResponse>(
        `/api/v1/assessments/${encodeURIComponent(id)}/execute`,
        { method: "POST" },
      ),
    createRetest: (
      assessmentId: string,
      projectId: string,
      profileId: string,
      origin: string,
      approvedAddress: string,
    ) =>
      request<AssessmentResponse>("/api/v1/retests", {
        method: "POST",
        body: JSON.stringify({
          assessment_id: assessmentId,
          project_id: projectId,
          profile_id: profileId,
          origin,
          approved_address: approvedAddress,
        }),
      }),
    correlate: (projectId: string, runIds: string[]) =>
      request<CorrelationResponse>("/api/v1/analysis/correlation", {
        method: "POST",
        body: JSON.stringify({ project_id: projectId, run_ids: runIds }),
      }),
    assess: (projectId: string, runIds: string[]) =>
      request<AssessmentReport>("/api/v1/analysis/assessment", {
        method: "POST",
        body: JSON.stringify({ project_id: projectId, run_ids: runIds }),
      }),
    compare: (
      projectId: string,
      baseline: ComparisonSide,
      current: ComparisonSide,
    ) =>
      request<ComparisonReport>("/api/v1/analysis/comparison", {
        method: "POST",
        body: JSON.stringify({ project_id: projectId, baseline, current }),
      }),
    getRecheck: (assessmentId: string, stageId: string) =>
      request<RecheckReport>(
        `/api/v1/assessments/${encodeURIComponent(assessmentId)}/stages/${encodeURIComponent(stageId)}/recheck`,
      ),
  };
};

export type ApiClient = ReturnType<typeof createApiClient>;
