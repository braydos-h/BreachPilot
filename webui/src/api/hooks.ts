import {
  useMutation,
  useQuery,
  useQueryClient,
  keepPreviousData,
} from "@tanstack/react-query";
import { useCallback } from "react";
import {
  apiFetch,
  ApiError,
  clearStoredToken,
} from "@/api/client";
import type {
  ArtifactListResponse,
  AuditResponse,
  Capabilities,
  ConfigPatchResponse,
  ConfigSchema,
  CampaignStateResponse,
  CreateRunResponse,
  CredentialRevealResponse,
  CredentialsResponse,
  DecisionAnswerResponse,
  DecisionListRow,
  DecisionOut,
  DeleteRunResponse,
  DiagnosticsResponse,
  GoalPreset,
  LiveModelsResponse,
  LogResponse,
  LootResponse,
  ModelRegistryInfo,
  PluginSummary,
  ResumeRunResponse,
  RunCreateRequest,
  RunDetail,
  RunListResponse,
  SecretsStatus,
  SkillDetail,
  SkillInstallRequest,
  SkillInstallResponse,
  SkillRemoveResponse,
  SkillSearchResult,
  SkillSummary,
  SwarmStateResponse,
  ToolCallRequest,
  ToolCallResponse,
  ToolsResponse,
} from "@/api/types";

export const queryKeys = {
  capabilities: ["capabilities"] as const,
  config: ["config"] as const,
  configSchema: ["config", "schema"] as const,
  secrets: ["secrets"] as const,
  models: ["models"] as const,
  modelsLive: ["models", "live"] as const,
  plugins: ["plugins"] as const,
  goals: ["goals"] as const,
  skills: ["skills"] as const,
  skillsSearch: (q: string) => ["skills", "search", q] as const,
  skill: (name: string) => ["skills", name] as const,
  runs: (limit: number, offset: number, sort: string = "created_desc") =>
    ["runs", { limit, offset, sort }] as const,
  run: (runId: string) => ["runs", runId] as const,
  runDecisions: (runId: string) => ["runs", runId, "decisions"] as const,
  decision: (runId: string, decisionId: string) => ["runs", runId, "decisions", decisionId] as const,
  runTools: (runId: string) => ["runs", runId, "tools"] as const,
  runArtifacts: (runId: string) => ["runs", runId, "artifacts"] as const,
  runAudit: (runId: string) => ["runs", runId, "audit"] as const,
  runSwarm: (runId: string) => ["runs", runId, "swarm"] as const,
  runCampaign: (runId: string) => ["runs", runId, "campaign"] as const,
  runLog: (runId: string, name: string, tail: number, attempt?: string, target?: string) =>
    ["runs", runId, "logs", name, tail, attempt ?? "", target ?? ""] as const,
  runCredentials: (runId: string) => ["runs", runId, "credentials"] as const,
  runLoot: (runId: string) => ["runs", runId, "loot"] as const,
};

const DEFAULT_RETRY = (failureCount: number, error: unknown) => {
  if (error instanceof ApiError) {
    if (error.status === 0) return failureCount < 3;
    if (error.status >= 400 && error.status < 500 && error.status !== 408 && error.status !== 429) {
      return false;
    }
  }
  return failureCount < 2;
};

export const defaultQueryOptions = {
  retry: DEFAULT_RETRY,
  staleTime: 15_000,
  gcTime: 5 * 60_000,
  meta: { onErrorAuthClear: true } as const,
};

export function useCapabilities(enabled = true) {
  return useQuery<Capabilities>({
    queryKey: queryKeys.capabilities,
    queryFn: () => apiFetch<Capabilities>("/capabilities"),
    ...defaultQueryOptions,
    enabled,
    staleTime: 60_000,
  });
}

export function useConfig() {
  return useQuery<Record<string, unknown>>({
    queryKey: queryKeys.config,
    queryFn: () => apiFetch<Record<string, unknown>>("/config"),
    ...defaultQueryOptions,
    staleTime: 30_000,
  });
}

export function useConfigSchema() {
  return useQuery<ConfigSchema>({
    queryKey: queryKeys.configSchema,
    queryFn: () => apiFetch<ConfigSchema>("/config/schema"),
    ...defaultQueryOptions,
    staleTime: Infinity,
  });
}

export function usePatchConfig() {
  const qc = useQueryClient();
  return useMutation<ConfigPatchResponse, ApiError, Record<string, unknown>>({
    mutationFn: (patch) =>
      apiFetch<ConfigPatchResponse>("/config", { method: "PATCH", body: patch }),
    onSuccess: (data) => {
      qc.setQueryData<Record<string, unknown>>(queryKeys.config, data.config);
    },
    onError: (error) => {
      if (error.isAuth) clearStoredToken();
    },
  });
}

export function useSecrets() {
  return useQuery<SecretsStatus>({
    queryKey: queryKeys.secrets,
    queryFn: () => apiFetch<SecretsStatus>("/secrets"),
    ...defaultQueryOptions,
    staleTime: 30_000,
  });
}

export function usePutSecrets() {
  const qc = useQueryClient();
  return useMutation<unknown, ApiError, Record<string, string>>({
    mutationFn: (secrets) =>
      apiFetch<unknown>("/secrets", { method: "PUT", body: { secrets } }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.secrets });
    },
  });
}

export function useModels() {
  return useQuery<ModelRegistryInfo>({
    queryKey: queryKeys.models,
    queryFn: () => apiFetch<ModelRegistryInfo>("/models"),
    ...defaultQueryOptions,
    staleTime: 60_000,
  });
}

export function useLiveModels() {
  return useQuery<LiveModelsResponse>({
    queryKey: queryKeys.modelsLive,
    queryFn: async () => {
      try {
        return await apiFetch<LiveModelsResponse>("/models/live", { raw: false });
      } catch (error) {
        if (error instanceof ApiError && error.status === 503 && error.raw) {
          return error.raw as LiveModelsResponse;
        }
        throw error;
      }
    },
    ...defaultQueryOptions,
    staleTime: 30_000,
  });
}

export function usePlugins() {
  return useQuery<{ plugins: PluginSummary[] }>({
    queryKey: queryKeys.plugins,
    queryFn: () => apiFetch<{ plugins: PluginSummary[] }>("/plugins"),
    ...defaultQueryOptions,
    staleTime: 60_000,
  });
}

export function useGoals() {
  return useQuery<{ goals: GoalPreset[] }>({
    queryKey: queryKeys.goals,
    queryFn: () => apiFetch<{ goals: GoalPreset[] }>("/goals"),
    ...defaultQueryOptions,
    staleTime: Infinity,
  });
}

export function useSkills() {
  return useQuery<{ skills: SkillSummary[]; error?: string }>({
    queryKey: queryKeys.skills,
    queryFn: () => apiFetch<{ skills: SkillSummary[]; error?: string }>("/skills"),
    ...defaultQueryOptions,
    staleTime: 60_000,
  });
}

export function useSkillSearch(q: string, enabled = true) {
  return useQuery<{ results: SkillSearchResult[] }>({
    queryKey: queryKeys.skillsSearch(q),
    queryFn: () => apiFetch<{ results: SkillSearchResult[] }>(`/skills/search?q=${encodeURIComponent(q)}`),
    ...defaultQueryOptions,
    enabled: enabled && q.trim().length > 0,
    staleTime: 60_000,
  });
}

export function useSkillDetail(name: string | null) {
  return useQuery<SkillDetail>({
    queryKey: queryKeys.skill(name ?? ""),
    queryFn: () => apiFetch<SkillDetail>(`/skills/${encodeURIComponent(name as string)}`),
    ...defaultQueryOptions,
    enabled: !!name,
  });
}

export function useInstallSkill() {
  const qc = useQueryClient();
  return useMutation<SkillInstallResponse, ApiError, SkillInstallRequest>({
    mutationFn: (body) => apiFetch<SkillInstallResponse>("/skills", { method: "POST", body }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.skills });
    },
  });
}

export function useRemoveSkill() {
  const qc = useQueryClient();
  return useMutation<SkillRemoveResponse, ApiError, string>({
    mutationFn: (name) =>
      apiFetch<SkillRemoveResponse>(`/skills/${encodeURIComponent(name)}`, { method: "DELETE" }),
    onSuccess: (_data, name) => {
      void qc.invalidateQueries({ queryKey: queryKeys.skills });
      void qc.removeQueries({ queryKey: queryKeys.skill(name) });
    },
  });
}

export function useDiagnostics() {
  const useMut = useMutation<DiagnosticsResponse, ApiError, "doctor" | "self-test">;
  return useMut({
    mutationFn: (kind) =>
      apiFetch<DiagnosticsResponse>(`/diagnostics/${kind}`, { method: "POST", body: {} }),
  });
}

export function useRuns(limit = 50, offset = 0, sort: string = "created_desc") {
  return useQuery<RunListResponse>({
    queryKey: queryKeys.runs(limit, offset, sort),
    queryFn: () =>
      apiFetch<RunListResponse>(`/runs?limit=${limit}&offset=${offset}&sort=${encodeURIComponent(sort)}`),
    ...defaultQueryOptions,
    refetchInterval: 5_000,
    placeholderData: keepPreviousData,
  });
}

export function useRun(runId: string | null | undefined) {
  return useQuery<RunDetail>({
    queryKey: queryKeys.run(runId ?? ""),
    queryFn: () => apiFetch<RunDetail>(`/runs/${encodeURIComponent(runId as string)}`),
    ...defaultQueryOptions,
    enabled: !!runId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return 5_000;
      if (data.state === "running" || data.state === "queued" || data.state === "cancelling") {
        return 5_000;
      }
      return false;
    },
  });
}

export function useCreateRun() {
  const qc = useQueryClient();
  return useMutation<CreateRunResponse, ApiError, RunCreateRequest>({
    mutationFn: (body) => apiFetch<CreateRunResponse>("/runs", { method: "POST", body }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useCancelRun() {
  const qc = useQueryClient();
  return useMutation<{ run_id: string; state: string }, ApiError, string>({
    mutationFn: (runId) =>
      apiFetch<{ run_id: string; state: string }>(`/runs/${encodeURIComponent(runId)}/cancel`, {
        method: "POST",
        body: {},
      }),
    onSuccess: (_data, runId) => {
      void qc.invalidateQueries({ queryKey: queryKeys.run(runId) });
      void qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useResumeRun() {
  const qc = useQueryClient();
  return useMutation<ResumeRunResponse, ApiError, string>({
    mutationFn: (runId) =>
      apiFetch<ResumeRunResponse>(`/runs/${encodeURIComponent(runId)}/resume`, { method: "POST", body: {} }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useDeleteRun() {
  const qc = useQueryClient();
  return useMutation<DeleteRunResponse, ApiError, { runId: string; purge?: boolean }>({
    mutationFn: ({ runId, purge }) =>
      apiFetch<DeleteRunResponse>(
        `/runs/${encodeURIComponent(runId)}?purge=${purge ? "true" : "false"}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useRetitleRun() {
  const qc = useQueryClient();
  return useMutation<
    { run_id: string; title: string; regenerated: boolean },
    ApiError,
    { runId: string; title?: string; regen?: boolean }
  >({
    mutationFn: ({ runId, title, regen }) =>
      apiFetch<{ run_id: string; title: string; regenerated: boolean }>(
        `/runs/${encodeURIComponent(runId)}/title`,
        { method: "POST", body: { title: title ?? null, regen: !!regen } },
      ),
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({ queryKey: queryKeys.run(vars.runId) });
      void qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useDecisions(runId: string | null | undefined) {
  return useQuery<{ decisions: DecisionListRow[] }>({
    queryKey: queryKeys.runDecisions(runId ?? ""),
    queryFn: () => apiFetch<{ decisions: DecisionListRow[] }>(`/runs/${encodeURIComponent(runId as string)}/decisions`),
    ...defaultQueryOptions,
    enabled: !!runId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return 10_000;
      const hasPending = data.decisions.some((d) => d.status === "pending");
      return hasPending ? 5_000 : false;
    },
  });
}

export function useDecision(runId: string | null, decisionId: string | null) {
  return useQuery<DecisionOut>({
    queryKey: queryKeys.decision(runId ?? "", decisionId ?? ""),
    queryFn: () =>
      apiFetch<DecisionOut>(
        `/runs/${encodeURIComponent(runId as string)}/decisions/${encodeURIComponent(decisionId as string)}`,
      ),
    ...defaultQueryOptions,
    enabled: !!runId && !!decisionId,
  });
}

export function useAnswerDecision(runId: string) {
  const qc = useQueryClient();
  return useMutation<DecisionAnswerResponse, ApiError, { decisionId: string; answer: string }>({
    mutationFn: ({ decisionId, answer }) =>
      apiFetch<DecisionAnswerResponse>(
        `/runs/${encodeURIComponent(runId)}/decisions/${encodeURIComponent(decisionId)}`,
        { method: "POST", body: { answer } },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.runDecisions(runId) });
      void qc.invalidateQueries({ queryKey: queryKeys.run(runId) });
      void qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useRunTools(runId: string | null | undefined, enabled = true) {
  return useQuery<ToolsResponse>({
    queryKey: queryKeys.runTools(runId ?? ""),
    queryFn: () => apiFetch<ToolsResponse>(`/runs/${encodeURIComponent(runId as string)}/tools`),
    ...defaultQueryOptions,
    enabled: !!runId && enabled,
    staleTime: 15_000,
  });
}

export function useCallTool(runId: string) {
  return useMutation<ToolCallResponse, ApiError, { tool: string; arguments: Record<string, unknown> }>({
    mutationFn: ({ tool, arguments: args }) =>
      apiFetch<ToolCallResponse>(
        `/runs/${encodeURIComponent(runId)}/tools/${encodeURIComponent(tool)}/calls`,
        { method: "POST", body: { arguments: args } as ToolCallRequest },
      ),
  });
}

export function useArtifacts(runId: string | null | undefined) {
  return useQuery<ArtifactListResponse>({
    queryKey: queryKeys.runArtifacts(runId ?? ""),
    queryFn: () => apiFetch<ArtifactListResponse>(`/runs/${encodeURIComponent(runId as string)}/artifacts`),
    ...defaultQueryOptions,
    enabled: !!runId,
    refetchInterval: (query) => {
      const run = query.state.data;
      if (!run) return 30_000;
      return 30_000;
    },
  });
}

export function useAudit(runId: string | null | undefined, enabled = true) {
  return useQuery<AuditResponse>({
    queryKey: queryKeys.runAudit(runId ?? ""),
    queryFn: () => apiFetch<AuditResponse>(`/runs/${encodeURIComponent(runId as string)}/audit`),
    ...defaultQueryOptions,
    enabled: !!runId && enabled,
  });
}

export function useSwarmState(runId: string | null | undefined, enabled = true) {
  return useQuery<SwarmStateResponse>({
    queryKey: queryKeys.runSwarm(runId ?? ""),
    queryFn: () => apiFetch<SwarmStateResponse>(`/runs/${encodeURIComponent(runId as string)}/swarm`),
    ...defaultQueryOptions,
    enabled: !!runId && enabled,
    retry: (count, error) => {
      if (error instanceof ApiError && error.isNotFound) return false;
      return DEFAULT_RETRY(count, error);
    },
  });
}

export function useCampaignState(runId: string | null | undefined, enabled = true) {
  return useQuery<CampaignStateResponse>({
    queryKey: queryKeys.runCampaign(runId ?? ""),
    queryFn: () => apiFetch<CampaignStateResponse>(`/runs/${encodeURIComponent(runId as string)}/campaign`),
    ...defaultQueryOptions,
    enabled: !!runId && enabled,
    retry: (count, error) => {
      if (error instanceof ApiError && error.isNotFound) return false;
      return DEFAULT_RETRY(count, error);
    },
  });
}

export function useRunLog(
  runId: string | null,
  name: string,
  tail: number,
  attemptId: string,
  targetIp: string,
  enabled = true,
) {
  return useQuery<LogResponse>({
    queryKey: queryKeys.runLog(runId ?? "", name, tail, attemptId, targetIp),
    queryFn: () => {
      const params = new URLSearchParams({ tail: String(tail) });
      if (attemptId) params.set("attempt_id", attemptId);
      if (targetIp) params.set("target_ip", targetIp);
      return apiFetch<LogResponse>(
        `/runs/${encodeURIComponent(runId as string)}/logs/${encodeURIComponent(name)}?${params.toString()}`,
      );
    },
    ...defaultQueryOptions,
    enabled: !!runId && !!name && enabled,
  });
}

export function useCredentials(runId: string | null | undefined) {
  return useQuery<CredentialsResponse>({
    queryKey: queryKeys.runCredentials(runId ?? ""),
    queryFn: () => apiFetch<CredentialsResponse>(`/runs/${encodeURIComponent(runId as string)}/credentials`),
    ...defaultQueryOptions,
    enabled: !!runId,
  });
}

export function useRevealCredential(runId: string) {
  const qc = useQueryClient();
  return useMutation<CredentialRevealResponse, ApiError, number>({
    mutationFn: (index) =>
      apiFetch<CredentialRevealResponse>(
        `/runs/${encodeURIComponent(runId)}/credentials/${index}/reveal`,
        { method: "POST", body: {} },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.runCredentials(runId) });
    },
  });
}

export function useLoot(runId: string | null | undefined) {
  return useQuery<LootResponse>({
    queryKey: queryKeys.runLoot(runId ?? ""),
    queryFn: () => apiFetch<LootResponse>(`/runs/${encodeURIComponent(runId as string)}/loot`),
    ...defaultQueryOptions,
    enabled: !!runId,
  });
}

export function useArtifactUrl(runId: string): (name: string) => string {
  return useCallback(
    (name: string) => `/api/v1/runs/${encodeURIComponent(runId)}/artifacts/${name.split("/").map(encodeURIComponent).join("/")}`,
    [runId],
  );
}

export function useFetchArtifactBlob(runId: string) {
  return useMutation<Blob, ApiError, string>({
    mutationFn: (name) =>
      apiFetch<Blob>(
        `/runs/${encodeURIComponent(runId)}/artifacts/${name.split("/").map(encodeURIComponent).join("/")}`,
        { raw: true },
      ),
  });
}
