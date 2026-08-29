// NetAttackAI by @braydos-h — https://github.com/braydos-h/NetAttackAi
// API accessors for the benchmark suite (/api/v1/benchmarks/*).
import { apiFetch } from "@/api/client";
import type {
  ActiveRunStatus,
  BaselineMeta,
  BenchmarkEvent,
  BenchmarkRunRequest,
  RunComparison,
  RunDetail,
  RunIndexRow,
  ScenarioInfo,
  SuiteInfo,
} from "@/features/benchmarks/types";

export async function fetchOverview(): Promise<{
  suites: SuiteInfo[];
  runs: RunIndexRow[];
  active: ActiveRunStatus;
  baseline: BaselineMeta;
}> {
  return apiFetch("/api/v1/benchmarks");
}

export async function fetchSuites(): Promise<{ suites: SuiteInfo[] }> {
  return apiFetch("/api/v1/benchmarks/suites");
}

export async function fetchSuiteScenarios(suite: string): Promise<{ suite: string; scenarios: ScenarioInfo[] }> {
  return apiFetch(`/api/v1/benchmarks/suites/${encodeURIComponent(suite)}/scenarios`);
}

export async function fetchRuns(suite?: string, limit = 50): Promise<{ runs: RunIndexRow[] }> {
  const params = new URLSearchParams();
  if (suite) params.set("suite", suite);
  params.set("limit", String(limit));
  return apiFetch(`/api/v1/benchmarks/runs?${params.toString()}`);
}

export async function fetchRun(runId: string): Promise<RunDetail> {
  return apiFetch(`/api/v1/benchmarks/runs/${encodeURIComponent(runId)}`);
}

export async function fetchRunScenarios(runId: string): Promise<{ run_id: string; scenarios: unknown[] }> {
  return apiFetch(`/api/v1/benchmarks/runs/${encodeURIComponent(runId)}/scenarios`);
}

export async function fetchRunEvents(
  runId: string,
  opts: { after?: number; trialId?: string; limit?: number } = {},
): Promise<{ run_id: string; events: BenchmarkEvent[]; latest_sequence: number }> {
  const params = new URLSearchParams();
  if (opts.after) params.set("after", String(opts.after));
  if (opts.trialId) params.set("trial_id", opts.trialId);
  params.set("limit", String(opts.limit ?? 1000));
  return apiFetch(`/api/v1/benchmarks/runs/${encodeURIComponent(runId)}/events?${params.toString()}`);
}

export async function startBenchmarkRun(req: BenchmarkRunRequest): Promise<{ run_id: string; state: string }> {
  return apiFetch("/api/v1/benchmarks/run", { method: "POST", body: req });
}

export async function cancelBenchmarkRun(runId: string): Promise<{ run_id: string; cancelled: boolean }> {
  return apiFetch(`/api/v1/benchmarks/runs/${encodeURIComponent(runId)}/cancel`, { method: "POST" });
}

export async function fetchBaseline(): Promise<BaselineMeta> {
  return apiFetch("/api/v1/benchmarks/baseline");
}

export async function saveBaseline(runId: string): Promise<{ saved: boolean; path: string; run_id: string }> {
  return apiFetch("/api/v1/benchmarks/baseline", { method: "POST", body: { run_id: runId } });
}

export async function compareRuns(runA: string, runB: string): Promise<RunComparison> {
  const params = new URLSearchParams({ run_a: runA, run_b: runB });
  return apiFetch(`/api/v1/benchmarks/compare?${params.toString()}`);
}
