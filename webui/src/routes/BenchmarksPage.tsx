// NetAttackAI by @braydos-h — https://github.com/braydos-h/NetAttackAi
// Benchmarks dashboard: overview cards, run panel, history, run list, comparison.
// Optimized for fast perceived load: progressive skeletons, parallel fetches, incremental history.
import { useMemo } from "react";
import { Link } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Activity, Clock3, FlaskConical, Loader2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, SkeletonCards, SkeletonRows } from "@/components/Loading";
import { fetchOverview, fetchRun, fetchRunEvents, fetchRuns } from "@/features/benchmarks/api";
import { MetricCards } from "@/features/benchmarks/MetricCards";
import { RunBenchmarkPanel } from "@/features/benchmarks/RunBenchmarkPanel";
import { ScenarioResultsTable, StatusBadge } from "@/features/benchmarks/ScenarioResultsTable";
import { BenchmarkTimeline } from "@/features/benchmarks/BenchmarkTimeline";
import { ComparisonView } from "@/features/benchmarks/ComparisonView";
import { HistoryCharts } from "@/features/benchmarks/HistoryCharts";
import { formatCost, formatDuration, formatPct } from "@/features/benchmarks/MetricCards";
import type { RunDetail, RunSummary } from "@/features/benchmarks/types";
import { useModels } from "@/api/hooks";
import { formatRelative } from "@/lib/utils";

const REFRESH_MS = 3000;

function isActiveState(state: string): boolean {
  return state === "running" || state === "starting" || state === "cancelling";
}

export function BenchmarksPage() {
  const models = useModels();
  const defaultModel = models.data?.default_alias ?? "";

  const overview = useQuery({
    queryKey: ["benchmarks", "overview"],
    queryFn: fetchOverview,
    placeholderData: keepPreviousData,
    staleTime: 15_000,
    gcTime: 5 * 60_000,
    refetchInterval: (query) => {
      const active = query.state.data?.active;
      return active && isActiveState(active.state) ? REFRESH_MS : false;
    },
  });

  // Extended history: fetch 100 rows in parallel with latest-run, but don't block
  // the dashboard on it. Overview already delivers 20 rows instantly — we merge.
  const runsExtended = useQuery({
    queryKey: ["benchmarks", "runs", 100],
    queryFn: () => fetchRuns(undefined, 100),
    enabled: !!overview.data,
    placeholderData: keepPreviousData,
    staleTime: 15_000,
    refetchInterval: () => {
      const active = overview.data?.active;
      return active && isActiveState(active.state) ? REFRESH_MS : false;
    },
  });

  // Derive latest completed run from overview immediately — no wait for runsExtended.
  const latestRunId = useMemo(() => {
    const rows = overview.data?.runs.filter((r) => r.status === "completed") ?? [];
    return rows[0]?.run_id ?? null;
  }, [overview.data]);

  const latestRunQuery = useQuery({
    queryKey: ["benchmarks", "latest-run", latestRunId],
    queryFn: async (): Promise<RunDetail | null> => {
      if (!latestRunId) return null;
      return fetchRun(latestRunId);
    },
    enabled: !!latestRunId,
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });

  const latestEventsQuery = useQuery({
    queryKey: ["benchmarks", "latest-run-events", latestRunQuery.data?.run_id],
    queryFn: async () => {
      const runId = latestRunQuery.data!.run_id;
      return fetchRunEvents(runId, { limit: 400 });
    },
    enabled: !!latestRunQuery.data,
    placeholderData: keepPreviousData,
    staleTime: 10_000,
  });

  const active = overview.data?.active ?? { run_id: null, state: "idle", error: "" };
  const suites = overview.data?.suites ?? [];
  // Progressive history: overview rows instantly, upgraded to 100 when extended lands.
  const historyRows = useMemo(() => {
    if (runsExtended.data?.runs?.length) return runsExtended.data.runs;
    return overview.data?.runs ?? [];
  }, [overview.data, runsExtended.data]);
  const summary: RunSummary | null = latestRunQuery.data?.summary ?? null;

  const overviewLoading = overview.isLoading && !overview.data;
  const overviewError = overview.isError ? overview.error : null;

  const latestLoading = !!latestRunId && latestRunQuery.isLoading;
  const activeBanner = active.run_id && isActiveState(active.state);

  return (
    <div className="mx-auto w-full max-w-6xl space-y-6 p-4 md:p-6">
      <header className="flex items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold">
            <FlaskConical className="h-5 w-5 text-primary" />
            Benchmarks
          </h1>
          <p className="text-sm text-muted-foreground">
            Verified benchmark results — ground truth comes from the independent oracle, never from agent claims.
          </p>
          {overviewLoading && (
            <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground" aria-live="polite">
              <Loader2 className="h-3 w-3 animate-spin" />
              Loading overview… suites, recent runs, baseline
            </div>
          )}
          {overviewError && (
            <div className="mt-2 text-xs text-destructive">{overviewError instanceof Error ? overviewError.message : String(overviewError)}</div>
          )}
        </div>
        {activeBanner ? (
          <Link
            to={`/benchmarks/${active.run_id}`}
            className="flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-sm text-yellow-300 shadow-sm"
          >
            <span className="relative flex h-2.5 w-2.5">
              <span className="absolute inline-flex h-2.5 w-2.5 animate-ping rounded-full bg-yellow-400 opacity-75" />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-yellow-400" />
            </span>
            <span className="flex flex-col leading-none">
              <span className="font-medium">Live run</span>
              <span className="font-mono text-[11px] opacity-80">{active.run_id}</span>
            </span>
          </Link>
        ) : null}
      </header>

      {overviewError && !overview.data ? (
        <ErrorState message={overviewError instanceof Error ? overviewError.message : "Failed to load benchmarks"} onRetry={() => void overview.refetch()} />
      ) : null}

      {/* Active run progress — always visible when a run is live, even while latestRun loads */}
      {activeBanner && (
        <Card className="border-yellow-500/30 bg-yellow-500/5" data-testid="benchmark-live-banner">
          <CardContent className="flex flex-wrap items-center gap-3 py-3">
            <Activity className="h-4 w-4 animate-pulse text-yellow-400" />
            <span className="text-sm font-medium">Benchmark running — {active.state}</span>
            <span className="font-mono text-xs text-muted-foreground">{active.run_id}</span>
            <span className="text-xs text-muted-foreground">live updates every 3s · events streaming</span>
            <Link to={`/benchmarks/${active.run_id}`} className="ml-auto text-sm font-medium text-yellow-300 underline-offset-4 hover:underline">
              View live progress →
            </Link>
          </CardContent>
        </Card>
      )}

      {/* Latest run — progressive: skeletons while overview/latestRun fetch */}
      {overviewLoading ? (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Latest run</CardTitle>
            <CardDescription>Loading most recent completed run…</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
              {Array.from({ length: 6 }).map((_, i) => (
                <Card key={i} className="p-3"><Skeleton className="h-16 w-full" /></Card>
              ))}
            </div>
            <SkeletonRows count={4} />
          </CardContent>
        </Card>
      ) : summary ? (
        <section className="space-y-3" aria-label="Latest run metrics">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">Latest run</h2>
            <Link to={`/benchmarks/${summary.run_id}`} className="font-mono text-sm underline-offset-4 hover:underline">
              {summary.run_id}
            </Link>
            <StatusBadge status="completed" />
            <span className="text-xs text-muted-foreground">{formatRelative(summary.timestamp)}</span>
            {latestLoading && <span className="flex items-center gap-1 text-xs text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" /> updating…</span>}
          </div>
          {latestLoading ? <SkeletonCards count={1} /> : <MetricCards summary={summary} />}
          <div className="grid gap-3 lg:grid-cols-2">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">Recent timeline <Clock3 className="h-3 w-3 text-muted-foreground" /></CardTitle>
                <CardDescription>Structured mission events from the latest run.</CardDescription>
              </CardHeader>
              <CardContent>
                <BenchmarkTimeline
                  events={latestEventsQuery.data?.events ?? []}
                  isLoading={latestEventsQuery.isLoading && !latestEventsQuery.data}
                  maxEvents={12}
                />
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Scenario results</CardTitle>
                <CardDescription>Latest run's per-trial outcomes.</CardDescription>
              </CardHeader>
              <CardContent>
                {latestRunQuery.isLoading ? <SkeletonRows count={3} /> : <ScenarioResultsTable trials={latestRunQuery.data?.trials ?? []} />}
              </CardContent>
            </Card>
          </div>
        </section>
      ) : latestLoading ? (
        <Card>
          <CardContent className="py-10 text-center"><SkeletonRows count={3} /></CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            No completed benchmark runs yet. Start one below — results will appear here and persist across restarts.
          </CardContent>
        </Card>
      )}

      {/* Run panel — never blocks on overview, shows suite loading skeletons */}
      {overviewLoading ? (
        <Card>
          <CardHeader><CardTitle className="text-sm">Run benchmark</CardTitle></CardHeader>
          <CardContent><Skeleton className="h-24 w-full" /></CardContent>
        </Card>
      ) : (
        <RunBenchmarkPanel suites={suites} active={active} defaultModel={defaultModel} />
      )}

      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">Run history</CardTitle>
            {runsExtended.isFetching && !runsExtended.isLoading && <span className="flex items-center gap-1 text-xs text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" /> refreshing…</span>}
          </div>
          <CardDescription>
            Verified success rate, false-positive rate, solve time and cost across runs (linked to their git revisions in each run's report).
            {overview.data ? ` · showing ${historyRows.length} run${historyRows.length === 1 ? "" : "s"}` : ""}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {overviewLoading ? (
            <SkeletonRows count={5} />
          ) : (
            <>
              <HistoryCharts runs={historyRows} />
              {historyRows.length > 0 ? (
                <div className="overflow-x-auto rounded-lg border">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-muted/40 text-xs uppercase tracking-wide text-muted-foreground">
                      <tr>
                        <th className="px-3 py-2.5 font-medium">Run</th>
                        <th className="px-3 py-2.5 font-medium">Suite</th>
                        <th className="px-3 py-2.5 font-medium">Status</th>
                        <th className="px-3 py-2.5 font-medium">Verified</th>
                        <th className="px-3 py-2.5 font-medium">FP</th>
                        <th className="px-3 py-2.5 font-medium">Median time</th>
                        <th className="px-3 py-2.5 font-medium">Cost</th>
                      </tr>
                    </thead>
                    <tbody>
                      {historyRows.map((r) => (
                        <tr key={`${r.suite}/${r.run_id}`} className="border-t hover:bg-muted/20">
                          <td className="px-3 py-2 font-mono text-xs">
                            <Link to={`/benchmarks/${r.run_id}`} className="underline-offset-4 hover:underline">
                              {r.run_id}
                            </Link>
                          </td>
                          <td className="px-3 py-2">{r.suite}</td>
                          <td className="px-3 py-2">
                            <StatusBadge status={r.status === "completed" ? "VERIFIED" : "FAILED"} />
                          </td>
                          <td className="px-3 py-2 tabular-nums">
                            {r.solved}/{r.trials_total} ({formatPct(r.verified_success_rate)})
                          </td>
                          <td className="px-3 py-2 tabular-nums">{formatPct(r.false_positive_rate)}</td>
                          <td className="px-3 py-2 tabular-nums">{formatDuration(r.median_solve_time)}</td>
                          <td className="px-3 py-2 tabular-nums">{formatCost(r.estimated_cost)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">No runs yet.</div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Compare runs</CardTitle>
          <CardDescription>Pick any two runs to see metric deltas and per-scenario changes.</CardDescription>
        </CardHeader>
        <CardContent>
          {overviewLoading ? <Skeleton className="h-20 w-full" /> : <ComparisonView runs={historyRows.map((r) => ({ run_id: r.run_id, suite: r.suite, timestamp: r.timestamp, status: r.status }))} />}
        </CardContent>
      </Card>
    </div>
  );
}
