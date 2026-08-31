// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Benchmarks Overview sub-page: live-run status, regression baseline, latest
// completed run (metrics + timeline + per-trial outcomes) and a recent-runs
// preview. Start a run from "New run"; full history + comparison live under
// "Past benchmarks".
import { useMemo } from "react";
import { Link } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Activity, ArrowRight, Bookmark, Clock3, FlaskConical, Loader2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, SkeletonCards, SkeletonRows } from "@/components/Loading";
import { fetchRun, fetchRunEvents } from "@/features/benchmarks/api";
import { runStatusToBadge } from "@/features/benchmarks/format";
import { BenchmarksShell } from "@/features/benchmarks/BenchmarksShell";
import { useBenchmarksOverview } from "@/features/benchmarks/useBenchmarksOverview";
import { MetricCards } from "@/features/benchmarks/MetricCards";
import { ScenarioResultsTable, StatusBadge } from "@/features/benchmarks/ScenarioResultsTable";
import { BenchmarkTimeline } from "@/features/benchmarks/BenchmarkTimeline";
import { formatCost, formatDuration, formatPct } from "@/features/benchmarks/format";
import type { RunDetail, RunSummary } from "@/features/benchmarks/types";
import { formatRelative } from "@/lib/utils";

export function BenchmarksPage() {
  const { overview, active, activeBusy } = useBenchmarksOverview();

  // Latest completed run: derive from the overview rows immediately, then
  // upgrade to the full run detail when it lands.
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

  const overviewLoading = overview.isLoading && !overview.data;
  const overviewError = overview.isError ? overview.error : null;
  const latestLoading = !!latestRunId && latestRunQuery.isLoading;
  const summary: RunSummary | null = latestRunQuery.data?.summary ?? null;
  const recentRuns = overview.data?.runs.slice(0, 5) ?? [];

  return (
    <BenchmarksShell>
      {overviewLoading && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground" aria-live="polite">
          <Loader2 className="h-3 w-3 animate-spin" />
          Loading overview… suites, recent runs, baseline
        </div>
      )}
      {overviewError && (
        <div className="text-xs text-destructive">{overviewError instanceof Error ? overviewError.message : String(overviewError)}</div>
      )}
      {overviewError && !overview.data ? (
        <ErrorState
          message={overviewError instanceof Error ? overviewError.message : "Failed to load benchmarks"}
          onRetry={() => void overview.refetch()}
        />
      ) : null}

      {/* A run failed to start/execute — surface the service's error instead of silently idling */}
      {active.state === "error" && active.error ? (
        <Card className="border-red-500/30 bg-red-500/5" data-testid="benchmark-error-banner">
          <CardContent className="flex flex-wrap items-center gap-3 py-3">
            <span className="text-sm font-medium text-red-400">Last benchmark attempt failed</span>
            <span className="min-w-0 flex-1 truncate text-xs text-muted-foreground" title={active.error}>
              {active.error}
            </span>
          </CardContent>
        </Card>
      ) : null}

      {/* Active run progress — always visible when a run is live, even while latestRun loads */}
      {activeBusy && active.run_id && (
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

      {/* Regression baseline — persisted reference for "Check regression vs baseline" */}
      {overview.data?.baseline?.exists && (
        <Card className="border-primary/20" data-testid="benchmark-baseline">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Bookmark className="h-3.5 w-3.5 text-primary" /> Regression baseline
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
            {overview.data.baseline.run_id ? (
              <Link
                to={`/benchmarks/${overview.data.baseline.run_id}`}
                className="font-mono text-xs underline-offset-4 hover:underline"
              >
                {overview.data.baseline.run_id}
              </Link>
            ) : (
              <span className="font-mono text-xs">{overview.data.baseline.path}</span>
            )}
            <span className="text-muted-foreground">
              success{" "}
              <span className="font-medium tabular-nums text-foreground">
                {formatPct(overview.data.baseline.verified_success_rate)}
              </span>
            </span>
            <span className="text-muted-foreground">
              FP{" "}
              <span className="font-medium tabular-nums text-foreground">
                {formatPct(overview.data.baseline.false_positive_rate)}
              </span>
            </span>
            {typeof overview.data.baseline.median_solve_time === "number" && (
              <span className="text-muted-foreground">
                median <span className="font-medium tabular-nums text-foreground">{formatDuration(overview.data.baseline.median_solve_time)}</span>
              </span>
            )}
            {typeof overview.data.baseline.estimated_cost === "number" && (
              <span className="text-muted-foreground">
                cost <span className="font-medium tabular-nums text-foreground">{formatCost(overview.data.baseline.estimated_cost)}</span>
              </span>
            )}
            <span className="text-xs text-muted-foreground">new runs can be checked against this in New run</span>
          </CardContent>
        </Card>
      )}

      {/* Latest completed run — progressive: skeletons while overview/latestRun fetch */}
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
            <StatusBadge status="VERIFIED" />
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
      ) : overview.data ? (
        <Card data-testid="benchmarks-empty-state">
          <CardContent className="flex flex-col items-center gap-2 py-10 text-center">
            <FlaskConical className="h-6 w-6 text-muted-foreground" />
            <div className="text-sm text-muted-foreground">
              No completed benchmark runs yet. Start one and results will appear here and persist across restarts.
            </div>
            <Link
              to="/benchmarks/new"
              className="mt-1 flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90"
            >
              Start a benchmark <ArrowRight className="h-3.5 w-3.5" aria-hidden />
            </Link>
          </CardContent>
        </Card>
      ) : null}

      {/* Recent runs preview — full history under "Past benchmarks" */}
      {overview.data && recentRuns.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between gap-2">
              <CardTitle className="text-sm">Recent runs</CardTitle>
              <Link to="/benchmarks/history" className="flex items-center gap-1 text-xs text-primary underline-offset-4 hover:underline">
                View all <ArrowRight className="h-3 w-3" aria-hidden />
              </Link>
            </div>
            <CardDescription>Last {recentRuns.length} recorded run{recentRuns.length === 1 ? "" : "s"}.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto rounded-lg border">
              <table className="w-full text-left text-sm">
                <thead className="bg-muted/40 text-xs uppercase tracking-wide text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2.5 font-medium">Run</th>
                    <th className="px-3 py-2.5 font-medium">Status</th>
                    <th className="px-3 py-2.5 font-medium">Verified</th>
                    <th className="px-3 py-2.5 font-medium">When</th>
                  </tr>
                </thead>
                <tbody>
                  {recentRuns.map((r) => (
                    <tr key={`${r.suite}/${r.run_id}`} className="border-t hover:bg-muted/20">
                      <td className="px-3 py-2 font-mono text-xs">
                        <Link to={`/benchmarks/${r.run_id}`} className="underline-offset-4 hover:underline">
                          {r.run_id}
                        </Link>
                      </td>
                      <td className="px-3 py-2">
                        <StatusBadge status={runStatusToBadge(r.status)} />
                      </td>
                      <td className="px-3 py-2 tabular-nums">
                        {r.solved}/{r.trials_total} ({formatPct(r.verified_success_rate)})
                      </td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{formatRelative(r.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </BenchmarksShell>
  );
}
