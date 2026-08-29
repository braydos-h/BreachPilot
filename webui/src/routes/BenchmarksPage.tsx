// NetAttackAI by @braydos-h — https://github.com/braydos-h/NetAttackAi
// Benchmarks dashboard: overview cards, run panel, history, run list, comparison.
import { useMemo } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { FlaskConical } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState, Spinner } from "@/components/Loading";
import { fetchOverview, fetchRuns } from "@/features/benchmarks/api";
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

export function BenchmarksPage() {
  const models = useModels();
  const defaultModel = models.data?.default_alias ?? "";

  const overview = useQuery({
    queryKey: ["benchmarks", "overview"],
    queryFn: fetchOverview,
    refetchInterval: (query) => {
      const active = query.state.data?.active;
      return active && (active.state === "running" || active.state === "starting" || active.state === "cancelling")
        ? REFRESH_MS
        : false;
    },
  });

  const runs = useQuery({
    queryKey: ["benchmarks", "runs"],
    queryFn: () => fetchRuns(undefined, 100),
    refetchInterval: () => {
      const active = overview.data?.active;
      return active && (active.state === "running" || active.state === "starting") ? REFRESH_MS : false;
    },
  });

  // Latest completed run powers the dashboard cards + preview sections.
  const latestRunQuery = useQuery({
    queryKey: ["benchmarks", "latest-run"],
    queryFn: async (): Promise<RunDetail | null> => {
      const rows = runs.data?.runs.filter((r) => r.status === "completed") ?? [];
      if (rows.length === 0) return null;
      const latest = rows[0];
      const { fetchRun } = await import("@/features/benchmarks/api");
      return fetchRun(latest.run_id);
    },
    enabled: !!runs.data,
  });

  const latestEventsQuery = useQuery({
    queryKey: ["benchmarks", "latest-run-events", latestRunQuery.data?.run_id],
    queryFn: async () => {
      const { fetchRunEvents } = await import("@/features/benchmarks/api");
      const runId = latestRunQuery.data!.run_id;
      return fetchRunEvents(runId, { limit: 500 });
    },
    enabled: !!latestRunQuery.data,
  });

  const active = overview.data?.active ?? { run_id: null, state: "idle", error: "" };
  const suites = overview.data?.suites ?? [];
  const historyRows = useMemo(() => runs.data?.runs ?? [], [runs.data]);
  const summary: RunSummary | null = latestRunQuery.data?.summary ?? null;

  if (overview.isLoading) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center">
        <Spinner label="Loading benchmarks…" />
      </div>
    );
  }
  if (overview.isError) {
    return <ErrorState message={overview.error instanceof Error ? overview.error.message : "Failed to load benchmarks"} onRetry={() => void overview.refetch()} />;
  }

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
        </div>
        {active.run_id && (
          <Link
            to={`/benchmarks/${active.run_id}`}
            className="flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-1.5 text-sm text-yellow-300"
          >
            <span className="relative flex h-2 w-2">
              <span className="relative inline-flex h-2 w-2 animate-pulse rounded-full bg-yellow-400" />
            </span>
            Live: {active.run_id}
          </Link>
        )}
      </header>

      {summary ? (
        <section className="space-y-3" aria-label="Latest run metrics">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">Latest run</h2>
            <Link to={`/benchmarks/${summary.run_id}`} className="font-mono text-sm underline-offset-4 hover:underline">
              {summary.run_id}
            </Link>
            <StatusBadge status="completed" />
            <span className="text-xs text-muted-foreground">{formatRelative(summary.timestamp)}</span>
          </div>
          <MetricCards summary={summary} />
          <div className="grid gap-3 lg:grid-cols-2">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Recent timeline</CardTitle>
                <CardDescription>Structured mission events from the latest run.</CardDescription>
              </CardHeader>
              <CardContent>
                <BenchmarkTimeline events={latestEventsQuery.data?.events ?? []} isLoading={latestEventsQuery.isLoading} maxEvents={10} />
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Scenario results</CardTitle>
                <CardDescription>Latest run's per-trial outcomes.</CardDescription>
              </CardHeader>
              <CardContent>
                <ScenarioResultsTable trials={latestRunQuery.data?.trials ?? []} />
              </CardContent>
            </Card>
          </div>
        </section>
      ) : (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            No completed benchmark runs yet. Start one below — results will appear here and persist across restarts.
          </CardContent>
        </Card>
      )}

      <RunBenchmarkPanel suites={suites} active={active} defaultModel={defaultModel} />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Run history</CardTitle>
          <CardDescription>
            Verified success rate, false-positive rate, solve time and cost across runs (linked to their git revisions in
            each run's report).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <HistoryCharts runs={historyRows} />
          {historyRows.length > 0 && (
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
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Compare runs</CardTitle>
          <CardDescription>Pick any two runs to see metric deltas and per-scenario changes.</CardDescription>
        </CardHeader>
        <CardContent>
          <ComparisonView runs={historyRows.map((r) => ({ run_id: r.run_id, suite: r.suite, timestamp: r.timestamp, status: r.status }))} />
        </CardContent>
      </Card>
    </div>
  );
}
