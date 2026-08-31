// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Benchmarks "Past benchmarks" sub-page: history charts, the full run index
// table and the two-run comparison view.
import { Link } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState, SkeletonRows } from "@/components/Loading";
import { fetchRuns } from "@/features/benchmarks/api";
import { formatCost, formatDuration, formatPct, isActiveState, runStatusToBadge } from "@/features/benchmarks/format";
import { BenchmarksShell } from "@/features/benchmarks/BenchmarksShell";
import { useBenchmarksOverview } from "@/features/benchmarks/useBenchmarksOverview";
import { HistoryCharts } from "@/features/benchmarks/HistoryCharts";
import { ComparisonView } from "@/features/benchmarks/ComparisonView";
import { StatusBadge } from "@/features/benchmarks/ScenarioResultsTable";

const REFRESH_MS = 3000;

export function BenchmarksHistoryPage() {
  const { overview, active } = useBenchmarksOverview();

  // Extended history: 100 rows in parallel with the overview, upgraded into
  // the charts/table once it lands (overview already delivers 20 instantly).
  const runsExtended = useQuery({
    queryKey: ["benchmarks", "runs", 100],
    queryFn: () => fetchRuns(undefined, 100),
    enabled: !!overview.data,
    placeholderData: keepPreviousData,
    staleTime: 15_000,
    refetchInterval: () => (isActiveState(active.state) ? REFRESH_MS : false),
  });

  const historyRows = runsExtended.data?.runs?.length ? runsExtended.data.runs : (overview.data?.runs ?? []);
  const loading = !overview.data && overview.isLoading;
  const error = overview.isError && !overview.data ? overview.error : null;

  return (
    <BenchmarksShell>
      {error ? (
        <ErrorState
          message={error instanceof Error ? error.message : "Failed to load benchmark history"}
          onRetry={() => void overview.refetch()}
        />
      ) : null}

      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between gap-2">
            <CardTitle className="text-sm">Run history</CardTitle>
            {runsExtended.isFetching && !runsExtended.isLoading && (
              <span className="flex items-center gap-1 text-xs text-muted-foreground">
                <Loader2 className="h-3 w-3 animate-spin" /> refreshing…
              </span>
            )}
          </div>
          <CardDescription>
            Verified success rate, false-positive rate, solve time and cost across runs (linked to their git revisions
            in each run's report).
            {overview.data ? ` · showing ${historyRows.length} run${historyRows.length === 1 ? "" : "s"}` : ""}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {loading ? (
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
                            <StatusBadge status={runStatusToBadge(r.status)} />
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
                <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
                  No runs recorded yet — start one under <Link to="/benchmarks/new" className="text-primary underline-offset-4 hover:underline">New run</Link>.
                </div>
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
          {loading ? (
            <SkeletonRows count={2} />
          ) : (
            <ComparisonView
              runs={historyRows.map((r) => ({ run_id: r.run_id, suite: r.suite, timestamp: r.timestamp, status: r.status }))}
            />
          )}
        </CardContent>
      </Card>
    </BenchmarksShell>
  );
}
