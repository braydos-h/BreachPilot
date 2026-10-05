// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Comparison view: two benchmark runs side by side (metric deltas + per-scenario rollup).
import { useMemo, useState } from "react";
import { ArrowDownRight, ArrowLeftRight, ArrowUpRight, Loader2, Minus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { formatRelative } from "@/lib/utils";
import { formatCost, formatDuration, formatPct } from "@/features/benchmarks/MetricCards";
import { StatusBadge } from "@/features/benchmarks/ScenarioResultsTable";
import { compareRuns } from "@/features/benchmarks/api";
import type { CompareMetricRow, RunComparison } from "@/features/benchmarks/types";

const METRIC_LABELS: Record<string, string> = {
  verified_success_rate: "Verified success",
  false_positive_rate: "False positives",
  stuck_loop_rate: "Stuck-loop rate",
  reproduced_twice_rate: "Reproduced twice",
  scope_violation_count: "Scope violations",
  median_solve_time: "Median solve time",
  median_tool_actions: "Median actions",
  estimated_cost: "Cost",
  total_tokens: "Tokens",
  solved: "Solved",
  infra_error_count: "Infra errors",
};

const CATEGORY_LABELS: Record<string, string> = {
  newly_solved: "Newly solved",
  regressed: "Regressed",
  still_solved: "Still solved",
  still_failing: "Still failing",
  not_compared: "Not compared",
};

function formatMetricValue(metric: string, value: number | null): string {
  if (value === null || value === undefined) return "n/a";
  switch (metric) {
    case "verified_success_rate":
    case "false_positive_rate":
    case "stuck_loop_rate":
    case "reproduced_twice_rate":
      return formatPct(value);
    case "median_solve_time":
      return formatDuration(value);
    case "estimated_cost":
      return formatCost(value);
    case "total_tokens":
      return value.toLocaleString();
    default:
      return String(value);
  }
}

function formatDelta(metric: string, row: CompareMetricRow): string {
  if (row.direction === "incomparable") return "Not comparable (suite, scenarios, or trial counts differ)";
  if (row.direction === "unavailable") return "Unavailable";
  if (row.delta === null || row.direction === "unchanged") return "";
  const absoluteSign = row.delta > 0 ? "+" : row.delta < 0 ? "-" : "";
  switch (metric) {
    case "verified_success_rate":
    case "false_positive_rate":
    case "stuck_loop_rate":
    case "reproduced_twice_rate":
      return `${row.delta > 0 ? "+" : ""}${(row.delta * 100).toFixed(1)}%`;
    case "median_solve_time":
      return `${absoluteSign}${formatDuration(Math.abs(row.delta))}`;
    case "estimated_cost":
      return `${absoluteSign}$${Math.abs(row.delta).toFixed(2)}`;
    default:
      return `${row.delta > 0 ? "+" : ""}${row.delta.toLocaleString()}`;
  }
}

export interface ComparisonViewProps {
  runs: Array<{ run_id: string; suite: string; timestamp: string; status: string }>;
}

export function ComparisonView({ runs }: ComparisonViewProps) {
  const [runA, setRunA] = useState("");
  const [runB, setRunB] = useState("");
  const [comparison, setComparison] = useState<RunComparison | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const eligibleRuns = useMemo(() => runs.filter((run) => run.status === "completed"), [runs]);
  const canCompare = useMemo(
    () =>
      runA !== runB &&
      eligibleRuns.some((run) => run.run_id === runA) &&
      eligibleRuns.some((run) => run.run_id === runB),
    [eligibleRuns, runA, runB],
  );

  // A previous comparison must never linger next to a new (unchanged) pair of
  // pickers — drop the result + error as soon as either selection changes.
  const onPick = (setter: (v: string) => void) => (v: string) => {
    setter(v);
    setComparison(null);
    setError("");
  };

  const onCompare = async () => {
    if (!canCompare) return;
    setLoading(true);
    setError("");
    try {
      setComparison(await compareRuns(runA, runB));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setComparison(null);
    } finally {
      setLoading(false);
    }
  };

  const runPicker = (value: string, onChange: (v: string) => void, label: string) => (
    <label className="flex min-w-0 flex-1 flex-col gap-1">
      <span className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={loading}
        className="h-9 w-full min-w-0 rounded-md border bg-background px-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        aria-label={label}
      >
        <option value="">Select run…</option>
        {eligibleRuns.map((r) => (
          <option key={r.run_id} value={r.run_id}>
            {r.run_id} · {formatRelative(r.timestamp)}
          </option>
        ))}
      </select>
    </label>
  );

  return (
    <div className="space-y-4" data-testid="benchmark-comparison">
      <div className="flex flex-wrap items-end gap-3">
        {runPicker(runA, onPick(setRunA), "Baseline run")}
        <Button
          variant="ghost"
          size="icon"
          className="mb-0.5"
          disabled={loading}
          aria-label="Swap runs"
          onClick={() => {
            setRunA(runB);
            setRunB(runA);
            setComparison(null);
            setError("");
          }}
        >
          <ArrowLeftRight className="h-4 w-4" />
        </Button>
        {runPicker(runB, onPick(setRunB), "Candidate run")}
        <Button size="sm" className="mb-0.5" disabled={!canCompare || loading} onClick={onCompare}>
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
          Compare
        </Button>
      </div>
      {loading && <div role="status" aria-live="polite" className="sr-only">Comparing selected benchmark runs…</div>}
      {error && <div role="alert" className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">{error}</div>}
      {!comparison && !error && (
        <p className="text-xs text-muted-foreground">
          Pick a baseline and a candidate run, then press Compare to see metric deltas and per-scenario changes.
        </p>
      )}
      {comparison && (
        <div className="space-y-4">
          <div className="overflow-x-auto rounded-lg border">
            <table className="w-full text-left text-sm">
              <thead className="bg-muted/40 text-xs uppercase tracking-wide text-muted-foreground">
                <tr>
                  <th className="px-3 py-2.5 font-medium">Metric</th>
                  <th className="px-3 py-2.5 font-medium">Baseline ({comparison.run_a.run_id})</th>
                  <th className="px-3 py-2.5 font-medium">Candidate ({comparison.run_b.run_id})</th>
                  <th className="px-3 py-2.5 font-medium">Change</th>
                </tr>
              </thead>
              <tbody>
                {comparison.comparison.metrics.map((row) => (
                  <tr key={row.metric} className="border-t">
                    <td className="px-3 py-2">{METRIC_LABELS[row.metric] ?? row.metric}</td>
                    <td className="px-3 py-2 tabular-nums">{formatMetricValue(row.metric, row.baseline)}</td>
                    <td className="px-3 py-2 tabular-nums">{formatMetricValue(row.metric, row.current)}</td>
                    <td className="px-3 py-2 tabular-nums">
                      <span className="inline-flex items-center gap-1">
                        {row.safety_gate === "failed" && (
                          <span className="font-medium text-red-700 dark:text-red-300" role="status">
                            Hard safety gate failed
                          </span>
                        )}
                        {row.safety_gate === "passed" && (
                          <span className="text-emerald-700 dark:text-emerald-300" role="status">
                            Safety gate clear
                          </span>
                        )}
                        {row.metric === "scope_violation_count" && row.safety_gate === "unavailable" && (
                          <span className="text-muted-foreground" role="status">
                            Safety telemetry unavailable
                          </span>
                        )}
                        {row.direction === "improved" && (
                          <>
                            <ArrowUpRight className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" aria-label="improved" />
                            <span className="text-emerald-700 dark:text-emerald-300">{formatDelta(row.metric, row)}</span>
                          </>
                        )}
                        {row.direction === "regressed" && (
                          <>
                            <ArrowDownRight className="h-3.5 w-3.5 text-red-600 dark:text-red-400" aria-label="regressed" />
                            <span className="text-red-700 dark:text-red-300">{formatDelta(row.metric, row)}</span>
                          </>
                        )}
                        {row.direction !== "improved" && row.direction !== "regressed" && (
                          <>
                            {row.direction === "unchanged" && (
                              <Minus className="h-3.5 w-3.5 text-muted-foreground" aria-label="unchanged" />
                            )}
                            <span className="text-muted-foreground">{formatDelta(row.metric, row) || "—"}</span>
                          </>
                        )}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {Object.entries(comparison.comparison.categories).map(([category, ids]) => (
              <div key={category} className="rounded-lg border p-3">
                <div className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  {category === "regressed" && <ArrowDownRight className="h-3.5 w-3.5 text-red-600 dark:text-red-400" aria-hidden />}
                  {category === "newly_solved" && <ArrowUpRight className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" aria-hidden />}
                  {CATEGORY_LABELS[category] ?? category}
                </div>
                <div className="mt-1 text-xl font-semibold tabular-nums">{ids.length}</div>
                {ids.length > 0 && (
                  <div className="mt-1 truncate font-mono text-[10px] text-muted-foreground" title={ids.join(", ")}>
                    {ids.join(", ")}
                  </div>
                )}
              </div>
            ))}
          </div>
          <div className="overflow-x-auto rounded-lg border">
            <table className="w-full text-left text-sm">
              <thead className="bg-muted/40 text-xs uppercase tracking-wide text-muted-foreground">
                <tr>
                  <th className="px-3 py-2.5 font-medium">Scenario</th>
                  <th className="px-3 py-2.5 font-medium">Baseline P(success)</th>
                  <th className="px-3 py-2.5 font-medium">Candidate P(success)</th>
                  <th className="px-3 py-2.5 font-medium">Category</th>
                </tr>
              </thead>
              <tbody>
                {comparison.comparison.scenarios.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-3 py-4 text-center text-sm text-muted-foreground">
                      No comparable scenarios recorded in either run.
                    </td>
                  </tr>
                ) : (
                  comparison.comparison.scenarios.map((row) => (
                    <tr key={row.scenario_id} className="border-t">
                      <td className="px-3 py-2 font-mono text-xs">{row.scenario_id}</td>
                      <td className="px-3 py-2 tabular-nums">{row.baseline == null ? "n/a" : row.baseline.toFixed(2)}</td>
                      <td className="px-3 py-2 tabular-nums">{row.current == null ? "n/a" : row.current.toFixed(2)}</td>
                      <td className="px-3 py-2">
                        {row.category !== "not_compared" && (
                          <StatusBadge
                            status={
                              row.category === "newly_solved"
                                ? "VERIFIED"
                                : row.category === "regressed"
                                  ? "REGRESSED"
                                  : row.category === "still_solved"
                                    ? "VERIFIED"
                                    : "FAILED"
                            }
                          />
                        )}
                        <span className="ml-2 text-xs text-muted-foreground">{CATEGORY_LABELS[row.category]}</span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
