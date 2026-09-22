import { Link } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge } from "@/features/benchmarks/ScenarioResultsTable";
import { formatCost, formatDuration, formatPct } from "@/features/benchmarks/MetricCards";
import type { BenchmarkRunState } from "./useBenchmarkRun";

export function BenchmarkRunAside({ page }: { page: BenchmarkRunState }) {
  const {
    summary,
    manifest,
    orphaned,
    isActiveRun,
    events,
    eventCount,
    displayTrials,
    completedTrials,
    totalTrials,
    progressPct,
    elapsedSec,
  } = page;
  return (
    <aside className="flex min-w-0 shrink-0 flex-col gap-2 xl:w-[320px] xl:min-h-0 xl:overflow-y-auto xl:overflow-x-hidden scrollbar-thin">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Run telemetry</CardTitle>
          <CardDescription>
            {orphaned ? "Frozen (run interrupted)" : isActiveRun ? "Live until terminal" : "Frozen at completion"}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div className="grid grid-cols-2 gap-2">
            <div className="rounded-md bg-muted/40 p-2">
              <div className="text-[11px] uppercase tracking-wide text-muted-foreground">Trials</div>
              <div className="font-medium tabular-nums">
                {completedTrials}/{totalTrials}
              </div>
              <div className="text-[11px] text-muted-foreground">{progressPct}%</div>
            </div>
            <div className="rounded-md bg-muted/40 p-2">
              <div className="text-[11px] uppercase tracking-wide text-muted-foreground">Events</div>
              <div className="font-medium tabular-nums">{eventCount}</div>
              <div className="text-[11px] text-muted-foreground">{formatDuration(elapsedSec)}</div>
            </div>
            <div className="rounded-md bg-muted/40 p-2">
              <div className="text-[11px] uppercase tracking-wide text-muted-foreground">Tokens</div>
              <div className="font-medium tabular-nums">{summary ? summary.total_tokens.toLocaleString() : displayTrials.reduce((a, t) => a + (t.total_tokens ?? 0), 0).toLocaleString()}</div>
              <div className="text-[11px] text-muted-foreground">{summary ? formatCost(summary.estimated_cost) : "—"}</div>
            </div>
            <div className="rounded-md bg-muted/40 p-2">
              <div className="text-[11px] uppercase tracking-wide text-muted-foreground">Verified</div>
              <div className="font-medium tabular-nums">{summary ? `${summary.solved}/${summary.trials_total}` : `${displayTrials.filter((t) => t.oracle_verified_success).length}/${displayTrials.length}`}</div>
              <div className="text-[11px] text-muted-foreground">{summary ? formatPct(summary.verified_success_rate) : "—"}</div>
            </div>
          </div>
          {summary && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs"><span className="text-muted-foreground">False positives</span><span className="tabular-nums">{formatPct(summary.false_positive_rate)}</span></div>
              <div className="flex justify-between text-xs"><span className="text-muted-foreground">Infra errors</span><span className="tabular-nums">{summary.infra_error_count}</span></div>
              <div className="flex justify-between text-xs"><span className="text-muted-foreground">Sandbox blocks</span><span className="tabular-nums">{summary.sandbox_blocked_actions}</span></div>
            </div>
          )}
          {!summary && displayTrials.length > 0 && (
            <div className="space-y-1">
              <div className="text-xs text-muted-foreground">Current trials</div>
              {displayTrials.slice(0, 4).map((t) => (
                <div key={t.trial_id} className="flex items-center justify-between rounded bg-muted/30 px-2 py-1">
                  <span className="font-mono text-[11px]">{t.scenario_id}</span>
                  <StatusBadge status={t.status} />
                </div>
              ))}
              {displayTrials.length > 4 && <div className="text-center text-[11px] text-muted-foreground">+{displayTrials.length - 4} more</div>}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Replay</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="rounded bg-muted p-2 font-mono text-xs break-all">{manifest?.replay_command ?? "n/a"}</div>
          <Button variant="outline" size="sm" className="w-full" asChild>
            <Link to="/benchmarks">Back to benchmarks</Link>
          </Button>
          {isActiveRun && <div className="flex items-center gap-1 text-xs text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" /> live updates every 2 s</div>}
          {events.isFetching && <div className="text-xs text-muted-foreground">{eventCount} events · polling…</div>}
        </CardContent>
      </Card>
    </aside>
  );
}
