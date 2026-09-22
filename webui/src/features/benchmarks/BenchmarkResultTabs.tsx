import { Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ScenarioResultsTable, StatusBadge } from "@/features/benchmarks/ScenarioResultsTable";
import { BenchmarkTimeline } from "@/features/benchmarks/BenchmarkTimeline";
import { formatDuration } from "@/features/benchmarks/MetricCards";
import type { BenchmarkRunState } from "./useBenchmarkRun";

export function BenchmarkTrialsTab({ page }: { page: BenchmarkRunState }) {
  const { displayTrials, trialsAreLive } = page;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Scenario results</CardTitle>
        <CardDescription>
          Verified outcomes from the independent oracle. “Agent claimed” is recorded separately for false-positive detection.
          {trialsAreLive ? " Showing live results — the final trial list is written when the run completes." : ""}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ScenarioResultsTable trials={displayTrials} />
      </CardContent>
    </Card>
  );
}

export function BenchmarkTimelineTab({ page }: { page: BenchmarkRunState }) {
  const { eventList, events, trialIds, timelineTrial, setTimelineTrial, eventCount } = page;
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-sm">Mission timeline</CardTitle>
          <div className="flex items-center gap-2">
            <select
              value={timelineTrial}
              onChange={(e) => setTimelineTrial(e.target.value)}
              className="h-7 rounded-md border bg-background px-2 text-xs"
              aria-label="Filter by trial"
            >
              <option value="">All trials</option>
              {trialIds.map((tid) => (
                <option key={tid} value={tid}>
                  {tid}
                </option>
              ))}
            </select>
            <span className="text-xs tabular-nums text-muted-foreground">
              {eventCount} events {events.isFetching ? "· updating…" : ""}
            </span>
          </div>
        </div>
        <CardDescription>Structured events — increments live while the run is active.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        <BenchmarkTimeline
          events={eventList}
          trialId={timelineTrial || undefined}
          isLoading={events.isLoading && eventList.length === 0}
          maxEvents={400}
        />
        {events.isFetching && eventList.length > 0 ? (
          <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" /> polling for new events…
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

export function BenchmarkEvidenceTab({ page }: { page: BenchmarkRunState }) {
  const { displayTrials, isActiveRun } = page;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Evidence & flags</CardTitle>
        <CardDescription>Per-trial oracle flags, captured evidence, audit trails and workspaces.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {displayTrials.length === 0 ? (
          <div className="py-6 text-center text-sm text-muted-foreground">
            {isActiveRun ? "No trial has finished yet — results appear here as each trial completes." : "No trials recorded."}
          </div>
        ) : (
          displayTrials.map((t) => (
            <div key={t.trial_id} className="rounded-md border p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs font-medium">{t.scenario_id}</span>
                <StatusBadge status={t.status} />
                <span className="text-xs text-muted-foreground">
                  {t.flags_captured}/{t.flags_total} flags · {formatDuration(t.duration_seconds)} · {t.tool_calls} actions
                </span>
                <span className="ml-auto text-[11px] text-muted-foreground">{t.trial_id}</span>
              </div>
              {t.flags.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {t.flags.map((f, fi) => (
                    <Badge
                      key={`${t.trial_id}:${fi}:${String(f.flag_id)}`}
                      variant={f.passed ? "secondary" : "destructive"}
                      className="font-mono text-[10px]"
                    >
                      {String(f.flag_id ?? "flag")}: {f.passed ? "passed" : "failed"}
                    </Badge>
                  ))}
                </div>
              )}
              <div className="mt-2 grid gap-1 text-xs">
                {t.claimed_summary && (
                  <div className="text-muted-foreground">
                    <span className="font-medium text-foreground">Claimed:</span> {t.claimed_summary.slice(0, 240)}
                  </div>
                )}
                {t.failure_detail && (
                  <div className="text-muted-foreground">
                    <span className="font-medium text-foreground">Detail:</span> {t.failure_detail.slice(0, 300)}
                  </div>
                )}
                <div className="flex flex-wrap gap-3 font-mono text-[11px] text-muted-foreground">
                  {t.audit_path && <span>audit: {t.audit_path}</span>}
                  {t.workspace && <span>workspace: {t.workspace}</span>}
                  {t.evidence_refs.length > 0 && <span>evidence: {t.evidence_refs.join(", ")}</span>}
                </div>
              </div>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
}
