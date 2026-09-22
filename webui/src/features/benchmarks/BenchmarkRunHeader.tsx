import { Link } from "react-router-dom";
import { ClipboardList, Clock3, FlaskConical, Loader2, ShieldCheck, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/features/benchmarks/ScenarioResultsTable";
import { formatDuration } from "@/features/benchmarks/MetricCards";
import { formatRelative } from "@/lib/utils";
import type { BenchmarkRunState } from "./useBenchmarkRun";

export function BenchmarkRunHeader({ page }: { page: BenchmarkRunState }) {
  const {
    data,
    displayTrials,
    summary,
    env,
    manifest,
    isActiveRun,
    headerBadge,
    onCancel,
    onSaveBaseline,
    cancelMutation,
    baselineMutation,
    completedTrials,
    totalTrials,
    progressPct,
    elapsedSec,
    eventCount,
    activeTrial,
    liveHint,
  } = page;
  if (!data || !env) return null;
  return (
    <div className="rounded-md border bg-card/50 px-2.5 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <Link to="/benchmarks" className="text-xs text-muted-foreground underline-offset-4 hover:underline">
          Benchmarks
        </Link>
        <span className="text-muted-foreground">/</span>
        <h1 className="flex items-center gap-2 font-mono text-sm font-semibold">
          <FlaskConical className="h-4 w-4 text-primary" />
          {data.run_id}
        </h1>
        <StatusBadge status={headerBadge} />
        <span className="text-xs text-muted-foreground">
          {data.suite} · {displayTrials[0]?.started_at ? formatRelative(displayTrials[0].started_at) : "new run"}
        </span>
        {isActiveRun && (
          <span className="flex items-center gap-1 rounded-full bg-yellow-500/10 px-2 py-0.5 text-xs text-yellow-300">
            <span className="h-2 w-2 animate-pulse rounded-full bg-yellow-400" />
            live · {completedTrials}/{totalTrials} · {eventCount} events
          </span>
        )}
        <span className="ml-auto flex items-center gap-2">
          {isActiveRun ? (
            <Button size="sm" variant="destructive" className="h-7" onClick={onCancel} disabled={cancelMutation.isPending}>
              {cancelMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <XCircle className="h-3.5 w-3.5" />}
              Cancel
            </Button>
          ) : summary ? (
            <Button size="sm" variant="outline" className="h-7" onClick={onSaveBaseline} disabled={baselineMutation.isPending}>
              {baselineMutation.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              Save baseline
            </Button>
          ) : null}
        </span>
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
        <span className="flex items-center gap-1">
          <ClipboardList className="h-3 w-3" /> {data.config.trials} trial(s) × {data.scenario_ids.length || data.trials.length || 1} scenario(s)
        </span>
        <span className="flex items-center gap-1">
          <Clock3 className="h-3 w-3" /> timeout {formatDuration(data.config.timeout_seconds)}
        </span>
        <span className="flex items-center gap-1">
          <ShieldCheck className="h-3 w-3" /> sandbox {data.config.sandbox_required ? "required" : "optional"} · {env.sandbox_enabled ? "enabled" : "disabled"}
        </span>
        <span className="font-mono text-[11px]">{data.config.tags.length ? `tags: ${data.config.tags.join(", ")}` : "all tags"}</span>
      </div>
      {isActiveRun && (
        <div className="mt-2">
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
            <div className="h-full bg-yellow-500 transition-all duration-500" style={{ width: `${progressPct}%` }} />
          </div>
          <div className="mt-1 flex items-center gap-2 text-[11px] text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" /> {completedTrials}/{totalTrials} trials completed
            {(activeTrial?.scenario_id ?? liveHint?.scenario_id) ? ` · now: ${activeTrial?.scenario_id ?? liveHint?.scenario_id}` : ""}
            <span className="ml-auto tabular-nums">
              {formatDuration(elapsedSec)} · {eventCount} events · polling 2s
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
