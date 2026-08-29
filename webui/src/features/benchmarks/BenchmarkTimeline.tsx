// NetAttackAI by @braydos-h — https://github.com/braydos-h/NetAttackAi
// Structured mission-event timeline for a benchmark run.
import { useMemo } from "react";
import { AlertCircle, CheckCircle2, Clock, PlayCircle, ShieldAlert, Wrench } from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDuration } from "@/features/benchmarks/MetricCards";
import type { BenchmarkEvent } from "@/features/benchmarks/types";

const EVENT_ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  run_start: PlayCircle,
  target_ready: CheckCircle2,
  sandbox_unavailable: ShieldAlert,
  mission_start: PlayCircle,
  agent_phase: Clock,
  agent_tool_start: Wrench,
  agent_tool_result: Wrench,
  oracle_result: CheckCircle2,
  mission_error: AlertCircle,
  mission_timeout: AlertCircle,
  run_end: CheckCircle2,
};

const VERIFIED_TYPES = new Set(["oracle_result", "run_end"]);

function eventLabel(event: BenchmarkEvent): string {
  switch (event.type) {
    case "run_start":
      return `Benchmark started — ${String(event.payload.scenarios ?? "").slice(0, 120)}`;
    case "target_ready":
      return `Target ready: ${event.target || String(event.payload.host ?? "")} (ports ${JSON.stringify(event.payload.ports ?? [])})`;
    case "sandbox_unavailable":
      return "Sandbox unavailable — no host-execution fallback";
    case "mission_start":
      return `Mission started (goal: ${String(event.payload.goal ?? "?")})`;
    case "agent_phase":
      return `Phase: ${String(event.payload.phase ?? "")}`;
    case "agent_tool_request":
      return `Tool requested: ${event.tool}`;
    case "agent_tool_start":
      return `Tool started: ${event.tool}`;
    case "agent_tool_result":
      return `Tool result: ${event.tool} — ${String(event.payload.status ?? "")}`;
    case "model_usage":
      return `Model usage: ${String(event.payload.model_calls ?? 0)} calls, ${String(event.payload.total_tokens ?? 0)} tokens`;
    case "oracle_result":
      return `Oracle: ${event.payload.verified ? "VERIFIED" : "NOT verified"} (${String(event.payload.flags_captured ?? 0)}/${String(event.payload.flags_total ?? 0)} flags)`;
    case "mission_timeout":
      return "Mission timed out";
    case "mission_error":
      return `Error: ${String(event.payload.error ?? "").slice(0, 160)}`;
    case "run_end":
      return `Run ${String(event.payload.status ?? "ended")} — solved ${String(event.payload.solved ?? 0)}/${String(event.payload.trials_total ?? 0)}`;
    default:
      return event.type;
  }
}

export interface BenchmarkTimelineProps {
  events: BenchmarkEvent[];
  trialId?: string;
  isLoading?: boolean;
  maxEvents?: number;
}

export function BenchmarkTimeline({ events, trialId, isLoading, maxEvents = 200 }: BenchmarkTimelineProps) {
  const filtered = useMemo(() => {
    const rows = trialId ? events.filter((e) => e.trial_id === trialId) : events;
    return rows.slice(0, maxEvents);
  }, [events, trialId, maxEvents]);

  if (isLoading) {
    return <div className="py-8 text-center text-sm text-muted-foreground">Loading timeline…</div>;
  }
  if (filtered.length === 0) {
    return <div className="py-8 text-center text-sm text-muted-foreground">No events recorded.</div>;
  }

  return (
    <ol className="relative space-y-0" data-testid="benchmark-timeline">
      {filtered.map((event) => {
        const Icon = EVENT_ICON[event.type] ?? Clock;
        const isError = event.level === "error" || event.type.includes("error") || event.type.includes("timeout");
        const isVerified = VERIFIED_TYPES.has(event.type) && event.payload.verified !== false;
        return (
          <li key={`${event.sequence}-${event.type}`} className="relative flex gap-3 pb-4">
            {filtered.indexOf(event) < filtered.length - 1 && (
              <span className="absolute left-[11px] top-6 h-[calc(100%-1rem)] w-px bg-border" aria-hidden />
            )}
            <span
              className={cn(
                "relative z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border bg-background",
                isError
                  ? "border-red-500/40 text-red-500"
                  : isVerified
                    ? "border-emerald-500/40 text-emerald-500"
                    : "border-border text-muted-foreground",
              )}
            >
              <Icon className="h-3.5 w-3.5" />
            </span>
            <div className="min-w-0 flex-1 pt-0.5">
              <div className="flex flex-wrap items-baseline gap-x-2">
                <span className="text-[10px] font-medium tabular-nums text-muted-foreground">
                  {formatDuration(event.elapsed_seconds)}
                </span>
                <span className={cn("text-sm", isError && "text-red-500")}>{eventLabel(event)}</span>
              </div>
              <div className="mt-0.5 flex flex-wrap gap-2 text-[10px] text-muted-foreground">
                {event.scenario_id && <span className="font-mono">{event.scenario_id}</span>}
                {event.tool && (
                  <span className="font-mono">
                    tool: {event.tool}
                    {event.agent ? ` · agent: ${event.agent}` : ""}
                  </span>
                )}
                <span className="font-mono">#{event.sequence}</span>
              </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
