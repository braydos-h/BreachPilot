import { memo } from "react";
import {
  Activity,
  AlertTriangle,
  Clock,
  FileCheck,
  Layers,
  MessageSquare,
  ShieldCheck,
  Terminal,
  Timer,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { fmtElapsed } from "@/lib/format";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { phaseInfo, type DerivedRun } from "@/lib/deriveRun";
import type { RunState } from "@/api/types";
import { isTerminalState } from "@/api/types";

interface LiveRunSummaryProps {
  derived: DerivedRun;
  runState?: RunState;
  className?: string;
}

function truncate(s: string, n: number): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length <= n ? one : `${one.slice(0, n - 1)}…`;
}

/**
 * Rail summary — the "health → progress → errors → activity" reading order.
 * Pure presentation over {@link DerivedRun}; telemetry values live in
 * RunTelemetryCard so nothing is shown twice.
 */
export const LiveRunSummary = memo(function LiveRunSummary({
  derived,
  runState,
  className,
}: LiveRunSummaryProps) {
  const terminal = isTerminalState(runState as RunState);
  const hasAny =
    derived.phase ||
    derived.round != null ||
    derived.actions != null ||
    derived.lastTool?.name ||
    derived.lastAssistant ||
    derived.bootTotal > 0;

  if (!hasAny) {
    return (
      <Card className={cn(className)}>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Activity className="h-4 w-4" aria-hidden /> Live activity
          </CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-muted-foreground">
          Waiting for the agent to start…
        </CardContent>
      </Card>
    );
  }

  const bootComplete = derived.bootTotal > 0 && derived.bootDone >= derived.bootTotal;
  const errorCount = derived.toolErrors + derived.errorEvents;
  const info = phaseInfo(derived.phase);

  const health = terminal
    ? { tone: "neutral", text: "Finished" }
    : derived.bootTotal > 0 && !bootComplete
      ? { tone: "warn", text: `Booting ${derived.bootDone}/${derived.bootTotal}` }
      : errorCount > 0
        ? { tone: "danger", text: `${errorCount} error${errorCount === 1 ? "" : "s"}` }
        : { tone: "ok", text: "Running" };

  return (
    <Card className={cn(className)}>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Activity className="h-4 w-4 text-primary" aria-hidden /> Run activity
          {derived.phase && (
            <Badge variant="info" className="ml-auto font-mono text-[10px] uppercase">
              {info.short}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2.5 text-xs">
        <div className="flex items-center gap-1.5">
          {health.tone === "ok" ? (
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400/60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
            </span>
          ) : (
            <ShieldCheck className={cn("h-3.5 w-3.5", health.tone === "danger" ? "text-red-400" : health.tone === "warn" ? "text-yellow-300" : "text-muted-foreground")} aria-hidden />
          )}
          <span
            className={cn(
              "text-[11px] font-medium",
              health.tone === "danger"
                ? "text-red-300"
                : health.tone === "warn"
                  ? "text-yellow-300"
                  : health.tone === "ok"
                    ? "text-emerald-300"
                    : "text-muted-foreground",
            )}
          >
            {health.text}
          </span>
          {info.summary && <span className="ml-auto truncate text-[11px] text-muted-foreground">{info.summary}</span>}
        </div>

        <div className="grid grid-cols-3 gap-2 font-mono">
          <Stat icon={<Layers className="h-3 w-3" />} label="round" value={derived.round != null ? String(derived.round) : "—"} />
          <Stat icon={<Terminal className="h-3 w-3" />} label="actions" value={derived.actions != null ? String(derived.actions) : "—"} />
          <Stat icon={<Clock className="h-3 w-3" />} label="elapsed" value={derived.elapsedSeconds != null ? fmtElapsed(derived.elapsedSeconds) : "—"} />
        </div>

        <div className="grid grid-cols-2 gap-2 font-mono">
          <Stat icon={<Terminal className="h-3 w-3" />} label="tool calls" value={String(derived.toolCount)} />
          <Stat icon={<MessageSquare className="h-3 w-3" />} label="msgs" value={String(derived.assistantCount)} />
          <Stat icon={<FileCheck className="h-3 w-3" />} label="artifacts" value={String(derived.artifacts)} />
          <Stat icon={<Activity className="h-3 w-3" />} label="events/min" value={derived.eventsPerMin != null ? String(derived.eventsPerMin) : "—"} />
        </div>

        {errorCount > 0 && (
          <div className="flex items-center gap-1.5 rounded-md border border-destructive/40 bg-destructive/10 p-1.5 text-[11px] text-red-300">
            <AlertTriangle className="h-3 w-3 shrink-0" aria-hidden />
            <span>
              {derived.toolErrors > 0 && `${derived.toolErrors} failed tool call${derived.toolErrors === 1 ? "" : "s"}`}
              {derived.toolErrors > 0 && derived.errorEvents > 0 && " · "}
              {derived.errorEvents > 0 && `${derived.errorEvents} error event${derived.errorEvents === 1 ? "" : "s"}`}
            </span>
          </div>
        )}

        {derived.lastTool?.name && (
          <div className="space-y-1 rounded-md border bg-muted/30 p-2">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Terminal className="h-3 w-3" aria-hidden /> Last tool
            </div>
            <div className="flex items-center gap-2">
              <span className="truncate font-mono text-foreground">{derived.lastTool.name}</span>
              <Badge
                variant={
                  derived.lastTool.completed
                    ? derived.lastTool.success === true
                      ? "success"
                      : "danger"
                    : derived.lastTool.started
                      ? "warn"
                      : "info"
                }
                className="ml-auto shrink-0 text-[10px]"
              >
                {derived.lastTool.completed
                  ? derived.lastTool.success === true
                    ? "done"
                    : "failed"
                  : derived.lastTool.started
                    ? "running"
                    : "queued"}
              </Badge>
            </div>
          </div>
        )}

        {derived.lastAssistant && (
          <div className="space-y-1 rounded-md border border-primary/20 bg-primary/5 p-2">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <MessageSquare className="h-3 w-3" aria-hidden /> Agent said
            </div>
            <div className="whitespace-pre-wrap break-words text-foreground">
              {truncate(derived.lastAssistant, 240)}
            </div>
          </div>
        )}

        {derived.elapsedSeconds != null && (
          <div className="flex items-center gap-1.5 pt-0.5 text-muted-foreground">
            <Timer className="h-3 w-3" aria-hidden /> updated {fmtElapsed(derived.elapsedSeconds)} ago
          </div>
        )}
      </CardContent>
    </Card>
  );
});

function Stat({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="space-y-0.5 rounded-md border bg-card/40 p-1.5">
      <div className="flex items-center gap-1 text-muted-foreground">
        {icon}
        <span className="text-[10px] uppercase tracking-wide">{label}</span>
      </div>
      <div className="tabular-nums text-foreground">{value}</div>
    </div>
  );
}
