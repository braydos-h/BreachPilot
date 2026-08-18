import { memo, useMemo } from "react";
import { Activity, AlertTriangle, Clock, Cpu, FileCheck, Layers, MessageSquare, Terminal, Timer } from "lucide-react";
import { cn } from "@/lib/utils";
import { fmtElapsed } from "@/lib/format";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { RunEvent } from "@/api/types";

interface LiveRunSummaryProps {
  events: RunEvent[];
  className?: string;
}

interface Derived {
  phase: string;
  round: number | null;
  actions: number | null;
  elapsedSeconds: number | null;
  lastAssistant: string;
  lastTool: string;
  lastToolStatus: string;
  toolCount: number;
  toolErrors: number;
  assistantCount: number;
  bootDone: number;
  bootTotal: number;
  artifacts: number;
  tokens: number | null;
  eventsPerMin: number | null;
  telemetrySeries: Array<{ tokens: number; ctxPct: number | null }>;
}

function derive(events: RunEvent[]): Derived {
  let phase = "";
  let round: number | null = null;
  let actions: number | null = null;
  let elapsedSeconds: number | null = null;
  let lastAssistant = "";
  let lastTool = "";
  let lastToolStatus = "";
  let toolCount = 0;
  let toolErrors = 0;
  let assistantCount = 0;
  const bootSteps = new Map<string, boolean>();
  let artifacts = 0;
  let tokens: number | null = null;
  const telemetrySeries: Array<{ tokens: number; ctxPct: number | null }> = [];

  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    switch (ev.type) {
      case "progress": {
        const p = ev.payload ?? {};
        if (typeof p.phase === "string" && p.phase) phase = p.phase;
        if (typeof p.round === "number") round = p.round;
        if (typeof p.actions === "number") actions = p.actions;
        if (typeof p.elapsed_seconds === "number") elapsedSeconds = p.elapsed_seconds;
        const tel = p.telemetry as Record<string, unknown> | undefined;
        if (tel && typeof tel.total_tokens === "number") {
          tokens = tel.total_tokens as number;
          telemetrySeries.push({
            tokens: tel.total_tokens as number,
            ctxPct: typeof tel.last_ctx_pct === "number" ? (tel.last_ctx_pct as number) : null,
          });
          if (telemetrySeries.length > 200) telemetrySeries.shift();
        }
        break;
      }
      case "assistant": {
        const txt = typeof ev.payload.text === "string" ? ev.payload.text : "";
        if (txt.trim()) {
          lastAssistant = txt;
          assistantCount++;
        }
        break;
      }
      case "tool_request":
      case "tool_start":
      case "tool_result": {
        if (ev.type === "tool_request") toolCount++;
        const name = typeof ev.payload.name === "string" ? ev.payload.name : "";
        if (name) lastTool = name;
        if (ev.type === "tool_result") {
          if (ev.payload.error) {
            lastToolStatus = "error";
            toolErrors++;
          } else {
            lastToolStatus = "done";
          }
        } else if (ev.type === "tool_start") {
          if (lastToolStatus !== "error" && lastToolStatus !== "done") lastToolStatus = "running";
        }
        break;
      }
      case "boot":
      case "ok": {
        const step = typeof ev.payload.step === "string" ? ev.payload.step : "";
        if (step) {
          const ok = ev.payload.ok === true || ev.type === "ok";
          bootSteps.set(step, ok || (bootSteps.get(step) ?? false));
        }
        break;
      }
      case "artifact":
        artifacts++;
        break;
      default:
        break;
    }
  }

  const bootDone = Array.from(bootSteps.values()).filter(Boolean).length;
  const bootTotal = bootSteps.size;

  // ponytail: wall-clock events/min from first→last timestamp; cheap and good enough.
  let eventsPerMin: number | null = null;
  if (events.length >= 2) {
    const first = events[0].timestamp ? Date.parse(events[0].timestamp) : NaN;
    const last = events[events.length - 1].timestamp ? Date.parse(events[events.length - 1].timestamp) : NaN;
    if (Number.isFinite(first) && Number.isFinite(last) && last > first) {
      const mins = (last - first) / 60000;
      eventsPerMin = mins > 0 ? Math.round(events.length / mins) : null;
    }
  }

  return {
    phase, round, actions, elapsedSeconds,
    lastAssistant, lastTool, lastToolStatus,
    toolCount, toolErrors, assistantCount,
    bootDone, bootTotal, artifacts, tokens, eventsPerMin, telemetrySeries,
  };
}

function truncate(s: string, n: number): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length <= n ? one : one.slice(0, n - 1) + "\u2026";
}

export const LiveRunSummary = memo(function LiveRunSummary({ events, className }: LiveRunSummaryProps) {
  const d = useMemo(() => derive(events), [events]);
  const ctxValues = d.telemetrySeries.map((s) => s.ctxPct).filter((v): v is number => v != null);
  const hasAny =
    d.phase || d.round != null || d.actions != null || d.lastTool || d.lastAssistant || d.bootTotal > 0;

  if (!hasAny) {
    return (
      <Card className={cn(className)}>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Activity className="h-4 w-4" /> Live activity
          </CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-muted-foreground">
          Waiting for the agent to start…
        </CardContent>
      </Card>
    );
  }

  const errorRate = d.toolCount > 0 ? (d.toolErrors / d.toolCount) * 100 : 0;
  const bootComplete = d.bootTotal > 0 && d.bootDone >= d.bootTotal;

  return (
    <Card className={cn(className)}>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Activity className="h-4 w-4" /> Live activity
          {d.phase && (
            <Badge variant="info" className="ml-auto font-mono text-[10px] uppercase">
              {d.phase}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2.5 text-xs">
        <div className="grid grid-cols-3 gap-2 font-mono">
          <Stat icon={<Layers className="h-3 w-3" />} label="round" value={d.round != null ? String(d.round) : "\u2014"} />
          <Stat icon={<Terminal className="h-3 w-3" />} label="actions" value={d.actions != null ? String(d.actions) : "\u2014"} />
          <Stat icon={<Clock className="h-3 w-3" />} label="elapsed" value={d.elapsedSeconds != null ? fmtElapsed(d.elapsedSeconds) : "\u2014"} />
        </div>

        <div className="grid grid-cols-2 gap-2 font-mono">
          <Stat icon={<Cpu className="h-3 w-3" />} label="tool calls" value={toolCountLabel(d)} />
          <Stat icon={<MessageSquare className="h-3 w-3" />} label="msgs" value={String(d.assistantCount)} />
        </div>

        <div className="grid grid-cols-3 gap-2 font-mono">
          <Stat
            icon={<AlertTriangle className="h-3 w-3" />}
            label="tool errors"
            value={d.toolErrors > 0 ? `${d.toolErrors} (${errorRate.toFixed(0)}%)` : "0"}
            tone={d.toolErrors > 0 ? "danger" : undefined}
          />
          <Stat icon={<FileCheck className="h-3 w-3" />} label="artifacts" value={String(d.artifacts)} />
          <Stat
            icon={<Layers className="h-3 w-3" />}
            label="boot"
            value={d.bootTotal > 0 ? `${d.bootDone}/${d.bootTotal}` : "\u2014"}
            tone={bootComplete ? "success" : undefined}
          />
        </div>

        {(d.tokens != null || d.eventsPerMin != null) && (
          <div className="grid grid-cols-2 gap-2 font-mono">
            {d.tokens != null && (
              <Stat icon={<Cpu className="h-3 w-3" />} label="tokens" value={Number(d.tokens).toLocaleString()} />
            )}
            {d.eventsPerMin != null && (
              <Stat icon={<Activity className="h-3 w-3" />} label="events/min" value={String(d.eventsPerMin)} />
            )}
          </div>
        )}

        {d.telemetrySeries.length >= 2 &&
          (ctxValues.length >= 2 ? (
            <div className="grid grid-cols-2 gap-2">
              <Sparkline label="tokens" values={d.telemetrySeries.map((s) => s.tokens)} />
              <Sparkline label="ctx %" values={ctxValues} format={(v) => `${v.toFixed(1)}%`} />
            </div>
          ) : (
            <Sparkline label="tokens" values={d.telemetrySeries.map((s) => s.tokens)} />
          ))}

        {d.lastTool && (
          <div className="space-y-1 rounded-md border bg-muted/30 p-2">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Terminal className="h-3 w-3" /> Last tool
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-foreground">{d.lastTool}</span>
              {d.lastToolStatus && (
                <Badge
                  variant={d.lastToolStatus === "error" ? "danger" : d.lastToolStatus === "done" ? "success" : "warn"}
                  className="ml-auto text-[10px]"
                >
                  {d.lastToolStatus}
                </Badge>
              )}
            </div>
          </div>
        )}

        {d.lastAssistant && (
          <div className="space-y-1 rounded-md border border-primary/20 bg-primary/5 p-2">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <MessageSquare className="h-3 w-3" /> Agent said
            </div>
            <div className="whitespace-pre-wrap break-words text-foreground">
              {truncate(d.lastAssistant, 240)}
            </div>
          </div>
        )}

        {d.elapsedSeconds != null && (
          <div className="flex items-center gap-1.5 pt-0.5 text-muted-foreground">
            <Timer className="h-3 w-3" /> updated {fmtElapsed(d.elapsedSeconds)} ago
          </div>
        )}
      </CardContent>
    </Card>
  );
});

function Sparkline({
  label,
  values,
  format,
}: {
  label: string;
  values: number[];
  format?: (v: number) => string;
}) {
  if (values.length < 2) return null;
  let min = values[0];
  let max = values[0];
  for (let i = 1; i < values.length; i++) {
    if (values[i] < min) min = values[i];
    if (values[i] > max) max = values[i];
  }
  const span = max - min || 1;
  const W = 120;
  const H = 28;
  const points = values
    .map((v, i) => {
      const x = (i / (values.length - 1)) * (W - 2) + 1;
      const y = H - 2 - ((v - min) / span) * (H - 4);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <div className="space-y-1 rounded-md border bg-card/40 p-1.5">
      <div className="flex items-center justify-between text-[10px] uppercase tracking-wide text-muted-foreground">
        <span>{label}</span>
        <span className="tabular-nums text-foreground">
          {format ? format(values[values.length - 1]) : values[values.length - 1].toLocaleString()}
        </span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-7 w-full" role="img" aria-label={`${label} over time`}>
        <polyline
          points={points}
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          strokeLinejoin="round"
          strokeLinecap="round"
          className="text-primary/80"
        />
      </svg>
    </div>
  );
}

function toolCountLabel(d: Derived): string {
  if (d.actions != null) return `${d.toolCount}/${d.actions}`;
  return String(d.toolCount);
}

function Stat({
  icon,
  label,
  value,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  tone?: "success" | "danger";
}) {
  return (
    <div
      className={cn(
        "space-y-0.5 rounded-md border bg-card/40 p-1.5",
        tone === "success" && "border-emerald-500/40 bg-emerald-500/5",
        tone === "danger" && "border-destructive/40 bg-destructive/5",
      )}
    >
      <div className="flex items-center gap-1 text-muted-foreground">
        {icon}
        <span className="text-[10px] uppercase tracking-wide">{label}</span>
      </div>
      <div className="tabular-nums text-foreground">{value}</div>
    </div>
  );
}