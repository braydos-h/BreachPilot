import { memo } from "react";
import { Activity, Clock, Cpu, Layers, MessageSquare, Sparkles, Terminal } from "lucide-react";
import { cn, formatRelative } from "@/lib/utils";
import { fmtElapsed } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { phaseInfo, type DerivedRun } from "@/lib/deriveRun";
import type { RunState } from "@/api/types";

interface RunNowCardProps {
  derived: DerivedRun;
  active: boolean;
  state: RunState;
}

function truncate(s: string, n: number): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length <= n ? one : `${one.slice(0, n - 1)}…`;
}

/**
 * "What is NetAttackAI doing right now?" — the single operator-facing answer
 * derived from the existing event stream. Never shows chain-of-thought: only
 * the phase, the latest assistant message, the tool currently executing (or
 * waiting on a decision), and run counters the backend already emits.
 */
export const RunNowCard = memo(function RunNowCard({
  derived,
  active,
  state,
}: RunNowCardProps) {
  const info = phaseInfo(derived.phase);
  const waiting = state === "awaiting_input" || state === "awaiting_confirmation";

  return (
    <Card className="border-primary/20 bg-card/60">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <span className="relative flex h-2.5 w-2.5">
            {active && !waiting ? (
              <>
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400/60" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-400" />
              </>
            ) : (
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-yellow-400" />
            )}
          </span>
          <span>What is the agent doing right now?</span>
          {waiting && (
            <Badge variant="warn" className="ml-auto text-[10px]">
              waiting on operator
            </Badge>
          )}
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-2.5 text-sm">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1">
            <Activity className="h-3 w-3" aria-hidden />
            Phase: <span className="font-mono text-foreground">{info.label}</span>
          </span>
          <span className="text-muted-foreground/70">{info.summary}</span>
          {derived.source && (
            <Badge variant="secondary" className="text-[10px] uppercase">
              {derived.source === "swarm" ? "swarm" : "agent"}
            </Badge>
          )}
        </div>

        <div aria-live="polite" className="space-y-2">
          <ActivityBlock derived={derived} />
        </div>

        {derived.lastAssistant && (
          <div className="flex gap-2 rounded-md border border-primary/20 bg-primary/5 p-2.5 text-xs">
            <Sparkles className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary" aria-hidden />
            <div className="min-w-0">
              <div className="mb-0.5 flex items-center gap-2 text-[10px] uppercase tracking-wide text-muted-foreground">
                Agent message
                {derived.lastAssistantAt && (
                  <span className="normal-case text-muted-foreground/60">
                    {formatRelative(derived.lastAssistantAt)}
                  </span>
                )}
              </div>
              <p className="whitespace-pre-wrap break-words text-foreground">
                {truncate(derived.lastAssistant, 300)}
              </p>
            </div>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
          <Chip icon={<Layers className="h-3 w-3" />} label="round" value={derived.round != null ? String(derived.round) : "—"} />
          <Chip icon={<Terminal className="h-3 w-3" />} label="actions" value={derived.actions != null ? String(derived.actions) : "—"} />
          <Chip icon={<Clock className="h-3 w-3" />} label="elapsed" value={derived.elapsedSeconds != null ? fmtElapsed(derived.elapsedSeconds) : "—"} />
          <Chip icon={<Cpu className="h-3 w-3" />} label="events/min" value={derived.eventsPerMin != null ? String(derived.eventsPerMin) : "—"} />
          {derived.lastMeaningfulAt && (
            <span className="ml-auto inline-flex items-center gap-1 text-[10px] text-muted-foreground">
              <MessageSquare className="h-3 w-3" aria-hidden />
              last activity {formatRelative(derived.lastMeaningfulAt)}
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
});

function ActivityBlock({ derived }: { derived: DerivedRun }) {
  const t = derived.currentTool;
  if (t) {
    const running = t.started;
    return (
      <div className="flex flex-wrap items-center gap-2 rounded-md border bg-card/40 p-2.5">
        <Terminal className={cn("h-3.5 w-3.5 shrink-0", running ? "animate-pulse text-primary" : "text-yellow-300")} aria-hidden />
        <span className="font-mono text-xs text-foreground">{t.name}</span>
        {t.args && <span className="min-w-0 truncate font-mono text-[11px] text-muted-foreground">{t.args}</span>}
        <Badge
          variant={running ? "warn" : "info"}
          className="ml-auto shrink-0 text-[10px]"
          title={running ? "Tool is executing" : "Awaiting operator approval"}
        >
          {running ? "running" : "awaiting approval"}
        </Badge>
      </div>
    );
  }
  if (derived.lastTool && derived.lastTool.completed) {
    const ok = derived.lastTool.success === true;
    return (
      <div className="flex flex-wrap items-center gap-2 rounded-md border bg-card/40 p-2.5">
        <Terminal className={cn("h-3.5 w-3.5 shrink-0", ok ? "text-emerald-400" : "text-red-400")} aria-hidden />
        <span className="font-mono text-xs text-foreground">{derived.lastTool.name}</span>
        {derived.lastTool.exitCode != null && (
          <span className="font-mono text-[11px] text-muted-foreground">exit {derived.lastTool.exitCode}</span>
        )}
        <Badge variant={ok ? "success" : "danger"} className="ml-auto shrink-0 text-[10px]">
          {ok ? "done" : "failed"}
        </Badge>
      </div>
    );
  }
  return (
    <p className="rounded-md border border-dashed p-2.5 text-xs text-muted-foreground">
      No tool activity yet — {derived.phase === "starting" ? "booting the agent and MCP tools…" : "working…"}
    </p>
  );
}

function Chip({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <span className="inline-flex items-center gap-1 rounded-md border bg-card/40 px-2 py-1 text-[11px] text-muted-foreground">
      {icon}
      <span>{label}</span>
      <span className="font-mono tabular-nums text-foreground">{value}</span>
    </span>
  );
}
