import { useMemo, useRef, useEffect, useState } from "react";
import { AlertTriangle, ArrowUpToLine, Cpu, Sparkles, ListChecks } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { BootChecklist } from "@/components/BootChecklist";
import { ToolCallCard } from "@/components/ToolCallCard";
import { DecisionCard } from "@/components/DecisionCard";
import { ReconAssessmentCard } from "@/components/ReconAssessmentCard";
import { GoalSuggestionCard } from "@/components/GoalSuggestionCard";
import type { RunEvent, SuggestedGoal, ReconAssessment } from "@/api/types";
import type { DecisionListRow } from "@/api/types";

interface EventListProps {
  events: RunEvent[];
  decisions: DecisionListRow[];
  runId: string;
  className?: string;
}

interface ToolGroup {
  correlationId: string;
  toolName: string;
  started: boolean;
  completed: boolean;
  result?: string;
  error?: string;
  arguments?: unknown;
  timestamp?: string;
}

function corrIdOf(event: RunEvent): string {
  const payload = event.payload ?? {};
  // The backend emits a stable `action` counter per tool call across
  // tool_request/tool_start/tool_result (tools/exploit_agent/loop.py).
  // Prefer it over name-sequence which differs per event stage.
  if (typeof payload.action === "number" && payload.action > 0) {
    return `action-${payload.action}`;
  }
  const candidate =
    payload.correlation_id ?? payload.call_id ?? payload.tool_call_id ?? payload.request_id;
  if (typeof candidate === "string" && candidate) return candidate;
  if (typeof payload.name === "string" && payload.name) return `${payload.name}-${event.sequence}`;
  return `tool-${event.sequence}`;
}

export function EventList({ events, decisions, runId, className }: EventListProps) {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const [stick, setStick] = useState(true);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    if (stick) el.scrollTop = 0;
  }, [events, stick]);

  const onScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    setStick(el.scrollTop < 40);
  };

  const rendered = useMemo(() => {
    const toolGroups = new Map<string, ToolGroup>();
    const decisionIds = new Set<string>();
    const nodes: React.ReactNode[] = [];
    let lastBootIndex = -1;
    const goalSelectAnswered = decisions.some(
      (d) => d.kind === "goal_select" && d.status !== "pending",
    );

    events.forEach((event) => {
      if (event.type === "boot" || event.type === "ok") {
        lastBootIndex = event.sequence;
        return;
      }
      if (event.type === "tool_request" || event.type === "tool_start" || event.type === "tool_result") {
        const id = corrIdOf(event);
        const existing = toolGroups.get(id);
        const name =
          (event.payload.name as string | undefined) ?? existing?.toolName ?? `tool-${event.sequence}`;
        if (!existing) {
          toolGroups.set(id, {
            correlationId: id,
            toolName: name,
            started: event.type === "tool_start",
            completed: false,
            arguments: event.type === "tool_request" ? event.payload.arguments : undefined,
            timestamp: event.timestamp,
          });
        } else {
          if (event.type === "tool_start") existing.started = true;
          if (event.type === "tool_request" && event.payload.arguments !== undefined) {
            existing.arguments = event.payload.arguments;
          }
          if (event.type === "tool_result") {
            existing.completed = true;
            existing.result = typeof event.payload.result === "string" ? event.payload.result : undefined;
            // Backend signals failure via `success: false` OR a string `error`.
            const success = event.payload.success;
            const errStr = typeof event.payload.error === "string" ? event.payload.error : undefined;
            existing.error = (success === false) ? (errStr ?? "tool failed") : errStr;
          }
        }
        return;
      }
      if (event.type === "approval") {
        const decisionId = event.payload.decision_id;
        if (typeof decisionId === "string") decisionIds.add(decisionId);
      }
    });

    events.forEach((event) => {
      if (event.type === "boot" || event.type === "ok") return;
      if (event.type === "tool_request" || event.type === "tool_start" || event.type === "tool_result") {
        if (event.type === "tool_request") {
          const id = corrIdOf(event);
          const group = toolGroups.get(id);
          if (group) {
            nodes.push(
              <ToolCallCard
                key={`tool-${id}`}
                toolName={group.toolName}
                arguments={group.arguments}
                result={group.result}
                error={group.error}
                started={group.started}
                completed={group.completed}
                timestamp={group.timestamp}
                className="mb-2"
              />,
            );
          }
        }
        return;
      }
      if (event.type === "approval") {
        const decisionId = event.payload.decision_id;
        if (typeof decisionId !== "string") return;
        const decision = decisions.find((d) => d.id === decisionId);
        if (!decision || decision.status !== "pending") return;
        nodes.push(
          <DecisionCard
            key={`approval-${decisionId}`}
            decision={decision}
            runId={runId}
            className="mb-2"
          />,
        );
        return;
      }
      if (event.type === "goal_suggestions" && goalSelectAnswered) return;
      nodes.push(renderSimpleEvent(event, `evt-${event.sequence}`));
    });

    if (lastBootIndex >= 0) {
      nodes.unshift(<BootChecklist key="boot-checklist" events={events} className="mb-3 rounded-md border bg-card/40 p-3" />);
    }

    nodes.reverse();
    return nodes;
  }, [events, decisions, runId]);

  if (events.length === 0) {
    return (
      <div className={cn("space-y-2", className)}>
        <div className="relative flex-1 overflow-hidden rounded-md border border-dashed bg-grid-sm/30 p-3">
          <div className="space-y-2" aria-hidden>
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-6 w-2/3" />
            <Skeleton className="h-6 w-4/5" />
            <Skeleton className="h-8 w-1/2" />
          </div>
        </div>
        <p className="text-center text-xs text-muted-foreground">Waiting for events…</p>
      </div>
    );
  }

  return (
    <div className={cn("relative flex flex-col", className)}>
      <div
        ref={scrollRef}
        onScroll={onScroll}
        className="relative flex-1 overflow-y-auto rounded-md border bg-background/40 bg-grid-sm/20 p-3 scrollbar-thin"
        aria-live="polite"
      >
        <div className="relative space-y-2">{rendered}</div>
      </div>
      {!stick && (
        <Button
          type="button"
          size="icon"
          variant="outline"
          className="absolute bottom-3 right-3 h-8 w-8 rounded-full"
          onClick={() => {
            const el = scrollRef.current;
            if (el) el.scrollTop = 0;
            setStick(true);
          }}
          aria-label="Jump to latest"
        >
          <ArrowUpToLine className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}

function renderSimpleEvent(event: RunEvent, key: string): React.ReactNode {
  switch (event.type) {
    case "state":
      return (
        <div key={key} className="flex items-center gap-2 rounded-md bg-secondary/40 px-3 py-1.5 text-sm">
          <Badge variant="secondary" className="text-xs">state</Badge>
          <span className="font-mono text-xs">{String(event.payload.state ?? "")}</span>
          {event.timestamp && <span className="ml-auto text-xs text-muted-foreground">{event.timestamp}</span>}
        </div>
      );
    case "progress": {
      const tel = event.payload.telemetry as
        | {
            calls?: number;
            total_tokens?: number;
            last_ctx_pct?: number | null;
            context_window_tokens?: number | null;
            last_estimated_context_tokens?: number | null;
            avg_ctx?: number | null;
            max_ctx?: number | null;
          }
        | undefined;
      const ctxPct = tel?.last_ctx_pct ?? null;
      const ctxWindow = tel?.context_window_tokens ?? null;
      const ctxUsed = tel?.last_estimated_context_tokens ?? null;
      const ctxBar = ctxPct != null ? Math.max(0, Math.min(100, Math.round(ctxPct))) : null;
      return (
        <div key={key} className="rounded-md bg-secondary/40 px-3 py-1.5 text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <Cpu className="h-3 w-3" />
            <span>
              round {String(event.payload.round ?? "\u2014")} · {String(event.payload.actions ?? event.payload.action ?? "\u2014")} · {String(event.payload.phase ?? "\u2014")}
            </span>
            {event.payload.elapsed_seconds != null && (
              <span className="ml-auto tabular-nums">{formatElapsed(Number(event.payload.elapsed_seconds))}</span>
            )}
          </div>
          {tel && (tel.calls || tel.total_tokens || ctxPct != null) && (
            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 pl-5 text-[11px]">
              {tel.calls != null && (
                <span>
                  LLM <span className="tabular-nums text-foreground">{tel.calls}</span> calls
                </span>
              )}
              {tel.total_tokens != null && (
                <span>
                  <span className="tabular-nums text-foreground">{formatTokens(tel.total_tokens)}</span> tokens
                </span>
              )}
              {ctxPct != null && (
                <span className="inline-flex items-center gap-1">
                  <span>ctx</span>
                  <span className="relative inline-block h-1.5 w-16 overflow-hidden rounded-full bg-muted">
                    <span
                      className="absolute left-0 top-0 h-full rounded-full bg-primary/70"
                      style={{ width: `${ctxBar ?? 0}%` }}
                    />
                  </span>
                  <span className="tabular-nums text-foreground">{ctxBar}%</span>
                </span>
              )}
              {ctxUsed != null && ctxWindow != null && (
                <span className="tabular-nums">
                  {formatTokens(ctxUsed)}/{formatTokens(ctxWindow)}
                </span>
              )}
            </div>
          )}
        </div>
      );
    }
    case "assistant":
      return (
        <div key={key} className="flex gap-2 rounded-md border border-primary/20 bg-primary/5 px-3 py-2 text-sm">
          <Sparkles className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary" />
          <div className="whitespace-pre-wrap break-words text-sm">
            {String(event.payload.text ?? "")}
          </div>
        </div>
      );
    case "phase":
      return (
        <div key={key} className="flex items-center gap-2 rounded-md border border-primary/30 bg-primary/10 px-3 py-1.5 text-sm">
          <Badge variant="info" className="text-xs uppercase">phase</Badge>
          <span className="font-mono text-xs text-foreground">
            {String(event.payload.previous ?? "")} → {String(event.payload.phase ?? "")}
          </span>
          {event.timestamp && <span className="ml-auto text-xs text-muted-foreground">{event.timestamp}</span>}
        </div>
      );
    case "recon_assessment": {
      const assessment = event.payload.assessment as ReconAssessment | undefined;
      if (!assessment) return null;
      return <ReconAssessmentCard key={key} assessment={assessment} className="mb-2" />;
    }
    case "goal_suggestions": {
      const raw = Array.isArray(event.payload.suggestions) ? event.payload.suggestions : [];
      const suggestions = raw as SuggestedGoal[];
      const aiGoals = suggestions.filter((s) => s.is_ai_generated === true);
      const presetGoals = suggestions.filter((s) => s.is_ai_generated !== true);
      const sorted = [...aiGoals, ...presetGoals];
      return (
        <div key={key} className="rounded-md border bg-card/40 p-3 text-sm">
          <div className="mb-2 flex items-center gap-1.5 text-xs uppercase tracking-wide text-muted-foreground">
            <ListChecks className="h-3.5 w-3.5" />
            Suggested goals (ranked by exploit success rating)
          </div>
          <div className="space-y-2">
            {sorted.map((s, i) => (
              <GoalSuggestionCard key={i} goal={s} compact />
            ))}
          </div>
        </div>
      );
    }
    case "swarm":
      return (
        <div key={key} className="rounded-md bg-muted/40 px-3 py-2 text-xs">
          <span className="text-muted-foreground">swarm</span>: {safeStringify(event.payload)}
        </div>
      );
    case "artifact":
      return (
        <div key={key} className="flex items-center gap-2 rounded-md border bg-card/30 px-3 py-1.5 text-xs">
          <Badge variant="outline">artifact</Badge>
          <span className="truncate font-mono">{String(event.payload.name ?? event.payload.path ?? "")}</span>
        </div>
      );
    case "completion":
      return (
        <div key={key} className="rounded-md border border-emerald-500/40 bg-emerald-500/10 p-3 text-sm text-emerald-200">
          <div className="text-xs uppercase tracking-wide">Completed</div>
          <pre className="mt-1 whitespace-pre-wrap break-words text-xs">
            {safeStringify(event.payload.result ?? event.payload)}
          </pre>
        </div>
      );
    case "error":
      return (
        <div key={key} className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-red-200">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <div className="whitespace-pre-wrap break-words">{String(event.payload.message ?? safeStringify(event.payload))}</div>
        </div>
      );
    default:
      return (
        <div key={key} className="rounded-md bg-muted/30 px-3 py-1.5 text-xs text-muted-foreground">
          <span className="font-mono">{event.type}</span>: {safeStringify(event.payload)}
        </div>
      );
  }
}

function safeStringify(value: unknown): string {
  try {
    return typeof value === "string" ? value : JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function formatElapsed(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds));
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m >= 60) {
    const h = Math.floor(m / 60);
    const mm = m % 60;
    return `${h}h${String(mm).padStart(2, "0")}m`;
  }
  if (m > 0) return `${m}m${String(rem).padStart(2, "0")}s`;
  return `${rem}s`;
}

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}