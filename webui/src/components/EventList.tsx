import { useMemo, useRef, useEffect, useState } from "react";
import { AlertTriangle, ArrowDownToLine, Cpu, Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { BootChecklist } from "@/components/BootChecklist";
import { ToolCallCard } from "@/components/ToolCallCard";
import { DecisionCard } from "@/components/DecisionCard";
import type { RunEvent } from "@/api/types";
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
    if (stick) el.scrollTop = el.scrollHeight;
  }, [events, stick]);

  const onScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    const distance = el.scrollHeight - el.scrollTop - el.clientHeight;
    setStick(distance < 40);
  };

  const rendered = useMemo(() => {
    const toolGroups = new Map<string, ToolGroup>();
    const decisionIds = new Set<string>();
    const nodes: React.ReactNode[] = [];
    let lastBootIndex = -1;

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
            existing.error =
              typeof event.payload.error === "string" ? event.payload.error : undefined;
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
      nodes.push(renderSimpleEvent(event, `evt-${event.sequence}`));
    });

    if (lastBootIndex >= 0) {
      nodes.unshift(<BootChecklist key="boot-checklist" events={events} className="mb-3 rounded-md border bg-card/40 p-3" />);
    }

    return nodes;
  }, [events, decisions, runId]);

  if (events.length === 0) {
    return (
      <div className={cn("flex items-center justify-center rounded-md border border-dashed p-8 text-sm text-muted-foreground", className)}>
        Waiting for events...
      </div>
    );
  }

  return (
    <div className={cn("relative flex flex-col", className)}>
      <div
        ref={scrollRef}
        onScroll={onScroll}
        className="flex-1 overflow-y-auto rounded-md border bg-background/40 p-3 scrollbar-thin"
        aria-live="polite"
      >
        <div className="space-y-2">{rendered}</div>
      </div>
      {!stick && (
        <Button
          type="button"
          size="icon"
          variant="outline"
          className="absolute bottom-3 right-3 h-8 w-8 rounded-full"
          onClick={() => {
            const el = scrollRef.current;
            if (el) el.scrollTop = el.scrollHeight;
            setStick(true);
          }}
          aria-label="Jump to latest"
        >
          <ArrowDownToLine className="h-4 w-4" />
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
    case "progress":
      return (
        <div key={key} className="flex items-center gap-2 px-3 py-1 text-xs text-muted-foreground">
          <Cpu className="h-3 w-3" />
          <span>
            round {String(event.payload.round ?? "\u2014")} · {String(event.payload.action ?? "\u2014")} · {String(event.payload.phase ?? "\u2014")}
          </span>
          {event.payload.elapsed_seconds != null && (
            <span className="ml-auto tabular-nums">{String(event.payload.elapsed_seconds)}s</span>
          )}
        </div>
      );
    case "assistant":
      return (
        <div key={key} className="flex gap-2 rounded-md border bg-card/40 px-3 py-2 text-sm">
          <Sparkles className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          <div className="whitespace-pre-wrap break-words text-sm">
            {String(event.payload.text ?? "")}
          </div>
        </div>
      );
    case "goal_suggestions": {
      const suggestions = Array.isArray(event.payload.suggestions) ? event.payload.suggestions : [];
      return (
        <div key={key} className="rounded-md border bg-card/40 p-3 text-sm">
          <div className="mb-2 text-xs uppercase tracking-wide text-muted-foreground">Goal suggestions</div>
          <ul className="space-y-1.5">
            {suggestions.map((s, i) => {
              const item = s as Record<string, unknown>;
              return (
                <li key={i} className="flex flex-col gap-0.5">
                  <span className="font-medium">{String(item.name ?? "\u2014")}</span>
                  <span className="text-xs text-muted-foreground">{String(item.description ?? "")}</span>
                </li>
              );
            })}
          </ul>
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