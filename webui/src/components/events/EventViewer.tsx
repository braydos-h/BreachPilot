import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer, type ReactVirtualizer } from "@tanstack/react-virtual";
import {
  AlertTriangle,
  ArrowDownToLine,
  Cpu,
  ListChecks,
  Pause,
  Play,
  Search,
  Sparkles,
  X,
} from "lucide-react";
import { cn, formatRelative } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { BootChecklist } from "@/components/BootChecklist";
import { ToolCallCard } from "@/components/ToolCallCard";
import { DecisionCard } from "@/components/DecisionCard";
import { ReconAssessmentCard } from "@/components/ReconAssessmentCard";
import { GoalSuggestionCard } from "@/components/GoalSuggestionCard";
import { apiFetch } from "@/api/client";
import { formatElapsed, formatTokens, safeStringify } from "@/lib/format";
import type { EventReplayResponse, RunEvent, SuggestedGoal, ReconAssessment } from "@/api/types";
import type { DecisionListRow } from "@/api/types";
import type { WsStatus } from "@/api/ws";

interface EventViewerProps {
  /** Ascending (oldest → newest); the live bounded buffer. */
  events: RunEvent[];
  decisions: DecisionListRow[];
  runId: string;
  status: WsStatus;
  transport: "websocket" | "sse" | "none";
  authError?: string;
  /** True when the stream is open but no frames (incl. heartbeats) have
   *  arrived recently — the socket is probably dead without a close event. */
  stale?: boolean;
  /** Events omitted from the bounded window (still exist server-side). */
  dropped?: number;
  className?: string;
  terminal?: boolean;
}

const FILTERS = [
  { key: "all", label: "All" },
  { key: "tools", label: "Tools" },
  { key: "assistant", label: "Assistant" },
  { key: "decisions", label: "Decisions" },
  { key: "errors", label: "Errors" },
  { key: "progress", label: "Progress" },
] as const;

type FilterKey = (typeof FILTERS)[number]["key"];

function matchesFilter(type: string, filter: FilterKey): boolean {
  switch (filter) {
    case "all":
      return true;
    case "tools":
      return type === "tool_request" || type === "tool_start" || type === "tool_result";
    case "assistant":
      return type === "assistant";
    case "decisions":
      return type === "approval";
    case "errors":
      return type === "error";
    case "progress":
      return type === "progress";
  }
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
  searchText: string;
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

function payloadText(event: RunEvent): string {
  try {
    return `${event.type} ${JSON.stringify(event.payload ?? {})} ${event.timestamp ?? ""}`.toLowerCase();
  } catch {
    return event.type;
  }
}

interface Row {
  key: string;
  node: React.ReactNode;
  /** Lowercased searchable text for the free-text filter. */
  searchText: string;
}

const NEAR_BOTTOM_PX = 40;

export function EventViewer({
  events,
  decisions,
  runId,
  status,
  transport,
  authError,
  stale = false,
  dropped = 0,
  className,
  terminal = false,
}: EventViewerProps) {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const virtualizerRef = useRef<ReactVirtualizer<HTMLDivElement, Element> | null>(null);

  const [filter, setFilter] = useState<FilterKey>("all");
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [paused, setPaused] = useState(false);
  const [unseen, setUnseen] = useState(0);
  const [older, setOlder] = useState<RunEvent[]>([]);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [hasMoreOlder, setHasMoreOlder] = useState(false);

  const followRef = useRef(true);
  const pausedRef = useRef(false);
  const prevPausedRef = useRef(false);
  const lastRowCountRef = useRef(0);

  // Debounce the free-text filter.
  useEffect(() => {
    const t = setTimeout(() => setDebouncedQuery(query), 200);
    return () => clearTimeout(t);
  }, [query]);

  const rows = useMemo<Row[]>(() => {
    const merged = [...older, ...events];
    const q = debouncedQuery.trim().toLowerCase();

    const toolGroups = new Map<string, ToolGroup>();
    const decisionIds = new Set<string>();

    for (const event of merged) {
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
            searchText: "",
          });
        } else {
          if (event.type === "tool_start") existing.started = true;
          if (event.type === "tool_request" && event.payload.arguments !== undefined) {
            existing.arguments = event.payload.arguments;
          }
          if (event.type === "tool_result") {
            existing.completed = true;
            existing.result = typeof event.payload.result === "string" ? event.payload.result : undefined;
            const success = event.payload.success;
            const errStr = typeof event.payload.error === "string" ? event.payload.error : undefined;
            existing.error = success === false ? (errStr ?? "tool failed") : errStr;
          }
        }
        if (existing) {
          existing.searchText = payloadText(event);
        }
        continue;
      }
      if (event.type === "approval") {
        const decisionId = event.payload.decision_id;
        if (typeof decisionId === "string") decisionIds.add(decisionId);
      }
    }

    const out: Row[] = [];
    const goalSelectAnswered = decisions.some(
      (d) => d.kind === "goal_select" && d.status !== "pending",
    );

    const maybePush = (row: Row) => {
      if (q && !row.searchText.includes(q)) return;
      out.push(row);
    };

    for (const event of merged) {
      if (event.type === "boot" || event.type === "ok") continue;
      if (event.type === "tool_request" || event.type === "tool_start" || event.type === "tool_result") {
        if (filter !== "all" && filter !== "tools") continue;
        if (event.type !== "tool_request") continue;
        const id = corrIdOf(event);
        const group = toolGroups.get(id);
        if (!group) continue;
        group.searchText += ` ${group.toolName} ${safeStringify(group.arguments)} ${group.result ?? ""} ${group.error ?? ""}`.toLowerCase();
        maybePush({
          key: `tool-${id}`,
          searchText: group.searchText,
          node: (
            <ToolCallCard
              toolName={group.toolName}
              arguments={group.arguments}
              result={group.result}
              error={group.error}
              started={group.started}
              completed={group.completed}
              timestamp={group.timestamp}
              className="mb-2"
            />
          ),
        });
        continue;
      }
      if (event.type === "approval") {
        if (filter !== "all" && filter !== "decisions") continue;
        const decisionId = event.payload.decision_id;
        if (typeof decisionId !== "string") continue;
        const decision = decisions.find((d) => d.id === decisionId);
        if (!decision || decision.status !== "pending") continue;
        maybePush({
          key: `approval-${decisionId}`,
          searchText: `${decision.kind} ${decision.required_text ?? ""} ${decision.options?.map((o) => (o as { name?: string }).name).join(" ") ?? ""}`.toLowerCase(),
          node: (
            <DecisionCard
              key={`approval-${decisionId}`}
              decision={decision}
              runId={runId}
              className="mb-2"
            />
          ),
        });
        continue;
      }
      if (event.type === "goal_suggestions" && goalSelectAnswered) continue;
      if (!matchesFilter(event.type, filter)) continue;
      maybePush({
        key: `evt-${event.sequence}`,
        searchText: payloadText(event),
        node: renderSimpleEvent(event, `evt-${event.sequence}`),
      });
    }
    return out;
  }, [older, events, decisions, runId, filter, debouncedQuery]);

  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 64,
    overscan: 8,
  });
  virtualizerRef.current = rowVirtualizer;

  const scrollToLatest = useCallback(() => {
    const v = virtualizerRef.current;
    if (v && rows.length > 0) v.scrollToIndex(rows.length - 1, { align: "end" });
  }, [rows.length]);

  // Auto-follow: while following (near bottom) and unpaused, keep the newest
  // event pinned; otherwise count new rows as unseen.
  useEffect(() => {
    const delta = rows.length - lastRowCountRef.current;
    if (delta <= 0) {
      lastRowCountRef.current = rows.length;
      return;
    }
    lastRowCountRef.current = rows.length;
    if (followRef.current && !pausedRef.current) {
      scrollToLatest();
    } else {
      setUnseen((u) => u + delta);
    }
  }, [rows.length, scrollToLatest]);

  // Keep the explicit pause button in sync with the ref used by the effect.
  // Guarded to act only on an actual pause↔resume transition (scrollToLatest
  // changes identity on every new event — without the guard, that would wipe
  // the unseen counter each time a run emits).
  useEffect(() => {
    pausedRef.current = paused;
    if (paused === prevPausedRef.current) return;
    prevPausedRef.current = paused;
    if (!paused) {
      // Resuming shows the latest and clears the unseen counter.
      setUnseen(0);
      scrollToLatest();
    }
  }, [paused, scrollToLatest]);

  const onScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < NEAR_BOTTOM_PX;
    followRef.current = nearBottom;
    if (nearBottom) setUnseen(0);
  }, []);

  const togglePause = useCallback(() => setPaused((p) => !p), []);

  const clearFilters = useCallback(() => {
    setFilter("all");
    setQuery("");
    setDebouncedQuery("");
  }, []);

  const activeFilterCount =
    (filter !== "all" ? 1 : 0) + (debouncedQuery.trim() ? 1 : 0);

  const loadOlder = useCallback(async () => {
    const firstSeq = older.length > 0 ? older[0].sequence : events[0]?.sequence;
    if (!firstSeq || loadingOlder) return;
    setLoadingOlder(true);
    try {
      const res = await apiFetch<EventReplayResponse>(
        `/runs/${encodeURIComponent(runId)}/events?before=${firstSeq}&limit=500`,
      );
      const prev = res.events ?? []; // newest-first per the backend
      setOlder((o) => [...prev.slice().reverse(), ...o]);
      setHasMoreOlder(!!res.has_more_before);
    } catch {
      // Leave the window as-is; the banner already notes history is preserved.
    } finally {
      setLoadingOlder(false);
    }
  }, [older, events, runId, loadingOlder]);

  const remainingOlder = Math.max(0, dropped - older.length);

  if (events.length === 0 && older.length === 0) {
    if (terminal) {
      return (
        <div
          className={cn(
            "flex items-center justify-center rounded-md border border-dashed p-6 text-sm text-muted-foreground",
            className,
          )}
        >
          No events recorded for this run.
        </div>
      );
    }
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

  const bootVisible = filter === "all" && debouncedQuery.trim() === "";

  return (
    <div className={cn("relative flex flex-col", className)}>
      {/* Toolbar: filters + connection status + pause */}
      <div className="mb-2 flex flex-wrap items-center gap-1.5">
        <div className="relative min-w-[160px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter events…"
            aria-label="Filter events by text"
            className="h-8 pl-8 pr-7 text-xs"
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery("")}
              aria-label="Clear text filter"
              className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-0.5 text-muted-foreground hover:text-foreground"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        {FILTERS.map((f) => (
          <button
            key={f.key}
            type="button"
            onClick={() => setFilter(f.key)}
            aria-pressed={filter === f.key}
            className={cn(
              "rounded-full border px-2.5 py-1 text-xs transition-colors",
              filter === f.key
                ? "border-primary bg-primary/10 text-foreground"
                : "border-border text-muted-foreground hover:bg-accent",
            )}
          >
            {f.label}
          </button>
        ))}

        {activeFilterCount > 0 && (
          <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={clearFilters}>
            Clear filters
          </Button>
        )}

        <Button
          variant={paused ? "default" : "outline"}
          size="sm"
          className="h-8 gap-1.5 text-xs"
          onClick={togglePause}
          aria-pressed={paused}
          aria-label={paused ? "Resume live view" : "Pause live view"}
        >
          {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
          {paused ? "Resume" : "Pause"}
        </Button>

        <ConnectionStatus status={status} transport={transport} authError={authError} stale={stale} paused={paused} unseen={unseen} />
      </div>

      {/* Truncation notice: the bound is client-side; history is preserved. */}
      {(dropped > 0 || older.length > 0) && (
        <div className="mb-2 flex flex-wrap items-center gap-x-2 gap-y-1 rounded-md border border-dashed bg-muted/20 px-2.5 py-1.5 text-[11px] text-muted-foreground">
          <span>
            Showing latest {older.length + events.length} events
            {remainingOlder > 0 && ` · ${remainingOlder} older events omitted (full history is preserved server-side)`}
          </span>
          {hasMoreOlder && (
            <button
              type="button"
              onClick={() => void loadOlder()}
              disabled={loadingOlder}
              className="underline underline-offset-2 hover:text-foreground"
            >
              {loadingOlder ? "Loading…" : "Load older events"}
            </button>
          )}
        </div>
      )}

      {bootVisible && (
        <BootChecklist
          events={events}
          className="mb-3 rounded-md border bg-card/40 p-3"
        />
      )}

      <div className="relative flex-1 overflow-hidden rounded-md border bg-background/40 bg-grid-sm/20">
        <div
          ref={scrollRef}
          onScroll={onScroll}
          className="h-full overflow-y-auto scrollbar-thin"
          aria-label="Run events"
        >
          {rows.length === 0 ? (
            <div className="flex items-center justify-center p-6 text-sm text-muted-foreground">
              No matching events.
            </div>
          ) : (
            <div className="relative" style={{ height: rowVirtualizer.getTotalSize() }}>
              {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                const row = rows[virtualRow.index];
                return (
                  <div
                    key={row.key}
                    data-index={virtualRow.index}
                    ref={rowVirtualizer.measureElement}
                    className="absolute left-0 top-0 w-full px-3 pt-1.5"
                    style={{ transform: `translateY(${virtualRow.start}px)` }}
                  >
                    {row.node}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {unseen > 0 && (
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="absolute bottom-3 right-3 gap-1.5 rounded-full text-xs shadow"
            onClick={() => {
              setUnseen(0);
              followRef.current = true;
              scrollToLatest();
            }}
            aria-label={`Jump to latest (${unseen} new event${unseen === 1 ? "" : "s"})`}
          >
            <ArrowDownToLine className="h-3.5 w-3.5" />
            {unseen} new
          </Button>
        )}
      </div>
    </div>
  );
}

function ConnectionStatus({
  status,
  transport,
  authError,
  stale,
  paused,
  unseen,
}: {
  status: WsStatus;
  transport: EventViewerProps["transport"];
  authError?: string;
  stale?: boolean;
  paused: boolean;
  unseen: number;
}) {
  // Connection state is communicated by text + icon, not color alone.
  let dot = "●";
  let label: string;
  let cls: string;
  if (authError) {
    dot = "⚠";
    label = "Auth error";
    cls = "text-destructive";
  } else if (paused) {
    dot = "⏸";
    label = `Paused${unseen > 0 ? ` · ${unseen} new` : ""}`;
    cls = "text-foreground";
  } else if (status === "open" && stale) {
    dot = "◐";
    label = "Stale";
    cls = "text-yellow-300";
  } else if (status === "open") {
    dot = "●";
    label = "Live";
    cls = "text-emerald-400";
  } else if (status === "connecting") {
    dot = "●";
    label = "Connecting";
    cls = "text-muted-foreground";
  } else if (status === "reconnecting") {
    dot = "○";
    label = "Reconnecting";
    cls = "text-yellow-300";
  } else {
    dot = "⚠";
    label = "Disconnected";
    cls = "text-destructive";
  }
  const transportLabel =
    transport === "sse" ? "SSE" : transport === "websocket" ? "WS" : null;
  const title = `${label}${transportLabel ? ` · ${transportLabel}` : ""}${
    authError ? ` — ${authError}` : ""
  }`;
  return (
    <span
      className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground"
      title={title}
    >
      <span className={cls} aria-hidden>
        {dot}
      </span>
      <span>{label}</span>
      {transportLabel && <span className="text-muted-foreground/60">· {transportLabel}</span>}
    </span>
  );
}

function renderSimpleEvent(event: RunEvent, key: string): React.ReactNode {
  switch (event.type) {
    case "state":
      return (
        <div key={key} className="flex items-center gap-2 rounded-md bg-secondary/40 px-3 py-1.5 text-sm">
          <Badge variant="secondary" className="text-xs">state</Badge>
          <span className="font-mono text-xs">{String(event.payload.state ?? "")}</span>
          {event.timestamp && (
            <span className="ml-auto text-xs text-muted-foreground" title={event.timestamp}>
              {formatRelative(event.timestamp)}
            </span>
          )}
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
              round {String(event.payload.round ?? "—")} · {String(event.payload.actions ?? event.payload.action ?? "—")} · {String(event.payload.phase ?? "—")}
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
          {event.timestamp && (
            <span className="ml-auto text-xs text-muted-foreground" title={event.timestamp}>
              {formatRelative(event.timestamp)}
            </span>
          )}
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
    case "title":
      return (
        <div key={key} className="flex items-center gap-2 rounded-md bg-muted/30 px-3 py-1.5 text-xs">
          <Badge variant="outline" className="text-[10px] uppercase">title</Badge>
          <span className="truncate font-mono text-foreground">
            {String(event.payload.title ?? "")}
          </span>
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
