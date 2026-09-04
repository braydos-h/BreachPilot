import { safeStringify } from "@/lib/format";
import type { DecisionListRow, RunEvent } from "@/api/types";

export type EventRowFilter = "all" | "tools" | "assistant" | "decisions" | "errors" | "progress";

export function matchesRowFilter(type: string, filter: EventRowFilter): boolean {
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

export function corrIdOf(event: RunEvent): string {
  const payload = event.payload ?? {};
  if (typeof payload.action === "number" && payload.action > 0) {
    return `action-${payload.action}`;
  }
  const candidate = payload.correlation_id ?? payload.call_id ?? payload.tool_call_id ?? payload.request_id;
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

export interface ToolGroupSnapshot {
  correlationId: string;
  toolName: string;
  started: boolean;
  completed: boolean;
  result?: string;
  error?: string;
  arguments?: unknown;
  timestamp?: string;
}

export type EventRowDef =
  | { key: string; searchText: string; kind: "tool"; group: ToolGroupSnapshot }
  | { key: string; searchText: string; kind: "approval"; decisionId: string }
  | { key: string; searchText: string; kind: "event"; event: RunEvent };

interface MutableGroup extends ToolGroupSnapshot {
  searchText: string;
}

interface BuildArgs {
  older: RunEvent[];
  events: RunEvent[];
  decisionsById: Map<string, DecisionListRow>;
  goalSelectAnswered: boolean;
  filter: EventRowFilter;
  query: string;
}

/**
 * Pure row planner for the virtualized event stream. Returns light data —
 * never React nodes — so a 10k-deep window costs one linear scan of plain
 * objects and only the ~15 visible rows pay for element creation + stringify.
 * The free-text index is built only when a query is active; the live
 * unfiltered path stores "" and skips every JSON.stringify.
 */
export function buildEventRows({ older, events, decisionsById, goalSelectAnswered, filter, query }: BuildArgs): EventRowDef[] {
  const q = query.trim().toLowerCase();
  const needSearch = q.length > 0;
  const merged = older.length > 0 ? [...older, ...events] : events;

  const toolGroups = new Map<string, MutableGroup>();
  for (const event of merged) {
    if (event.type !== "tool_request" && event.type !== "tool_start" && event.type !== "tool_result") continue;
    const id = corrIdOf(event);
    const existing = toolGroups.get(id);
    const name = (event.payload.name as string | undefined) ?? existing?.toolName ?? `tool-${event.sequence}`;
    if (!existing) {
      toolGroups.set(id, {
        correlationId: id,
        toolName: name,
        started: event.type === "tool_start",
        completed: false,
        arguments: event.type === "tool_request" ? event.payload.arguments : undefined,
        timestamp: event.timestamp,
        searchText: needSearch ? payloadText(event) : "",
      });
    } else {
      if (event.type === "tool_start") existing.started = true;
      if (event.type === "tool_request" && event.payload.arguments !== undefined) {
        existing.arguments = event.payload.arguments;
      }
      if (event.type === "tool_result") {
        existing.completed = true;
        existing.result = typeof event.payload.result === "string" ? event.payload.result : undefined;
        const errStr = typeof event.payload.error === "string" ? event.payload.error : undefined;
        existing.error = event.payload.success === false ? (errStr ?? "tool failed") : errStr;
      }
      if (needSearch) existing.searchText += ` ${payloadText(event)}`;
    }
  }

  const out: EventRowDef[] = [];
  const maybePush = (row: EventRowDef) => {
    if (needSearch && !row.searchText.includes(q)) return;
    out.push(row);
  };

  for (const event of merged) {
    if (event.type === "boot" || event.type === "ok") continue;
    if (event.type === "tool_request" || event.type === "tool_start" || event.type === "tool_result") {
      if (filter !== "all" && filter !== "tools") continue;
      if (event.type !== "tool_request") continue;
      const group = toolGroups.get(corrIdOf(event));
      if (!group) continue;
      let searchText = group.searchText;
      if (needSearch) {
        searchText += ` ${group.toolName} ${safeStringify(group.arguments)} ${group.result ?? ""} ${group.error ?? ""}`.toLowerCase();
      }
      const { searchText: _drop, ...snapshot } = group;
      void _drop;
      maybePush({ key: `tool-${group.correlationId}`, searchText, kind: "tool", group: snapshot });
      continue;
    }
    if (event.type === "approval") {
      if (filter !== "all" && filter !== "decisions") continue;
      const decisionId = event.payload.decision_id;
      if (typeof decisionId !== "string") continue;
      const decision = decisionsById.get(decisionId);
      if (!decision || decision.status !== "pending") continue;
      const searchText = needSearch
        ? `${decision.kind} ${decision.required_text ?? ""} ${(decision.options ?? []).map((o) => (o as { name?: string }).name).join(" ")}`.toLowerCase()
        : "";
      maybePush({ key: `approval-${decisionId}`, searchText, kind: "approval", decisionId });
      continue;
    }
    if (event.type === "goal_suggestions" && goalSelectAnswered) continue;
    if (!matchesRowFilter(event.type, filter)) continue;
    maybePush({ key: `evt-${event.sequence}`, searchText: needSearch ? payloadText(event) : "", kind: "event", event });
  }
  return out;
}
