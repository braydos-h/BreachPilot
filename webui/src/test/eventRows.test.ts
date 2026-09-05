import { describe, expect, it } from "vitest";
import { buildEventRows, corrIdOf, matchesRowFilter } from "@/components/events/eventRows";
import type { DecisionListRow, EventType, RunEvent } from "@/api/types";

function event(seq: number, type: EventType, payload: Record<string, unknown> = {}): RunEvent {
  return { sequence: seq, timestamp: "2026-08-21T00:00:00Z", run_id: "r1", type, payload };
}

function decisionsById(rows: DecisionListRow[]): Map<string, DecisionListRow> {
  return new Map(rows.map((d) => [d.id, d]));
}

const noDecisions = decisionsById([]);

function build(
  events: RunEvent[],
  opts: {
    older?: RunEvent[];
    decisions?: Map<string, DecisionListRow>;
    goalSelectAnswered?: boolean;
    filter?: "all" | "tools" | "assistant" | "decisions" | "errors" | "progress";
    query?: string;
  } = {},
) {
  return buildEventRows({
    older: opts.older ?? [],
    events,
    decisionsById: opts.decisions ?? noDecisions,
    goalSelectAnswered: opts.goalSelectAnswered ?? false,
    filter: opts.filter ?? "all",
    query: opts.query ?? "",
  });
}

describe("buildEventRows", () => {
  it("groups request/start/result into one tool row and emits nothing for lone start/result", () => {
    const rows = build([
      event(1, "tool_request", { name: "nmap", action: 1, arguments: { target: "10.0.0.5" } }),
      event(2, "tool_start", { name: "nmap", action: 1 }),
      event(3, "tool_result", { action: 1, result: "port 80 open", success: true }),
      event(4, "tool_start", { name: "orphan", action: 99 }),
      event(5, "tool_result", { action: 100, result: "x", success: true }),
    ]);
    const tools = rows.filter((r) => r.kind === "tool");
    expect(tools).toHaveLength(1);
    const first = tools[0];
    expect(first?.key).toBe("tool-action-1");
    if (first?.kind === "tool") {
      expect(first.group.toolName).toBe("nmap");
      expect(first.group.completed).toBe(true);
      expect(first.group.result).toBe("port 80 open");
    }
  });

  it("marks failed results with the backend error", () => {
    const rows = build([
      event(1, "tool_request", { name: "hydra", action: 2 }),
      event(2, "tool_result", { action: 2, success: false, error: "connection refused" }),
    ]);
    expect(rows).toHaveLength(1);
    const row = rows[0];
    expect(row?.kind).toBe("tool");
    if (row?.kind === "tool") expect(row.group.error).toBe("connection refused");
  });

  it("skips boot/ok and renders only pending approvals with a known decision", () => {
    const pending: DecisionListRow = { id: "d1", kind: "tool_approval", status: "pending", answer: "" };
    const answered: DecisionListRow = { id: "d2", kind: "tool_approval", status: "answered", answer: "y" };
    const rows = build(
      [
        event(1, "boot", { step: "mcp" }),
        event(2, "ok", { step: "mcp" }),
        event(3, "approval", { decision_id: "d1", kind: "tool_approval" }),
        event(4, "approval", { decision_id: "d2", kind: "tool_approval" }),
        event(5, "approval", { decision_id: "missing", kind: "tool_approval" }),
      ],
      { decisions: decisionsById([pending, answered]) },
    );
    expect(rows.map((r) => r.key)).toEqual(["approval-d1"]);
  });

  it("hides goal suggestions once goal_select is answered", () => {
    const evts = [event(1, "goal_suggestions", { suggestions: [] })];
    expect(build(evts)).toHaveLength(1);
    expect(build(evts, { goalSelectAnswered: true })).toHaveLength(0);
  });

  it("filters by category via matchesRowFilter", () => {
    expect(matchesRowFilter("assistant", "assistant")).toBe(true);
    expect(matchesRowFilter("error", "assistant")).toBe(false);
    expect(matchesRowFilter("tool_result", "tools")).toBe(true);
    const rows = build(
      [
        event(1, "assistant", { text: "hi" }),
        event(2, "error", { message: "boom" }),
        event(3, "progress", { round: 1 }),
      ],
      { filter: "errors" },
    );
    expect(rows.map((r) => r.key)).toEqual(["evt-2"]);
  });

  it("matches free text case-insensitively", () => {
    const evts = [
      event(1, "assistant", { text: "hello from agent" }),
      event(2, "error", { message: "connection refused" }),
    ];
    expect(build(evts, { query: "CONNECTION" }).map((r) => r.key)).toEqual(["evt-2"]);
    expect(build(evts, { query: "  " })).toHaveLength(2);
  });

  it("skips the search index on the live unfiltered path", () => {
    const rows = build([event(1, "assistant", { text: "hello" }), event(2, "progress", { round: 1 })]);
    expect(rows.every((r) => r.searchText === "")).toBe(true);
  });

  it("keeps corrId stable across request/start/result stages", () => {
    expect(corrIdOf(event(1, "tool_request", { name: "nmap", action: 7 }))).toBe(
      corrIdOf(event(9, "tool_result", { action: 7 })),
    );
  });

  it("handles a 10k-event window as light data rows", () => {
    const events = Array.from({ length: 10_000 }, (_, i) =>
      event(i + 1, "progress", { round: i + 1, phase: "recon" }),
    );
    const started = Date.now();
    const rows = build(events);
    expect(rows).toHaveLength(10_000);
    expect(Date.now() - started).toBeLessThan(5000);
  });
});
