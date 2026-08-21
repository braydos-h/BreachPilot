import { describe, expect, it } from "vitest";
import { aggregateRunsByDay, aggregateTokensByDay } from "@/routes/StatsPage";
import type { RunListRow, TelemetryRecord } from "@/api/types";

function run(overrides: Partial<RunListRow> = {}): RunListRow {
  return {
    id: "run-1",
    state: "completed",
    created_at: "2026-08-20T12:00:00",
    target: "127.0.0.1",
    mode: "recon",
    goal_name: "initial_access",
    target_ip: "127.0.0.1",
    model_alias: "glm",
    ...overrides,
  };
}

describe("Stats aggregations", () => {
  it("groups valid run dates and keeps non-terminal states in other", () => {
    const result = aggregateRunsByDay(["2026-08-20", "2026-08-21"], [
      run(),
      run({ id: "run-2", state: "failed" }),
      run({ id: "run-3", state: "running" }),
      run({ id: "run-4", created_at: "not-a-date" }),
      run({ id: "run-5", created_at: "2026-08-21T12:00:00" }),
    ]);

    expect(result).toEqual([
      { date: "2026-08-20", total: 3, completed: 1, failed: 1, other: 1 },
      { date: "2026-08-21", total: 1, completed: 1, failed: 0, other: 0 },
    ]);
  });

  it("splits prompt/completion tokens, derives missing totals, and ignores invalid dates", () => {
    const result = aggregateTokensByDay(["2026-08-20"], [
      { started_at: "2026-08-20T10:00:00", prompt_tokens: 100, completion_tokens: 25, total_tokens: 125 },
      { ended_at: "2026-08-20T11:00:00", prompt_tokens: 10, completion_tokens: 5 },
      { started_at: "2026-08-20T12:00:00", prompt_tokens: 20, completion_tokens: 10, total_tokens: 50 },
      { started_at: "not-a-date", prompt_tokens: 100, completion_tokens: 100, total_tokens: 200 },
    ] as TelemetryRecord[]);

    expect(result[0]).toMatchObject({
      total: 190,
      prompt: 130,
      completion: 40,
      unattributed: 20,
      calls: 3,
    });
  });
});
