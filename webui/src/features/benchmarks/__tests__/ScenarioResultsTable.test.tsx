// @vitest-environment jsdom
// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ScenarioResultsTable, STATUS_META } from "@/features/benchmarks/ScenarioResultsTable";
import { BenchmarkTimeline } from "@/features/benchmarks/BenchmarkTimeline";
import type { Trial } from "@/features/benchmarks/types";

function makeTrial(overrides: Partial<Trial> & { scenario_id: string; trial_index: number }): Trial {
  return {
    run_id: "r1",
    suite: "xben",
    trial_id: `${overrides.scenario_id}#t${overrides.trial_index}`,
    status: "VERIFIED",
    agent_claimed_success: true,
    oracle_verified_success: true,
    false_positive: false,
    false_negative: false,
    failure_category: "UNKNOWN",
    failure_detail: "",
    started_at: "2026-08-29T00:00:00Z",
    ended_at: "2026-08-29T00:10:00Z",
    duration_seconds: 600,
    model_calls: 20,
    tool_calls: 12,
    total_tokens: 4200,
    estimated_cost: 0.11,
    claimed_summary: "",
    flags: [],
    flags_captured: 1,
    flags_total: 1,
    evidence_refs: [],
    audit_path: "",
    workspace: "",
    errors: [],
    sandbox: {
      enabled: true,
      required: true,
      image: "breachpilot-sandbox:latest",
      image_digest: "sha256:abc",
      container_id: "c1",
      network_policy_fingerprint: "",
      authorized_destinations: [],
      blocked_events: 0,
      failures: 0,
      last_error: "",
    },
    target: {
      host: "127.0.0.1",
      ports: [8080],
      image: "target:1",
      image_digest: "unknown",
      container_id: "t1",
      snapshot_id: "",
      reset_strategy: "recreate",
    },
    telemetry: {
      model_calls: 20,
      total_tokens: 4200,
      prompt_tokens: 3000,
      completion_tokens: 1200,
      estimated_cost: 0.11,
      tool_calls: 12,
      tool_errors: 0,
      sandbox_blocked_actions: 0,
    },
    ...overrides,
  } as Trial;
}

const TRIALS: Trial[] = [
  makeTrial({ scenario_id: "xben-dvwa", trial_index: 0, status: "VERIFIED", oracle_verified_success: true }),
  makeTrial({ scenario_id: "xben-dvwa", trial_index: 1, status: "VERIFIED", oracle_verified_success: true }),
  makeTrial({
    scenario_id: "xben-juice",
    trial_index: 0,
    status: "FALSE_POSITIVE",
    agent_claimed_success: true,
    oracle_verified_success: false,
    false_positive: true,
  }),
  makeTrial({
    scenario_id: "xben-k8s",
    trial_index: 0,
    status: "INFRASTRUCTURE_ERROR",
    failure_category: "SANDBOX_FAILED",
    agent_claimed_success: false,
    oracle_verified_success: false,
  }),
  makeTrial({ scenario_id: "xben-slow", trial_index: 0, status: "TIMEOUT", agent_claimed_success: false }),
];

describe("ScenarioResultsTable", () => {
  it("renders all trials with status indicators", () => {
    render(<ScenarioResultsTable trials={TRIALS} />);
    expect(screen.getByTestId("scenario-results-table")).toBeInTheDocument();
    expect(screen.getAllByText("xben-dvwa").length).toBe(2);
    // The "False positive" label appears on its filter button AND the status badge.
    expect(screen.getAllByText("False positive").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Infra error").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Timeout").length).toBeGreaterThanOrEqual(1);
  });

  it("marks false positives prominently", () => {
    render(<ScenarioResultsTable trials={TRIALS.filter((t) => t.false_positive)} />);
    expect(screen.getAllByText("FP").length).toBeGreaterThanOrEqual(1);
  });

  it("filters by status", async () => {
    const user = userEvent.setup();
    render(<ScenarioResultsTable trials={TRIALS} />);
    await user.click(screen.getByRole("button", { name: "Infra error" }));
    const table = screen.getByTestId("scenario-results-table");
    expect(within(table).getByText("xben-k8s")).toBeInTheDocument();
    expect(within(table).queryByText("xben-dvwa")).not.toBeInTheDocument();
    expect(within(table).getByText("1 of 5 trials")).toBeInTheDocument();
  });

  it("filters by scenario text", async () => {
    const user = userEvent.setup();
    render(<ScenarioResultsTable trials={TRIALS} />);
    await user.type(screen.getByLabelText("Filter scenarios"), "juice");
    expect(screen.getByText("1 of 5 trials")).toBeInTheDocument();
  });

  it("shows the empty state", () => {
    render(<ScenarioResultsTable trials={[]} />);
    expect(screen.getByText("No trials recorded yet.")).toBeInTheDocument();
  });
});

describe("BenchmarkTimeline", () => {
  const events = [
    {
      sequence: 1,
      timestamp: "2026-08-29T00:00:00Z",
      elapsed_seconds: 0,
      run_id: "r1",
      type: "run_start",
      level: "info",
      trial_id: "",
      scenario_id: "",
      agent: "",
      tool: "",
      target: "",
      payload: { scenarios: ["xben-dvwa"] },
    },
    {
      sequence: 2,
      timestamp: "2026-08-29T00:00:03Z",
      elapsed_seconds: 3,
      run_id: "r1",
      type: "target_ready",
      level: "info",
      trial_id: "xben-dvwa#t0",
      scenario_id: "xben-dvwa",
      agent: "",
      tool: "",
      target: "127.0.0.1",
      payload: { host: "127.0.0.1", ports: [8080] },
    },
    {
      sequence: 3,
      timestamp: "2026-08-29T00:00:53Z",
      elapsed_seconds: 53,
      run_id: "r1",
      type: "oracle_result",
      level: "info",
      trial_id: "xben-dvwa#t0",
      scenario_id: "xben-dvwa",
      agent: "",
      tool: "",
      target: "127.0.0.1",
      payload: { verified: true, flags_captured: 2, flags_total: 2 },
    },
  ];

  it("renders structured events with elapsed time and no raw chain-of-thought", () => {
    render(<BenchmarkTimeline events={events} />);
    expect(screen.getByTestId("benchmark-timeline")).toBeInTheDocument();
    expect(screen.getByText(/Benchmark started/)).toBeInTheDocument();
    expect(screen.getByText(/Target ready: 127.0.0.1/)).toBeInTheDocument();
    expect(screen.getByText(/Oracle: VERIFIED/)).toBeInTheDocument();
    expect(screen.getByText("0m 03s")).toBeInTheDocument();
  });

  it("filters events by trial id", () => {
    render(<BenchmarkTimeline events={events} trialId="xben-dvwa#t0" />);
    expect(screen.queryByText(/Benchmark started/)).not.toBeInTheDocument();
    expect(screen.getByText(/Oracle: VERIFIED/)).toBeInTheDocument();
  });

  it("shows the empty state", () => {
    render(<BenchmarkTimeline events={[]} />);
    expect(screen.getByText("No events recorded.")).toBeInTheDocument();
  });
});

describe("STATUS_META", () => {
  it("covers the benchmark status vocabulary", () => {
    expect(Object.keys(STATUS_META)).toEqual(
      expect.arrayContaining(["VERIFIED", "FAILED", "FALSE_POSITIVE", "TIMEOUT", "INFRASTRUCTURE_ERROR"]),
    );
  });
});
