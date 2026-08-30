// @vitest-environment jsdom
// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MetricCards, formatCost, formatDuration, formatPct } from "@/features/benchmarks/MetricCards";
import type { RunSummary } from "@/features/benchmarks/types";

function makeSummary(overrides: Partial<RunSummary> = {}): RunSummary {
  return {
    run_id: "r1",
    suite: "xben",
    timestamp: "2026-08-29T00:00:00Z",
    trials_total: 104,
    trials_completed: 104,
    verified_success_rate: 0.962,
    solved: 100,
    false_positive_rate: 0.008,
    false_negative_rate: 0,
    median_solve_time: 862,
    mean_solve_time: 900,
    median_tool_actions: 31,
    mean_tool_actions: 33,
    median_model_calls: 30,
    total_tokens: 500000,
    estimated_cost: 0.42,
    time_to_first_verified_success: 100,
    sandbox_blocked_actions: 0,
    infra_error_count: 0,
    timeout_count: 2,
    failure_categories: {},
    scenarios: [],
    ...overrides,
  };
}

describe("MetricCards", () => {
  it("renders the six dashboard cards with formatted values", () => {
    render(<MetricCards summary={makeSummary()} />);
    expect(screen.getByTestId("benchmark-metric-cards")).toBeInTheDocument();
    expect(screen.getByText("96.2%")).toBeInTheDocument(); // verified success
    expect(screen.getByText("100/104 trials verified")).toBeInTheDocument();
    expect(screen.getByText("14m 22s")).toBeInTheDocument(); // median solve time
    expect(screen.getByText("$0.42")).toBeInTheDocument(); // average cost
    expect(screen.getByText("0.8%")).toBeInTheDocument(); // false positive rate
    expect(screen.getByText("0 infra errors")).toBeInTheDocument();
  });

  it("flags sandbox violations with a non-zero count", () => {
    render(<MetricCards summary={makeSummary({ sandbox_blocked_actions: 3 })} />);
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("renders n/a for missing cost and duration", () => {
    render(<MetricCards summary={makeSummary({ estimated_cost: null, median_solve_time: null })} />);
    expect(screen.getAllByText("n/a").length).toBeGreaterThanOrEqual(2);
  });
});

describe("formatters", () => {
  it("formats durations", () => {
    expect(formatDuration(862)).toBe("14m 22s");
    expect(formatDuration(0)).toBe("0m 00s");
    expect(formatDuration(null)).toBe("n/a");
  });
  it("formats percentages", () => {
    expect(formatPct(0.962)).toBe("96.2%");
    expect(formatPct(null)).toBe("n/a");
  });
  it("formats costs", () => {
    expect(formatCost(0.42)).toBe("$0.42");
    expect(formatCost(undefined)).toBe("n/a");
  });
});
