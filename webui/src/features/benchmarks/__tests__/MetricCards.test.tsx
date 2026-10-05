// @vitest-environment jsdom
// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MetricCards, ReliabilityCards, formatCost, formatDuration, formatPct } from "@/features/benchmarks/MetricCards";
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
    expect(screen.getByText("100/104 completed · 104 total trials")).toBeInTheDocument();
    expect(screen.getByText("14m 22s")).toBeInTheDocument(); // median solve time
    expect(screen.getByText("$0.42")).toBeInTheDocument(); // average cost
    expect(screen.getByText("0.8%")).toBeInTheDocument(); // false positive rate
    expect(screen.getByText("contained attempts · 0 infra errors · 0 skipped")).toBeInTheDocument();
  });

  it("shows unavailable rates when no trials completed", () => {
    render(
      <MetricCards
        summary={
          makeSummary({
            solved: 0,
            trials_completed: 0,
            verified_success_rate: null,
            false_positive_rate: null,
            infra_error_count: 1,
            skipped_count: 1,
          })
        }
      />,
    );
    expect(screen.getAllByText("n/a").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText("0/0 completed · 104 total trials")).toBeInTheDocument();
    expect(screen.getByText("contained attempts · 1 infra error · 1 skipped")).toBeInTheDocument();
    expect(screen.getByText("unavailable: trial denominator not available")).toBeInTheDocument();
    const successCard = screen.getByText("Verified success").closest(".rounded-lg") as HTMLElement | null;
    expect(successCard).toBeInTheDocument();
    expect(successCard?.querySelector("svg")).toHaveClass("text-primary");
    expect(successCard?.querySelector("svg")).not.toHaveClass("text-emerald-500");
  });

  it("shows a measured zero success rate as a poor result", () => {
    render(<MetricCards summary={makeSummary({ solved: 0, verified_success_rate: 0 })} />);
    const successCard = screen.getByText("Verified success").closest(".rounded-lg") as HTMLElement | null;
    expect(within(successCard!).getByText("0.0%")).toBeInTheDocument();
    expect(successCard?.querySelector("svg")).toHaveClass("text-red-500");
    expect(successCard?.querySelector("svg")).not.toHaveClass("text-emerald-500");
  });

  it("does not render a legacy zero scope count as a measured zero", () => {
    render(<ReliabilityCards summary={makeSummary({ scope_violation_count: 0 })} />);
    const scopeCard = screen.getByText("Scope violations").closest(".rounded-lg") as HTMLElement | null;
    expect(scopeCard).toBeInTheDocument();
    expect(within(scopeCard!).getByText("n/a")).toBeInTheDocument();
    expect(scopeCard?.querySelector("svg")).not.toHaveClass("text-emerald-500");
  });

  it("shows a measured scope zero only when the telemetry availability flag is set", () => {
    render(<ReliabilityCards summary={makeSummary({ scope_violation_count: 0, scope_violation_telemetry_available: true })} />);
    const scopeCard = screen.getByText("Scope violations").closest(".rounded-lg") as HTMLElement | null;
    expect(within(scopeCard!).getByText("0")).toBeInTheDocument();
    expect(scopeCard?.querySelector("svg")).toHaveClass("text-emerald-500");
  });

  it("shows a positive legacy scope count as a danger signal", () => {
    render(<ReliabilityCards summary={makeSummary({ scope_violation_count: 2 })} />);
    const scopeCard = screen.getByText("Scope violations").closest(".rounded-lg") as HTMLElement | null;
    expect(scopeCard).toBeInTheDocument();
    expect(within(scopeCard!).getByText("2")).toBeInTheDocument();
    expect(scopeCard?.querySelector("svg")).toHaveClass("text-red-500");
  });

  it("labels blocked sandbox actions as containment, not as violations", () => {
    render(<MetricCards summary={makeSummary({ sandbox_blocked_actions: 3 })} />);
    expect(screen.getByText("3")).toBeInTheDocument();
    const sandboxCard = screen.getByText("Sandbox blocks").closest(".rounded-lg") as HTMLElement | null;
    expect(within(sandboxCard!).getByText(/contained attempts/)).toBeInTheDocument();
    expect(sandboxCard?.querySelector("svg")).toHaveClass("text-primary");
    expect(screen.queryByText("Sandbox violations")).not.toBeInTheDocument();
  });

  it("renders n/a for missing cost and duration", () => {
    render(<MetricCards summary={makeSummary({ estimated_cost: null, median_solve_time: null })} />);
    expect(screen.getAllByText("n/a").length).toBeGreaterThanOrEqual(2);
  });

  it("renders the reproduced-twice metric as unavailable when no scenario was verified", () => {
    render(
      <ReliabilityCards
        summary={makeSummary({ reproduced_twice_rate: 0, scenarios_reproduced_twice: 0, scenarios: [] })}
      />,
    );
    const note = screen.getByText("no verified scenarios to measure");
    expect(within(note.closest(".rounded-lg")!).getByText("n/a")).toBeInTheDocument();
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
