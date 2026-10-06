// @vitest-environment jsdom
// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ComparisonView } from "@/features/benchmarks/ComparisonView";
import { compareRuns } from "@/features/benchmarks/api";
import type { RunComparison, RunSummary } from "@/features/benchmarks/types";

vi.mock("@/features/benchmarks/api", () => ({ compareRuns: vi.fn() }));

const comparison = {
  run_a: { run_id: "base", suite: "xben", summary: {} as RunSummary },
  run_b: { run_id: "candidate", suite: "xben", summary: {} as RunSummary },
  comparison: {
    metrics: [
      { metric: "verified_success_rate", baseline: 0.75, current: null, delta: null, direction: "unknown" },
      { metric: "false_positive_rate", baseline: 0.1, current: null, delta: null, direction: "unknown" },
    ],
    scenarios: [{ scenario_id: "s1", baseline: 1, current: null, delta: null, category: "unknown" }],
    categories: { unknown: ["s1"] },
  },
} satisfies RunComparison;

describe("ComparisonView", () => {
  beforeEach(() => {
    vi.mocked(compareRuns).mockResolvedValue(comparison);
  });

  it("renders null metrics and scenarios as unmeasured instead of unchanged or failed", async () => {
    render(
      <ComparisonView
        runs={[
          { run_id: "base", suite: "xben", timestamp: "2026-09-01T00:00:00Z", status: "completed" },
          { run_id: "candidate", suite: "xben", timestamp: "2026-09-02T00:00:00Z", status: "completed" },
        ]}
      />,
    );

    fireEvent.change(screen.getByLabelText("Baseline run"), { target: { value: "base" } });
    fireEvent.change(screen.getByLabelText("Candidate run"), { target: { value: "candidate" } });
    fireEvent.click(screen.getByRole("button", { name: "Compare" }));

    expect((await screen.findAllByText("Unmeasured")).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("unmeasured")).toHaveLength(2);
    expect(screen.getAllByText("n/a").length).toBeGreaterThanOrEqual(3);
    expect(screen.queryByText("Failed")).not.toBeInTheDocument();
    expect(compareRuns).toHaveBeenCalledWith("base", "candidate");
  });
});
