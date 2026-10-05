// @vitest-environment jsdom
// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
import { render, screen, within } from "@testing-library/react";
import { act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ComparisonView } from "@/features/benchmarks/ComparisonView";
import type { RunComparison } from "@/features/benchmarks/types";

const { compareRunsMock } = vi.hoisted(() => ({ compareRunsMock: vi.fn() }));
vi.mock("@/features/benchmarks/api", () => ({ compareRuns: compareRunsMock }));

describe("ComparisonView", () => {
  beforeEach(() => compareRunsMock.mockReset());

  it("formats reliability rates as percentages and labels mismatched coverage incomparable", async () => {
    const comparison = {
      run_a: { run_id: "baseline", suite: "xben", summary: {} },
      run_b: { run_id: "selected", suite: "xben", summary: {} },
      comparison: {
        metrics: [
          { metric: "stuck_loop_rate", baseline: 0.2, current: 0.1, delta: -0.1, direction: "improved" },
          { metric: "reproduced_twice_rate", baseline: 0.5, current: 0.75, delta: 0.25, direction: "improved" },
          { metric: "median_solve_time", baseline: 10, current: 5, delta: -5, direction: "improved" },
          { metric: "estimated_cost", baseline: 0.5, current: 0.35, delta: -0.15, direction: "improved" },
          {
            metric: "verified_success_rate",
            baseline: 0.8,
            current: 0.5,
            delta: null,
            direction: "incomparable",
          },
          {
            metric: "scope_violation_count",
            baseline: 0,
            current: 2,
            delta: 2,
            direction: "regressed",
            safety_gate: "failed",
          },
        ],
        scenarios: [{ scenario_id: "s2", baseline: 0.8, current: 0.0, delta: null, category: "not_compared" }],
        categories: { newly_solved: [], regressed: [], still_solved: [], still_failing: [], not_compared: ["s2"] },
      },
    } as unknown as RunComparison;
    compareRunsMock.mockResolvedValue(comparison);

    const user = userEvent.setup();
    render(
      <ComparisonView
        runs={[
          { run_id: "baseline", suite: "xben", timestamp: "2026-01-01T00:00:00Z", status: "completed" },
          { run_id: "selected", suite: "xben", timestamp: "2026-01-02T00:00:00Z", status: "completed" },
          { run_id: "unfinished", suite: "xben", timestamp: "2026-01-03T00:00:00Z", status: "running" },
        ]}
      />,
    );

    await user.selectOptions(screen.getByRole("combobox", { name: "Baseline run" }), "baseline");
    await user.selectOptions(screen.getByRole("combobox", { name: "Candidate run" }), "selected");
    await user.click(screen.getByRole("button", { name: "Compare" }));

    const stuckRow = await screen.findByRole("row", { name: /Stuck-loop rate/ });
    expect(within(stuckRow).getByText("20.0%")).toBeInTheDocument();
    expect(within(stuckRow).getByText("10.0%")).toBeInTheDocument();
    expect(within(stuckRow).getByText("-10.0%")).toBeInTheDocument();

    const reproductionRow = screen.getByRole("row", { name: /Reproduced twice/ });
    expect(within(reproductionRow).getByText("50.0%")).toBeInTheDocument();
    expect(within(reproductionRow).getByText("75.0%")).toBeInTheDocument();
    expect(within(reproductionRow).getByText("+25.0%")).toBeInTheDocument();

    const timeRow = screen.getByRole("row", { name: /Median solve time/ });
    expect(within(timeRow).getByText("-0m 05s")).toBeInTheDocument();
    const costRow = screen.getByRole("row", { name: /Cost/ });
    expect(within(costRow).getByText("-$0.15")).toBeInTheDocument();

    const incomparableRow = screen.getByRole("row", { name: /Verified success/ });
    expect(
      within(incomparableRow).getByText("Not comparable (suite, scenarios, or trial counts differ)"),
    ).toBeInTheDocument();

    const scopeRow = screen.getByRole("row", { name: /Scope violations/ });
    expect(within(scopeRow).getByText("Hard safety gate failed")).toBeInTheDocument();

    const scenarioRow = screen.getByRole("row", { name: /s2/ });
    expect(within(scenarioRow).getByText("0.80")).toBeInTheDocument();
    expect(within(scenarioRow).getByText("0.00")).toBeInTheDocument();
    expect(within(scenarioRow).getByText("Not compared")).toBeInTheDocument();
    expect(within(scenarioRow).queryByText("REGRESSED")).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /unfinished/ })).not.toBeInTheDocument();
  });

  it("locks selectors while a comparison is pending and announces loading", async () => {
    let resolveComparison!: (value: RunComparison) => void;
    compareRunsMock.mockReturnValue(
      new Promise<RunComparison>((resolve) => {
        resolveComparison = resolve;
      }),
    );

    const user = userEvent.setup();
    render(
      <ComparisonView
        runs={[
          { run_id: "baseline", suite: "xben", timestamp: "2026-01-01T00:00:00Z", status: "completed" },
          { run_id: "candidate", suite: "xben", timestamp: "2026-01-02T00:00:00Z", status: "completed" },
        ]}
      />,
    );
    const baseline = screen.getByRole("combobox", { name: "Baseline run" });
    const candidate = screen.getByRole("combobox", { name: "Candidate run" });
    await user.selectOptions(baseline, "baseline");
    await user.selectOptions(candidate, "candidate");
    await user.click(screen.getByRole("button", { name: "Compare" }));

    expect(baseline).toBeDisabled();
    expect(candidate).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent("Comparing selected benchmark runs");

    await act(async () => {
      resolveComparison({
        run_a: { run_id: "baseline", suite: "xben", summary: {} },
        run_b: { run_id: "candidate", suite: "xben", summary: {} },
        comparison: { metrics: [], scenarios: [], categories: {} },
      } as unknown as RunComparison);
    });
    expect(await screen.findByText("Baseline (baseline)")).toBeInTheDocument();
  });

  it("labels unmeasured scope telemetry unavailable instead of clear", async () => {
    compareRunsMock.mockResolvedValue({
      run_a: { run_id: "baseline", suite: "xben", summary: {} },
      run_b: { run_id: "candidate", suite: "xben", summary: {} },
      comparison: {
        metrics: [
          {
            metric: "scope_violation_count",
            baseline: null,
            current: null,
            delta: null,
            direction: "incomparable",
            safety_gate: "unavailable",
          },
        ],
        scenarios: [],
        categories: { newly_solved: [], regressed: [], still_solved: [], still_failing: [] },
      },
    } as unknown as RunComparison);

    const user = userEvent.setup();
    render(
      <ComparisonView
        runs={[
          { run_id: "baseline", suite: "xben", timestamp: "2026-01-01T00:00:00Z", status: "completed" },
          { run_id: "candidate", suite: "xben", timestamp: "2026-01-02T00:00:00Z", status: "completed" },
        ]}
      />,
    );
    await user.selectOptions(screen.getByRole("combobox", { name: "Baseline run" }), "baseline");
    await user.selectOptions(screen.getByRole("combobox", { name: "Candidate run" }), "candidate");
    await user.click(screen.getByRole("button", { name: "Compare" }));

    expect(await screen.findByText("Safety telemetry unavailable")).toBeInTheDocument();
    expect(screen.queryByText("Safety gate clear")).not.toBeInTheDocument();
  });
});
