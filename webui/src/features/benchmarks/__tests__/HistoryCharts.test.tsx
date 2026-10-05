// @vitest-environment jsdom
// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { HistoryChart, HistoryCharts } from "@/features/benchmarks/HistoryCharts";
import type { RunIndexRow } from "@/features/benchmarks/types";

function makeRun(runId: string, timestamp: string, solveTime: number | null): RunIndexRow {
  return {
    run_id: runId,
    suite: "xben",
    status: "completed",
    timestamp,
    trials_total: 1,
    solved: 1,
    verified_success_rate: 1,
    false_positive_rate: 0,
    median_solve_time: solveTime,
    estimated_cost: null,
    total_tokens: 0,
  };
}

describe("HistoryChart", () => {
  it("shows n/a for the newest run when it has no metric, while preserving its timestamp", () => {
    const runs = [
      makeRun("missing-latest", "2025-01-01T00:00:00Z", null),
      makeRun("measured-newest", "2020-01-02T00:00:00Z", 120),
      makeRun("measured-oldest", "2020-01-01T00:00:00Z", 60),
    ];

    render(
      <HistoryChart
        runs={runs}
        label="Median solve time"
        extract={(run) => run.median_solve_time}
        format={(seconds) => `${Math.floor(seconds / 60)}m ${String(seconds % 60).padStart(2, "0")}s`}
      />,
    );

    expect(screen.getByText("2 measured runs · latest 2025-01-01")).toBeInTheDocument();
    expect(screen.getByText("n/a")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /latest n\/a/ })).toBeInTheDocument();
  });

  it("keeps a gap in the chart when an intermediate run has no measurement", () => {
    const runs = [
      makeRun("newest", "2025-01-03T00:00:00Z", 180),
      makeRun("missing", "2025-01-02T00:00:00Z", null),
      makeRun("oldest", "2025-01-01T00:00:00Z", 60),
    ];

    const { container } = render(<HistoryChart runs={runs} label="Median solve time" extract={(run) => run.median_solve_time} />);

    expect(container.querySelectorAll("polyline")).toHaveLength(0);
    expect(container.querySelectorAll('[data-testid="history-chart-point"]')).toHaveLength(2);
    expect(container.querySelectorAll('[data-testid="history-chart-point"]')[0]).toHaveAttribute("cx", "2.0");
    expect(container.querySelectorAll('[data-testid="history-chart-point"]')[1]).toHaveAttribute("cx", "318.0");
  });

  it("provides an accessible run-by-run equivalent for chart values", () => {
    const runs = [
      makeRun("newest", "2025-01-02T00:00:00Z", 120),
      makeRun("oldest", "2025-01-01T00:00:00Z", 60),
    ];

    render(
      <HistoryChart
        runs={runs}
        label="Median solve time"
        extract={(run) => run.median_solve_time}
        format={(seconds) => `${Math.floor(seconds / 60)}m ${String(seconds % 60).padStart(2, "0")}s`}
      />,
    );

    expect(screen.getByRole("list", { name: "Median solve time values by run" })).toHaveTextContent("oldest: 1m 00s");
    expect(screen.getByRole("list", { name: "Median solve time values by run" })).toHaveTextContent("newest: 2m 00s");
  });

  it("does not plot legacy success rates without a completed-trial denominator", () => {
    const legacy = makeRun("legacy", "2025-01-01T00:00:00Z", null);
    legacy.verified_success_rate = 0;
    legacy.false_positive_rate = 0;
    const measured = makeRun("measured", "2025-01-02T00:00:00Z", null);
    measured.trials_completed = 1;
    measured.verified_success_rate = 1;
    measured.false_positive_rate = 0;

    render(<HistoryCharts runs={[legacy, measured]} />);

    expect(screen.getByTestId("history-Verified success rate")).toHaveTextContent("Not enough data points yet");
    expect(screen.getByTestId("history-False-positive rate")).toHaveTextContent("Not enough data points yet");
    expect(screen.queryByText("0% – 100%")).not.toBeInTheDocument();
  });
});
