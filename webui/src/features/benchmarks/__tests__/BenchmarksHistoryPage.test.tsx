// @vitest-environment jsdom
// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BenchmarksHistoryPage } from "@/routes/BenchmarksHistoryPage";

const fetchOverview = vi.fn();
const fetchRuns = vi.fn();
vi.mock("@/features/benchmarks/api", () => ({
  fetchOverview: (...args: unknown[]) => fetchOverview(...args),
  fetchRuns: (...args: unknown[]) => fetchRuns(...args),
}));

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/benchmarks/history"]}>
        <BenchmarksHistoryPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const RUN = {
  run_id: "run-1",
  suite: "xben",
  status: "completed",
  timestamp: "2026-08-29T00:00:00Z",
  trials_total: 3,
  solved: 2,
  verified_success_rate: 0.6667,
  false_positive_rate: 0.3333,
  median_solve_time: 120,
  estimated_cost: 0.5,
  total_tokens: 9000,
};

describe("BenchmarksHistoryPage", () => {
  it("renders charts, the full run table and the comparison picker", async () => {
    fetchOverview.mockResolvedValue({
      suites: [],
      runs: [RUN],
      active: { run_id: null, state: "idle", error: "" },
      baseline: { exists: false, path: "reports/benchmarks/baseline.json" },
    });
    fetchRuns.mockResolvedValue({ runs: [RUN] });
    renderPage();
    await waitFor(() => {
      expect(screen.getByTestId("benchmark-history")).toBeInTheDocument();
    });
    expect(screen.getByTestId("benchmark-comparison")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "run-1" })).toHaveAttribute("href", "/benchmarks/run-1");
    expect(screen.getByText("2/3 (66.7%)")).toBeInTheDocument();
    expect(screen.getByText("2m 00s")).toBeInTheDocument(); // median solve time
  });

  it("shows the empty state when no runs are recorded", async () => {
    fetchOverview.mockResolvedValue({
      suites: [],
      runs: [],
      active: { run_id: null, state: "idle", error: "" },
      baseline: { exists: false, path: "reports/benchmarks/baseline.json" },
    });
    fetchRuns.mockResolvedValue({ runs: [] });
    renderPage();
    await waitFor(() => {
      expect(screen.getByText(/No runs recorded yet/)).toBeInTheDocument();
    });
  });
});
