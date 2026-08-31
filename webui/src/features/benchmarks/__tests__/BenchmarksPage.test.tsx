// @vitest-environment jsdom
// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BenchmarksPage } from "@/routes/BenchmarksPage";

vi.mock("@/features/benchmarks/api", () => ({
  fetchOverview: vi.fn().mockResolvedValue({
    suites: [{ suite_id: "xben", scenarios: 4, tags: { web: 2 } }],
    runs: [
      {
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
      },
      {
        run_id: "run-0",
        suite: "xben",
        status: "completed",
        timestamp: "2026-08-28T00:00:00Z",
        trials_total: 3,
        solved: 1,
        verified_success_rate: 0.3333,
        false_positive_rate: 0,
        median_solve_time: 140,
        estimated_cost: 0.4,
        total_tokens: 8000,
      },
    ],
    active: { run_id: null, state: "idle", error: "" },
    baseline: { exists: true, path: "reports/benchmarks/baseline.json", run_id: "run-0", verified_success_rate: 0.3333, false_positive_rate: 0 },
  }),
  fetchRun: vi.fn().mockResolvedValue({
    run_id: "run-1",
    suite: "xben",
    status: "completed",
    config: { suite: "xben", scenario_ids: [], tags: [], trials: 1, timeout_seconds: 1800, model_alias: "", reasoning_profile: "", sandbox_required: true, save_baseline: false, check_regression: false, output_dir: "" },
    environment: { breachpilot_version: "0.50.0", git_sha: "abc123", git_dirty: false, git_branch: "main", model_provider: "ollama", model_alias: "glm", model_id: "glm-5.2:cloud", model_version: "cloud", reasoning_config: {}, temperature: null, config_hash: "h1", benchmark_config_hash: "h2", sandbox_image: "breachpilot-sandbox:latest", sandbox_image_digest: "sha256:abc", sandbox_enabled: true, sandbox_required: true, target_images: {}, platform: "test", python_version: "3.11" },
    scenario_ids: ["s1"],
    trials: [],
    replay_manifest: { replay_command: "python main.py --benchmark xben" },
    summary: {
      run_id: "run-1",
      suite: "xben",
      timestamp: "2026-08-29T00:00:00Z",
      trials_total: 3,
      trials_completed: 3,
      verified_success_rate: 0.6667,
      solved: 2,
      false_positive_rate: 0.3333,
      false_negative_rate: 0,
      median_solve_time: 120,
      mean_solve_time: 130,
      median_tool_actions: 10,
      mean_tool_actions: 11,
      median_model_calls: 9,
      total_tokens: 9000,
      estimated_cost: 0.5,
      time_to_first_verified_success: 60,
      sandbox_blocked_actions: 0,
      infra_error_count: 0,
      timeout_count: 0,
      failure_categories: { NO_EXPLOIT_PATH: 1 },
      scenarios: [],
    },
  }),
  fetchRunEvents: vi.fn().mockResolvedValue({ run_id: "run-1", events: [], latest_sequence: 0 }),
}));

function renderPage(initialEntries = ["/benchmarks"]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={initialEntries}>
        <BenchmarksPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("BenchmarksPage (Overview)", () => {
  it("renders the sub-nav, latest run metrics, baseline and recent runs", async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /Benchmarks/ })).toBeInTheDocument();
    });
    // Sub-page navigation.
    expect(screen.getByRole("navigation", { name: "Benchmarks sections" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "New run" })).toHaveAttribute("href", "/benchmarks/new");
    expect(screen.getByRole("link", { name: "Past benchmarks" })).toHaveAttribute("href", "/benchmarks/history");
    // Verified success from the latest run summary.
    await waitFor(() => {
      expect(screen.getByTestId("benchmark-metric-cards")).toBeInTheDocument();
    });
    expect(screen.getByText("66.7%")).toBeInTheDocument();
    // Baseline card from overview.baseline.
    expect(screen.getByTestId("benchmark-baseline")).toBeInTheDocument();
    // Recent-runs preview links to the run detail + full history.
    expect(screen.getAllByRole("link", { name: "run-1" }).length).toBeGreaterThanOrEqual(1);
    for (const link of screen.getAllByRole("link", { name: "run-1" })) {
      expect(link).toHaveAttribute("href", "/benchmarks/run-1");
    }
    expect(screen.getByRole("link", { name: /View all/ })).toHaveAttribute("href", "/benchmarks/history");
  });

  it("shows a start CTA instead of broken charts when there are no runs", async () => {
    const { fetchOverview } = await import("@/features/benchmarks/api");
    (fetchOverview as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      suites: [{ suite_id: "xben", scenarios: 4 }],
      runs: [],
      active: { run_id: null, state: "idle", error: "" },
      baseline: { exists: false, path: "reports/benchmarks/baseline.json" },
    });
    renderPage();
    await waitFor(() => {
      expect(screen.getByTestId("benchmarks-empty-state")).toBeInTheDocument();
    });
    expect(screen.getByRole("link", { name: /Start a benchmark/ })).toHaveAttribute("href", "/benchmarks/new");
  });
});
