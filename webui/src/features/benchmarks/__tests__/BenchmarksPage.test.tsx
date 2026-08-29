// @vitest-environment jsdom
// NetAttackAI by @braydos-h — https://github.com/braydos-h/NetAttackAi
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BenchmarksPage } from "@/routes/BenchmarksPage";

vi.mock("@/api/hooks", () => ({
  useModels: () => ({ data: { default_alias: "glm", provider: "ollama" } }),
}));

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
    ],
    active: { run_id: null, state: "idle", error: "" },
    baseline: { exists: false, path: "reports/benchmarks/baseline.json" },
  }),
  fetchRuns: vi.fn().mockResolvedValue({
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
    ],
  }),
  fetchRun: vi.fn().mockResolvedValue({
    run_id: "run-1",
    suite: "xben",
    status: "completed",
    config: { suite: "xben", scenario_ids: [], tags: [], trials: 1, timeout_seconds: 1800, model_alias: "", reasoning_profile: "", sandbox_required: true, save_baseline: false, check_regression: false, output_dir: "" },
    environment: { netattack_version: "0.50.0", git_sha: "abc123", git_dirty: false, git_branch: "main", model_provider: "ollama", model_alias: "glm", model_id: "glm-5.2:cloud", model_version: "cloud", reasoning_config: {}, temperature: null, config_hash: "h1", benchmark_config_hash: "h2", sandbox_image: "netattackai-sandbox:latest", sandbox_image_digest: "sha256:abc", sandbox_enabled: true, sandbox_required: true, target_images: {}, platform: "test", python_version: "3.11" },
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
  fetchSuiteScenarios: vi.fn().mockResolvedValue({ suite: "xben", scenarios: [] }),
  startBenchmarkRun: vi.fn(),
  cancelBenchmarkRun: vi.fn(),
  saveBaseline: vi.fn(),
  compareRuns: vi.fn(),
}));

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <BenchmarksPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("BenchmarksPage", () => {
  it("renders the dashboard with metric cards, run panel, history and comparison", async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /Benchmarks/ })).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(screen.getByTestId("benchmark-metric-cards")).toBeInTheDocument();
    });
    // Verified success from the latest run summary.
    expect(screen.getByText("66.7%")).toBeInTheDocument();
    // Run panel present with suite picker.
    expect(screen.getByTestId("run-benchmark-panel")).toBeInTheDocument();
    expect(screen.getByLabelText(/Benchmark suite/)).toBeInTheDocument();
    // History + comparison sections.
    expect(screen.getByTestId("benchmark-history")).toBeInTheDocument();
    expect(screen.getByTestId("benchmark-comparison")).toBeInTheDocument();
    // Run history row links to the run detail page (latest-run header + history row).
    expect(screen.getAllByRole("link", { name: "run-1" }).length).toBeGreaterThanOrEqual(1);
    for (const link of screen.getAllByRole("link", { name: "run-1" })) {
      expect(link).toHaveAttribute("href", "/benchmarks/run-1");
    }
  });
});
