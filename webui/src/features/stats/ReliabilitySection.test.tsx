// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ReliabilitySection } from "@/features/stats/ReliabilitySection";
import { fetchOverview } from "@/features/benchmarks/api";

vi.mock("@/features/benchmarks/api", () => ({ fetchOverview: vi.fn() }));

describe("ReliabilitySection", () => {
  beforeEach(() => {
    vi.mocked(fetchOverview).mockResolvedValue({
      suites: [],
      runs: [],
      active: { run_id: null, state: "idle", error: "" },
      baseline: {
        exists: true,
        path: "reports/benchmarks/baseline.json",
        verified_success_rate: null,
        false_positive_rate: null,
      },
    });
  });

  it("keeps unmeasured baseline rates neutral and labels them as unmeasured", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <ReliabilitySection />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(await screen.findAllByText("unmeasured — no completed trials")).toHaveLength(2);
    expect(screen.getByText("Verified success").closest("[data-tone]")).toHaveAttribute("data-tone", "neutral");
    expect(screen.getByText("False positives").closest("[data-tone]")).toHaveAttribute("data-tone", "neutral");
    expect(screen.getAllByText("n/a").length).toBeGreaterThanOrEqual(2);
  });
});
