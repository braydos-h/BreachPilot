// @vitest-environment jsdom
import { describe, it, vi, beforeEach } from "vitest";
import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { CampaignTab } from "@/routes/run/tabs/CampaignTab";

vi.mock("@/api/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/hooks")>()),
  useCallTool: vi.fn(),
}));
import { useCallTool } from "@/api/hooks";

describe("debug aggression badge", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  it("dumps html", () => {
    vi.mocked(useCallTool).mockReturnValue({ mutate: vi.fn(), isPending: false, reset: vi.fn() } as never);
    const state = {
      saved_at: "2026-01-01T00:00:00Z",
      states: {
        a: { current_phase: "recon", aggression: "bogus", privilege_level: "none", access_achieved: false, successful_exploits: [], failed_attempts: {}, credentials_found: [], loot: [], pivot_targets: [] },
      },
      tasks: {},
      task_counter: 0,
    };
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const { container } = render(
      <QueryClientProvider client={qc}>
        <CampaignTab loading={false} error={null} state={state} runId="run-1" target="10.0.0.50" runActive={true} tools={["start_autonomous_campaign", "run_campaign_step", "stop_campaign"]} />
      </QueryClientProvider>,
    );
    console.log("HTML_START" + container.innerHTML + "HTML_END");
  });
});