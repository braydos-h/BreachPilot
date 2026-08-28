// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { CampaignTab } from "@/routes/run/tabs/CampaignTab";
import { ApiError } from "@/api/client";
import type { ToolCallResponse } from "@/api/types";

// ── module mocks ────────────────────────────────────────────────────────────

vi.mock("@/api/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/hooks")>()),
  useCallTool: vi.fn(),
}));

import { useCallTool } from "@/api/hooks";

const callToolMock = vi.mocked(useCallTool);

// ── fixtures ────────────────────────────────────────────────────────────────

function makeMutation(opts: {
  isPending?: boolean;
  result?: ToolCallResponse;
} = {}) {
  const mutate = vi.fn(
    // Fire the success path synchronously so CAMPAIGN_STARTED handling and
    // query invalidation can be asserted without fake timers.
    (_vars: unknown, handlers?: { onSuccess?: (data: ToolCallResponse) => void }) => {
      handlers?.onSuccess?.(
        opts.result ?? { tool: "start_autonomous_campaign", result: "CAMPAIGN_STARTED: campaign-20260101_000000-ab12cd34" },
      );
    },
  );
  return { mutate, isPending: opts.isPending ?? false, reset: vi.fn() };
}

function campaignState(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    saved_at: "2026-01-01T00:00:00Z",
    states: {
      "10.0.0.50": {
        current_phase: "exploit",
        aggression: "normal",
        privilege_level: "none",
        access_achieved: false,
        successful_exploits: ["ms17_010"],
        failed_attempts: {},
        credentials_found: [],
        loot: [],
        pivot_targets: [],
        timeline: [
          { timestamp: "2026-01-01T00:03:00Z", event_type: "exploit_success", description: "EternalBlue landed", metadata: { module: "ms17_010" } },
          { timestamp: "2026-01-01T00:01:00Z", event_type: "recon_started", description: "Port sweep" },
          { timestamp: "2026-01-01T00:02:00Z", event_type: "exploit_fail", description: "Payload rejected" },
        ],
        ...overrides,
      },
    },
    tasks: {},
    task_counter: 0,
  };
}

// ── harness ─────────────────────────────────────────────────────────────────

type MutationHandlers = {
  onSuccess?: (data: ToolCallResponse) => void;
  onError?: (err: unknown) => void;
  onSettled?: () => void;
};

function setup(
  props: Partial<Parameters<typeof CampaignTab>[0]> = {},
  mutation: { mutate: (vars: unknown, handlers?: MutationHandlers) => void; isPending: boolean; reset?: () => void } = makeMutation(),
) {
  callToolMock.mockReturnValue(mutation as never);
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const merged: Parameters<typeof CampaignTab>[0] = {
    loading: false,
    error: null,
    state: campaignState(),
    runId: "run-1",
    target: "10.0.0.50",
    runActive: true,
    tools: ["start_autonomous_campaign", "run_campaign_step", "stop_campaign"],
    ...props,
  };
  render(
    <QueryClientProvider client={qc}>
      <CampaignTab {...merged} />
    </QueryClientProvider>,
  );
  return mutation;
}

beforeEach(() => {
  vi.clearAllMocks();
});

// ── read-only surfaces (E2) ─────────────────────────────────────────────────

describe("CampaignView read-only surfaces", () => {
  it("renders an aggression badge for every tier plus a junk fallback", () => {
    const state = campaignState();
    state.states = {
      a: { current_phase: "recon", aggression: "stealth", privilege_level: "none", access_achieved: false, successful_exploits: [], failed_attempts: {}, credentials_found: [], loot: [], pivot_targets: [] },
      b: { current_phase: "recon", aggression: "normal", privilege_level: "none", access_achieved: false, successful_exploits: [], failed_attempts: {}, credentials_found: [], loot: [], pivot_targets: [] },
      c: { current_phase: "recon", aggression: "aggressive", privilege_level: "none", access_achieved: false, successful_exploits: [], failed_attempts: {}, credentials_found: [], loot: [], pivot_targets: [] },
      d: { current_phase: "recon", aggression: "maximum", privilege_level: "none", access_achieved: false, successful_exploits: [], failed_attempts: {}, credentials_found: [], loot: [], pivot_targets: [] },
      e: { current_phase: "recon", aggression: "bogus", privilege_level: "none", access_achieved: false, successful_exploits: [], failed_attempts: {}, credentials_found: [], loot: [], pivot_targets: [] },
    };
    setup({ state });
    // The control card's aggression SegmentedControl reuses the same labels,
    // so multiple matches per tier are expected — assert presence only.
    for (const level of ["stealth", "normal", "aggressive", "maximum", "bogus"]) {
      expect(screen.getAllByText(level).length).toBeGreaterThan(0);
    }
  });

  it("renders all 8 kill-chain chips and tolerates current_phase 'done'", () => {
    setup({ state: campaignState({ current_phase: "done" }) });
    for (const label of ["Recon", "Enumeration", "Exploit", "PrivEsc", "Lateral", "Persistence", "Validation", "Report"]) {
      expect(screen.getAllByText(label).length).toBe(1);
    }
    // "done" is not a known phase — it renders as the raw header badge only.
    expect(screen.getByText("done")).toBeInTheDocument();
  });

  it("sorts the timeline newest-first", () => {
    setup();
    const timeline = screen.getByText(/^Timeline \(/);
    expect(timeline).toHaveTextContent("Timeline (3)");
    // The row container is the parent of the first row div.
    const rows = screen.getByText("exploit_success").closest("div")!.parentElement!;
    const order = [...rows.querySelectorAll("span")]
      .filter((el) => /\d{2}:\d{2}:\d{2}/.test(el.textContent ?? ""))
      .map((el) => el.textContent);
    expect(order).toEqual(["00:03:00", "00:02:00", "00:01:00"]);
  });

  it("shows the metadata module badge on timeline rows", () => {
    // ms17_010 appears twice: the successful-exploits badge AND the timeline
    // row's metadata.module badge.
    setup();
    expect(screen.getAllByText("ms17_010")).toHaveLength(2);
  });
});

// ── manual controls (E3) ────────────────────────────────────────────────────

describe("Campaign manual controls", () => {
  it("hides the control card when the run is inactive", () => {
    setup({ runActive: false });
    expect(screen.queryByText("Manual campaign control")).not.toBeInTheDocument();
  });

  it("hides the control card when the exploit session lacks the campaign tools", () => {
    setup({ tools: ["quick_scan"] });
    expect(screen.queryByText("Manual campaign control")).not.toBeInTheDocument();
  });

  it("start requires a confirm dialog before mutating", async () => {
    const user = userEvent.setup();
    const mutation = makeMutation();
    setup({}, mutation);
    await user.click(screen.getByRole("button", { name: /Start campaign/ }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(mutation.mutate).not.toHaveBeenCalled();

    await user.click(dialog().getByRole("button", { name: /Start campaign/ }));
    expect(mutation.mutate).toHaveBeenCalledWith(
      expect.objectContaining({
        tool: "start_autonomous_campaign",
        arguments: { target_ip: "10.0.0.50", goal: "full_compromise", aggression_level: "normal" },
      }),
      expect.any(Object),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("CAMPAIGN_STARTED populates the campaign-id input", async () => {
    const user = userEvent.setup();
    const mutation = makeMutation({
      result: { tool: "start_autonomous_campaign", result: "CAMPAIGN_STARTED: campaign-xyz789\nTARGET: 10.0.0.50" },
    });
    setup({}, mutation);
    await user.click(screen.getByRole("button", { name: /Start campaign/ }));
    await user.click(dialog().getByRole("button", { name: /Start campaign/ }));
    expect(await screen.findByDisplayValue("campaign-xyz789")).toBeInTheDocument();
  });

  it("step/stop are disabled without a campaign id and enabled once one is set", async () => {
    const user = userEvent.setup();
    const mutation = makeMutation({
      result: { tool: "start_autonomous_campaign", result: "CAMPAIGN_STARTED: campaign-abc" },
    });
    setup({}, mutation);
    expect(screen.getByRole("button", { name: /Step/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Stop/ })).toBeDisabled();

    await user.click(screen.getByRole("button", { name: /Start campaign/ }));
    await user.click(dialog().getByRole("button", { name: /Start campaign/ }));
    await waitFor(() => expect(screen.getByDisplayValue("campaign-abc")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /Step/ })).toBeEnabled();
    expect(screen.getByRole("button", { name: /Stop/ })).toBeEnabled();
  });

  it("step sends the campaign id", async () => {
    const user = userEvent.setup();
    const mutate = vi.fn((_vars: unknown, handlers?: { onSuccess?: (d: ToolCallResponse) => void }) => {
      handlers?.onSuccess?.({ tool: "run_campaign_step", result: "step ok" });
    });
    setup({}, { mutate, isPending: false, reset: vi.fn() });
    await user.type(screen.getByLabelText("Campaign ID"), "campaign-abc");
    await user.click(screen.getByRole("button", { name: /Step/ }));
    expect(mutate).toHaveBeenCalledWith(
      expect.objectContaining({
        tool: "run_campaign_step",
        arguments: { campaign_id: "campaign-abc" },
      }),
      expect.any(Object),
    );
  });

  it("surfaces 403 policy denials with a plain message", async () => {
    const user = userEvent.setup();
    const mutate = vi.fn(
      (_vars: unknown, handlers?: { onError?: (err: unknown) => void }) => {
        handlers?.onError?.(
          new ApiError({ status: 403, message: "denied", code: "tool_denied", details: {}, requestId: "r1", raw: null }),
        );
      },
    );
    setup({}, { mutate, isPending: false, reset: vi.fn() });
    await user.type(screen.getByLabelText("Campaign ID"), "campaign-abc");
    await user.click(screen.getByRole("button", { name: /Stop/ }));
    expect(screen.getByRole("alert")).toHaveTextContent("The exploit policy denied this call.");
  });
});

/** Radix portals the dialog into document.body — scope queries to it. */
const dialog = () => within(screen.getByRole("dialog"));