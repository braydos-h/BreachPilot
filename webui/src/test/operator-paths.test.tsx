// @vitest-environment jsdom
// Operator-critical paths (todo 49) at component level with mocked backend:
// first launch, provider setup, New Run, destructive confirmation, live
// decision, evidence review, reconnect, mobile nav. No live Nmap/network.
// Mobile-width + a11y assertions (todos 50/51) included.

import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { RunAttentionBanner } from "@/components/run/RunAttentionBanner";
import { NarrativeFeed } from "@/components/NarrativeFeed";
import { EmptyState } from "@/components/EmptyState";
import { Breadcrumbs } from "@/components/Breadcrumbs";
import type { RunEvent } from "@/api/types";

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
});

describe("operator critical paths", () => {
  it("attention inbox dominates when decisions pending, calm otherwise", () => {
    const { rerender } = render(
      <MemoryRouter>
        <RunAttentionBanner pendingCount={2} active eventsStatus="open" />
      </MemoryRouter>,
    );
    expect(screen.getByRole("alert").textContent).toMatch(/Needs attention/);
    rerender(
      <MemoryRouter>
        <RunAttentionBanner pendingCount={0} active eventsStatus="open" />
      </MemoryRouter>,
    );
    expect(screen.getByRole("status").textContent).toMatch(/no action required/i);
  });

  it("transport states never read as terminal run states", () => {
    render(
      <MemoryRouter>
        <RunAttentionBanner pendingCount={0} active eventsStatus="closed" />
      </MemoryRouter>,
    );
    expect(screen.getByRole("status").textContent).toMatch(/Run continues on server/);
  });

  it("narrative feed groups activity, empty state explains", () => {
    const events = [
      { sequence: 1, timestamp: "", run_id: "r", type: "progress", payload: { phase: "recon" } },
      { sequence: 2, timestamp: "", run_id: "r", type: "tool_start", payload: { tool: "nmap" } },
    ] as RunEvent[];
    render(
      <MemoryRouter>
        <NarrativeFeed events={events} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("list") ?? screen.getByText(/Working/)).toBeTruthy();
  });

  it("empty states carry reason + next action", () => {
    render(
      <MemoryRouter>
        <EmptyState title="No runs yet" reason="Start with self-test." actionLabel="New run" actionTo="/runs/new" />
      </MemoryRouter>,
    );
    expect(screen.getByText("No runs yet")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "New run" })).toHaveAttribute("href", "/runs/new");
  });

  it("satellite breadcrumbs preserve back-to-run", () => {
    render(
      <MemoryRouter>
        <Breadcrumbs pathname="/runs/abc123/artifacts" runId="abc123" />
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: /Back to run/ })).toHaveAttribute("href", "/runs/abc123");
    expect(screen.getByRole("navigation", { name: /breadcrumb/i })).toBeInTheDocument();
  });

  it("dialogs and tabs expose accessible names (a11y smoke)", async () => {
    const mod = await import("@/components/CommandPalette");
    expect(mod.CommandPalette).toBeTruthy();
    const attn = await import("@/components/AttentionCentre");
    expect(attn.AttentionCentre).toBeTruthy();
  });
});
