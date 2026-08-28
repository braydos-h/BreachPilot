// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Layout } from "@/components/Layout";

// ── module mocks ────────────────────────────────────────────────────────────

vi.mock("@/api/hooks", () => ({
  useRuns: vi.fn(),
  useConnections: vi.fn(),
  useModels: vi.fn(),
}));

import { useConnections, useModels, useRuns } from "@/api/hooks";

const runsMock = vi.mocked(useRuns);
const connectionsMock = vi.mocked(useConnections);
const modelsMock = vi.mocked(useModels);

function setup({ activeRuns = [] as Array<{ id: string; state: string; target: string | null }> } = {}) {
  runsMock.mockReturnValue({
    data: { runs: activeRuns, total: activeRuns.length },
    isLoading: false,
    error: null,
  } as never);
  connectionsMock.mockReturnValue({
    data: { active: 2, connections: [], total: 0, stale: 0, removed: 0, error: 0 },
    isLoading: false,
    error: null,
  } as never);
  modelsMock.mockReturnValue({
    data: { provider: "ollama", default_alias: "glm" },
    isLoading: false,
    error: null,
  } as never);

  render(
    <MemoryRouter initialEntries={["/"]}>
      <Layout>
        <div data-testid="page">page body</div>
      </Layout>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  // Vite injects __APP_VERSION__ at build time; provide it for the test env.
  vi.stubGlobal("__APP_VERSION__", "0.0.0-test");
});

describe("Layout mobile navigation", () => {
  it("renders the hamburger in the mobile header (desktop aside still present)", () => {
    setup();
    expect(screen.getByRole("button", { name: "Open navigation" })).toBeInTheDocument();
    // Desktop nav is in the DOM (hidden by CSS, not by JS).
    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
  });

  it("opens a drawer containing every nav item and the footer controls", async () => {
    const user = userEvent.setup();
    setup();
    await user.click(screen.getByRole("button", { name: "Open navigation" }));

    const drawer = screen.getByRole("dialog");
    for (const label of [
      "Home",
      "Sessions",
      "Connections",
      "Modules",
      "Goals",
      "Attack Graph",
      "Stats",
      "Skills",
      "Memory",
      "Settings",
      "Help",
    ]) {
      expect(within(drawer).getByRole("link", { name: new RegExp(`^${label}`) })).toBeInTheDocument();
    }
    // Footer controls live in the drawer too.
    expect(within(drawer).getByRole("button", { name: "Clear token" })).toBeInTheDocument();
    expect(within(drawer).getByRole("button", { name: "Toggle theme" })).toBeInTheDocument();
  });

  it("clicking a nav link closes the drawer", async () => {
    const user = userEvent.setup();
    setup();
    await user.click(screen.getByRole("button", { name: "Open navigation" }));
    const drawer = screen.getByRole("dialog");
    await user.click(within(drawer).getByRole("link", { name: /^Sessions/ }));
    // Route change closes the drawer; Radix unmounts after the exit transition.
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("shows active-run rows in the drawer nav", async () => {
    const user = userEvent.setup();
    setup({
      activeRuns: [{ id: "run-abc123", state: "running", target: "10.0.0.50" }],
    });
    await user.click(screen.getByRole("button", { name: "Open navigation" }));
    const drawer = screen.getByRole("dialog");
    const runLink = within(drawer).getByRole("link", { name: /10\.0\.0\.50/ });
    expect(runLink).toHaveAttribute("href", "/runs/run-abc123");
  });
});