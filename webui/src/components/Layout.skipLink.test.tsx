// @vitest-environment jsdom
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";

vi.mock("@/api/hooks", () => ({
  useConnections: () => ({ data: { active: 0 } }),
  useHostPlatform: () => ({ data: { platform: "linux" } }),
  useRuns: () => ({ data: { runs: [] } }),
}));

vi.mock("@/components/ProviderSetup", () => ({
  useProviderStatus: () => ({
    status: "offline",
    label: "Ollama",
    statusText: "Offline",
  }),
}));

vi.mock("@/components/permission/PermissionControl", () => ({
  PermissionControl: () => null,
}));

vi.mock("@/components/WindowsPerformanceWarning", () => ({
  WindowsPerformanceWarning: () => null,
}));

vi.mock("@/components/CommandPalette", () => ({
  CommandPalette: () => null,
}));

vi.mock("@/components/AttentionCentre", () => ({
  AttentionCentre: () => null,
}));

vi.mock("@/lib/permissionMode", () => ({
  autoAnswerFor: () => null,
  usePermissionMode: () => ({ mode: "read_only", setMode: vi.fn() }),
}));

vi.mock("@/lib/sessionTokens", () => ({
  clearStoredBaseline: vi.fn(),
  useSessionTokens: () => ({ sessionTokens: 0 }),
}));

describe("Layout accessibility", () => {
  it("puts a keyboard skip link before navigation and gives it a focusable main target", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<h1>Home</h1>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );

    const skipLink = screen.getByRole("link", { name: "Skip to main content" });
    const main = screen.getByRole("main");
    expect(skipLink).toHaveAttribute("href", "#main-content");
    expect(main).toHaveAttribute("id", "main-content");
    expect(main).toHaveAttribute("tabindex", "-1");

    await user.tab();
    expect(skipLink).toHaveFocus();
  });
});
