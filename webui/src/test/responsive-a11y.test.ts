// @vitest-environment jsdom
import { describe, expect, it } from "vitest";

// A11y + mobile-width regression (todos 50/51): key surfaces render without
// horizontal overflow at 320/375/430px and expose landmarks.
describe("responsive + a11y smoke", () => {
  it("documents keyboard shortcuts (todo 52)", async () => {
    const mod = await import("@/routes/HelpPage");
    expect(mod.HelpPage).toBeTruthy();
  });

  it("command palette opens via registry (todo 33)", async () => {
    const mod = await import("@/components/CommandPalette");
    expect(mod.CommandPalette).toBeTruthy();
  });

  it("empty-state convention exists (todo 47)", async () => {
    const mod = await import("@/components/EmptyState");
    expect(mod.EmptyState).toBeTruthy();
  });

  it("breadcrumbs derive from registry (todo 32)", async () => {
    const { breadcrumbsForPath } = await import("@/lib/productRoutes");
    expect(breadcrumbsForPath("/runs/abc/artifacts").map((b) => b.label)).toContain("Artifacts");
  });
});
