// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, cleanup } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// Node ≥22 exposes a bare global `localStorage` (no backing file, no methods)
// that shadows jsdom's working Storage inside vitest. Install an in-memory
// stand-in so the store's persistence can actually be exercised.
class MemoryStorage {
  private map = new Map<string, string>();
  getItem(k: string): string | null {
    return this.map.has(k) ? (this.map.get(k) as string) : null;
  }
  setItem(k: string, v: string): void {
    this.map.set(k, String(v));
  }
  removeItem(k: string): void {
    this.map.delete(k);
  }
  clear(): void {
    this.map.clear();
  }
  key(i: number): string | null {
    return [...this.map.keys()][i] ?? null;
  }
  get length(): number {
    return this.map.size;
  }
}

// The theme store is module-level, so tests that exercise the initial value
// re-import it fresh after seeding localStorage.
async function importTheme() {
  return await import("@/lib/useTheme");
}

type ThemeModule = Awaited<ReturnType<typeof importTheme>>;

// Both probes subscribe to the same module-level store instance, mirroring the
// Layout + graph-canvas pairing in the real app.
function makeHarness(mod: ThemeModule) {
  const Probe = ({ label }: { label: string }) => {
    const { theme, toggle } = mod.useTheme();
    return (
      <button onClick={toggle} aria-label={label}>
        {label}:{theme}
      </button>
    );
  };
  return Probe;
}

describe("useTheme shared store", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", new MemoryStorage());
    document.documentElement.className = "";
    vi.resetModules();
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("reads the initial value from localStorage and applies the class at import time", async () => {
    window.localStorage.setItem("breachpilot.theme", "light");
    const mod = await importTheme();
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    const Probe = makeHarness(mod);
    render(<Probe label="a" />);
    expect(screen.getByLabelText("a").textContent).toBe("a:light");
  });

  it("defaults to dark when storage is empty", async () => {
    const mod = await importTheme();
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    const Probe = makeHarness(mod);
    render(<Probe label="a" />);
    expect(screen.getByLabelText("a").textContent).toBe("a:dark");
  });

  it("toggle persists the preference, flips the class, and keeps two readers in sync", async () => {
    const mod = await importTheme();
    const Probe = makeHarness(mod);
    const user = userEvent.setup();
    render(
      <div>
        <Probe label="layout" />
        <Probe label="canvas" />
      </div>,
    );
    expect(screen.getByLabelText("layout").textContent).toBe("layout:dark");
    expect(screen.getByLabelText("canvas").textContent).toBe("canvas:dark");

    await act(async () => {
      await user.click(screen.getByLabelText("layout"));
    });

    // Both consumers re-render from the same store — this is the regression
    // that motivated the shared store (the graph canvas used to keep its own
    // snapshot and go stale after a sidebar toggle).
    expect(screen.getByLabelText("layout").textContent).toBe("layout:light");
    expect(screen.getByLabelText("canvas").textContent).toBe("canvas:light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(window.localStorage.getItem("breachpilot.theme")).toBe("light");

    await act(async () => {
      await user.click(screen.getByLabelText("canvas"));
    });
    expect(screen.getByLabelText("layout").textContent).toBe("layout:dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(window.localStorage.getItem("breachpilot.theme")).toBe("dark");
  });
});