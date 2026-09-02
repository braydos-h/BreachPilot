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

async function importTheme() {
  return await import("@/lib/useTheme");
}

type ThemeModule = Awaited<ReturnType<typeof importTheme>>;

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

  it("always returns dark and applies dark class", async () => {
    const mod = await importTheme();
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    const Probe = makeHarness(mod);
    render(<Probe label="a" />);
    expect(screen.getByLabelText("a").textContent).toBe("a:dark");
  });

  it("ignores stored light preference and stays dark", async () => {
    window.localStorage.setItem("breachpilot.theme", "light");
    const mod = await importTheme();
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    const Probe = makeHarness(mod);
    render(<Probe label="a" />);
    expect(screen.getByLabelText("a").textContent).toBe("a:dark");
  });

  it("toggle is a no-op and keeps both readers in sync on dark", async () => {
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

    expect(screen.getByLabelText("layout").textContent).toBe("layout:dark");
    expect(screen.getByLabelText("canvas").textContent).toBe("canvas:dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);

    await act(async () => {
      await user.click(screen.getByLabelText("canvas"));
    });
    expect(screen.getByLabelText("layout").textContent).toBe("layout:dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });
});
