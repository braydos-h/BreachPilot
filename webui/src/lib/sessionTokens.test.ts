// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

vi.mock("@/api/hooks", () => ({
  useTelemetry: vi.fn(),
}));

import { useTelemetry } from "@/api/hooks";
import {
  SESSION_BASELINE_KEY,
  clearStoredBaseline,
  getStoredBaseline,
  setStoredBaseline,
  useSessionTokens,
} from "@/lib/sessionTokens";
import { formatTokens } from "@/lib/format";

const telemetryMock = vi.mocked(useTelemetry);

function mockTelemetry(total: number | null, isLoading = false) {
  if (total == null) {
    telemetryMock.mockReturnValue({
      data: undefined,
      isLoading,
      error: null,
    } as never);
  } else {
    telemetryMock.mockReturnValue({
      data: { summary: { total_tokens: total, prompt_tokens: 0, completion_tokens: 0, calls: 1 } as never, recent: [] },
      isLoading,
      error: null,
    } as never);
  }
}

beforeEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
});

describe("session baseline storage helpers", () => {
  it("round-trips baseline via sessionStorage", () => {
    expect(getStoredBaseline()).toBeNull();
    setStoredBaseline(100000);
    expect(getStoredBaseline()).toBe(100000);
    expect(sessionStorage.getItem(SESSION_BASELINE_KEY)).toBe("100000");
    clearStoredBaseline();
    expect(getStoredBaseline()).toBeNull();
    expect(sessionStorage.getItem(SESSION_BASELINE_KEY)).toBeNull();
  });

  it("ignores invalid stored values", () => {
    sessionStorage.setItem(SESSION_BASELINE_KEY, "not-a-number");
    expect(getStoredBaseline()).toBeNull();
    sessionStorage.setItem(SESSION_BASELINE_KEY, "-5");
    expect(getStoredBaseline()).toBeNull();
  });

  it("uses sessionStorage, not localStorage", () => {
    setStoredBaseline(12345);
    expect(sessionStorage.getItem(SESSION_BASELINE_KEY)).toBe("12345");
    // In jsdom localStorage should be empty for this key; in Node 22 bare global may be broken, so guard
    if (typeof localStorage !== "undefined" && typeof localStorage.getItem === "function") {
      expect(localStorage.getItem(SESSION_BASELINE_KEY)).toBeNull();
    }
  });
});

describe("formatTokens", () => {
  it("formats tokens as specified", () => {
    expect(formatTokens(842)).toBe("842");
    expect(formatTokens(8421)).toBe("8.4K");
    expect(formatTokens(126400)).toBe("126.4K");
    expect(formatTokens(103250 - 100000)).toBe("3.3K");
    expect(formatTokens(4302)).toBe("4.3K");
    expect(formatTokens(12400)).toBe("12.4K");
  });
});

describe("useSessionTokens hook", () => {
  it("initial telemetry: session count starts at zero after baseline", async () => {
    mockTelemetry(100000);
    const { result } = renderHook(() => useSessionTokens());
    // Initially baseline is null, sessionTokens 0 before effect runs
    expect(result.current.sessionTokens).toBe(0);
    // After effect, baseline persisted
    await waitFor(() => expect(getStoredBaseline()).toBe(100000));
    expect(result.current.sessionTokens).toBe(0);
    expect(result.current.baseline).toBe(100000);
  });

  it("telemetry increases: 100,000 baseline later 103,250 shows 3,250", async () => {
    mockTelemetry(100000);
    const { result, rerender } = renderHook(() => useSessionTokens());
    await waitFor(() => expect(getStoredBaseline()).toBe(100000));
    expect(result.current.sessionTokens).toBe(0);

    mockTelemetry(103250);
    rerender();
    // Baseline unchanged, sessionTokens = 3250
    expect(result.current.sessionTokens).toBe(3250);
    expect(result.current.baseline).toBe(100000);
    // Formatted check
    expect(formatTokens(result.current.sessionTokens)).toBe("3.3K");
  });

  it("browser refresh: stored sessionStorage baseline is reused", async () => {
    // Simulate prior session baseline already stored
    setStoredBaseline(100000);
    mockTelemetry(101500);
    const { result } = renderHook(() => useSessionTokens());
    // Baseline already present -> no new capture, just compute diff
    expect(result.current.baseline).toBe(100000);
    expect(result.current.sessionTokens).toBe(1500);
    expect(formatTokens(result.current.sessionTokens)).toBe("1.5K");
  });

  it("telemetry reset: no negative token number is shown, re-baselines", async () => {
    setStoredBaseline(100000);
    mockTelemetry(50000); // backend cleared, total dropped
    const { result } = renderHook(() => useSessionTokens());
    // Hook should detect total < baseline and re-baseline
    await waitFor(() => expect(getStoredBaseline()).toBe(50000));
    expect(result.current.sessionTokens).toBe(0);
    expect(result.current.baseline).toBe(50000);
    // Should be max(0, ...) not negative
    expect(result.current.sessionTokens).toBeGreaterThanOrEqual(0);
  });

  it("shows 0 while telemetry is loading", () => {
    mockTelemetry(null, true);
    const { result } = renderHook(() => useSessionTokens());
    expect(result.current.sessionTokens).toBe(0);
    expect(result.current.isLoading).toBe(true);
  });

  it("clearing baseline via sessionStorage clear is reflected (sign-out)", async () => {
    setStoredBaseline(90000);
    mockTelemetry(95000);
    const { result } = renderHook(() => useSessionTokens());
    expect(result.current.sessionTokens).toBe(5000);
    clearStoredBaseline();
    // Hook's internal baseline state still old until it reacts to storage event or re-render with new total?
    // After explicit clear, next telemetry load should re-baseline. Simulate new hook instance (as page reload)
    const { result: result2 } = renderHook(() => useSessionTokens());
    // With no baseline stored, first load will capture current total as baseline
    // But our second hook still sees total 95000 with no baseline -> will capture 95000
    await waitFor(() => expect(getStoredBaseline()).toBe(95000));
    expect(result2.current.sessionTokens).toBe(0);
  });
});
