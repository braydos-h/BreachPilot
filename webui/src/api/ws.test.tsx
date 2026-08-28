// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, act } from "@testing-library/react";
import React from "react";

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client");
  return { ...actual, apiFetch: vi.fn() };
});

import { apiFetch, clearStoredToken, getStoredToken, setStoredToken, AUTH_EXPIRED_EVENT } from "@/api/client";
import { useRunEvents } from "@/api/ws";

const apiFetchMock = vi.mocked(apiFetch);

/** Minimal WebSocket double: records sends, defers onclose to a macrotask
 *  like a real socket, and exposes server-side simulation helpers. */
class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  static reset(): void {
    this.instances = [];
  }
  static last(): FakeWebSocket {
    return this.instances[this.instances.length - 1];
  }
  url: string;
  readyState = 0;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: { code: number }) => void) | null = null;
  onerror: (() => void) | null = null;
  sent: string[] = [];
  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }
  send(data: string): void {
    this.sent.push(data);
  }
  close(code?: number): void {
    // Real sockets defer onclose to a macrotask; a synchronous dispatch would
    // hide stale-socket ordering bugs the guards are supposed to catch.
    setTimeout(() => {
      this.readyState = 3;
      this.onclose?.({ code: code ?? 1000 });
    }, 0);
  }
  serverOpen(): void {
    this.readyState = 1;
    this.onopen?.();
  }
  serverEvent(event: unknown): void {
    this.onmessage?.({ data: JSON.stringify(event) });
  }
}

function makeWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

async function mount(runId: string) {
  // Seed fetch fails on purpose: seedEvents swallows it and connects anyway.
  apiFetchMock.mockRejectedValue(new Error("no seed in tests"));
  const utils = renderHook(() => useRunEvents(runId), { wrapper: makeWrapper() });
  // Flush the async seed → connectWs chain.
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
  return utils;
}

/** Advance fake time inside act(), flushing the WS close/backoff chain. */
async function advance(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  FakeWebSocket.reset();
  vi.stubGlobal("WebSocket", FakeWebSocket);
  sessionStorage.clear();
  clearStoredToken();
  setStoredToken("tok-123");
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("useRunEvents silence watchdog", () => {
  it("opens with the stored token in the auth frame", async () => {
    const { result } = await mount("run-auth");
    expect(FakeWebSocket.instances).toHaveLength(1);
    const ws = FakeWebSocket.last();
    act(() => ws.serverOpen());
    expect(result.current.status).toBe("open");
    expect(result.current.transport).toBe("websocket");
    const authFrame = JSON.parse(ws.sent[0]) as { auth: string; after: number };
    expect(authFrame.auth).toBe("tok-123");
  });

  it("heartbeats keep the stream fresh — never stale, never reconnecting", async () => {
    const { result } = await mount("run-heartbeat");
    const ws = FakeWebSocket.last();
    act(() => ws.serverOpen());
    // Four minutes of heartbeats at the server's 30s cadence.
    for (let i = 0; i < 8; i += 1) {
      await advance(30_000);
      act(() => ws.serverEvent({ type: "heartbeat", sequence: i + 1 }));
      expect(result.current.stale).toBe(false);
    }
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(result.current.status).toBe("open");
  });

  it("marks the stream stale after 45s of silence", async () => {
    const { result } = await mount("run-stale");
    const ws = FakeWebSocket.last();
    act(() => ws.serverOpen());
    await advance(50_000);
    expect(result.current.stale).toBe(true);
    // The socket is still open — stale is a warning, not a reconnect.
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(result.current.status).toBe("open");
  });

  it("a fresh frame clears the stale flag", async () => {
    const { result } = await mount("run-unstale");
    const ws = FakeWebSocket.last();
    act(() => ws.serverOpen());
    await advance(50_000);
    expect(result.current.stale).toBe(true);
    act(() =>
      ws.serverEvent({
        type: "state",
        sequence: 1,
        run_id: "run-unstale",
        payload: { state: "running" },
      }),
    );
    expect(result.current.stale).toBe(false);
  });

  it("force-reconnects a silently dead socket after 90s and resets the backoff ladder", async () => {
    const { result } = await mount("run-dead");
    const ws = FakeWebSocket.last();
    act(() => ws.serverOpen());
    // 101s of total silence: the 100s watchdog tick (90s silence threshold,
    // checked every 10s) closes the socket; the deferred onclose schedules a
    // 2s reconnect (attempt ladder was reset by the watchdog).
    await advance(105_000);
    expect(FakeWebSocket.instances).toHaveLength(2);
    const second = FakeWebSocket.last();
    expect(second).not.toBe(ws);
    expect(result.current.transport).toBe("websocket");
  });

  it("does not reconnect while frames keep arriving past the stale window", async () => {
    await mount("run-alive");
    const ws = FakeWebSocket.last();
    act(() => ws.serverOpen());
    // Keep sending frames every 30s for six minutes.
    for (let i = 0; i < 12; i += 1) {
      await advance(30_000);
      act(() => ws.serverEvent({ type: "heartbeat", sequence: i + 1 }));
    }
    expect(FakeWebSocket.instances).toHaveLength(1);
  });
});

describe("useRunEvents reconnect paths", () => {
  it("visibilitychange wakes a closed stream immediately", async () => {
    const { result } = await mount("run-wake");
    const ws = FakeWebSocket.last();
    act(() => ws.serverOpen());
    act(() => ws.close(1000));
    await advance(10);
    expect(result.current.status).toBe("closed");
    // A closed socket would normally wait out the 2s backoff...
    await advance(10);
    act(() => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    // ...but the wake listener reconnects right away.
    expect(FakeWebSocket.instances).toHaveLength(2);
  });

  it("a 4401 close routes through the shared expireSession funnel", async () => {
    const { result } = await mount("run-4401");
    const ws = FakeWebSocket.last();
    act(() => ws.serverOpen());
    const expired = vi.fn();
    window.addEventListener(AUTH_EXPIRED_EVENT, expired);
    try {
      act(() => ws.close(4401));
      await advance(10);
      expect(getStoredToken()).toBe("");
      expect(expired).toHaveBeenCalledTimes(1);
      expect(result.current.authError).not.toBe("");
      expect(result.current.status).toBe("error");
    } finally {
      window.removeEventListener(AUTH_EXPIRED_EVENT, expired);
    }
  });

  it("a normal close falls back toward SSE after repeated failures", async () => {
    const { result } = await mount("run-fallback");
    // Three closes in a row (each with enough time for the reconnect timer to
    // fire first) trip the SSE fallback — and it must stay on SSE, not be
    // clobbered by a stale WS reconnect timer.
    for (let i = 0; i < 3; i += 1) {
      act(() => FakeWebSocket.last().close(1006));
      await advance(5_000);
    }
    expect(result.current.transport).toBe("sse");
    expect(result.current.status).toBe("reconnecting");
  });
});