import { describe, expect, it, vi, afterEach } from "vitest";
import { SSE_WATCHDOG_MS, SseParser, streamSSE, type SseMessage } from "@/api/sse";

function messagesFrom(...chunks: string[]): SseMessage[] {
  const parser = new SseParser();
  const out: SseMessage[] = [];
  for (const chunk of chunks) out.push(...parser.push(chunk));
  out.push(...parser.finish());
  return out;
}

async function waitFor(assert: () => void, timeoutMs = 500): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      assert();
      return;
    } catch {
      if (Date.now() >= deadline) {
        assert(); // throw the real error once out of time
      }
      await new Promise((r) => setTimeout(r, 10));
    }
  }
}

function sseResponse(chunks: string[]): Response {
  const encoder = new TextEncoder();
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
        controller.close();
      },
    }),
    { status: 200, headers: { "content-type": "text/event-stream" } },
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("SseParser", () => {
  it("parses a single event", () => {
    const msgs = messagesFrom('data: {"a":1}\n\n');
    expect(msgs).toHaveLength(1);
    expect(msgs[0]!.data).toBe('{"a":1}');
    expect(msgs[0]!.event).toBe("message");
  });

  it("parses multiple events in one chunk", () => {
    const msgs = messagesFrom('data: one\n\ndata: two\n\n');
    expect(msgs.map((m) => m.data)).toEqual(["one", "two"]);
  });

  it("parses one event split across multiple chunks", () => {
    const msgs = messagesFrom('data: hel', 'lo\n\n');
    expect(msgs).toHaveLength(1);
    expect(msgs[0]!.data).toBe("hello");
  });

  it("splits a single line across several chunks", () => {
    const msgs = messagesFrom("data: 12", "345", "6789\n\n");
    expect(msgs).toHaveLength(1);
    expect(msgs[0]!.data).toBe("123456789");
  });

  it("joins multiline data with newlines", () => {
    const msgs = messagesFrom("data: line1\ndata: line2\ndata: line3\n\n");
    expect(msgs).toHaveLength(1);
    expect(msgs[0]!.data).toBe("line1\nline2\nline3");
  });

  it("ignores keepalive comments starting with colon", () => {
    const msgs = messagesFrom(": heartbeat\n: still here\n\ndata: real\n\n");
    expect(msgs).toHaveLength(1);
    expect(msgs[0]!.data).toBe("real");
  });

  it("handles event: and id: fields", () => {
    const msgs = messagesFrom('id: 42\nevent: status\ndata: ok\n\n');
    expect(msgs).toHaveLength(1);
    expect(msgs[0]!.id).toBe("42");
    expect(msgs[0]!.event).toBe("status");
    expect(msgs[0]!.data).toBe("ok");
  });

  it("handles CRLF line endings", () => {
    const msgs = messagesFrom("data: hello\r\n\r\n");
    expect(msgs).toHaveLength(1);
    expect(msgs[0]!.data).toBe("hello");
  });

  it("emits an unterminated trailing event on finish", () => {
    const msgs = messagesFrom("data: trailing");
    expect(msgs).toHaveLength(1);
    expect(msgs[0]!.data).toBe("trailing");
  });

  it("handles a blank line with no pending data without emitting", () => {
    const msgs = messagesFrom("\n\n");
    expect(msgs).toHaveLength(0);
  });

  it("passes through non-JSON data untouched (parser never parses payloads)", () => {
    const msgs = messagesFrom('data: not json {broken\n\ndata: {"seq": 2}\n\n');
    expect(msgs.map((m) => m.data)).toEqual(["not json {broken", '{"seq": 2}']);
  });
});

describe("streamSSE", () => {
  it("authenticates with the Authorization header and never puts the token in the URL", async () => {
    const fetchMock = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) =>
      sseResponse(['data: {"seq":1}\n\n']),
    );
    vi.stubGlobal("fetch", fetchMock);

    const events: string[] = [];
    const controller = new AbortController();
    const handle = streamSSE({
      url: "http://localhost:8765/api/v1/runs/r1/events/stream?after=0",
      token: "super-secret-token",
      signal: controller.signal,
      onEvent: (m) => events.push(m.data ?? ""),
    });
    await waitFor(() => expect(events).toEqual(['{"seq":1}']));
    handle.close();

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).not.toContain("super-secret-token");
    expect(String(url)).not.toContain("token=");
    const headers = init?.headers as Record<string, string> | undefined;
    expect(headers?.Authorization).toBe("Bearer super-secret-token");
    expect(headers?.Accept).toBe("text/event-stream");
  });

  it("rejects 401 without reconnecting", async () => {
    const fetchMock = vi.fn(async () => new Response("unauthorized", { status: 401 }));
    vi.stubGlobal("fetch", fetchMock);

    const fatal = vi.fn();
    const statuses: string[] = [];
    const controller = new AbortController();
    streamSSE({
      url: "http://localhost:8765/api/v1/runs/r1/events/stream",
      token: "t",
      signal: controller.signal,
      onEvent: () => undefined,
      onStatus: (s) => statuses.push(s),
      onFatal: fatal,
    });

    await new Promise((r) => setTimeout(r, 10));
    controller.abort();

    expect(fatal).toHaveBeenCalledTimes(1);
    expect(fatal.mock.calls[0]![0]!.authError).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(statuses.filter((s) => s === "reconnecting")).toHaveLength(0);
  });

  it("reconnects after a transient network failure", async () => {
    let failFirst = true;
    const fetchMock = vi.fn(async () => {
      if (failFirst) {
        failFirst = false;
        throw new TypeError("network unreachable");
      }
      return sseResponse(['data: {"seq":2}\n\n']);
    });
    vi.stubGlobal("fetch", fetchMock);

    const events: string[] = [];
    const statuses: string[] = [];
    const controller = new AbortController();
    streamSSE({
      // Reset the cursor per attempt to exercise the url-factory path.
      url: () => `http://localhost:8765/events/stream?after=${events.length}`,
      token: "t",
      signal: controller.signal,
      onEvent: (m) => events.push(m.data ?? ""),
      onStatus: (s) => statuses.push(s),
    });

    // First retry waits 2s of backoff, so allow a generous poll window.
    await waitFor(() => expect(events).toContain('{"seq":2}'), 3500);
    controller.abort();

    expect(fetchMock.mock.calls.length).toBeGreaterThan(1);
    expect(statuses).toContain("reconnecting");
    expect(statuses).toContain("open");
  });

  it("streams multiple events split across network reads", async () => {
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        // Split mid-event: first chunk ends after "data: {\"seq\":1}\n" (no blank line yet)
        // Second chunk carries the terminator plus the start of the next event.
        controller.enqueue(encoder.encode('data: {"seq":1}\n\n'));
        controller.enqueue(encoder.encode('data: {"seq":2}\n\n'));
        controller.close();
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } })),
    );

    const events: string[] = [];
    const controller = new AbortController();
    const handle = streamSSE({
      url: "http://localhost:8765/events/stream",
      token: "t",
      signal: controller.signal,
      onEvent: (m) => events.push(m.data ?? ""),
    });
    await new Promise((r) => setTimeout(r, 10));
    handle.close();

    expect(events).toEqual(['{"seq":1}', '{"seq":2}']);
  });

  it("cancels cleanly on AbortController abort", async () => {
    const encoder = new TextEncoder();
    // A stream that stays open forever (never closes the controller).
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"seq":1}\n\n'));
        // keep open
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } })),
    );

    const events: string[] = [];
    const statuses: string[] = [];
    const controller = new AbortController();
    streamSSE({
      url: "http://localhost:8765/events/stream",
      token: "t",
      signal: controller.signal,
      onEvent: (m) => events.push(m.data ?? ""),
      onStatus: (s) => statuses.push(s),
    });

    await new Promise((r) => setTimeout(r, 10));
    const callsBeforeAbort = events.length;
    controller.abort();
    await new Promise((r) => setTimeout(r, 10));

    expect(events.length).toBe(callsBeforeAbort);
    // No reconnect after abort.
    expect(statuses.filter((s) => s === "reconnecting")).toHaveLength(0);
  });

  it("fires onActivity on every read, including keepalive-only chunks that never reach onEvent", async () => {
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(": keepalive 1\n"));
        controller.enqueue(encoder.encode(": keepalive 2\n"));
        controller.enqueue(encoder.encode('data: {"seq":1}\n\n'));
        controller.close();
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } })),
    );

    let activity = 0;
    const events: string[] = [];
    const controller = new AbortController();
    const handle = streamSSE({
      url: "http://localhost:8765/events/stream",
      token: "t",
      signal: controller.signal,
      onEvent: (m) => events.push(m.data ?? ""),
      onActivity: () => {
        activity += 1;
      },
    });
    await new Promise((r) => setTimeout(r, 10));
    handle.close();

    // Three enqueued chunks + the final done-read = 4 reads. Keepalives never
    // reach onEvent, so per-message activity would have counted just one.
    expect(activity).toBe(4);
    expect(events).toEqual(['{"seq":1}']);
  });

  it("watchdog aborts a silent stream and reconnects with a reset backoff ladder", async () => {
    vi.useFakeTimers();
    try {
      const encoder = new TextEncoder();
      let openCount = 0;
      vi.stubGlobal(
        "fetch",
        vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
          openCount += 1;
          if (openCount === 1) {
            // A stream that opens and then goes permanently silent. Real fetch
            // aborts the body stream when the signal fires — mimic that, or
            // the abort would never reject the pending read in the test.
            const body = new ReadableStream<Uint8Array>({
              start(controller) {
                controller.enqueue(encoder.encode('data: {"seq":1}\n\n'));
                // keep open, never enqueue again
                init?.signal?.addEventListener("abort", () => {
                  controller.error(new DOMException("The operation was aborted.", "AbortError"));
                });
              },
            });
            return new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } });
          }
          return sseResponse(['data: {"seq":2}\n\n']);
        }),
      );

      const events: string[] = [];
      const statuses: string[] = [];
      const controller = new AbortController();
      const handle = streamSSE({
        url: "http://localhost:8765/events/stream",
        token: "t",
        signal: controller.signal,
        onEvent: (m) => events.push(m.data ?? ""),
        onStatus: (s) => statuses.push(s),
      });

      // Let the first connection open.
      await vi.advanceTimersByTimeAsync(10);
      expect(events).toEqual(['{"seq":1}']);
      expect(statuses).toContain("open");

      // Just under the watchdog: nothing happens.
      await vi.advanceTimersByTimeAsync(SSE_WATCHDOG_MS - 100);
      expect(fetchMockCalls()).toBe(1);

      // Crossing the watchdog aborts the silent stream and schedules a
      // reconnect (2s ladder reset — not an accumulated-attempt backoff).
      await vi.advanceTimersByTimeAsync(200);
      expect(statuses).toContain("reconnecting");
      expect(fetchMockCalls()).toBe(1);
      await vi.advanceTimersByTimeAsync(2_000);
      expect(fetchMockCalls()).toBe(2);
      expect(events).toContain('{"seq":2}');

      handle.close();
      controller.abort();
    } finally {
      vi.useRealTimers();
    }

    function fetchMockCalls(): number {
      return (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length;
    }
  });

  it("watchdog stays quiet while reads keep arriving", async () => {
    vi.useFakeTimers();
    try {
      const encoder = new TextEncoder();
      // A server that sends a keepalive comment every 30s, forever.
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => {
          const stream = new ReadableStream<Uint8Array>({
            start(controller) {
              const interval = setInterval(() => {
                try {
                  controller.enqueue(encoder.encode(": keepalive\n"));
                } catch {
                  clearInterval(interval);
                }
              }, 30_000);
              // The stream never closes; the watchdog is what must not fire.
            },
          });
          return new Response(stream, { status: 200, headers: { "content-type": "text/event-stream" } });
        }),
      );

      const statuses: string[] = [];
      const controller = new AbortController();
      const handle = streamSSE({
        url: "http://localhost:8765/events/stream",
        token: "t",
        signal: controller.signal,
        onEvent: () => undefined,
        onStatus: (s) => statuses.push(s),
      });

      // Six simulated minutes of keepalives — far past the 90s watchdog.
      await vi.advanceTimersByTimeAsync(10);
      for (let i = 0; i < 12; i += 1) {
        await vi.advanceTimersByTimeAsync(30_000);
      }
      // Only the initial fetch: no watchdog abort, no reconnect.
      expect((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length).toBe(1);
      expect(statuses).toContain("open");
      expect(statuses).not.toContain("reconnecting");

      handle.close();
      controller.abort();
    } finally {
      vi.useRealTimers();
    }
  });
});
