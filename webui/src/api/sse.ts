/**
 * Fetch-based Server-Sent Events client.
 *
 * The browser's native `EventSource` cannot set an Authorization header, so
 * the previous WebUI put the bearer token in the URL (`?token=...`) — which
 * leaks it into history/logs. This module streams over `fetch` and sends the
 * token in the `Authorization` header, exactly like every other API call.
 *
 * Responsibilities (all in this file):
 *  - connection (fetch + stream reading)
 *  - UTF-8 decoding (TextDecoder, chunk-safe)
 *  - SSE parsing (data:/event:/id:/retry:, multiline data, comments, blank-line
 *    termination, partial chunks split across reads)
 *  - reconnect with exponential backoff (stops on auth failures and abort)
 *
 * The token is never logged, never exposed in errors, and never placed in the
 * URL. Fatal/auth errors are reported through `onFatal`; transient failures
 * retry internally via `onStatus("reconnecting")`.
 */

export interface SseMessage {
  /** Last-seen `id:` value (may be null if the server sends none). */
  id: string | null;
  /** Event name from `event:` (defaults to "message"). */
  event: string;
  /** Joined `data:` payload (multiline data joined with "\n"). */
  data: string | null;
  /** `retry:` value in ms, if the server sent one. */
  retry: number | null;
}

export type SseConnectionState = "connecting" | "open" | "reconnecting" | "closed";

export interface SseFatalError {
  /** True when the server rejected the stream (401/403) — do NOT reconnect. */
  authError: boolean;
  /** Human message. Never contains the token. */
  message: string;
}

export interface StreamSseOptions {
  /** Absolute URL, or a factory re-invoked per connection attempt so the
   *  caller can advance a cursor (e.g. `?after=`). Never includes the token. */
  url: string | (() => string);
  /** Bearer token, sent only in the Authorization header. */
  token: string;
  /** External cancellation (run switched, component unmounted, auth changed). */
  signal: AbortSignal;
  onEvent: (message: SseMessage) => void;
  onOpen?: () => void;
  onStatus?: (state: SseConnectionState) => void;
  /** Non-retryable failure (auth rejection, permanent HTTP error, exhaust). */
  onFatal?: (error: SseFatalError) => void;
  /** Max reconnect attempts before giving up. Default: unlimited (transient). */
  maxRetries?: number;
  /** Fired on every successful transport-level read. Server keepalives are
   *  `:` comments that SseParser drops, so they never reach onEvent — this
   *  hook is what lets a caller (and the internal watchdog) see that the
   *  stream is alive during idle-but-healthy periods. */
  onActivity?: () => void;
}

export interface SseHandle {
  /** Abort the stream and stop all reconnect timers. Idempotent. */
  close: () => void;
  /** Drop the current connection and reconnect immediately (cursor fresh). */
  restart: () => void;
}

const MAX_BACKOFF_MS = 10_000;

/** The API daemon emits a keepalive comment every 30s while a stream is open
 *  (tools/api/routes/events.py). Three missed keepalives means the connection
 *  is silently dead (laptop sleep, NAT drop, no TCP RST) — abort it and let
 *  the normal reconnect path recover. Kept well above the cadence so a slow
 *  server never trips it on a healthy stream. */
export const SSE_WATCHDOG_MS = 90_000;

function backoffMs(attempt: number): number {
  return Math.min(MAX_BACKOFF_MS, 1000 * 2 ** attempt);
}

/**
 * Incremental SSE field parser. Feed decoded text chunks; it buffers partial
 * lines and emits a complete `SseMessage` per blank-line-terminated event.
 * Safe for chunks that split a line, a field, or an event across reads.
 */
export class SseParser {
  private lineBuffer = "";
  private data: string[] = [];
  private eventType = "message";
  private lastId: string | null = null;
  private retry: number | null = null;

  /** Feed a text chunk; returns any complete events terminated by blank lines. */
  push(chunk: string): SseMessage[] {
    this.lineBuffer += chunk;
    const messages: SseMessage[] = [];
    let newline: number;
    while ((newline = this.lineBuffer.indexOf("\n")) !== -1) {
      const line = this.lineBuffer.slice(0, newline);
      this.lineBuffer = this.lineBuffer.slice(newline + 1);
      this.processLine(line.replace(/\r$/, ""), messages);
    }
    return messages;
  }

  /** Flush any pending event when the stream ends (no trailing blank line). */
  finish(): SseMessage[] {
    const messages: SseMessage[] = [];
    if (this.lineBuffer) {
      this.processLine(this.lineBuffer, messages);
      this.lineBuffer = "";
    }
    this.dispatch(messages);
    return messages;
  }

  private processLine(line: string, messages: SseMessage[]): void {
    if (line === "") {
      this.dispatch(messages);
      return;
    }
    // Lines starting with ":" are comments/keepalives — ignore.
    if (line.startsWith(":")) return;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    switch (field) {
      case "data":
        this.data.push(value);
        break;
      case "event":
        if (value) this.eventType = value;
        break;
      case "id":
        if (!value.includes("\0")) this.lastId = value;
        break;
      case "retry": {
        const n = Number.parseInt(value, 10);
        if (!Number.isNaN(n)) this.retry = n;
        break;
      }
      default:
        break; // unknown fields are ignored per spec
    }
  }

  private dispatch(messages: SseMessage[]): void {
    if (this.data.length === 0) return;
    messages.push({
      id: this.lastId,
      event: this.eventType,
      data: this.data.join("\n"),
      retry: this.retry,
    });
    this.data = [];
    this.eventType = "message";
  }
}

/**
 * Open a fetch-backed SSE stream. Manages the connection, decoding, parsing,
 * and reconnect; callers receive parsed messages and connection state.
 */
export function streamSSE(options: StreamSseOptions): SseHandle {
  const { token, signal } = options;
  if (signal.aborted) {
    return { close: () => undefined, restart: () => undefined };
  }

  let closed = false;
  let generation = 0;
  let attempt = 0;
  let activeController: AbortController | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  // Set when the watchdog (not the external signal) aborted the current
  // attempt, so the catch branch can reconnect instead of returning silently.
  let watchdogTripped = false;
  let watchdogTimer: ReturnType<typeof setTimeout> | null = null;

  const emitStatus = (state: SseConnectionState) => options.onStatus?.(state);

  const clearWatchdog = () => {
    if (watchdogTimer) {
      clearTimeout(watchdogTimer);
      watchdogTimer = null;
    }
  };

  const resetWatchdog = () => {
    if (closed) return;
    clearWatchdog();
    watchdogTimer = setTimeout(() => {
      watchdogTimer = null;
      if (closed) return;
      // A silent stream is stale, not failed: restart the backoff ladder so a
      // healthy-then-idle connection doesn't inherit accumulated attempts.
      attempt = 0;
      watchdogTripped = true;
      activeController?.abort();
    }, SSE_WATCHDOG_MS);
  };

  const fatal = (error: SseFatalError) => {
    if (closed) return;
    closed = true;
    clearWatchdog();
    activeController?.abort();
    options.onFatal?.(error);
  };

  const close = () => {
    if (closed) return;
    closed = true;
    generation += 1;
    clearWatchdog();
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    activeController?.abort();
    activeController = null;
  };

  const onAbort = () => close();

  async function connect(): Promise<void> {
    const gen = ++generation;
    const controller = new AbortController();
    activeController = controller;
    watchdogTripped = false;
    emitStatus("connecting");
    // Arm before the fetch too: a server that accepts the TCP connection but
    // never answers headers is exactly the silent-death case we're guarding.
    resetWatchdog();
    try {
      const url = typeof options.url === "function" ? options.url() : options.url;
      const headers: Record<string, string> = {
        Accept: "text/event-stream",
        "Cache-Control": "no-cache",
      };
      if (token) headers.Authorization = `Bearer ${token}`;

      const response = await fetch(url, {
        headers,
        signal: controller.signal,
      });
      if (closed || gen !== generation) return;

      if (response.status === 401 || response.status === 403) {
        fatal({ authError: true, message: `Event stream rejected (${response.status}).` });
        return;
      }
      if (!response.ok) {
        fatal({ authError: false, message: `Event stream failed (HTTP ${response.status}).` });
        return;
      }
      if (!response.body) {
        fatal({ authError: false, message: "Event stream returned no body." });
        return;
      }

      attempt = 0;
      emitStatus("open");
      options.onOpen?.();
      resetWatchdog();

      const reader = response.body.getReader();
      const parser = new SseParser();
      const decoder = new TextDecoder();
      while (!closed && gen === generation) {
        const { done, value } = await reader.read();
        // Activity is measured at the read level: keepalive comments are
        // dropped by the parser, so per-message activity would never fire on
        // an idle-but-healthy stream.
        resetWatchdog();
        options.onActivity?.();
        if (done) break;
        const text = decoder.decode(value, { stream: true });
        for (const message of parser.push(text)) options.onEvent(message);
      }
      clearWatchdog();
      // Flush any bytes still in the decoder, then any unterminated event.
      for (const message of parser.push(decoder.decode())) options.onEvent(message);
      for (const message of parser.finish()) options.onEvent(message);
      if (closed || gen !== generation) return;
      if (signal.aborted) {
        close();
        return;
      }
      // Stream ended server-side (normal close). Treat as a reconnect trigger
      // so long-lived runs survive blips; `closed` from our side never gets here.
      emitStatus("reconnecting");
      scheduleReconnect(gen);
    } catch (error) {
      if (closed || gen !== generation) return;
      if (isAbortError(error) && controller.signal.aborted) {
        // Two abort sources share this path: our own watchdog (stale stream —
        // reconnect) and close()/restart() (closed already handled above).
        if (watchdogTripped) {
          watchdogTripped = false;
          emitStatus("reconnecting");
          scheduleReconnect(gen);
        }
        return;
      }
      emitStatus("reconnecting");
      scheduleReconnect(gen);
    }
  }

  function scheduleReconnect(gen: number): void {
    if (closed || gen !== generation) return;
    if (options.maxRetries != null && attempt >= options.maxRetries) {
      fatal({ authError: false, message: "Event stream gave up after repeated failures." });
      return;
    }
    attempt += 1;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      if (closed || gen !== generation) return;
      void connect();
    }, backoffMs(attempt));
  }

  function restart(): void {
    if (closed) return;
    generation += 1;
    // Kill any watchdog armed for the previous generation — left alone it
    // would fire later and abort the *fresh* connection.
    clearWatchdog();
    watchdogTripped = false;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    activeController?.abort();
    void connect();
  }

  signal.addEventListener("abort", onAbort, { once: true });
  void connect();

  return {
    close,
    restart,
  };
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}
