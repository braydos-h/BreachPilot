import { useCallback, useEffect, useRef, useState } from "react";
import { clearStoredToken } from "@/api/client";
import type { RunEvent } from "@/api/types";

export type WsStatus = "idle" | "connecting" | "open" | "closed" | "error";

interface UseRunEventsOptions {
  after?: number;
  enabled?: boolean;
}

const WS_CLOSE_AUTH = 4401;
const WS_CLOSE_ORIGIN = 4403;
const WS_CLOSE_CURSOR = 4400;
const WS_CLOSE_NOT_FOUND = 4404;
const MAX_BACKOFF = 10_000;
const SSE_FALLBACK_THRESHOLD = 3;

function backoffMs(attempt: number): number {
  return Math.min(MAX_BACKOFF, 1000 * 2 ** attempt);
}

export function useRunEvents(runId: string | null | undefined, options: UseRunEventsOptions = {}) {
  const { after: initialAfter = 0, enabled = true } = options;
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [status, setStatus] = useState<WsStatus>("idle");
  const [authError, setAuthError] = useState<string>("");
  const [transport, setTransport] = useState<"websocket" | "sse" | "none">("none");

  const lastSeqRef = useRef<number>(initialAfter);
  const wsRef = useRef<WebSocket | null>(null);
  const esRef = useRef<EventSource | null>(null);
  const attemptRef = useRef<number>(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const closedByUnmountRef = useRef(false);
  const wsFailureCountRef = useRef(0);
  const sseActiveRef = useRef(false);
  const runIdRef = useRef<string | null>(null);

  const appendEvent = useCallback((event: RunEvent) => {
    if (event.type === "heartbeat") {
      if (typeof event.sequence === "number" && event.sequence > lastSeqRef.current) {
        lastSeqRef.current = event.sequence;
      }
      return;
    }
    if (typeof event.sequence === "number") {
      if (event.sequence <= lastSeqRef.current) return;
      lastSeqRef.current = event.sequence;
    }
    // Backend delivers monotonic sequences (replay in order, then live in
    // order), and the `sequence <= lastSeqRef.current` guard above already
    // drops duplicates/out-of-order events — so a plain append keeps the
    // array sorted without an O(n) dedup + O(n log n) sort per event.
    setEvents((prev) => [...prev, event]);
  }, []);

  const closeSse = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    sseActiveRef.current = false;
  }, []);

  const connectSse = useCallback(
    (id: string) => {
      closeSse();
      const token = sessionStorage.getItem("netattackai.apiToken.v1") ?? "";
      const loc = window.location;
      const url =
        `${loc.origin}/api/v1/runs/${encodeURIComponent(id)}/events/stream` +
        `?after=${lastSeqRef.current}&token=${encodeURIComponent(token)}`;
      const es = new EventSource(url);
      esRef.current = es;
      sseActiveRef.current = true;
      setTransport("sse");
      setStatus("open");

      es.onmessage = (msg) => {
        try {
          const event = JSON.parse(msg.data) as RunEvent;
          appendEvent(event);
        } catch {
          // Ignore malformed frames.
        }
      };
      es.onerror = () => {
        setStatus("error");
        closeSse();
        setTransport("none");
        if (closedByUnmountRef.current) return;
        attemptRef.current += 1;
        reconnectTimerRef.current = setTimeout(() => {
          if (runIdRef.current === id && !closedByUnmountRef.current) connectSse(id);
        }, backoffMs(attemptRef.current));
      };
    },
    [appendEvent, closeSse],
  );

  const connectWs = useCallback(
    (id: string) => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      const token = sessionStorage.getItem("netattackai.apiToken.v1") ?? "";
      const loc = window.location;
      const scheme = loc.protocol === "https:" ? "wss" : "ws";
      const url = `${scheme}://${loc.host}/api/v1/ws/v1/runs/${encodeURIComponent(id)}`;
      let socket: WebSocket;
      try {
        socket = new WebSocket(url);
      } catch {
        setStatus("error");
        return;
      }
      wsRef.current = socket;
      setTransport("websocket");
      setStatus("connecting");

      socket.onopen = () => {
        attemptRef.current = 0;
        setStatus("open");
        try {
          socket.send(JSON.stringify({ auth: token, after: lastSeqRef.current }));
        } catch {
          socket.close();
        }
      };

      socket.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data) as RunEvent;
          appendEvent(event);
        } catch {
          // Ignore malformed frames.
        }
      };

      socket.onerror = () => {
        setStatus("error");
      };

      socket.onclose = (event) => {
        wsRef.current = null;
        setStatus("closed");
        if (closedByUnmountRef.current) return;
        if (event.code === WS_CLOSE_AUTH) {
          setAuthError("Authentication failed. Token rejected by the API.");
          clearStoredToken();
          setStatus("error");
          return;
        }
        if (event.code === WS_CLOSE_ORIGIN) {
          setAuthError("Origin rejected by the API.");
          setStatus("error");
          return;
        }
        if (event.code === WS_CLOSE_CURSOR) {
          lastSeqRef.current = 0;
          setEvents([]);
        }
        if (event.code === WS_CLOSE_NOT_FOUND) {
          setAuthError("Run not found.");
          setStatus("error");
          return;
        }
        wsFailureCountRef.current += 1;
        if (wsFailureCountRef.current >= SSE_FALLBACK_THRESHOLD) {
          wsFailureCountRef.current = 0;
          connectSse(id);
          return;
        }
        attemptRef.current += 1;
        reconnectTimerRef.current = setTimeout(() => {
          if (runIdRef.current === id && !closedByUnmountRef.current) connectWs(id);
        }, backoffMs(attemptRef.current));
      };
    },
    [appendEvent, connectSse],
  );

  const reconnect = useCallback(() => {
    if (!runIdRef.current || closedByUnmountRef.current) return;
    attemptRef.current = 0;
    wsFailureCountRef.current = 0;
    closeSse();
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    connectWs(runIdRef.current);
  }, [closeSse, connectWs]);

  useEffect(() => {
    runIdRef.current = runId ?? null;
    if (!runId || !enabled) {
      setStatus("idle");
      return;
    }
    closedByUnmountRef.current = false;
    lastSeqRef.current = initialAfter;
    setEvents([]);
    setAuthError("");
    attemptRef.current = 0;
    wsFailureCountRef.current = 0;
    connectWs(runId);

    return () => {
      closedByUnmountRef.current = true;
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      closeSse();
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId, enabled]);

  return { events, status, authError, transport, reconnect, lastSeq: lastSeqRef };
}