import { useCallback, useEffect, useRef, useState } from "react";
import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { apiFetch, clearStoredToken } from "@/api/client";
import { queryKeys } from "@/api/hooks";
import { eventStore } from "@/api/eventStore";
import type { EventReplayResponse, RunDetail, RunEvent, RunState } from "@/api/types";

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

// Event types that must reach the UI immediately (terminal state, decisions,
// errors, and title updates) rather than waiting for the next animation frame.
const IMMEDIATE_EVENT_TYPES = new Set(["state", "approval", "error", "title"]);

function backoffMs(attempt: number): number {
  return Math.min(MAX_BACKOFF, 1000 * 2 ** attempt);
}

function useSafeQueryClient(): QueryClient {
  return useQueryClient();
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
  const pendingRef = useRef<RunEvent[]>([]);
  const rafRef = useRef<number | null>(null);

  const queryClient = useSafeQueryClient();

  const patchCaches = useCallback(
    (event: RunEvent) => {
      if (!queryClient) return;
      const id = runIdRef.current;
      if (!id) return;
      try {
        if (event.type === "state") {
          const state = event.payload?.state;
          if (typeof state === "string") {
            queryClient.setQueryData<RunDetail>(queryKeys.run(id), (prev) => {
              if (!prev) return prev;
              const next: RunDetail = { ...prev, state: state as RunState };
              if (event.payload?.result !== undefined) {
                next.result = event.payload.result as RunDetail["result"];
              }
              return next;
            });
          }
          void queryClient.invalidateQueries({ queryKey: ["runs"] });
        } else if (event.type === "approval") {
          void queryClient.invalidateQueries({ queryKey: queryKeys.runDecisions(id) });
        } else if (event.type === "artifact") {
          void queryClient.invalidateQueries({ queryKey: queryKeys.runArtifacts(id) });
          // The attack graph is rebuilt from audit/report artifacts; a new
          // artifact can change it, so invalidate the explorer queries too
          // (lightweight refetch — the backend rebuilds lazily).
          void queryClient.invalidateQueries({ queryKey: ["graphExplorer", id] });
        }
      } catch {
        // Cache patching is best-effort; never let it break the event stream.
      }
    },
    [queryClient],
  );

  const flushPending = useCallback(() => {
    rafRef.current = null;
    const batch = pendingRef.current;
    if (batch.length === 0) return;
    pendingRef.current = [];
    setEvents((prev) => [...prev, ...batch]);
  }, []);

  const scheduleFlush = useCallback(() => {
    if (rafRef.current !== null) return;
    rafRef.current = requestAnimationFrame(flushPending);
  }, [flushPending]);

  const handleEvent = useCallback(
    (event: RunEvent) => {
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
      const id = runIdRef.current ?? event.run_id;
      if (id) eventStore.append(id, event);
      patchCaches(event);
      if (IMMEDIATE_EVENT_TYPES.has(event.type)) {
        if (rafRef.current !== null) {
          cancelAnimationFrame(rafRef.current);
          rafRef.current = null;
        }
        const pending = pendingRef.current;
        pendingRef.current = [];
        setEvents((prev) => [...prev, ...pending, event]);
      } else {
        pendingRef.current.push(event);
        scheduleFlush();
      }
    },
    [patchCaches, scheduleFlush],
  );

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
          handleEvent(event);
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
    [handleEvent, closeSse],
  );

  const seedEvents = useCallback(
    async (id: string, isCancelled?: () => boolean) => {
      try {
        const res = await apiFetch<EventReplayResponse>(
          `/runs/${encodeURIComponent(id)}/events?tail=1000`,
        );
        if (isCancelled?.()) return;
        const seeded = res.events ?? [];
        const latest = typeof res.latest_sequence === "number" ? res.latest_sequence : 0;
        lastSeqRef.current = latest;
        eventStore.set(id, seeded, latest);
        setEvents(seeded);
      } catch {
        // Seed failed (run not found / network). Connect from the current
        // cursor anyway; the WS/SSE path surfaces auth/404 errors.
      }
    },
    [],
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
          handleEvent(event);
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
          eventStore.clear(id);
          void seedEvents(id);
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
    [handleEvent, connectSse, seedEvents],
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
    setAuthError("");
    attemptRef.current = 0;
    wsFailureCountRef.current = 0;

    let cancelled = false;

    const cached = eventStore.get(runId);
    if (cached) {
      // Reuse the in-memory cursor + events instead of replaying from zero.
      lastSeqRef.current = cached.cursor;
      setEvents(cached.events);
      connectWs(runId);
    } else {
      lastSeqRef.current = initialAfter;
      setEvents([]);
      void (async () => {
        await seedEvents(runId, () => cancelled);
        if (cancelled) return;
        connectWs(runId);
      })();
    }

    return () => {
      cancelled = true;
      closedByUnmountRef.current = true;
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
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
