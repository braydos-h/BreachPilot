"""Per-run event broker: JSONL persistence + in-memory ring + WebSocket pub/sub.

Events are sanitized before persistence. ``sequence`` is monotonically
increasing per run. ``GET /runs/{id}/events?after=<seq>`` replays from JSONL;
``WS /ws/v1/runs/{id}`` pushes live. A browser disconnect does NOT cancel the
run — the ring buffer holds recent events for reconnect.
"""

from __future__ import annotations

import asyncio
import json
from collections import OrderedDict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.api.errors import sanitize


class RunEventBroker:
    """Per-run event broker: one instance per active run.

    Events are written to ``reports/<run_id>/events.jsonl`` (authoritative)
    and held in a bounded in-memory ring for live WS delivery. Subscribers
    are notified via an ``asyncio.Condition``.
    """

    def __init__(self, run_id: str, reports_dir: Path, *, buffer_size: int = 1000) -> None:
        self._run_id = run_id
        self._reports_dir = reports_dir
        self._events_path = reports_dir / "events.jsonl"
        self._ring: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._seq = 0
        self._lock = asyncio.Lock()
        self._closed = False
        self._subscribers: list[asyncio.Queue[dict[str, Any] | None]] = []

    async def emit(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Emit an event: assign sequence, sanitize, write JSONL, notify subscribers."""
        async with self._lock:
            if self._closed:
                raise RuntimeError("Event broker is closed.")
            self._seq += 1
            event = {
                "sequence": self._seq,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "run_id": self._run_id,
                "type": event_type,
                "payload": sanitize(payload),
            }
            self._events_path.parent.mkdir(parents=True, exist_ok=True)
            with self._events_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, default=str) + "\n")
            self._ring.append(event)
            for queue in tuple(self._subscribers):
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    self._subscribers.remove(queue)
                    self._stop_queue(queue)
        # Plugin event subscribers (outbound-only webhook/ticketing). Fired
        # AFTER JSONL persistence + WS fan-out so a slow/failed subscriber
        # never blocks the run or drops the event. Best-effort: any exception
        # is swallowed. See tools/plugins.py::PluginRegistry.register_event_subscriber.
        _fire_plugin_event_subscribers(event)
        return event

    async def replay(self, after: int = 0) -> list[dict[str, Any]]:
        """Replay events with sequence > ``after`` from JSONL."""
        async with self._lock:
            return self._replay_locked(after)

    def _replay_locked(self, after: int) -> list[dict[str, Any]]:
        if self._ring and after >= self._ring[0]["sequence"] - 1:
            return [event for event in self._ring if event["sequence"] > after]
        events: list[dict[str, Any]] = []
        if not self._events_path.exists():
            return events
        with self._events_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sequence = evt.get("sequence")
                if isinstance(sequence, int) and not isinstance(sequence, bool) and sequence > after:
                    events.append(evt)
        return events

    @staticmethod
    def _read_jsonl_events(path: Path) -> list[dict[str, Any]]:
        """Read the full ordered list of parsed events from ``events.jsonl``."""
        events: list[dict[str, Any]] = []
        if not path.exists():
            return events
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                events.append(evt)
        return events

    async def replay_page(
        self,
        after: int = 0,
        *,
        tail: int | None = None,
        before: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """Paged replay with cursor metadata.

        Returns ``{"events": [...], "oldest_sequence": int|None,
        "latest_sequence": int|None, "has_more_before": bool,
        "first_returned_sequence": int|None, "last_returned_sequence": int|None,
        "omitted_before": int, "next_before": int|None}``.

        - ``tail=N``: newest N events, ascending by sequence.
        - ``before=X`` + ``limit=N``: up to N events with sequence < X,
          newest-first (descending) so the client can page older.
        - ``after=X``: events with sequence > X, ascending (unchanged).
        """
        async with self._lock:
            if self._ring and self._ring[0]["sequence"] == 1:
                full = list(self._ring)
            else:
                full = await asyncio.to_thread(self._read_jsonl_events, self._events_path)

            oldest = full[0]["sequence"] if full else None
            latest = full[-1]["sequence"] if full else None

            first_returned: int | None = None
            last_returned: int | None = None
            omitted_before = 0
            next_before: int | None = None
            has_more_before = False

            if tail is not None:
                if tail < len(full):
                    events = full[-tail:]
                else:
                    events = list(full)
                if events:
                    first_returned = events[0]["sequence"]  # type: ignore[index]
                    last_returned = events[-1]["sequence"]  # type: ignore[index]
                    omitted_before = len(full) - len(events)
                    has_more_before = omitted_before > 0
                    next_before = first_returned if has_more_before else None
                else:
                    events = []
                    has_more_before = False
                    omitted_before = 0
            elif before is not None:
                older_full = [e for e in full if e["sequence"] < before]  # type: ignore[index]
                if limit is not None:
                    if limit < len(older_full):
                        older = older_full[-limit:]
                    else:
                        older = list(older_full)
                else:
                    older = older_full
                events = list(reversed(older))
                if events:
                    # older is ascending; events is descending.
                    first_returned = older[0]["sequence"]  # oldest in page
                    last_returned = older[-1]["sequence"]  # newest in page
                    omitted_before = len(older_full) - len(older)
                    has_more_before = omitted_before > 0
                    next_before = first_returned if has_more_before else None
                else:
                    has_more_before = False
                    omitted_before = 0
            else:
                events = [e for e in full if e["sequence"] > after]  # type: ignore[index]
                if events:
                    first_returned = events[0]["sequence"]  # type: ignore[index]
                    last_returned = events[-1]["sequence"]  # type: ignore[index]
                has_more_before = False
                omitted_before = 0
                next_before = None

            return {
                "events": events,
                "oldest_sequence": oldest,
                "latest_sequence": latest,
                "has_more_before": has_more_before,
                "first_returned_sequence": first_returned,
                "last_returned_sequence": last_returned,
                "omitted_before": omitted_before,
                "next_before": next_before,
            }

    async def subscribe(self, after: int = 0) -> "EventSubscription":
        """Subscribe to live events. ``after`` replays from that cursor first."""
        async with self._lock:
            subscription = EventSubscription(
                broker=self,
                initial=self._replay_locked(after),
            )
            if not self._closed:
                self._subscribers.append(subscription._queue)
            return subscription

    def close(self) -> None:
        self._closed = True
        for queue in self._subscribers:
            self._stop_queue(queue)
        self._subscribers.clear()

    @staticmethod
    def _stop_queue(queue: asyncio.Queue[dict[str, Any] | None]) -> None:
        while not queue.empty():
            queue.get_nowait()
        queue.put_nowait(None)


class EventSubscription:
    """A live event subscription backed by an ``asyncio.Queue``."""

    def __init__(self, *, broker: RunEventBroker, initial: list[dict[str, Any]]) -> None:
        self._broker = broker
        self._queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(
            maxsize=broker._ring.maxlen or 256,
        )
        self._initial = deque(initial)
        self._closed = False

    def __aiter__(self):
        return self

    async def __anext__(self) -> dict[str, Any]:
        if self._closed:
            raise StopAsyncIteration
        if self._initial:
            return self._initial.popleft()
        if self._broker._closed and self._queue.empty():
            raise StopAsyncIteration
        try:
            event = await asyncio.wait_for(self._queue.get(), timeout=30.0)
        except asyncio.TimeoutError:
            # Heartbeat: keep the WS alive.
            return {"type": "heartbeat", "run_id": self._broker._run_id}
        if event is None:
            self._closed = True
            raise StopAsyncIteration
        return event

    def close(self) -> None:
        self._closed = True
        if self._queue in self._broker._subscribers:
            self._broker._subscribers.remove(self._queue)


class EventBrokerRegistry:
    """Registry of per-run event brokers. One active broker at a time."""

    def __init__(self, reports_dir: Path, *, buffer_size: int = 1000, max_brokers: int = 10) -> None:
        self._reports_dir = reports_dir
        self._buffer_size = buffer_size
        self._max_brokers = max_brokers
        self._brokers: OrderedDict[str, RunEventBroker] = OrderedDict()

    def get_or_create(self, run_id: str, *, reports_dir: Path | None = None) -> RunEventBroker:
        broker = self._brokers.get(run_id)
        if broker is not None:
            self._brokers.move_to_end(run_id)
            return broker
        rd = reports_dir or self._reports_dir / run_id
        broker = RunEventBroker(run_id, rd, buffer_size=self._buffer_size)
        self._brokers[run_id] = broker
        while len(self._brokers) > self._max_brokers:
            _, evicted = self._brokers.popitem(last=False)
            evicted.close()
        return broker

    def get(self, run_id: str) -> RunEventBroker | None:
        return self._brokers.get(run_id)

    def close_all(self) -> None:
        for b in self._brokers.values():
            b.close()
        self._brokers.clear()


def _fire_plugin_event_subscribers(event: dict[str, Any]) -> None:
    """Best-effort fan-out of an emitted event to plugin event subscribers.

    Outbound-only subscribers (webhook/ticketing) registered via
    ``PluginRegistry.register_event_subscriber`` are invoked after the event
    is persisted to JSONL and pushed to live WS subscribers. Any exception is
    swallowed so a broken/endpoint-down subscriber never blocks the run or
    kills sibling subscribers. Import is lazy so ``tools.api.event_broker``
    stays import-clean when no plugin has registered a subscriber.
    """
    try:
        from tools.plugins import PLUGIN_REGISTRY

        subscribers = list(PLUGIN_REGISTRY.event_subscribers)
    except Exception:  # noqa: BLE001 -- plugins module import must never break emit
        return
    for fn in subscribers:
        try:
            fn(event)
        except Exception:  # noqa: BLE001 -- one bad subscriber never breaks the rest
            import logging as _logging

            _logging.getLogger("tools.api.event_broker").warning(
                "plugin event subscriber %r failed",
                getattr(fn, "__name__", fn),
                exc_info=True,
            )
