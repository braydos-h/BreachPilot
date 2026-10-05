"""Per-run event broker: JSONL persistence + in-memory ring + WebSocket pub/sub.

Events are sanitized before persistence. ``sequence`` is monotonically
increasing per run. ``GET /runs/{id}/events?after=<seq>`` replays from JSONL;
``WS /ws/v1/runs/{id}`` pushes live. A browser disconnect does NOT cancel the
run — the ring buffer holds recent events for reconnect.

Plugin dispatch
---------------

``RunEventBroker.emit()`` assigns ``sequence`` under ``_lock``, appends to
the ring, fans out to WS subscribers, then hands the event to the single
writer thread's ``queue.Queue`` (one open FD, batched flush — no per-event
open/fsync, no ``asyncio.to_thread`` hop). After the lock is released the
event is handed to a bounded producer/consumer dispatcher for outbound-only
plugin subscribers (``webhook_notify`` etc.).

* The dispatcher queue is bounded (``max_queue_size``) and workers are bounded
  (``max_workers``) — no unbounded ``create_task`` or thread explosion when
  events outpace a down webhook.
* Blocking subscriber code (``urllib.request.urlopen`` + ``time.sleep``
  backoff) executes off the asyncio event-loop thread via
  ``asyncio.to_thread`` inside the worker pool, so ``emit()`` never stalls
  the run (a down webhook with default ``timeout_seconds=5``,
  ``max_retries=3``, ``backoff_seconds=2`` would otherwise stall ``emit()``
  ~20 s).
* Queue-full is explicit: the webhook delivery for that event is dropped
  (persistence already succeeded) and a ``WARNING`` is emitted with
  ``qsize``, ``sequence`` and a cumulative drop counter.
* Subscriber exceptions are caught per-subscriber, logged at ``WARNING`` with
  ``exc_info``, and never propagate to the broker or sibling subscribers.

Shutdown / lifecycle
--------------------

Pending webhook work is best-effort. ``await shutdown_plugin_dispatcher()``
(or ``await dispatcher.shutdown()``) attempts to drain the queue for at most
``drain_timeout`` seconds (default 5 s) via ``queue.join()``. If the drain
deadline expires the remainder is logged and discarded, workers are
cancelled, and the dispatcher resets so the next ``emit()`` lazily restarts
it. With ``drain_timeout=0`` the queue is discarded immediately. This bound
prevents shutdown from blocking on a down webhook's retry loop.
``RunEventBroker.close()`` / ``EventBrokerRegistry.close_all()`` close only
the WS fan-out queues; they do **not** implicitly drain the plugin
dispatcher — call ``await shutdown_plugin_dispatcher()`` at process shutdown
(e.g. ``RunManager.shutdown``) for an explicit bounded drain.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import queue as _queue
import threading
from collections import OrderedDict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.api.errors import sanitize
from tools.api.event_log import (
    _DURABILITY_MODES,
    _FSYNC_INTERVAL_SECONDS,
    _IDX_EVERY,
    _IDX_NAME,
    _IDX_STRUCT,
    _is_important_event,
    _open_index_for_append,
    _parse_last_seq,
    _read_indexed_slice,
    _read_jsonl_events,
    _rebuild_index,
)
from tools.api.plugin_event_dispatcher import (
    _enqueue_plugin_event,
)
from tools.api.plugin_event_dispatcher import (
    _PluginEventDispatcher as _PluginEventDispatcher,
)
from tools.api.plugin_event_dispatcher import (
    _reset_plugin_dispatcher as _reset_plugin_dispatcher,
)
from tools.api.plugin_event_dispatcher import (
    _set_plugin_dispatcher as _set_plugin_dispatcher,
)
from tools.api.plugin_event_dispatcher import (
    shutdown_plugin_dispatcher as shutdown_plugin_dispatcher,
)
from tools.api.plugin_event_dispatcher import (
    wait_for_plugin_dispatcher_empty as wait_for_plugin_dispatcher_empty,
)

log = logging.getLogger("tools.api.event_broker")


class _CloseResult:
    """Awaitable shim returned by ``RunEventBroker.close()``.

    The drain is performed synchronously inside ``close()``; this object only
    exists so ``await broker.close()`` type-checks and runs. Bare
    ``broker.close()`` callers ignore it.
    """

    __slots__ = ()

    def __await__(self):  # type: ignore[no-untyped-def]
        async def _done() -> None:
            return None

        return _done().__await__()

    def __bool__(self) -> bool:
        return True


_CLOSED_OK = _CloseResult()


class _Pending:
    """Unsequenced emit waiting for the writer thread (P1-03).

    The writer assigns ``sequence`` in queue order, persists, appends to the
    ring, then resolves ``future`` with the full event dict. ``emit()`` awaits
    the future (no thread hop) so its return value still carries ``sequence``.
    """

    __slots__ = ("event", "event_type", "future", "payload", "timestamp")

    def __init__(self, event_type: str, payload: dict[str, Any], timestamp: str) -> None:
        import concurrent.futures as _futures

        self.event: dict[str, Any] | None = None
        self.event_type = event_type
        self.payload = payload
        self.timestamp = timestamp
        self.future: _futures.Future[Any] = _futures.Future()


class _Barrier:
    """Flush marker for read-your-writes consistency (P1-01).

    ``replay`` / ``replay_page`` / ``subscribe`` enqueue a barrier before
    reading the file; the writer flushes everything ahead of it and sets the
    future, so readers never miss queued-but-unflushed tail events. Best
    effort: on timeout the read proceeds anyway (never break serving).
    ``checkpoint()`` uses a barrier with ``fsync=True`` to force durability
    regardless of mode.
    """

    __slots__ = ("fsync", "future")

    def __init__(self, *, fsync: bool = False) -> None:
        import concurrent.futures as _futures

        self.fsync = fsync
        self.future: _futures.Future[Any] = _futures.Future()


class RunEventBroker:
    """Per-run event broker: one instance per active run.

    Events are written to ``reports/<run_id>/events.jsonl`` (authoritative)
    and held in a bounded in-memory ring for live WS delivery. Subscribers
    are notified via an ``asyncio.Condition``.

    Persistence uses a single-writer batched pipeline (P1-01): ``emit()``
    sanitizes, then hands an unsequenced pending item to a ``queue.Queue``.
    One dedicated daemon thread owns a single open FD and drains up to 128
    events (or every ~20ms), writing + flushing once per batch. fsync policy
    follows the durability mode (P1-02: ``strict`` per event, ``balanced``
    per batch window + important transitions, ``fast`` on checkpoint/close).

    Sequencing is writer-side (P1-03): the writer is the only sequencer, so
    file order == sequence order, gapless, even under concurrent ``emit()``.
    The writer appends to the ring in batch order and resolves each pending
    future with the full event dict; ``emit()`` awaits the ack (no thread
    hop) and then fans out to WS subscribers + the plugin dispatcher.
    ``close()`` enqueues a sentinel, joins the writer (tail flush + fsync),
    then stops fan-out queues. Replay paths drain the writer first so the
    file tail is never missed (read-your-writes).
    """

    _BATCH_MAX = 128
    # No linger window: with P1-03 ack-per-emit, one loop cannot outpace the
    # writer (each emit waits for its ack), so a linger would only tax
    # sequential flows without batching anything. Concurrent bursts still
    # batch: while the writer is busy, arrivals backlog and the non-blocking
    # drain collects them (up to _BATCH_MAX) after each blocking take.
    _BATCH_WAIT_SECONDS = 0.0

    def __init__(
        self, run_id: str, reports_dir: Path, *, buffer_size: int = 1000, durability: str = "balanced"
    ) -> None:
        self._run_id = run_id
        self._reports_dir = reports_dir
        self._events_path = reports_dir / "events.jsonl"
        self._ring: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        try:
            events_size = self._events_path.stat().st_size
        except OSError:
            self._seq = 0
        else:
            last_seq = _parse_last_seq(self._events_path, events_size)
            self._seq = last_seq if last_seq is not None else 0
        self._lock = asyncio.Lock()
        # Guards the ring: the writer thread appends (P1-03) while the event
        # loop reads. Short critical sections, never held across awaits.
        # Lock order: _lock -> _ring_lock (the writer takes only _ring_lock).
        self._ring_lock = threading.Lock()
        self._closed = False
        self._subscribers: list[asyncio.Queue[dict[str, Any] | None]] = []
        self._replay_watermarks: dict[asyncio.Queue[dict[str, Any] | None], int] = {}
        if durability not in _DURABILITY_MODES:
            log.warning(
                "unknown event durability %r — falling back to 'balanced' (never silently 'fast')",
                durability,
            )
            durability = "balanced"
        self._durability = durability
        # P1-01: single-writer batched JSONL pipeline.
        self._write_q: _queue.Queue = _queue.Queue()
        self._writer_lock = threading.Lock()
        self._writer_thread: threading.Thread | None = None

    @property
    def durability(self) -> str:
        """Effective durability mode (`strict` | `balanced` | `fast`)."""
        return self._durability

    def _ensure_writer_locked(self) -> None:
        """Start the writer thread (call with ``_writer_lock`` held)."""
        thread = self._writer_thread
        if thread is not None and thread.is_alive():
            return
        thread = threading.Thread(target=self._writer_loop, name=f"event-writer-{self._run_id}", daemon=True)
        self._writer_thread = thread
        thread.start()

    def _ensure_writer(self) -> None:
        with self._writer_lock:
            self._ensure_writer_locked()

    def _sequence_pending(self, item: _Pending) -> dict[str, Any]:
        """Assign the next sequence number and build the event dict.

        Runs only on the writer thread: the single sequencer, so file order
        == sequence order with no gaps even under concurrent emit().
        """
        self._seq += 1
        event = {
            "sequence": self._seq,
            "timestamp": item.timestamp,
            "run_id": self._run_id,
            "type": item.event_type,
            "payload": item.payload,
        }
        item.event = event
        return event

    def _writer_loop(self) -> None:
        import time as _time

        self._events_path.parent.mkdir(parents=True, exist_ok=True)
        f = self._events_path.open("a", encoding="utf-8")
        idx_f = _open_index_for_append(self._events_path.parent / _IDX_NAME)
        durability = self._durability
        last_fsync = _time.monotonic()

        def _checkpoint(seq: int) -> None:
            """Append an index record every _IDX_EVERY events (no extra fsync)."""
            if seq % _IDX_EVERY == 0:
                try:
                    idx_f.write(_IDX_STRUCT.pack(seq, f.tell()))
                except OSError:
                    pass

        def _flush_all() -> None:
            f.flush()
            idx_f.flush()

        def _fsync_all() -> None:
            os.fsync(f.fileno())
            try:
                os.fsync(idx_f.fileno())
            except OSError:
                pass

        try:
            while True:
                try:
                    batch: list[Any] = [self._write_q.get()]
                    while len(batch) < self._BATCH_MAX:
                        try:
                            batch.append(self._write_q.get(timeout=self._BATCH_WAIT_SECONDS))
                        except _queue.Empty:
                            break
                except Exception:  # noqa: BLE001 -- queue glitch must never kill the writer
                    log.warning("event writer queue error", exc_info=True)
                    continue
                done = False
                try:
                    # Phase 1: sequence pendings in queue order, then write.
                    # File order == sequence order by construction (P1-03):
                    # the writer is the only sequencer.
                    events: list[dict[str, Any] | _Barrier | _Pending | None] = []
                    if durability == "strict":
                        # Old behavior, kept for forensics: fsync per event.
                        for item in batch:
                            if item is None:
                                done = True
                                events.append(None)
                            elif isinstance(item, _Barrier):
                                events.append(item)
                                _flush_all()
                                _fsync_all()
                                last_fsync = _time.monotonic()
                            elif isinstance(item, _Pending):
                                event = self._sequence_pending(item)
                                f.write(json.dumps(event, default=str) + "\n")
                                _checkpoint(event["sequence"])
                                _flush_all()
                                _fsync_all()
                                last_fsync = _time.monotonic()
                                events.append(item)
                            else:  # pragma: no cover - defensive: unknown item
                                log.warning("event writer: unknown queue item %r", type(item))
                            self._write_q.task_done()
                    else:
                        important = False
                        for item in batch:
                            if item is None:
                                done = True
                                events.append(None)
                            elif isinstance(item, _Barrier):
                                events.append(item)
                            elif isinstance(item, _Pending):
                                event = self._sequence_pending(item)
                                f.write(json.dumps(event, default=str) + "\n")
                                _checkpoint(event["sequence"])
                                events.append(item)
                                if _is_important_event(str(event.get("type", "")), event.get("payload")):
                                    important = True
                            else:  # pragma: no cover - defensive: unknown item
                                log.warning("event writer: unknown queue item %r", type(item))
                            self._write_q.task_done()
                        # Phase 2: flush once per batch; fsync per policy.
                        _flush_all()
                        now = _time.monotonic()
                        if durability == "balanced":
                            if important or (now - last_fsync) >= _FSYNC_INTERVAL_SECONDS or done:
                                _fsync_all()
                                last_fsync = now
                        # `fast`: fsync only on sentinel/close + checkpoint().
                        for item in events:
                            if isinstance(item, _Barrier) and (item.fsync or durability == "balanced"):
                                # checkpoint() forces durability in any mode;
                                # balanced also fsyncs read barriers so replay
                                # cursors are crash-consistent.
                                _fsync_all()
                                last_fsync = _time.monotonic()
                    # Phase 3: publish in batch order — ring append, then
                    # resolve futures/barriers so emit() callers observe
                    # sequence order and read-your-writes holds.
                    with self._ring_lock:
                        for item in events:
                            if isinstance(item, _Pending) and item.event is not None:
                                self._ring.append(item.event)
                    for item in events:
                        if isinstance(item, _Barrier):
                            if not item.future.done():
                                item.future.set_result(None)
                        elif isinstance(item, _Pending):
                            if not item.future.done() and item.event is not None:
                                item.future.set_result(item.event)
                    if done:
                        # Sentinel/close always fsyncs regardless of mode.
                        try:
                            _flush_all()
                            _fsync_all()
                        except OSError:
                            pass
                        return
                except Exception:  # noqa: BLE001 -- one bad batch must never kill the writer
                    log.warning("event writer batch failed", exc_info=True)
                    continue
        finally:
            try:
                idx_f.close()
            except OSError:
                pass
            f.close()

    def _writer_alive(self) -> bool:
        thread = self._writer_thread
        return thread is not None and thread.is_alive()

    async def _drain_writer(self, timeout: float = 2.0) -> bool:
        """Wait until all queued events are flushed (read-your-writes)."""
        if not self._writer_alive():
            return True
        barrier = _Barrier()
        self._write_q.put(barrier)
        try:
            await asyncio.wait_for(asyncio.wrap_future(barrier.future), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def checkpoint(self, timeout: float = 10.0) -> bool:
        """Force an fsync of everything queued so far, regardless of mode.

        Used by `fast` mode callers at safe points (and available in every
        mode). Synchronous; returns False on timeout instead of raising.
        """
        import concurrent.futures as _futures

        if not self._writer_alive():
            return True
        barrier = _Barrier(fsync=True)
        self._write_q.put(barrier)
        try:
            barrier.future.result(timeout=timeout)
            return True
        except _futures.TimeoutError:
            return False

    async def emit(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Emit an event: sanitize, queue, await the writer's ack, fan out.

        P1-03 writer-side sequencing: the writer thread assigns ``sequence``
        in queue order (the single sequencer), persists, appends to the ring,
        then resolves the pending future. ``emit()`` awaits the ack off the
        event loop (no thread hop) so the return value still carries the full
        event dict with ``sequence``. File order == sequence order, gapless.
        """
        # ponytail: sanitize (CPU) outside any lock.
        clean = sanitize(payload)
        async with self._lock:
            if self._closed:
                raise RuntimeError("Event broker is closed.")
        # The writer lock serializes against close()'s sentinel so no event
        # can land behind the shutdown marker.
        pending = _Pending(event_type, clean, datetime.now(timezone.utc).isoformat())
        with self._writer_lock:
            if self._closed:
                raise RuntimeError("Event broker is closed.")
            self._ensure_writer_locked()
            self._write_q.put(pending)
        try:
            event = await asyncio.wait_for(asyncio.wrap_future(pending.future), timeout=30.0)
        except asyncio.TimeoutError as exc:
            raise RuntimeError("Event broker writer did not acknowledge emit.") from exc
        async with self._lock:
            subscribers = tuple((queue, self._replay_watermarks.get(queue, 0)) for queue in self._subscribers)
        for queue, replay_through in subscribers:
            # Persistence publishes to replay before emit's acknowledgement.
            # A subscriber may already have captured this event in its replay
            # while emit was awaiting that acknowledgement.
            if event["sequence"] <= replay_through:
                continue
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                async with self._lock:
                    if queue in self._subscribers:
                        self._subscribers.remove(queue)
                    self._replay_watermarks.pop(queue, None)
                self._stop_queue(queue)
        # Bounded dispatch for outbound-only plugin subscribers (webhook/ticketing).
        # Enqueued AFTER the writer persisted + published (ack) so a slow/failed
        # webhook never blocks the run or drops the event. The dispatcher runs
        # blocking subscribers off the event-loop thread via ``asyncio.to_thread``
        # and bounds queue/concurrency. See module docstring for shutdown semantics.
        _enqueue_plugin_event(event)
        return event

    async def replay(self, after: int = 0) -> list[dict[str, Any]]:
        """Replay events with sequence > ``after`` from JSONL."""
        async with self._lock:
            with self._ring_lock:
                if self._ring and after >= self._ring[0]["sequence"] - 1:
                    return [event for event in self._ring if event["sequence"] > after]
            path = self._events_path
        # P1-01: the writer flushes asynchronously; drain it before reading
        # the file so the tail is never missed (read-your-writes).
        await self._drain_writer()
        # ponytail: file read off-loop without the lock (was a sync read
        # under the lock). Ring fast-path above keeps the common case lock-only.
        full = await asyncio.to_thread(self._read_jsonl_events, path)
        return [
            evt
            for evt in full
            if isinstance(evt.get("sequence"), int)
            and not isinstance(evt.get("sequence"), bool)
            and evt["sequence"] > after
        ]

    def _replay_locked(self, after: int) -> list[dict[str, Any]]:
        with self._ring_lock:
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

    _read_jsonl_events = staticmethod(_read_jsonl_events)
    _rebuild_index = staticmethod(_rebuild_index)
    _read_indexed_slice = staticmethod(_read_indexed_slice)

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
        # ponytail: snapshot under the lock, release, then read the file
        # off-loop without the lock (was holding the lock across the await,
        # stalling every emitter/subscriber for the whole file read).
        async with self._lock:
            with self._ring_lock:
                if self._ring and self._ring[0]["sequence"] == 1:
                    full: list[dict[str, Any]] = list(self._ring)
                    path: Path | None = None
                else:
                    full = []
                    path = self._events_path
        if path is not None:
            await self._drain_writer()
            indexed = await asyncio.to_thread(self._read_indexed_slice, path, after, tail, before, limit)
            if indexed is not None:
                return indexed
            full = await asyncio.to_thread(self._read_jsonl_events, path)
            await asyncio.to_thread(self._rebuild_index, path)

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
        await self._drain_writer()
        async with self._lock:
            initial = self._replay_locked(after)
            subscription = EventSubscription(
                broker=self,
                initial=initial,
            )
            if not self._closed:
                self._subscribers.append(subscription._queue)
                self._replay_watermarks[subscription._queue] = max(
                    (event["sequence"] for event in initial), default=after
                )
            return subscription

    def close(self) -> "_CloseResult":
        """Flush the tail, fsync, stop the writer, then stop WS fan-out queues.

        Synchronous: drains the write queue via a sentinel + bounded thread
        join, so bare ``broker.close()`` (existing callers) persists
        everything. Returns an awaitable shim so ``await broker.close()``
        works too; the drain is already complete in either case.
        """
        with self._writer_lock:
            self._closed = True
            thread = self._writer_thread
            if thread is not None and thread.is_alive():
                self._write_q.put(None)
        if thread is not None and thread.is_alive():
            thread.join(timeout=10.0)
        with self._writer_lock:
            self._writer_thread = None
        for queue in self._subscribers:
            self._stop_queue(queue)
        self._subscribers.clear()
        self._replay_watermarks.clear()
        return _CLOSED_OK

    def reopen(self) -> None:
        """Re-arm a closed broker for post-run operator annotations.

        ``RunManager`` closes a run's broker when the run leaves active
        handling, but operator actions after the run (HITL decisions, …)
        still need a durable, sequenced event. Reopening resumes the stored
        sequence counter, so replay stays monotonic and future subscribers
        (poll/WS/SSE) observe the late event. No-op on an open broker. The
        writer thread restarts lazily on the next emit.
        """
        with self._writer_lock:
            self._closed = False

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
        self._broker._replay_watermarks.pop(self._queue, None)


class EventBrokerRegistry:
    """Owned run brokers plus a bounded LRU cache of unowned brokers.

    Active run owners acquire/release their broker. Archived-history reads
    can evict cache entries, but never a broker still owned by a live run.
    """

    def __init__(
        self, reports_dir: Path, *, buffer_size: int = 1000, max_brokers: int = 10, durability: str = "balanced"
    ) -> None:
        self._reports_dir = reports_dir
        self._buffer_size = buffer_size
        self._max_brokers = max(1, max_brokers)
        self._durability = durability
        self._brokers: OrderedDict[str, RunEventBroker] = OrderedDict()
        self._owners: dict[str, int] = {}

    def acquire(self, run_id: str, *, reports_dir: Path | None = None) -> RunEventBroker:
        """Pin the broker until the owner calls release (no eviction window)."""
        self._owners[run_id] = self._owners.get(run_id, 0) + 1
        try:
            return self.get_or_create(run_id, reports_dir=reports_dir)
        except BaseException:
            self.release(run_id)
            raise

    def release(self, run_id: str) -> None:
        """Release one owner; the broker becomes evictable after the last."""
        owners = self._owners.get(run_id, 0)
        if owners > 1:
            self._owners[run_id] = owners - 1
        else:
            self._owners.pop(run_id, None)
        self._trim_cache()

    def _trim_cache(self) -> None:
        unowned = [run_id for run_id in self._brokers if run_id not in self._owners]
        for run_id in unowned[: max(0, len(unowned) - self._max_brokers)]:
            self._brokers.pop(run_id).close()

    def get_or_create(self, run_id: str, *, reports_dir: Path | None = None) -> RunEventBroker:
        broker = self._brokers.get(run_id)
        if broker is not None:
            self._brokers.move_to_end(run_id)
            return broker
        rd = reports_dir or self._reports_dir / run_id
        broker = RunEventBroker(run_id, rd, buffer_size=self._buffer_size, durability=self._durability)
        self._brokers[run_id] = broker
        self._trim_cache()
        return broker

    def get(self, run_id: str) -> RunEventBroker | None:
        return self._brokers.get(run_id)

    def close_all(self) -> None:
        for b in self._brokers.values():
            b.close()
        self._brokers.clear()
        self._owners.clear()


def _fire_plugin_event_subscribers(event: dict[str, Any]) -> None:
    """Legacy synchronous fan-out — now enqueues to the bounded dispatcher.

    Preserved for backward compatibility (tests/external callers may import
    this symbol). New code should rely on ``RunEventBroker.emit()`` which
    enqueues via ``_enqueue_plugin_event``. This wrapper still never blocks:
    it hands the event to the dispatcher queue and returns immediately.
    Subscriber exceptions are handled inside the dispatcher workers.
    """
    _enqueue_plugin_event(event)
