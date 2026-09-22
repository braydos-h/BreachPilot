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
import struct
import threading
from collections import OrderedDict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.api.errors import sanitize

log = logging.getLogger("tools.api.event_broker")

_DEFAULT_PLUGIN_QUEUE_SIZE = 100
_DEFAULT_PLUGIN_WORKERS = 2
_DEFAULT_DRAIN_TIMEOUT = 5.0


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


_DURABILITY_MODES = ("strict", "balanced", "fast")
_FSYNC_INTERVAL_SECONDS = 0.25

# P2-01 indexed replay: `events.idx` sidecar — binary rows
# `(sequence:u64, byte_offset:u64)` checkpointed every _IDX_EVERY events by
# the writer thread. A checkpoint (S, O) means "event S+1 begins at byte
# offset O". Paged reads seek to the nearest checkpoint below the target and
# parse only the needed byte range: O(page), not O(N).
_IDX_EVERY = 256
_IDX_STRUCT = struct.Struct("<QQ")
_IDX_NAME = "events.idx"
_IDX_MAGIC = b"BPIDX1\x00\x00"
_IDX_HEADER = struct.Struct("<8sQQ")
_IDX_ORDER_SORTED = 0x01
# Events that force an fsync even in `balanced` (never lose decisions /
# terminal transitions to a crash inside the 250ms window).
_IMPORTANT_EVENT_TYPES = frozenset(
    {
        "run_finished",
        "run_failed",
        "run_checkpoint",
        "decision",
        "decision_created",
        "hitl_decision",
        "approval",
    }
)
_TERMINAL_STATES = frozenset({"completed", "failed", "cancelled", "interrupted"})


def _is_important_event(event_type: str, payload: Any) -> bool:
    """True when an event must survive a crash even in `balanced` mode."""
    if event_type in _IMPORTANT_EVENT_TYPES:
        return True
    if event_type == "state" and isinstance(payload, dict):
        return str(payload.get("state", "")) in _TERMINAL_STATES
    return False


def _load_index(idx_path: Path, file_size: int) -> list[tuple[int, int]] | None:
    """Load and validate checkpoints; None when missing/corrupt/stale/unsorted.

    Corrupt, truncated, or unordered sidecars are never fatal: the caller
    falls back to a full read once, then rebuilds the index. The
    ORDER_SORTED flag is required: only files the new writer produced (or
    verified-sorted rebuilds) may use O(page) seeks.
    """
    try:
        data = idx_path.read_bytes()
    except OSError:
        return None
    if len(data) < _IDX_HEADER.size or (len(data) - _IDX_HEADER.size) % _IDX_STRUCT.size != 0:
        return None
    try:
        magic, flags, _reserved = _IDX_HEADER.unpack_from(data)
    except struct.error:
        return None
    if magic != _IDX_MAGIC or not (flags & _IDX_ORDER_SORTED):
        return None
    recs = [(int(s), int(o)) for s, o in _IDX_STRUCT.iter_unpack(data[_IDX_HEADER.size :])]
    prev_s, prev_o = 0, 0
    for s, o in recs:
        if s <= prev_s or o < prev_o or o > file_size:
            return None
        prev_s, prev_o = s, o
    return recs


def _seek_for_seq(recs: list[tuple[int, int]], seq: int) -> int:
    """Byte offset from which parsing covers ``seq`` (largest checkpoint below it)."""
    offset = 0
    for s, o in recs:
        if s < seq:
            offset = o
        else:
            break
    return offset


def _parse_first_seq(path: Path) -> int | None:
    """Sequence of the first event (one line parsed)."""
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                seq = evt.get("sequence") if isinstance(evt, dict) else None
                if isinstance(seq, int) and not isinstance(seq, bool):
                    return seq
                return None
    except OSError:
        return None
    return None


def _parse_last_seq(path: Path, file_size: int) -> int | None:
    """Sequence of the last event (tail block parsed, no full scan)."""
    if file_size <= 0:
        return None
    try:
        with path.open("rb") as f:
            tail = min(file_size, 65536)
            f.seek(file_size - tail)
            chunk = f.read(tail).decode("utf-8", errors="replace")
    except OSError:
        return None
    for line in reversed(chunk.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        seq = evt.get("sequence") if isinstance(evt, dict) else None
        if isinstance(seq, int) and not isinstance(seq, bool):
            return seq
    return None


def _parse_seq_range(
    path: Path, start_offset: int, want_from: int, want_to: int | None, end_size: int
) -> list[dict[str, Any]]:
    """Parse events with ``want_from <= seq < want_to`` from ``start_offset``.

    Stops at ``end_size`` (concurrent-writer snapshot) or ``want_to``.
    Assumes gapless sequencing (guaranteed by writer-side sequencing).
    """
    events: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as f:
            f.seek(start_offset)
            while True:
                if f.tell() >= end_size:
                    break
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                seq = evt.get("sequence") if isinstance(evt, dict) else None
                if not isinstance(seq, int) or isinstance(seq, bool):
                    continue
                if seq < want_from:
                    continue
                if want_to is not None and seq >= want_to:
                    break
                events.append(evt)
    except OSError:
        return events
    return events


def _empty_page() -> dict[str, Any]:
    return {
        "events": [],
        "oldest_sequence": None,
        "latest_sequence": None,
        "has_more_before": False,
        "first_returned_sequence": None,
        "last_returned_sequence": None,
        "omitted_before": 0,
        "next_before": None,
    }


def _shape_indexed_page(
    window: list[dict[str, Any]],
    oldest: int,
    latest: int,
    base_count: int,
    after: int,
    tail: int | None,
    before: int | None,
    limit: int | None,
) -> dict[str, Any]:
    """Shape a paged result from an indexed window (gapless arithmetic).

    ``base_count`` is the population the window was drawn from (``total``
    for tail pages, the ``seq < before`` count for before pages). Mirrors
    the legacy full-read branches in ``replay_page`` exactly: same keys,
    same newest-first order for ``before`` pages, same ``tail=0``-means-all
    edge.
    """
    if tail is not None:
        want = base_count if tail <= 0 else min(tail, base_count)
        events = window[-want:] if want < len(window) else list(window)
        if events:
            first_returned = events[0]["sequence"]
            last_returned = events[-1]["sequence"]
            omitted_before = base_count - len(events)
            has_more_before = omitted_before > 0
            next_before = first_returned if has_more_before else None
        else:
            first_returned = last_returned = next_before = None
            has_more_before = False
            omitted_before = 0
    elif before is not None:
        events = list(reversed(window))
        if events:
            first_returned = window[0]["sequence"]
            last_returned = window[-1]["sequence"]
            omitted_before = base_count - len(window)
            has_more_before = omitted_before > 0
            next_before = first_returned if has_more_before else None
        else:
            first_returned = last_returned = next_before = None
            has_more_before = False
            omitted_before = 0
    else:
        events = list(window)
        if events:
            first_returned = events[0]["sequence"]
            last_returned = events[-1]["sequence"]
        else:
            first_returned = last_returned = None
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


def _open_index_for_append(idx_path: Path) -> Any:
    """Open the sidecar for appends, (re)writing the header when needed.

    A corrupt/foreign file is truncated back to a fresh header so the writer
    never grows garbage the reader would reject.
    """
    try:
        size = idx_path.stat().st_size
    except OSError:
        size = 0
    if size == 0:
        handle = idx_path.open("ab")
        try:
            handle.write(_IDX_HEADER.pack(_IDX_MAGIC, _IDX_ORDER_SORTED, 0))
            handle.flush()
        except OSError:
            pass
        return handle
    try:
        head = idx_path.read_bytes()[: _IDX_HEADER.size]
        magic, _flags, _reserved = _IDX_HEADER.unpack(head)
        if magic == _IDX_MAGIC:
            return idx_path.open("ab")
    except (OSError, struct.error):
        pass
    handle = idx_path.open("wb")
    try:
        handle.write(_IDX_HEADER.pack(_IDX_MAGIC, _IDX_ORDER_SORTED, 0))
        handle.flush()
    except OSError:
        pass
    return handle


class _PluginEventDispatcher:
    """Bounded producer/consumer dispatcher for plugin event subscribers.

    See module docstring for architecture and shutdown semantics.
    """

    def __init__(
        self,
        max_queue_size: int = _DEFAULT_PLUGIN_QUEUE_SIZE,
        max_workers: int = _DEFAULT_PLUGIN_WORKERS,
    ) -> None:
        self._max_queue_size = max_queue_size
        self._max_workers = max_workers
        self._queue: asyncio.Queue[dict[str, Any] | None] | None = None
        self._workers: list[asyncio.Task[Any]] = []
        self._started_loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()
        self._closed = False
        self._dropped = 0
        self._enqueued = 0
        self._processed = 0

    @property
    def max_queue_size(self) -> int:
        return self._max_queue_size

    @property
    def max_workers(self) -> int:
        return self._max_workers

    @property
    def dropped(self) -> int:
        return self._dropped

    @property
    def enqueued(self) -> int:
        return self._enqueued

    @property
    def qsize(self) -> int:
        return self._queue.qsize() if self._queue is not None else 0

    def _ensure_started(self, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            if self._queue is not None and self._started_loop is loop and self._workers:
                if all(not w.done() for w in self._workers):
                    return
            if self._queue is not None and self._started_loop is not loop:
                stale = list(self._workers)
                self._workers.clear()
                for w in stale:
                    try:
                        if hasattr(w, "get_loop") and w.get_loop() is loop:
                            w.cancel()
                    except Exception:
                        pass
                old_q = self._queue
                self._queue = None
                self._started_loop = None
                if old_q is not None:
                    while True:
                        try:
                            old_q.get_nowait()
                            try:
                                old_q.task_done()
                            except ValueError:
                                pass
                        except asyncio.QueueEmpty:
                            break
                        except Exception:
                            break
            if self._queue is None:
                self._queue = asyncio.Queue(maxsize=self._max_queue_size)
                self._started_loop = loop
            self._workers = [w for w in self._workers if not w.done()]
            needed = self._max_workers - len(self._workers)
            for _ in range(needed):
                idx = len(self._workers)
                task = loop.create_task(self._worker_loop(idx))
                try:
                    task.set_name(f"plugin-event-dispatcher-{idx}")
                except Exception:
                    pass
                self._workers.append(task)

    def enqueue(self, event: dict[str, Any]) -> bool:
        """Non-blocking enqueue; returns True if accepted, False if dropped."""
        if self._closed:
            return False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            log.warning(
                "plugin event dispatcher: no running loop, dropping event %s seq=%s",
                event.get("type"),
                event.get("sequence"),
            )
            return False
        self._ensure_started(loop)
        assert self._queue is not None
        try:
            self._queue.put_nowait(event)
            self._enqueued += 1
            return True
        except asyncio.QueueFull:
            self._dropped += 1
            log.warning(
                "plugin event dispatcher queue full (%d/%d) — dropping webhook delivery for event %s seq=%s (total dropped %d)",
                self._queue.qsize(),
                self._max_queue_size,
                event.get("type"),
                event.get("sequence"),
                self._dropped,
            )
            return False

    async def _worker_loop(self, idx: int) -> None:
        assert self._queue is not None
        q = self._queue
        try:
            worker_loop = asyncio.get_running_loop()
        except RuntimeError:
            worker_loop = None
        while True:
            if q is not self._queue:
                break
            if worker_loop is not None and self._started_loop is not worker_loop:
                break
            try:
                event = await q.get()
                if event is None:
                    q.task_done()
                    break
                try:
                    await self._dispatch_one(event)
                finally:
                    q.task_done()
                    self._processed += 1
            except asyncio.CancelledError:
                break
            except GeneratorExit:
                break
            except RuntimeError as exc:
                if "bound to a different event loop" in str(exc):
                    log.warning("plugin event dispatcher worker %d exiting: queue bound to different loop", idx)
                    break
                if "no running event loop" in str(exc):
                    break
                log.warning("plugin event dispatcher worker %d crashed", idx, exc_info=True)
                try:
                    await asyncio.sleep(0.05)
                except (asyncio.CancelledError, GeneratorExit, RuntimeError):
                    break
                continue
            except BaseException:
                log.warning("plugin event dispatcher worker %d crashed", idx, exc_info=True)
                try:
                    await asyncio.sleep(0.05)
                except (asyncio.CancelledError, GeneratorExit, RuntimeError):
                    break
                continue

    async def _dispatch_one(self, event: dict[str, Any]) -> None:
        try:
            from tools.plugins import PLUGIN_REGISTRY

            subscribers = list(PLUGIN_REGISTRY.event_subscribers)
        except Exception:  # noqa: BLE001
            return
        for fn in subscribers:
            try:
                await asyncio.to_thread(fn, event)
            except BaseException:
                log.warning(
                    "plugin event subscriber %r failed",
                    getattr(fn, "__name__", fn),
                    exc_info=True,
                )

    async def wait_until_empty(self, timeout: float | None = _DEFAULT_DRAIN_TIMEOUT) -> bool:
        """Wait until the queue is empty (all enqueued events processed).

        Returns True if drained within timeout, False on timeout.
        """
        q = self._queue
        if q is None:
            return True
        try:
            if timeout is None:
                await q.join()
                return True
            await asyncio.wait_for(q.join(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def shutdown(self, drain_timeout: float | None = _DEFAULT_DRAIN_TIMEOUT) -> None:
        """Bounded drain then discard and reset dispatcher.

        See module docstring for shutdown semantics.
        """
        self._closed = True
        q = self._queue
        if q is None:
            for w in list(self._workers):
                w.cancel()
            if self._workers:
                await asyncio.gather(*self._workers, return_exceptions=True)
            self._workers.clear()
            self._started_loop = None
            self._closed = False
            return
        if drain_timeout is None:
            drain_timeout = _DEFAULT_DRAIN_TIMEOUT
        if drain_timeout > 0:
            try:
                await asyncio.wait_for(q.join(), timeout=drain_timeout)
            except asyncio.TimeoutError:
                pending = q.qsize()
                log.warning(
                    "plugin event dispatcher drain timed out after %.1fs — discarding %d pending webhook events (processed %d, dropped %d)",
                    drain_timeout,
                    pending,
                    self._processed,
                    self._dropped,
                )
                while True:
                    try:
                        q.get_nowait()
                        q.task_done()
                    except asyncio.QueueEmpty:
                        break
                    except Exception:
                        break
        else:
            pending = q.qsize()
            if pending:
                log.warning(
                    "plugin event dispatcher discarding %d pending webhook events on shutdown (drain_timeout=0)",
                    pending,
                )
            while True:
                try:
                    q.get_nowait()
                    q.task_done()
                except asyncio.QueueEmpty:
                    break
                except Exception:
                    break
        for _ in list(self._workers):
            try:
                q.put_nowait(None)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.task_done()
                    q.put_nowait(None)
                except Exception:
                    pass
            except Exception:
                pass
        if self._workers:
            try:
                await asyncio.wait_for(asyncio.gather(*self._workers, return_exceptions=True), timeout=2.0)
            except asyncio.TimeoutError:
                for w in self._workers:
                    w.cancel()
                await asyncio.gather(*self._workers, return_exceptions=True)
            self._workers.clear()
        self._queue = None
        self._started_loop = None
        self._closed = False

    def reset_for_tests(self) -> None:
        """Synchronous reset for tests when no loop is running."""
        self._closed = False
        self._dropped = 0
        self._enqueued = 0
        self._processed = 0
        if self._queue is not None:
            while True:
                try:
                    self._queue.get_nowait()
                    try:
                        self._queue.task_done()
                    except ValueError:
                        pass
                except asyncio.QueueEmpty:
                    break
                except RuntimeError:
                    break
                except Exception:
                    break
        for w in list(self._workers):
            try:
                if not w.done():
                    w.cancel()
            except RuntimeError:
                pass
            except Exception:
                pass
        self._workers.clear()
        self._queue = None
        self._started_loop = None


_PLUGIN_DISPATCHER: _PluginEventDispatcher | None = None
_PLUGIN_DISPATCHER_LOCK = threading.Lock()


def _get_plugin_dispatcher() -> _PluginEventDispatcher:
    global _PLUGIN_DISPATCHER
    with _PLUGIN_DISPATCHER_LOCK:
        if _PLUGIN_DISPATCHER is None:
            _PLUGIN_DISPATCHER = _PluginEventDispatcher(
                max_queue_size=_DEFAULT_PLUGIN_QUEUE_SIZE,
                max_workers=_DEFAULT_PLUGIN_WORKERS,
            )
        return _PLUGIN_DISPATCHER


def _set_plugin_dispatcher(dispatcher: _PluginEventDispatcher | None) -> None:
    global _PLUGIN_DISPATCHER
    with _PLUGIN_DISPATCHER_LOCK:
        _PLUGIN_DISPATCHER = dispatcher


def _reset_plugin_dispatcher() -> None:
    global _PLUGIN_DISPATCHER
    with _PLUGIN_DISPATCHER_LOCK:
        if _PLUGIN_DISPATCHER is not None:
            _PLUGIN_DISPATCHER.reset_for_tests()
        _PLUGIN_DISPATCHER = None


def _enqueue_plugin_event(event: dict[str, Any]) -> None:
    try:
        disp = _get_plugin_dispatcher()
        disp.enqueue(event)
    except Exception:  # noqa: BLE001
        log.warning("failed to enqueue plugin event %s", event.get("type"), exc_info=True)


async def shutdown_plugin_dispatcher(drain_timeout: float | None = _DEFAULT_DRAIN_TIMEOUT) -> None:
    """Public shutdown helper: bounded drain of pending webhook deliveries."""
    disp: _PluginEventDispatcher | None
    with _PLUGIN_DISPATCHER_LOCK:
        disp = _PLUGIN_DISPATCHER
    if disp is not None:
        await disp.shutdown(drain_timeout=drain_timeout)


async def wait_for_plugin_dispatcher_empty(timeout: float | None = _DEFAULT_DRAIN_TIMEOUT) -> bool:
    """Wait until the plugin dispatcher queue is drained (for tests)."""
    disp: _PluginEventDispatcher | None
    with _PLUGIN_DISPATCHER_LOCK:
        disp = _PLUGIN_DISPATCHER
    if disp is None:
        return True
    return await disp.wait_until_empty(timeout=timeout)


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
        self._seq = 0
        self._lock = asyncio.Lock()
        # Guards the ring: the writer thread appends (P1-03) while the event
        # loop reads. Short critical sections, never held across awaits.
        # Lock order: _lock -> _ring_lock (the writer takes only _ring_lock).
        self._ring_lock = threading.Lock()
        self._closed = False
        self._subscribers: list[asyncio.Queue[dict[str, Any] | None]] = []
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
            subscribers = tuple(self._subscribers)
        for queue in subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                async with self._lock:
                    if queue in self._subscribers:
                        self._subscribers.remove(queue)
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
        # ponytail perf: concurrent emits may append out of sequence order
        # (sequence is assigned under the asyncio lock, file write happens
        # outside it). Sort so replay cursors stay correct.
        try:
            events.sort(key=lambda e: e.get("sequence", 0) if isinstance(e, dict) else 0)
        except TypeError:
            pass
        return events

    @staticmethod
    def _rebuild_index(path: Path) -> None:
        """Full scan once + atomic idx rewrite (only when file order is sorted).

        Legacy files without a sidecar take one slow read, then get an index
        for every later page. Unsorted legacy files are left alone (slow path
        stays correct for them).
        """
        idx_path = path.parent / _IDX_NAME
        try:
            seqs: list[tuple[int, int]] = []  # (sequence, end_offset)
            with path.open("rb") as f:
                while True:
                    line = f.readline()
                    if not line:
                        break
                    end = f.tell()
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    seq = evt.get("sequence") if isinstance(evt, dict) else None
                    if isinstance(seq, int) and not isinstance(seq, bool):
                        seqs.append((seq, end))
        except OSError:
            return
        if not seqs:
            return
        if any(b < a for a, b in zip([s for s, _ in seqs], [s for s, _ in seqs][1:])):
            return  # unordered legacy file: keep the correct slow path
        try:
            tmp = idx_path.with_name(_IDX_NAME + ".tmp")
            with tmp.open("wb") as out:
                out.write(_IDX_HEADER.pack(_IDX_MAGIC, _IDX_ORDER_SORTED, 0))
                for seq, end in seqs:
                    if seq % _IDX_EVERY == 0:
                        out.write(_IDX_STRUCT.pack(seq, end))
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, idx_path)
        except OSError:
            pass

    def _read_indexed_slice(
        self, path: Path, after: int, tail: int | None, before: int | None, limit: int | None
    ) -> dict[str, Any] | None:
        """O(page) paged read via ``events.idx``; None when the index is unusable.

        Runs off the event loop (blocking file I/O). Snapshots the file size
        at entry so a concurrently appending writer cannot corrupt the read.
        """
        try:
            size = path.stat().st_size
        except OSError:
            return _empty_page()
        if size == 0:
            return _empty_page()
        recs = _load_index(path.parent / _IDX_NAME, size)
        if recs is None:
            return None
        oldest = _parse_first_seq(path)
        latest = _parse_last_seq(path, size)
        if oldest is None or latest is None or oldest != 1 or latest < oldest:
            # Truncated/rotated or unreadable: the index no longer describes
            # this file — slow path (which also rebuilds when sortable).
            return None
        total = latest - oldest + 1
        if tail is not None:
            want = total if tail <= 0 else min(tail, total)
            start = latest - want + 1
            window = _parse_seq_range(path, _seek_for_seq(recs, start), start, latest + 1, size)
            return _shape_indexed_page(window, oldest, latest, total, after, tail, before, limit)
        if before is not None:
            hi = min(before, latest + 1)
            base_count = max(0, hi - oldest)
            want = base_count if limit is None else min(limit, base_count)
            start = hi - want
            window = _parse_seq_range(path, _seek_for_seq(recs, start), start, hi, size)
            return _shape_indexed_page(window, oldest, latest, base_count, after, tail, before, limit)
        window = _parse_seq_range(path, _seek_for_seq(recs, after + 1), after + 1, latest + 1, size)
        return _shape_indexed_page(window, oldest, latest, len(window), after, tail, before, limit)

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
            subscription = EventSubscription(
                broker=self,
                initial=self._replay_locked(after),
            )
            if not self._closed:
                self._subscribers.append(subscription._queue)
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


class EventBrokerRegistry:
    """Registry of per-run event brokers. One active broker at a time."""

    def __init__(
        self, reports_dir: Path, *, buffer_size: int = 1000, max_brokers: int = 10, durability: str = "balanced"
    ) -> None:
        self._reports_dir = reports_dir
        self._buffer_size = buffer_size
        self._max_brokers = max_brokers
        self._durability = durability
        self._brokers: OrderedDict[str, RunEventBroker] = OrderedDict()

    def get_or_create(self, run_id: str, *, reports_dir: Path | None = None) -> RunEventBroker:
        broker = self._brokers.get(run_id)
        if broker is not None:
            self._brokers.move_to_end(run_id)
            return broker
        rd = reports_dir or self._reports_dir / run_id
        broker = RunEventBroker(run_id, rd, buffer_size=self._buffer_size, durability=self._durability)
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
    """Legacy synchronous fan-out — now enqueues to the bounded dispatcher.

    Preserved for backward compatibility (tests/external callers may import
    this symbol). New code should rely on ``RunEventBroker.emit()`` which
    enqueues via ``_enqueue_plugin_event``. This wrapper still never blocks:
    it hands the event to the dispatcher queue and returns immediately.
    Subscriber exceptions are handled inside the dispatcher workers.
    """
    _enqueue_plugin_event(event)
