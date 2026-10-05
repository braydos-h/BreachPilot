"""Bounded FIFO worker for SQLite operations used by the API service.

The actor keeps synchronous SQLite work off the async request loop. Its
public compatibility import remains available from ``tools.api.persistence``.
"""

from __future__ import annotations

import asyncio
import queue as _queue
import threading
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tools.api.persistence import ApiPersistence


class DbActor:
    """Single-threaded FIFO front for :class:`ApiPersistence` (P1-10).

    Async server paths use ``await actor.arun(fn, *args, **kwargs)`` so the
    event loop never blocks on SQLite I/O; sync shims keep calling the
    persistence methods directly. One worker thread executes submissions in
    FIFO order; :meth:`submit_batch` groups calls into a single transaction
    via :meth:`ApiPersistence.batched`. The queue is bounded and fail-closed
    (``RuntimeError`` on full instead of unbounded growth). Errors propagate
    to the submitter. :meth:`close` drains the queue, then stops the worker.
    The worker never calls back into async code.
    """

    def __init__(self, persistence: ApiPersistence, *, max_queue: int = 1000) -> None:
        self._persistence = persistence
        self._queue: _queue.Queue = _queue.Queue(maxsize=max_queue)
        self._closed = False
        self._state_lock = threading.Lock()
        self._worker = threading.Thread(target=self._worker_loop, name="db-actor", daemon=True)
        self._worker.start()

    def _worker_loop(self) -> None:
        while True:
            try:
                op = self._queue.get()
            except Exception:  # noqa: BLE001 -- queue glitch must never kill the actor
                continue
            try:
                if op is None:  # sentinel
                    return
                future, kind, payload = op
                if future.done():
                    continue
                try:
                    if kind == "call":
                        fn, args, kwargs = payload
                        future.set_result(fn(*args, **kwargs))
                    else:  # "batch"
                        results = []
                        with self._persistence.batched():
                            for fn, args, kwargs in payload:
                                results.append(fn(*args, **kwargs))
                        future.set_result(results)
                except BaseException as exc:
                    if not future.done():
                        future.set_exception(exc)
            finally:
                try:
                    self._queue.task_done()
                except ValueError:
                    pass

    def submit(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Run ``fn(*args, **kwargs)`` on the DB thread; block for the result.

        Never call from the event loop (use :meth:`arun` there) — this blocks
        the calling thread until the worker finishes the op.
        """
        import concurrent.futures as _futures

        with self._state_lock:
            if self._closed:
                raise RuntimeError("DbActor is closed.")
            future: _futures.Future = _futures.Future()
            try:
                self._queue.put_nowait((future, "call", (fn, args, kwargs)))
            except _queue.Full as exc:
                raise RuntimeError("DbActor queue is full.") from exc
        return future.result()

    def submit_batch(self, calls: list[tuple[Any, tuple[Any, ...], dict[str, Any]]]) -> list[Any]:
        """Run ``calls`` back-to-back in one transaction; block for results."""
        import concurrent.futures as _futures

        with self._state_lock:
            if self._closed:
                raise RuntimeError("DbActor is closed.")
            future: _futures.Future = _futures.Future()
            try:
                self._queue.put_nowait((future, "batch", list(calls)))
            except _queue.Full as exc:
                raise RuntimeError("DbActor queue is full.") from exc
        return future.result()

    async def arun(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Async front for :meth:`submit` (off the event loop, FIFO ordered)."""
        return await asyncio.to_thread(self.submit, fn, *args, **kwargs)

    async def abatch(self, calls: list[tuple[Any, tuple[Any, ...], dict[str, Any]]]) -> list[Any]:
        """Async front for :meth:`submit_batch` (one transaction)."""
        return await asyncio.to_thread(self.submit_batch, calls)

    def close(self, timeout: float = 10.0) -> None:
        """Drain queued ops, then stop the worker (idempotent)."""
        with self._state_lock:
            if self._closed:
                worker = self._worker
            else:
                self._closed = True
                worker = self._worker
                try:
                    self._queue.put_nowait(None)
                except _queue.Full:
                    pass
        if worker.is_alive() and threading.current_thread() is not worker:
            worker.join(timeout=timeout)
