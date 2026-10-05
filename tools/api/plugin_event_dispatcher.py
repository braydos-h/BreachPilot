"""Bounded asynchronous dispatch for outbound plugin event subscribers."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

log = logging.getLogger("tools.api.event_broker")

_DEFAULT_PLUGIN_QUEUE_SIZE = 100
_DEFAULT_PLUGIN_WORKERS = 2
_DEFAULT_DRAIN_TIMEOUT = 5.0


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
