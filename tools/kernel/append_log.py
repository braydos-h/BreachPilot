"""Shared append-only log writer (PERF P2-07).

One reusable primitive for every append-only JSONL log in the codebase
(``tools/kernel/audit.py``, the exploit-policy audit chain,
``llm_usage.jsonl``, ``decision_log.jsonl``, ``activity.jsonl``). Each log
keeps its own schema -- only the transport is shared: a single open FD per
path, serialization in the caller thread, batched background flush, explicit
``checkpoint()``/``close()``.

Durability modes (aligned with the P1-02 event-broker modes):

- ``strict``: fsync after every batch. Slowest; nothing acked is lost.
- ``balanced`` (default): flush every batch, fsync at most once per second
  plus on ``checkpoint()``/``close()``. A crash loses at most the recent
  acked-but-unfsynced tail (the documented durability window).
- ``fast``: flush every batch, fsync only on ``checkpoint()``/``close()``.
  A crash may lose everything since the last checkpoint.

``append()`` blocks until the caller's line is flushed to the OS, so
read-your-writes holds: a reader opening the file after ``append()`` returns
sees the line. Batching pays off under concurrency (simultaneous appends
land in one write); sequential callers cost one flush each but never pay
open/close per record (the P2-07 win -- ``audit.py`` used to open+close
twice per tool call).

Multi-process appends (sandbox worker vs host): every writer opens its file
with ``O_APPEND`` and each batch is emitted as a single ``write()`` syscall,
which the kernel applies atomically against other ``O_APPEND`` writers, so
lines from two processes never interleave mid-line. Cross-process total
order is kernel arrival order (there is no global sequence number);
hash-chained logs (``ExploitPolicy``) additionally require a SINGLE chained
writer per file per host -- chain serialization (``prev_hash`` assignment)
happens under the caller's lock *before* enqueue, so in-process order ==
file order, but two processes chaining into one file would fork the chain.
Unchained rows from a second process interleave as whole lines and are
skipped by the chain verifier.

Never share one writer across different schemas/paths: the registry below
is keyed by path so each file gets exactly one writer; do not multiplex two
schemas into one file.
"""

from __future__ import annotations

import atexit
import logging
import os
import queue
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)

DURABILITY_MODES = ("strict", "balanced", "fast")

# Balanced mode fsyncs at most this often; checkpoint()/close() always fsync.
_BALANCED_FSYNC_SECONDS = 1.0

# Queue entry: (payload, ack, errors). Payload is a text line, a _Barrier
# (forces fsync, then acks), or None (close sentinel, acks nothing).
_QueueEntry = tuple[object, threading.Event, list[BaseException]]

_MKDIR_CACHE: set[str] = set()
_MKDIR_LOCK = threading.Lock()


def _mkdir_cached(path: Path) -> None:
    """Create ``path.parent`` once per process (mirrors audit._MKDIR_CACHE)."""
    key = str(path.parent)
    with _MKDIR_LOCK:
        if key in _MKDIR_CACHE:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        _MKDIR_CACHE.add(key)


class _Barrier:
    """Checkpoint marker: the writer fsyncs, then sets ``done``."""

    __slots__ = ("done", "error")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.error: list[BaseException] = []


class AppendLogWriter:
    """Single-FD batched append writer for one log file.

    Serialization (``json.dumps``) happens in the caller thread; ``append()``
    only enqueues the finished line. One background thread owns the FD and
    drains up to ``batch_max`` lines per write+flush.
    """

    def __init__(
        self,
        path: Path | str,
        durability: str = "balanced",
        batch_max: int = 128,
        flush_ms: float = 20,
    ) -> None:
        if durability not in DURABILITY_MODES:
            log.warning("unknown append durability %r -- falling back to 'balanced'", durability)
            durability = "balanced"
        self._path = Path(path)
        self._durability = durability
        self._batch_max = max(1, int(batch_max))
        # Idle-queue poll cadence. Acked appends are already flushed, so this
        # only bounds how long the writer sleeps with nothing to do; it adds
        # no latency to append() (which wakes the writer via the queue).
        self._flush_s = max(0.0, float(flush_ms) / 1000.0)
        _mkdir_cached(self._path)
        # 0o600 from the first byte (os.open mode); tighten pre-existing
        # files best-effort so ported logs keep the audit perm contract.
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        self._file = os.fdopen(fd, "a", encoding="utf-8")
        self._queue: queue.Queue[_QueueEntry] = queue.Queue()
        self._state_lock = threading.Lock()
        self._closed = False
        self._thread = threading.Thread(
            target=self._writer_loop,
            name=f"append-log-{self._path.name}",
            daemon=True,
        )
        self._thread.start()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def durability(self) -> str:
        return self._durability

    @property
    def closed(self) -> bool:
        with self._state_lock:
            return self._closed

    def append(self, line: str) -> None:
        """Enqueue one line and wait until it is flushed to the OS."""
        if not line.endswith("\n"):
            line += "\n"
        ack = threading.Event()
        errors: list[BaseException] = []
        with self._state_lock:
            if self._closed:
                raise ValueError(f"AppendLogWriter for {self._path} is closed")
            self._queue.put((line, ack, errors))
        ack.wait()
        if errors:
            raise errors[0]

    def checkpoint(self) -> None:
        """Flush + fsync everything appended so far; returns when durable."""
        barrier = _Barrier()
        with self._state_lock:
            if self._closed:
                return  # close() already fsynced the tail.
            self._queue.put((barrier, barrier.done, barrier.error))
        barrier.done.wait()
        if barrier.error:
            raise barrier.error[0]

    def close(self) -> None:
        """Drain the queue, fsync, join the writer thread. Idempotent."""
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            self._queue.put((None, threading.Event(), []))
        self._thread.join()

    def _writer_loop(self) -> None:
        f = self._file
        durability = self._durability
        last_fsync = time.monotonic()
        try:
            while True:
                try:
                    first = self._queue.get(timeout=self._flush_s or 0.05)
                except queue.Empty:
                    continue
                batch: list[_QueueEntry] = [first]
                while len(batch) < self._batch_max:
                    try:
                        batch.append(self._queue.get_nowait())
                    except queue.Empty:
                        break
                closing = False
                force_fsync = False
                texts: list[str] = []
                for payload, _ack, _errs in batch:
                    if payload is None:
                        closing = True
                    elif isinstance(payload, _Barrier):
                        force_fsync = True
                    else:
                        texts.append(str(payload))
                try:
                    if texts:
                        # Single write() on an O_APPEND fd: atomic against
                        # other processes appending to the same file, so
                        # lines never interleave mid-line (see module docs).
                        f.write("".join(texts))
                        f.flush()
                    now = time.monotonic()
                    if durability == "strict":
                        if texts or closing or force_fsync:
                            self._fsync_best_effort(f.fileno())
                            last_fsync = now
                    elif durability == "balanced":
                        if force_fsync or closing or (texts and now - last_fsync >= _BALANCED_FSYNC_SECONDS):
                            self._fsync_best_effort(f.fileno())
                            last_fsync = now
                    elif force_fsync or closing:
                        # fast: fsync only on checkpoint/close.
                        self._fsync_best_effort(f.fileno())
                        last_fsync = now
                    for _payload, ack, _errs in batch:
                        ack.set()
                    if closing:
                        return
                except Exception as exc:  # noqa: BLE001 -- ack the failure, keep the thread alive
                    for _payload, ack, errs in batch:
                        errs.append(exc)
                        ack.set()
                    if closing:
                        return
        finally:
            try:
                f.close()
            except OSError:
                pass

    @staticmethod
    def _fsync_best_effort(fileno: int) -> None:
        try:
            os.fsync(fileno)
        except OSError as exc:
            # Durability is best-effort on filesystems that reject fsync;
            # failing the tool call would be worse than a wider crash window.
            log.warning("append-log fsync failed: %s", exc)


_WRITERS: dict[str, AppendLogWriter] = {}
_WRITERS_LOCK = threading.Lock()


def _registry_key(path: Path | str) -> str:
    return os.path.abspath(os.fspath(path))


def get_append_writer(
    path: Path | str,
    durability: str = "balanced",
    batch_max: int = 128,
    flush_ms: float = 20,
) -> AppendLogWriter:
    """Return the process-wide writer for ``path``, creating it on demand.

    One writer per path (never share across schemas/paths -- give each log
    file its own path and it gets its own FD/ordering). The first call wins
    on durability; later calls with a different mode get the existing writer.
    """
    key = _registry_key(path)
    with _WRITERS_LOCK:
        existing = _WRITERS.get(key)
        if existing is not None and not existing.closed:
            return existing
        writer = AppendLogWriter(key, durability=durability, batch_max=batch_max, flush_ms=flush_ms)
        _WRITERS[key] = writer
        return writer


def checkpoint_all() -> None:
    """fsync every registered writer (bounded; errors raise per writer)."""
    with _WRITERS_LOCK:
        writers = list(_WRITERS.values())
    for writer in writers:
        try:
            writer.checkpoint()
        except Exception:  # noqa: BLE001 -- one stuck writer must not block shutdown fsync of the rest
            log.warning("append-log checkpoint failed for %s", writer.path, exc_info=True)


def close_all_writers() -> None:
    """Drain + fsync + close every registered writer. Idempotent."""
    with _WRITERS_LOCK:
        writers = list(_WRITERS.values())
        _WRITERS.clear()
    for writer in writers:
        try:
            writer.close()
        except Exception:  # noqa: BLE001 -- best-effort shutdown path
            log.warning("append-log close failed for %s", writer.path, exc_info=True)


def _close_all_at_exit() -> None:
    try:
        close_all_writers()
    except Exception:  # noqa: BLE001 -- interpreter shutdown is best-effort
        pass


atexit.register(_close_all_at_exit)
