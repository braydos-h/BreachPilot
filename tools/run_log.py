"""Per-run run.log capture for console output and logging records.

The console streams and root logging handler are process-global, while API
assessments can execute concurrently. A context-local session routes each
write to the run that produced it; closing one run leaves other sessions
attached. Calls made in an unpropagated worker thread are routed only when
there is exactly one active session, avoiding cross-run attribution.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import re
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s:%(funcName)s:%(lineno)d — %(message)s"
_FORMATTER = logging.Formatter(_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")


class _RunSession:
    """One run's log file and serialized write operations."""

    def __init__(self, path: Path, handle: TextIO | None) -> None:
        self.path = path
        self.handle = handle
        self.lock = threading.Lock()
        self.active = True
        self.context_token: contextvars.Token[_RunSession | None] | None = None

    def write(self, text: str) -> None:
        with self.lock:
            if not self.active:
                return
            if self.handle is None:
                return
            try:
                self.handle.write(text)
                self.handle.flush()
            except Exception:
                pass

    def close(self) -> None:
        with self.lock:
            if not self.active:
                return
            self.active = False
            if self.handle is None:
                return
            try:
                self.handle.close()
            except OSError:
                pass


_CURRENT_SESSION: contextvars.ContextVar[_RunSession | None] = contextvars.ContextVar(
    "breachpilot_run_log_session", default=None
)


class _Tee:
    """Mirror a process stream and route captured text by execution context."""

    def __init__(self, real: TextIO) -> None:
        self._real = real

    def write(self, data: str) -> int:
        try:
            self._real.write(data)
        except Exception:
            pass
        session = RunLog._current_session()
        if session is not None:
            session.write(_ANSI_RE.sub("", data).replace("\r", ""))
        return len(data)

    def flush(self) -> None:
        try:
            self._real.flush()
        except Exception:
            pass

    def fileno(self) -> int:
        return self._real.fileno()

    def isatty(self) -> bool:
        return self._real.isatty()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class _ContextLogHandler(logging.Handler):
    """Single process-wide handler that routes each record to its run context."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.setFormatter(_FORMATTER)

    def emit(self, record: logging.LogRecord) -> None:
        session = RunLog._current_session()
        if session is None:
            return
        try:
            session.write(self.format(record) + "\n")
        except Exception:
            self.handleError(record)


class RunLog:
    """Capture console and logging output in context-local per-run files."""

    _lock = threading.RLock()
    _sessions: set[_RunSession] = set()
    _stdout: TextIO | None = None
    _stderr: TextIO | None = None
    _stdout_tee: _Tee | None = None
    _stderr_tee: _Tee | None = None
    _handler: _ContextLogHandler | None = None
    _old_root_level: int | None = None

    @classmethod
    def _current_session(cls) -> _RunSession | None:
        session = _CURRENT_SESSION.get()
        if session is not None:
            return session if session.active else None
        # asyncio.to_thread copies context, but run_in_executor does not. Keep
        # legacy single-run CLI capture for unpropagated workers while refusing
        # to guess when concurrent runs make ownership ambiguous. Never apply
        # this fallback to another asyncio task, such as an unrelated API
        # request running alongside the assessment.
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            return None
        with cls._lock:
            active = [candidate for candidate in cls._sessions if candidate.active]
            return active[0] if len(active) == 1 else None

    @classmethod
    def attach(cls, reports_dir: Path) -> None:
        """Attach the current execution context to ``reports_dir/run.log``."""
        path = Path(reports_dir) / "run.log"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle = path.open("a", encoding="utf-8", errors="replace")
        except OSError as exc:
            # Install a disabled context so this failed run cannot accidentally
            # fall back to another concurrent run's log.
            disabled = _RunSession(path, None)
            disabled.close()
            disabled.context_token = _CURRENT_SESSION.set(disabled)
            logging.getLogger(__name__).warning("run.log unavailable (%s): %s", path, exc)
            return

        session = _RunSession(path, handle)
        session.write(
            f"\n===== run started {datetime.now(timezone.utc).isoformat()} argv={sys.argv!r} log={path} =====\n"
        )
        with cls._lock:
            if not cls._sessions:
                cls._stdout, cls._stderr = sys.stdout, sys.stderr
                cls._stdout_tee = _Tee(cls._stdout)
                cls._stderr_tee = _Tee(cls._stderr)
                sys.stdout, sys.stderr = cls._stdout_tee, cls._stderr_tee

                root = logging.getLogger()
                cls._old_root_level = root.level
                root.setLevel(logging.DEBUG)
                cls._handler = _ContextLogHandler()
                root.addHandler(cls._handler)
            cls._sessions.add(session)
            session.context_token = _CURRENT_SESSION.set(session)

    @classmethod
    def detach(cls) -> None:
        """Detach and close only the current context's run log."""
        session = _CURRENT_SESSION.get()
        if session is None:
            return
        token = session.context_token
        if token is not None:
            try:
                _CURRENT_SESSION.reset(token)
            except ValueError:
                # A copied context cannot reset a token created by its parent.
                _CURRENT_SESSION.set(None)
        else:
            _CURRENT_SESSION.set(None)

        with cls._lock:
            session.close()
            cls._sessions.discard(session)
            if cls._sessions:
                return

            root = logging.getLogger()
            handler = cls._handler
            if handler is not None:
                root.removeHandler(handler)
            if cls._old_root_level is not None:
                root.setLevel(cls._old_root_level)
            if sys.stdout is cls._stdout_tee and cls._stdout is not None:
                sys.stdout = cls._stdout
            if sys.stderr is cls._stderr_tee and cls._stderr is not None:
                sys.stderr = cls._stderr
            cls._stdout = cls._stderr = None
            cls._stdout_tee = cls._stderr_tee = None
            cls._handler = None
            cls._old_root_level = None
        if handler is not None:
            handler.close()
