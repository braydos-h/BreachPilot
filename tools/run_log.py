"""Per-run run.log: tees console output and all logging records into reports/<run_id>/run.log.

``RunLog.attach`` is process-global: the API daemon runs runs sequentially in
one process, so attach() re-points the same global tee/handler to the new
run's file. attach() detaches any previous run first, and a stale attach
self-heals on the next attach (the crash window's lines stay in the old log,
which is exactly what you want when debugging).
"""

from __future__ import annotations

import logging
import re
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s:%(funcName)s:%(lineno)d — %(message)s"


class _Tee:
    """Mirrors writes to the real stream and the run log."""

    def __init__(self, real: TextIO, log_handle: Any) -> None:
        self._real = real
        self._log = log_handle
        self._lock = threading.Lock()

    def write(self, data: str) -> int:
        try:
            self._real.write(data)
        except Exception:
            pass
        try:
            with self._lock:
                text = _ANSI_RE.sub("", data).replace("\r", "")
                self._log.write(text)
                self._log.flush()
        except Exception:
            pass
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


class RunLog:
    """One process-wide run log, re-attached per run."""

    _instance: "RunLog | None" = None

    @classmethod
    def attach(cls, reports_dir: Path) -> None:
        inst = cls._instance or cls()
        cls._instance = inst
        inst._attach(reports_dir)

    @classmethod
    def detach(cls) -> None:
        if cls._instance is not None:
            cls._instance._detach()

    def _attach(self, reports_dir: Path) -> None:
        self._detach()
        self._path = Path(reports_dir) / "run.log"
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = self._path.open("a", encoding="utf-8", errors="replace")
        except OSError as exc:
            self._handle = None
            logging.getLogger(__name__).warning("run.log unavailable (%s): %s", self._path, exc)
            return
        # Let every module's NOTSET-level logger propagate DEBUG+ records to
        # the single run.log handler; the root logger has no other handlers,
        # so console output is unchanged. Restored on detach.
        self._old_root_level = logging.getLogger().level
        logging.getLogger().setLevel(logging.DEBUG)
        self._handler = logging.FileHandler(self._path, encoding="utf-8")
        self._handler.setLevel(logging.DEBUG)
        self._handler.setFormatter(logging.Formatter(_FORMAT, datefmt="%Y-%m-%d %H:%M:%S"))
        logging.getLogger().addHandler(self._handler)
        self._stdout, self._stderr = sys.stdout, sys.stderr
        sys.stdout = _Tee(self._stdout, self._handle)
        sys.stderr = _Tee(self._stderr, self._handle)
        self._handle.write(
            f"\n===== run started {datetime.now(timezone.utc).isoformat()} argv={sys.argv!r} log={self._path} =====\n"
        )
        self._handle.flush()

    def _detach(self) -> None:
        handler = getattr(self, "_handler", None)
        if handler is not None:
            logging.getLogger().removeHandler(handler)
            handler.close()
        if getattr(self, "_stdout", None) is not None:
            sys.stdout = self._stdout
            sys.stderr = self._stderr
        if getattr(self, "_old_root_level", None) is not None:
            logging.getLogger().setLevel(self._old_root_level)
        handle = getattr(self, "_handle", None)
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass
        self._handler = None
        self._stdout = self._stderr = None
        self._handle = None
        self._old_root_level = None
