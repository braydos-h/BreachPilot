"""Campaign state — enums, task/state dataclasses, retry engine.

Canonical source for AttackTask / AttackState / AggressionLevel / AttackPhase /
TaskStatus / RetryEngine and the autonomous progress ContextVar helpers.
Moved from tools.autonomous_orchestrator (2743 LOC) to break the god file.
See tools/campaign/__init__.py and tools/autonomous_orchestrator.py shim.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Iterator

from tools.attack_ui import get_ui
from tools.logging_setup import get_logger
from tools.recon_pipeline import HostReconResult

logger = get_logger()
ui = get_ui()

_AUTONOMOUS_PROGRESS: ContextVar[Callable[[dict[str, Any]], None] | None] = ContextVar(
    "autonomous_progress",
    default=None,
)


@contextmanager
def observe_autonomous_progress(
    callback: Callable[[dict[str, Any]], None],
) -> Iterator[None]:
    """Route this task's autonomous phase/action updates to ``callback``."""
    token = _AUTONOMOUS_PROGRESS.set(callback)
    try:
        yield
    finally:
        _AUTONOMOUS_PROGRESS.reset(token)


def _report_autonomous_progress(**payload: Any) -> None:
    callback = _AUTONOMOUS_PROGRESS.get()
    if callback is not None:
        try:
            callback(payload)
        except Exception:  # noqa: BLE001 -- observability must never stop a campaign
            pass


