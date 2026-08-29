"""Structured mission-event logging for benchmark runs.

Writes one JSONL event stream per benchmark run (``events.jsonl``) plus a
per-trial stream, with monotonic ``sequence`` numbers, ISO timestamps, and
secret redaction reused from the project's audit kernel
(:func:`tools.kernel.audit._mask_secret_content`).

Events capture *operational* structure — planner decisions, tool requests and
results, sandbox verdicts, scope decisions, oracle results, phase changes —
never raw chain-of-thought. Long outputs are truncated before storage.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from tools.kernel.audit import _mask_secret_content

__all__ = ["BenchmarkEventLogger", "EventSink", "truncate_output"]

#: Maximum stored size for a single string payload field (raw outputs).
_MAX_FIELD = 2000

#: Payload fields whose entire value is truncated to a short marker.
_VERBATIM_FIELDS = frozenset({"stdout", "stderr", "output_text", "reasoning_text"})


def truncate_output(text: str, limit: int = _MAX_FIELD) -> str:
    """Redact secrets then truncate an output string for event storage."""
    masked = _mask_secret_content(str(text or ""))
    if len(masked) <= limit:
        return masked
    return masked[:limit] + f"... [truncated {len(masked) - limit} chars]"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class BenchmarkEventLogger:
    """Append-only structured event stream for one benchmark run.

    A single logger instance serves the whole run; ``trial_id`` tagging lets
    the API/WebUI filter the timeline per scenario trial. A write never raises
    to the caller — persistence best-effort, logging failures are swallowed so
    an event hiccup can never abort a benchmark.
    """

    path: Path
    run_id: str = ""
    sink: "EventSink | None" = None  # optional live subscriber fan-out (API)
    _seq: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _start: float = field(default_factory=time.monotonic, repr=False)

    def log(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        trial_id: str = "",
        scenario_id: str = "",
        agent: str = "",
        tool: str = "",
        target: str = "",
        level: str = "info",
    ) -> dict[str, Any]:
        """Append one event; returns the stored event dict."""
        with self._lock:
            self._seq += 1
            event: dict[str, Any] = {
                "sequence": self._seq,
                "timestamp": _now_iso(),
                "elapsed_seconds": round(time.monotonic() - self._start, 3),
                "run_id": self.run_id,
                "type": str(event_type),
                "level": level,
                "trial_id": trial_id,
                "scenario_id": scenario_id,
                "agent": agent,
                "tool": tool,
                "target": target,
                "payload": _redact_payload(payload or {}),
            }
            line = json.dumps(event, sort_keys=False, default=str)
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            except OSError:
                pass  # best-effort; never abort a benchmark over event I/O
        if self.sink is not None:
            try:
                self.sink(event)
            except Exception:  # noqa: BLE001 -- subscriber errors are never fatal
                pass
        return event

    @property
    def sequence(self) -> int:
        return self._seq


def _redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Redact secrets + bound sizes in one event payload (shallow, recursive)."""
    redacted: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, str):
            if key in _VERBATIM_FIELDS:
                redacted[key] = truncate_output(value)
            elif len(value) > _MAX_FIELD:
                redacted[key] = truncate_output(value)
            else:
                redacted[key] = truncate_output(value)
        elif isinstance(value, dict):
            redacted[key] = _redact_payload(value)
        elif isinstance(value, list):
            redacted[key] = [
                _redact_payload(item) if isinstance(item, dict) else truncate_output(item) if isinstance(item, str) else item
                for item in value
            ]
        else:
            redacted[key] = value
    return redacted


#: A live event subscriber: one serialized event dict per call.
EventSink = Callable[[dict[str, Any]], None]
