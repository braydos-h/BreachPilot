"""Structured AI decision logging (observability §17).

One append-only ``decision_log.jsonl`` per run directory. Each record is a
compact, field-typed decision event -- never hidden chain-of-thought, never
raw tool output. The WebUI can eventually render hypothesis -> action ->
evidence -> conclusion from these records; fields are chosen to be exactly
what that view needs.

Fail-silent by design: logging must never break the agent loop.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def decision_log_path(run_dir: Path | str) -> Path:
    return Path(run_dir) / "decision_log.jsonl"


def log_decision(
    run_dir: Path | str,
    *,
    round_num: int | None = None,
    task_id: str = "",
    target: str = "",
    capability: str = "",
    reason: str = "",
    applicability: float | None = None,
    model_role: str = "",
    duration_s: float | None = None,
    outcome: str = "",
    failure_class: str = "",
    success: bool | None = None,
    evidence_refs: list[str] | None = None,
) -> None:
    """Append one decision record. Never raises (observability is best-effort).
    """
    try:
        record: dict[str, Any] = {
            "ts": time.time(),
            "round": round_num,
            "task_id": task_id,
            "target": target,
            "capability": capability,
            "reason": reason[:300],
            "applicability": applicability,
            "model_role": model_role,
            "duration_s": duration_s,
            "outcome": outcome,
            "failure_class": failure_class,
            "success": success,
            "evidence_refs": list(evidence_refs or [])[:20],
        }
        path = decision_log_path(run_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except Exception:  # noqa: BLE001 -- logging must never break the loop
        pass
