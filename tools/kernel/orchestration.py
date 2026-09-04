"""Orchestration kernel — one vocabulary for swarm + campaign.

``SwarmOrchestrator`` (``tools/swarm/``) and ``AutonomousOrchestrator``
(``tools/campaign/``) are alternative execution paths within a run (never
concurrent): the swarm decomposes one target across six specialist agents
with a critic pre-check, while the campaign drives a persistent multi-phase
attack queue with adaptive aggression. They keep SEPARATE state models on
purpose — the blackboard is volatile cross-agent intel, ``AttackState`` is
durable per-target campaign state (see the overlap table in docs/swarm.md).

This module holds the small pieces both engines genuinely reuse so the two
can't drift apart on them:

- ``MAX_MODULE_FAILURES`` — the "3 strikes" retry budget: the campaign
  ``_max_module_failures`` cap / per-task ``max_retries`` and the swarm
  reflection failure-pattern thresholds share one constant.
- ``atomic_write_json`` — crash-safe progress-state persistence (tmp file +
  atomic replace, Windows-safe): ``swarm_state.json`` and
  ``attack_states.json`` both write through it.
- ``safe_emit`` — fire-and-forget progress callbacks: the swarm
  ``event_callback`` and the campaign ``_report_autonomous_progress``
  ContextVar hook share the swallow-all-errors contract (observability must
  never break an attack path).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

# ponytail: single retry-budget precedent (campaign _max_module_failures=3).
# A module/pattern that fails this many times is dropped or pivoted away
# from, never retried forever.
MAX_MODULE_FAILURES: int = 3


def atomic_write_json(path: Path | str, payload: dict[str, Any]) -> None:
    """Write ``payload`` as JSON without ever leaving a partial file.

    Tmp file + ``os.replace`` (atomic overwrite on Windows and POSIX —
    ``Path.rename`` raises ``FileExistsError`` on Windows when the target
    exists, which is why this helper exists). Swallows I/O and encoding
    errors: a failed progress write must never break an attack path.
    """
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        os.replace(tmp, p)
    except (OSError, ValueError, TypeError):
        pass


def safe_emit(callback: Callable[..., None] | None, *args: Any, **kwargs: Any) -> None:
    """Invoke an observability callback; never raise, never block the path.

    ``None`` callback is a no-op. Any callback error is swallowed —
    progress reporting (swarm events, campaign phase hooks) is advisory.
    """
    if callback is None:
        return
    try:
        callback(*args, **kwargs)
    except Exception:  # noqa: BLE001 -- observability must never stop a campaign
        pass
