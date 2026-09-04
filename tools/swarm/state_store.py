"""Swarm state persistence — history bounding + ``swarm_state.json``.

Extracted from ``SwarmOrchestrator`` (see ``tools/swarm/orchestrator.py``) to
keep the orchestrator under 500 lines. The functions below are bound onto
``SwarmOrchestrator`` after its definition, so ``self._persist_state`` call
sites and tests keep working unchanged. Disk writes go through
``tools.kernel.atomic_write_json`` (the shared crash-safe write both
engines use).
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from tools.kernel.orchestration import atomic_write_json


def _trim_history(self) -> None:
    """Bound ``_results`` and ``_battle_log`` in memory.

    Both lists are read only for their length and a recent tail
    (``_persist_state`` snapshots ``battle_log[-200:]``;
    ``_distill_episode_summary`` rolls up win-counts over the log). The
    full per-task outcome is persisted to ``swarm_state.json`` on every
    event, so dropping old in-memory entries reclaims the memory a long
    multi-cycle campaign would otherwise leak without losing any data a
    consumer actually reads.
    """
    if len(self._results) > self._max_results:
        del self._results[: len(self._results) - self._max_results]
    if len(self._battle_log) > self._max_battle_log:
        del self._battle_log[: len(self._battle_log) - self._max_battle_log]


def _persist_state(self, *, force: bool = False) -> None:
    """Persist a snapshot of swarm state for resume and live CLI progress.

    Throttled to at most one disk write per ``_state_persist_interval``
    (5s) unless ``force=True`` — bursty event paths (route per task,
    spawn per agent) otherwise fsync-spam a 200-cycle campaign. Resume
    correctness is kept: ``route_parallel`` forces a write at batch end,
    so the tail is never older than one batch.
    """
    if self._state_path is None:
        return
    if not force:
        now = time.monotonic()
        if now - self._last_persist < self._state_persist_interval:
            return
        self._last_persist = now
    else:
        self._last_persist = time.monotonic()
    snapshot = {
        "agents": [
            {
                "agent_id": agent.agent_id,
                "agent_type": agent.agent_type,
                "status": agent.status.value,
                "task_id": getattr(agent, "_task_id", ""),
            }
            for agent in self._agents.values()
        ],
        # Persist the FULL namespaced snapshot (global + per-target
        # buckets) so a resumed run restores per-host findings too,
        # not just the legacy flat global view. ``Blackboard.snapshot``
        # returns ``{__global__: {...}, "<target>": {...}, ...}``.
        "blackboard": self._blackboard.snapshot(),
        "blackboard_schema": "namespaced",
        # 200 entries gives the WebUI battle-log card a useful history
        # while keeping the snapshot bounded (_max_battle_log is 500).
        "battle_log_tail": self._battle_log[-200:],
        "results_count": len(self._results),
        "last_reflection": self._blackboard.get("last_reflection", {}),
        "strategy_shift": self._blackboard.get("strategy_shift", ""),
        "updated_at": time.time(),
    }
    atomic_write_json(self._state_path, snapshot)


def load_state(self, path: Path | str | None = None) -> bool:
    """Restore the shared blackboard from a persisted swarm_state.json.

    Tier 1.3: ``_persist_state`` already writes the blackboard snapshot on
    every event, but nothing originally read it back — so a
    resumed swarm started with a fresh blackboard, losing every discovered
    service / vulnerability hypothesis / credential / failed-module the
    prior run had accumulated. This restores those keys so the resumed
    swarm's agents (and critic, which is blackboard-aware) see the prior
    run's findings and don't repeat already-tried-and-failed work.

    Only the blackboard is restored (the agent list and battle-log tail are
    per-run execution state, not resumable intelligence). Unknown/extra
    keys in the file are ignored; missing keys keep their defaults. A
    missing/corrupt file returns False (fresh start), never raises — so a
    bad state file can't wedge the swarm.

    Handles two on-disk shapes:

    * **Namespaced** (current, ``blackboard_schema == "namespaced"`` or
      detected by presence of a ``__global__`` key): the value is
      ``{__global__: {...}, "<target>": {...}, ...}`` and is passed to
      ``Blackboard.merge_snapshot`` which restores both the global bucket
      and per-target buckets.
    * **Flat** (legacy, pre-parallel-swarm): the value is a plain
      ``{k: v}`` dict (the old ``dict(self._blackboard)`` global view).
      Merged key-by-key into the global bucket to preserve the original
      resume semantics — list values extended (order-preserving dedup),
      scalars replaced.
    """
    state_path = Path(path) if path is not None else self._state_path
    if state_path is None or not state_path.exists():
        return False
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    bb = data.get("blackboard")
    if not isinstance(bb, dict):
        return False

    # Namespaced shape (current): delegate to Blackboard.merge_snapshot.
    if data.get("blackboard_schema") == "namespaced" or "__global__" in bb:
        self._blackboard.merge_snapshot(bb)
        return True

    # Legacy flat shape: merge key-by-key into the global bucket. Keeps
    # the original resume semantics (list extend w/ dedup, scalar replace)
    # so a pre-parallel-swarm state file still resumes cleanly.
    for key, value in bb.items():
        current = self._blackboard.get(key)
        if isinstance(current, list) and isinstance(value, list):
            # Preserve ordering + dedup so resumed findings don't double up.
            self._blackboard.extend_list(key, value)
        else:
            self._blackboard.set_scalar(key, value)
    return True
