"""Campaign state persistence — ``attack_states.json`` save/load + stop.

Extracted from ``AutonomousOrchestrator`` (see
``tools/campaign/orchestrator.py``) to keep the orchestrator under 500
lines. Bound onto ``AutonomousOrchestrator`` after its definition, so
``self.save_state`` / ``self.load_state`` call sites and tests keep working
unchanged. Disk writes go through ``tools.kernel.orchestration``
(the shared crash-safe write both engines use).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from tools.campaign.state import AttackState, AttackTask
from tools.kernel.orchestration import atomic_write_json
from tools.logging_setup import get_logger

logger = get_logger()


def save_state(self, path: Path | None = None) -> Path:
    """Save all attack states to disk."""
    save_path = path or self._workspace / "attack_states.json"
    data = {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "states": {t: s.to_dict() for t, s in self._states.items()},
        "tasks": {tid: t.to_dict() for tid, t in self._tasks.items()},
        # ponytail: without this, load_state leaves _task_counter at 0 and
        # _new_task_id restarts at ATK-00001, colliding with restored task
        # IDs and overwriting them (silent data loss on every resume).
        "task_counter": self._task_counter,
    }
    atomic_write_json(save_path, data)
    logger.info(f"Attack state saved to {save_path}")
    return save_path


def load_state(self, path: Path) -> bool:
    """Load attack states from disk (Tier 1.3 — made real).

    Reconstructs ``self._states`` (per-target AttackState, including the
    embedded recon_result) and ``self._tasks`` (the task queue with
    statuses/priorities/chain links intact) from a state file previously
    written by ``save_state``. This is what lets a resumed campaign skip
    already-completed recon and not re-fire succeeded/failed modules.

    Returns True if state was loaded, False if the file is missing/empty/
    unreadable (so callers can treat a missing file as a fresh start
    rather than an error). Never raises on malformed content — a corrupt
    state file logs a warning and is treated as no state, so a bad file
    can't wedge the orchestrator out of starting.
    """
    if not path.exists():
        logger.info(f"load_state: no state file at {path} (fresh start)")
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning(f"load_state: corrupt state file {path} ({exc}); starting fresh")
        return False
    if not isinstance(data, dict):
        logger.warning(f"load_state: {path} is not a JSON object; starting fresh")
        return False

    states_data = data.get("states", {}) or {}
    tasks_data = data.get("tasks", {}) or {}
    # Restore the counter BEFORE any new task can be minted so resumed
    # campaigns do not re-issue ATK-00001 and clobber loaded task records.
    try:
        self._task_counter = int(data.get("task_counter", 0))
    except (TypeError, ValueError):
        self._task_counter = 0
    loaded_states = 0
    loaded_tasks = 0
    for target, sdict in states_data.items():
        if not isinstance(sdict, dict):
            continue
        try:
            self._states[str(target)] = AttackState.from_dict(sdict)
            loaded_states += 1
        except Exception as exc:  # defensive: one bad state shouldn't kill resume
            logger.warning(f"load_state: skipping state for {target} ({exc})")
    for tid, tdict in tasks_data.items():
        if not isinstance(tdict, dict):
            continue
        try:
            self._tasks[str(tid)] = AttackTask.from_dict(tdict)
            loaded_tasks += 1
        except Exception as exc:
            logger.warning(f"load_state: skipping task {tid} ({exc})")

    logger.info(f"Attack state loaded from {path} ({loaded_states} states, {loaded_tasks} tasks)")
    return loaded_states > 0 or loaded_tasks > 0


def stop(self) -> None:
    """Gracefully stop the orchestrator."""
    self._running = False
    logger.info("Orchestrator stop signal received")
