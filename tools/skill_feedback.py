"""Cross-mission skill feedback bridge.

Records which runtime skills the model actually loaded and whether the
phase they informed produced wins, then exposes a Beta posterior
``skill_prior`` the selector uses as a **boost-only** score term. Reuses
``ExperienceStore``'s ``lessons`` table so skill feedback lives alongside
the exploit-action confidence data and persists across missions via the
same SQLite DB.

Storage shape (advisory data only -- never execution authority):

- ``target_signature`` = ``"skill:<name>"``
- ``action_type``      = ``"skill"``
- ``outcome``          = ``"partial"`` for a *load* (a neutral observation
  that increments the sample count without skewing the posterior), or
  ``"success``/``failure`` for a phase-end *outcome*.

Advisory invariant: outcomes only ever *boost* a skill in the selector; a
negative track record simply fails to boost (it never excludes
safety-relevant methodology, never changes scope/permission/audit). Every
entry is wrapped in try/except so a store/DB issue can never break the
assessment loop.
"""

from __future__ import annotations

import threading
from typing import Any

_SKILL_ACTION = "skill"


def _sig(skill_name: str) -> str:
    return f"skill:{skill_name}"


def record_skill_loaded(
    store: Any | None,
    skill_name: str,
    *,
    metadata: dict[str, Any] | None = None,
) -> str | None:
    """Record a neutral ``skill_loaded`` observation. No-op without a store."""
    if store is None or not skill_name:
        return None
    try:
        meta: dict[str, Any] = {"event": "loaded"}
        if metadata:
            meta.update(metadata)
        return store.record_outcome(_sig(skill_name), _SKILL_ACTION, "partial", metadata=meta)
    except Exception:
        return None


def record_skill_outcome(
    store: Any | None,
    skill_name: str,
    *,
    success: bool,
    metadata: dict[str, Any] | None = None,
) -> str | None:
    """Record a phase-end success/failure outcome for a skill. No-op without a store."""
    if store is None or not skill_name:
        return None
    try:
        meta: dict[str, Any] = {"event": "outcome", "success": bool(success)}
        if metadata:
            meta.update(metadata)
        outcome = "success" if success else "failure"
        return store.record_outcome(_sig(skill_name), _SKILL_ACTION, outcome, metadata=meta)
    except Exception:
        return None


def skill_prior(store: Any | None, skill_name: str) -> float:
    """Beta posterior mean for a skill (0.5 neutral when below ``min_samples``)."""
    if store is None or not skill_name:
        return 0.5
    try:
        return float(store.get_confidence(_sig(skill_name), _SKILL_ACTION))
    except Exception:
        return 0.5


def skill_observation_count(store: Any | None, skill_name: str) -> int:
    """Total recorded observations (loads + outcomes) for a skill."""
    if store is None or not skill_name:
        return 0
    try:
        return int(store.observation_count(_sig(skill_name), _SKILL_ACTION))
    except Exception:
        return 0


def bootstrap_skill_priors(store: Any | None, registry: Any) -> None:
    """Reserved cold-start hook. Intentionally a no-op for now: the Beta(1,1)
    prior already gives every skill a neutral 0.5 until real observations
    arrive, so seeding is unnecessary. Kept so callers can wire it without
    depending on a later implementation."""
    return None


# ── Shared store accessor ────────────────────────────────────────────────

_shared_store: Any | None = None
_shared_store_lock = threading.Lock()


def get_shared_skill_store(config: dict[str, Any] | None) -> Any | None:
    """Lazily build and cache a process-wide ``ExperienceStore`` for skill
    feedback, backed by the default DB so priors persist across missions.

    Returns None if no DB is reachable (the selector then skips the feedback
    boost -- tag matching remains the floor). Separate from the exploit
    loop's own store, but both wrap the same SQLite DB so writes from either
    are visible to the other.
    """
    global _shared_store
    with _shared_store_lock:
        if _shared_store is not None:
            return _shared_store
        try:
            from db import get_default_db
            from tools.experience_store import ExperienceStore

            mem_cfg = (config or {}).get("memory", {}) or {}
            min_samples = int(mem_cfg.get("experience_min_samples", 3))
            decay = float(mem_cfg.get("experience_time_decay_days", 90.0))
            _shared_store = ExperienceStore(get_default_db(), min_samples=min_samples, time_decay_days=decay)
        except Exception:
            _shared_store = None
        return _shared_store


def reset_shared_skill_store() -> None:
    """Clear the cached shared store (tests use this between cases)."""
    global _shared_store
    with _shared_store_lock:
        _shared_store = None
