"""Milestone gating — per-(target, phase) completion events.

Extracted from ``SwarmOrchestrator`` (see ``tools/swarm/orchestrator.py``) to
keep the orchestrator under 500 lines. The functions below are bound onto
``SwarmOrchestrator`` after its definition, so ``self._mark_milestone`` call
sites and tests keep working unchanged.
"""

from __future__ import annotations

import threading


def _mark_milestone(self, target: str, phase: str) -> None:
    """Mark ``(target, phase)`` complete so dependent tasks can proceed.

    Idempotent: creating the event and setting it are both no-ops if
    already done. Called after every ``agent.run`` (even on failure) so a
    failed recon doesn't wedge a waiting vuln task forever — the vuln
    task will see an empty ``discovered_services`` and no-op, which is the
    correct degraded behavior, rather than hanging the campaign.
    """
    key = (target, phase)
    with self._lock:
        event = self._milestone_events.get(key)
        if event is None:
            event = threading.Event()
            self._milestone_events[key] = event
    event.set()


def is_milestone_set(self, target: str, phase: str) -> bool:
    """Check whether ``(target, phase)`` has completed (non-blocking).

    Useful for a caller deciding whether to skip a redundant task, or for
    the agent loop to avoid re-dispatching a phase that already ran.
    """
    with self._lock:
        event = self._milestone_events.get((target, phase))
    return event is not None and event.is_set()


def _await_milestone(self, target: str, phase: str, timeout: float | None = None) -> bool:
    """Block until ``(target, phase)`` is marked complete. Returns True if
    the event was set within timeout, False on timeout. Called from a
    worker thread (route_parallel runs agents via run_in_executor); safe
    to block here because only THIS task is waiting, not the whole loop.
    """
    with self._lock:
        event = self._milestone_events.get((target, phase))
        if event is None:
            event = threading.Event()
            self._milestone_events[(target, phase)] = event
    return event.wait(timeout=timeout)
