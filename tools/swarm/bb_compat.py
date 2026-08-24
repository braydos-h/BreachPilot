"""Backward-compat helpers for agents that write to the shared blackboard.

The swarm's ``Blackboard`` (``tools/swarm/blackboard.py``) exposes atomic
``set_scalar`` / ``append_to`` / ``extend_list`` / ``remove_from_list``
methods. Agents migrated to the atomic API call those methods to be safe
under ``route_parallel`` dispatch.

But several tests and a few non-swarm callers construct an agent directly and
pass a plain ``{}`` as the blackboard (e.g.
``tests/test_swarm_recon_fix.py`` does ``context = {"blackboard": {}}``).
A plain dict has no ``set_scalar`` — so the migrated agent would raise
``AttributeError``. We don't want to force every direct caller to construct a
``Blackboard``; the plain dict is the long-standing contract for "I just need
the agent to run, I don't care about parallel safety."

These helpers bridge the two: if the blackboard is a ``Blackboard`` (has the
method), use the atomic path; otherwise fall back to the legacy plain-dict
op. The fallback is NOT atomic — but it only runs in the test/legacy path
where there is no concurrency, so the race the atomic API exists to fix
cannot happen. Production (through ``SwarmOrchestrator``) always passes a
``Blackboard``, so the atomic path is the one that runs in production.
"""

from __future__ import annotations

from typing import Any


def bb_set(blackboard: Any, key: str, value: Any, *, target: str | None = None) -> None:
    """Set a scalar (overwrite). Atomic if blackboard is a Blackboard."""
    if hasattr(blackboard, "set_scalar"):
        blackboard.set_scalar(key, value, target=target)
    else:
        blackboard[key] = value


def bb_append(blackboard: Any, key: str, item: Any, *, target: str | None = None) -> None:
    """Append one item to a list key. Atomic if blackboard is a Blackboard.

    Creates the list if absent. On a plain dict this is the legacy
    get-then-set (NOT atomic, but fine for the single-threaded test/legacy
    path).
    """
    if hasattr(blackboard, "append_to"):
        blackboard.append_to(key, item, target=target)
    else:
        lst = blackboard.get(key)
        if not isinstance(lst, list):
            lst = []
            blackboard[key] = lst
        lst.append(item)


def bb_extend(
    blackboard: Any,
    key: str,
    items: list[Any] | tuple[Any, ...],
    *,
    target: str | None = None,
    dedupe: bool = True,
) -> None:
    """Extend a list key with multiple items. Atomic if blackboard is a Blackboard.

    On a plain dict falls back to order-preserving dedupe (matching the
    Blackboard default) so the test/legacy path behaves the same as production.
    """
    if hasattr(blackboard, "extend_list"):
        blackboard.extend_list(key, items, target=target, dedupe=dedupe)
    else:
        lst = blackboard.get(key)
        if not isinstance(lst, list):
            lst = []
            blackboard[key] = lst
        if dedupe:
            for item in items:
                if item not in lst:
                    lst.append(item)
        else:
            lst.extend(items)


def bb_remove(blackboard: Any, key: str, item: Any, *, target: str | None = None) -> None:
    """Remove one item from a list key (no-op if absent). Atomic if Blackboard."""
    if hasattr(blackboard, "remove_from_list"):
        blackboard.remove_from_list(key, item, target=target)
    else:
        lst = blackboard.get(key)
        if isinstance(lst, list):
            blackboard[key] = [m for m in lst if m != item]
