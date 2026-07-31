"""Thread- and async-safe shared blackboard for the multi-agent swarm.

Replaces the plain dict that ``SwarmOrchestrator`` originally used as its
inter-agent state. The plain dict had two classes of concurrency hazard once
``route_parallel`` is enabled (the 5 hazards documented at
``orchestrator.py:route_parallel``):

1. **List read-modify-write races** — every agent did
   ``bb["k"] = bb.get("k", []) + [x]`` (get-then-set, not atomic). Under
   parallel dispatch two agents can both read ``[]`` and both write ``[a]`` /
   ``[b]``, losing one entry. The orchestrator's own merge at :228 had the
   same shape (fixed once via setdefault-on-list bug, but still not atomic
   under unlock).
2. **Cross-target overwrite** — same-phase parallel tasks share one
   ``discovered_services`` / ``vulnerability_hypotheses`` key, so the last
   writer wins and earlier targets' findings are lost.

This class fixes both:

- **Atomic list ops** — ``append_to`` / ``extend_list`` take a process-wide
  ``threading.Lock`` (agents run in ``run_in_executor`` worker threads under
  ``route_parallel``) so the get-then-append-then-set sequence is atomic.
- **Per-target namespacing** — every write accepts an optional ``target``
  scope. ``bb.set_scalar("discovered_services", [...], target="10.0.0.5")``
  writes to ``targets["10.0.0.5"]["discovered_services"]``; a read with no
  target reads the ``__global__`` bucket (backward compat with the old single
  flat dict). The orchestrator's milestone keys (``recon_complete``,
  ``access_achieved``, etc.) stay global; per-host findings go namespaced.

Backward compatibility is the load-bearing constraint: ~25 read sites across
the 6 agents + the orchestrator + the autonomous orchestrator + the critic's
LLM prompt all do ``bb["k"]`` / ``bb.get("k")``. This class therefore
**subclasses ``dict``** so all existing reads work unchanged; only the
~12 *write* sites are migrated to the atomic methods. Reads see the
``__global__`` bucket (the legacy flat-dict view). Per-target reads go
through the explicit ``get(key, target=...)`` / ``get_target(target)`` API.
"""

from __future__ import annotations

import threading
from typing import Any


_GLOBAL = "__global__"


class Blackboard(dict):
    """A ``dict`` subclass with atomic list/scalar writes and per-target namespacing.

    Subclassing ``dict`` means every existing ``bb["k"]`` / ``bb.get("k", d)``
    read site in the swarm keeps working unchanged — those reads hit the
    ``__global__`` bucket. Migrate write sites to the atomic methods.
    """

    def __init__(self, initial: dict[str, Any] | None = None) -> None:
        super().__init__()
        # _buckets[__global__] is the legacy flat-dict view that dict.__getitem__
        # etc. read from. Per-target buckets are namespaced under target IPs.
        self._buckets: dict[str, dict[str, Any]] = {_GLOBAL: {}}
        # Single process-wide lock. Agents run in run_in_executor worker threads
        # (route_parallel) OR on the main loop (route); either way this process
        # is the sole owner, so a threading.Lock is the right primitive (an
        # asyncio.Lock would deadlock if acquired from a worker thread and vice
        # versa — threading.Lock works from both).
        self._lock = threading.Lock()
        # Seed the global bucket from any initial values so callers that
        # construct Blackboard({"k": v}) keep working.
        if initial:
            for k, v in initial.items():
                self.set_scalar(k, v)

    # ── Dict-compat surface (reads hit __global__) ──────────────────────

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            return self._buckets[_GLOBAL][key]

    def __setitem__(self, key: str, value: Any) -> None:
        # Kept for backward compat with any straggler write site we missed in
        # the migration. Routes through set_scalar so it's still atomic + hits
        # the global bucket. New code should call set_scalar / append_to
        # explicitly so the intent (overwrite vs. append) is clear.
        self.set_scalar(key, value)

    def __delitem__(self, key: str) -> None:
        with self._lock:
            del self._buckets[_GLOBAL][key]

    def __contains__(self, key: object) -> bool:
        with self._lock:
            return key in self._buckets[_GLOBAL]

    def get(self, key: str, default: Any = None, *, target: str | None = None) -> Any:
        """Read a key from the global bucket, or from a named target bucket.

        ``target=None`` (default) reads the global bucket — backward compat
        with the legacy flat dict. ``target="10.0.0.5"`` reads that target's
        namespaced state (e.g. its discovered_services).
        """
        with self._lock:
            bucket = self._buckets[target or _GLOBAL]
            return bucket.get(key, default)

    # ── Atomic writes ───────────────────────────────────────────────────

    def set_scalar(self, key: str, value: Any, *, target: str | None = None) -> None:
        """Atomically set a scalar (overwrite). Thread-safe. Auto-creates the
        target bucket if it doesn't exist yet (so a parallel recon agent can
        write to its target without the orchestrator pre-seeding the bucket).
        """
        with self._lock:
            bucket_key = target or _GLOBAL
            self._buckets.setdefault(bucket_key, {})[key] = value

    def append_to(self, key: str, item: Any, *, target: str | None = None) -> None:
        """Atomically append one item to a list key. Creates the list (and the
        target bucket) if absent.

        Replaces ``bb["k"] = bb.get("k", []) + [x]`` — the get-then-set race
        named in the route_parallel warning. Order-preserving dedup is NOT
        applied here (callers that want dedup use ``extend_list`` with the
        default); raw append keeps the common case O(1).
        """
        with self._lock:
            bucket_key = target or _GLOBAL
            bucket = self._buckets.setdefault(bucket_key, {})
            lst = bucket.get(key)
            if not isinstance(lst, list):
                lst = []
                bucket[key] = lst
            lst.append(item)

    def extend_list(
        self,
        key: str,
        items: list[Any] | tuple[Any, ...],
        *,
        target: str | None = None,
        dedupe: bool = True,
    ) -> None:
        """Atomically extend a list key with multiple items.

        Replaces the orchestrator's setdefault-on-list merge
        (``orchestrator.py:228``) which was order-preserving but not atomic
        under unlock. ``dedupe=True`` (default) preserves insertion order
        while skipping items already present — the same semantics the
        orchestrator's milestone-merge used, now thread-safe. ``dedupe=False``
        is a plain extend (faster, for high-volume non-dedupe cases).
        """
        with self._lock:
            bucket_key = target or _GLOBAL
            bucket = self._buckets.setdefault(bucket_key, {})
            lst = bucket.get(key)
            if not isinstance(lst, list):
                lst = []
                bucket[key] = lst
            if dedupe:
                for item in items:
                    if item not in lst:
                        lst.append(item)
            else:
                lst.extend(items)

    def remove_from_list(self, key: str, item: Any, *, target: str | None = None) -> None:
        """Atomically remove one item from a list key (no-op if absent).

        Used by the reflection agent's "clear modules that just succeeded"
        logic (``reflection_agent.py:243-245``) — that read-then-filter-then-set
        was another race under parallel dispatch.
        """
        with self._lock:
            bucket_key = target or _GLOBAL
            bucket = self._buckets.get(bucket_key)
            if not bucket:
                return
            lst = bucket.get(key)
            if isinstance(lst, list):
                bucket[key] = [m for m in lst if m != item]

    # ── Per-target bucket access ────────────────────────────────────────

    def get_target(self, target: str) -> dict[str, Any]:
        """Return a *copy* of one target's namespaced state."""
        with self._lock:
            return dict(self._buckets.get(target, {}))

    def set_target(self, target: str, updates: dict[str, Any]) -> None:
        """Merge updates into a target's bucket (scalars overwrite, lists extend)."""
        with self._lock:
            bucket = self._buckets.setdefault(target, {})
            for k, v in updates.items():
                if isinstance(v, list):
                    lst = bucket.get(k)
                    if not isinstance(lst, list):
                        lst = []
                        bucket[k] = lst
                    for item in v:
                        if item not in lst:
                            lst.append(item)
                else:
                    bucket[k] = v

    def targets(self) -> list[str]:
        """Return all target bucket names (excluding __global__)."""
        with self._lock:
            return [t for t in self._buckets if t != _GLOBAL]

    # ── Snapshot / merge ────────────────────────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        """Return a deep-ish copy of the full state for persistence / resume.

        Returns ``{__global__: {...}, "<target>": {...}, ...}``. The
        orchestrator's ``_persist_state`` and ``load_state`` consume this.
        Existing consumers that read ``snapshot()["blackboard"]`` expect a
        flat dict — the orchestrator adapts the shape on persist (see
        ``orchestrator._persist_state`` migration).
        """
        with self._lock:
            return {t: dict(b) for t, b in self._buckets.items()}

    def merge_snapshot(self, snapshot: dict[str, Any]) -> None:
        """Restore state from a ``snapshot()`` (the inverse).

        Used by ``orchestrator.load_state`` to restore a resumed run's
        blackboard. Scalars overwrite, lists extend (order-preserving dedupe)
        — matching the resume semantics the old ``load_state`` already had.
        """
        if not isinstance(snapshot, dict):
            return
        with self._lock:
            for t, bucket in snapshot.items():
                if not isinstance(bucket, dict):
                    continue
                target_key = t if t != _GLOBAL else _GLOBAL
                dst = self._buckets.setdefault(target_key, {})
                for k, v in bucket.items():
                    if isinstance(v, list):
                        lst = dst.get(k)
                        if not isinstance(lst, list):
                            lst = []
                            dst[k] = lst
                        for item in v:
                            if item not in lst:
                                lst.append(item)
                    else:
                        dst[k] = v

    # ── Flat-dict compat for code that iterates the whole blackboard ────

    def flat(self) -> dict[str, Any]:
        """Return the ``__global__`` bucket as a plain dict.

        For consumers that want the legacy flat view (e.g. the reflection
        agent's ``_llm_reflect`` prompt builder that does
        ``blackboard.get('access_achieved')``). Equivalent to casting this
        object to ``dict`` for reads — but explicit so the namespacing isn't
        accidentally lost.
        """
        with self._lock:
            return dict(self._buckets[_GLOBAL])

    def keys(self) -> Any:  # type: ignore[override]
        with self._lock:
            return self._buckets[_GLOBAL].keys()

    def values(self) -> Any:  # type: ignore[override]
        with self._lock:
            return self._buckets[_GLOBAL].values()

    def items(self) -> Any:  # type: ignore[override]
        with self._lock:
            return self._buckets[_GLOBAL].items()

    def update(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        """Dict-style update into the global bucket (atomic overwrite)."""
        with self._lock:
            self._buckets[_GLOBAL].update(*args, **kwargs)

    def __len__(self) -> int:
        with self._lock:
            return len(self._buckets[_GLOBAL])

    def __repr__(self) -> str:
        with self._lock:
            return f"Blackboard({self._buckets[_GLOBAL]!r}, targets={list(t for t in self._buckets if t != _GLOBAL)})"