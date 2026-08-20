"""In-memory evidence reference store with content-based dedup.

Pure reference store; the SQLite ``evidence`` table will wrap this later.
Thread-safe via a module-level lock.
"""

from __future__ import annotations

import threading

from .reference import EvidenceReference

_LOCK = threading.Lock()


class EvidenceStoreV2:
    """Dict-backed store keyed by ref_id.

    ``put`` is idempotent: a reference with the same (source_tool, target,
    content_hash) as an existing one returns the existing id and stores
    nothing new.
    """

    def __init__(self) -> None:
        self._refs: dict[str, EvidenceReference] = {}
        self._lock = _LOCK

    def put(self, ref: EvidenceReference) -> str:
        """Store a reference; returns its ref_id (existing id on dedup)."""
        with self._lock:
            for existing in self._refs.values():
                if (
                    existing.source_tool == ref.source_tool
                    and existing.target == ref.target
                    and existing.content_hash == ref.content_hash
                ):
                    return existing.ref_id
            self._refs[ref.ref_id] = ref
            return ref.ref_id

    def get(self, ref_id: str) -> EvidenceReference | None:
        """Fetch by ref_id, or None."""
        with self._lock:
            return self._refs.get(ref_id)

    def list_all(self) -> list[EvidenceReference]:
        """All stored references, in insertion order."""
        with self._lock:
            return list(self._refs.values())

    def find_by_source_tool(self, tool: str) -> list[EvidenceReference]:
        """All references produced by the given tool."""
        with self._lock:
            return [r for r in self._refs.values() if r.source_tool == tool]

    def find_by_target(self, target: str) -> list[EvidenceReference]:
        """All references about the given target."""
        with self._lock:
            return [r for r in self._refs.values() if r.target == target]

    def count(self) -> int:
        """Number of stored references."""
        with self._lock:
            return len(self._refs)
