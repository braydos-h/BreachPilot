"""Provenance chains: who produced what, from what, with what confidence.

Confidence along a chain is computed by multiplying each hop's confidence —
conservative by design: a chain of 0.9 hops of length 3 yields ~0.73, never
more than the weakest link.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Iterator

from .reference import EvidenceSource

_LOCK = threading.Lock()


@dataclass(slots=True)
class ProvenanceEntry:
    """One hop in a provenance chain."""

    evidence_id: str
    source: EvidenceSource
    produced_by: str
    producing_action: str
    timestamp: str
    content_hash: str
    parent_evidence_id: str = ""
    confidence: float = 0.5
    agent_interpretation: str = ""
    notes: str = ""


@dataclass(slots=True)
class ProvenanceChain:
    """A root evidence plus its derived descendants, ordered root → leaf."""

    root_evidence_id: str
    entries: list[ProvenanceEntry] = field(default_factory=list)

    def walk(self) -> Iterator[ProvenanceEntry]:
        """Yield entries in chain order (root first, leaves last)."""
        yield from self.entries

    def find_by_source(self, source: EvidenceSource) -> list[ProvenanceEntry]:
        """All entries produced by the given source."""
        return [e for e in self.entries if e.source is source]

    def lineage(self, evidence_id: str) -> list[ProvenanceEntry]:
        """Chain from root to the given id (inclusive), or [] if unknown."""
        by_id = {e.evidence_id: e for e in self.entries}
        if evidence_id not in by_id:
            return []
        chain: list[ProvenanceEntry] = []
        current: str | None = evidence_id
        while current is not None:
            entry = by_id.get(current)
            if entry is None:
                break
            chain.append(entry)
            current = entry.parent_evidence_id or None
        chain.reverse()
        return chain

    def confidence_at(self, evidence_id: str) -> float:
        """Derived confidence = product of each hop's confidence from root.

        Conservative: any hop below 1.0 drags the whole chain down. An
        unknown id yields 0.0.
        """
        chain = self.lineage(evidence_id)
        if not chain:
            return 0.0
        conf = 1.0
        for entry in chain:
            conf *= entry.confidence
        return conf

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "root_evidence_id": self.root_evidence_id,
            "entries": [
                {
                    "evidence_id": e.evidence_id,
                    "source": e.source.value,
                    "produced_by": e.produced_by,
                    "producing_action": e.producing_action,
                    "timestamp": e.timestamp,
                    "content_hash": e.content_hash,
                    "parent_evidence_id": e.parent_evidence_id,
                    "confidence": e.confidence,
                    "agent_interpretation": e.agent_interpretation,
                    "notes": e.notes,
                }
                for e in self.entries
            ],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ProvenanceChain":
        """Rebuild a chain from a dict."""
        return cls(
            root_evidence_id=d.get("root_evidence_id", ""),
            entries=[
                ProvenanceEntry(
                    evidence_id=e.get("evidence_id", ""),
                    source=EvidenceSource(e.get("source", EvidenceSource.TOOL_OUTPUT.value)),
                    produced_by=e.get("produced_by", ""),
                    producing_action=e.get("producing_action", ""),
                    timestamp=e.get("timestamp", ""),
                    content_hash=e.get("content_hash", ""),
                    parent_evidence_id=e.get("parent_evidence_id", ""),
                    confidence=float(e.get("confidence", 0.5)),
                    agent_interpretation=e.get("agent_interpretation", ""),
                    notes=e.get("notes", ""),
                )
                for e in d.get("entries", [])
            ],
        )


class ProvenanceTracker:
    """In-memory registry of provenance chains, keyed by evidence id.

    Thread-safe via a module-level lock; the lock is coarse (one for all
    chains) — per-chain locks only if contention ever matters.
    """

    def __init__(self) -> None:
        self._chains: dict[str, ProvenanceChain] = {}
        self._lock = _LOCK

    def register_root(
        self,
        evidence_id: str,
        source: EvidenceSource,
        produced_by: str,
        producing_action: str,
        timestamp: str,
        content_hash: str,
        confidence: float = 0.5,
        agent_interpretation: str = "",
        notes: str = "",
    ) -> ProvenanceChain:
        """Register a root evidence (no parent)."""
        entry = ProvenanceEntry(
            evidence_id=evidence_id,
            source=source,
            produced_by=produced_by,
            producing_action=producing_action,
            timestamp=timestamp,
            content_hash=content_hash,
            parent_evidence_id="",
            confidence=confidence,
            agent_interpretation=agent_interpretation,
            notes=notes,
        )
        chain = ProvenanceChain(root_evidence_id=evidence_id, entries=[entry])
        with self._lock:
            self._chains[evidence_id] = chain
        return chain

    def register_derived(
        self,
        parent_id: str,
        child_id: str,
        source: EvidenceSource,
        produced_by: str,
        producing_action: str,
        timestamp: str,
        content_hash: str,
        confidence: float = 0.5,
        agent_interpretation: str = "",
        notes: str = "",
    ) -> ProvenanceChain:
        """Attach a derived evidence to an existing chain.

        Raises ValueError if the child would be its own parent (cycle guard)
        or the parent chain is unknown.
        """
        if parent_id == child_id:
            raise ValueError("child evidence cannot be its own parent")
        with self._lock:
            chain = self._chains.get(parent_id)
            if chain is None:
                raise ValueError(f"no chain for parent evidence {parent_id!r}")
            entry = ProvenanceEntry(
                evidence_id=child_id,
                source=source,
                produced_by=produced_by,
                producing_action=producing_action,
                timestamp=timestamp,
                content_hash=content_hash,
                parent_evidence_id=parent_id,
                confidence=confidence,
                agent_interpretation=agent_interpretation,
                notes=notes,
            )
            chain.entries.append(entry)
            self._chains[child_id] = chain
        return chain

    def chain_for(self, evidence_id: str) -> ProvenanceChain | None:
        """The chain containing the given evidence id, or None."""
        with self._lock:
            return self._chains.get(evidence_id)

    def summary(self) -> dict[str, int]:
        """Count of entries per EvidenceSource across all chains."""
        counts: dict[str, int] = {}
        with self._lock:
            for chain in {id(c): c for c in self._chains.values()}.values():
                for entry in chain.entries:
                    counts[entry.source.value] = counts.get(entry.source.value, 0) + 1
        return counts
