"""Flow B adapters: MemoryManager grading + dedup (defect C6).

MemoryManager.remember defaults every fact to confidence 1.0 and never
dedups, so identical facts are stored N times at full certainty. This adapter
grades confidence, dedups writes, and ranks retrieval by confidence.
``agent_loop.py`` (off-limits) is the future call site for these methods.
"""

from __future__ import annotations

from typing import Any

from memory import MemoryManager


class MemoryAdapter:
    """Confidence-graded, deduplicated memory writes on top of MemoryManager."""

    def remember_graded(
        self,
        memory_manager: MemoryManager,
        target: str,
        fact: str,
        memory_type: str = "target",
        confidence: float = 0.5,
        source: str = "adapter",
    ) -> str:
        """Store a fact at an explicit confidence instead of the 1.0 default."""
        return memory_manager.remember(
            target=target,
            fact=fact,
            memory_type=memory_type,
            confidence=confidence,
            metadata={"source": source},
        )

    def find_existing(
        self,
        memory_manager: MemoryManager,
        target: str,
        fact: str,
        memory_type: str,
    ) -> dict[str, Any] | None:
        """First stored memory with an identical (target, type, fact), else None."""
        for memory in memory_manager.retrieve(target=target, memory_type=memory_type, limit=100):
            if memory.get("fact") == fact:
                return memory
        return None

    def dedup_remember(
        self,
        memory_manager: MemoryManager,
        target: str,
        fact: str,
        memory_type: str,
        confidence: float,
    ) -> str:
        """Store once: return the existing id on a duplicate, else grade+store."""
        existing = self.find_existing(memory_manager, target, fact, memory_type)
        if existing is not None:
            # ponytail: MemoryManager has no update API, so the confidence of an
            # existing row is left untouched; add an update when one exists.
            return existing["id"]
        return self.remember_graded(
            memory_manager, target, fact, memory_type=memory_type, confidence=confidence
        )

    @staticmethod
    def confidence_rank(retrieved: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Stable-sort retrieved memories by confidence desc; never mutates input."""
        return sorted(retrieved, key=lambda m: m.get("confidence", 0.0), reverse=True)
