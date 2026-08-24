"""In-memory belief store: dict-backed, persists nothing (caller persists)."""

from __future__ import annotations

from .state import BeliefState, HypothesisStatus


class BeliefStore:
    """Hold BeliefState objects by mission id in memory."""

    def __init__(self) -> None:
        """Create an empty in-memory store."""
        self._beliefs: dict[str, BeliefState] = {}

    def upsert(self, state: BeliefState) -> None:
        """Insert or replace a belief state by its mission id."""
        self._beliefs[state.mission_id] = state

    def get(self, mission_id: str) -> BeliefState | None:
        """Return the belief state for a mission, or None."""
        return self._beliefs.get(mission_id)

    def delete(self, mission_id: str) -> None:
        """Remove a belief state if present."""
        self._beliefs.pop(mission_id, None)

    def list_all(self) -> list[BeliefState]:
        """Return every belief state in insertion order."""
        return list(self._beliefs.values())

    def list_by_status(self, status: HypothesisStatus) -> list[BeliefState]:
        """Return belief states that contain at least one hypothesis with the status."""
        return [bs for bs in self._beliefs.values() if any(h.status is status for h in bs.hypotheses.values())]

    def find_by_statement(self, statement: str) -> list[BeliefState]:
        """Return belief states containing a hypothesis whose statement matches."""
        return [bs for bs in self._beliefs.values() if any(h.statement == statement for h in bs.hypotheses.values())]

    def __len__(self) -> int:
        """Number of belief states held."""
        return len(self._beliefs)

    def __contains__(self, mission_id: object) -> bool:
        """True if a belief state for this mission id is held."""
        return mission_id in self._beliefs

    def keys(self) -> list[str]:
        """Mission ids of every held belief state."""
        return list(self._beliefs.keys())
