"""Merge engine for AttackGraph v2: applies GraphUpdate proposals with conflict detection.

The store's upsert methods are the only mutators; this engine decides which
proposed mutations are safe to apply and records conflicts instead of
silently merging contradictory data.
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.intelligence.graph.store import AttackGraphStore
from tools.intelligence.graph.types import (
    EdgeType,
    GraphNode,
    GraphUpdate,
    NodeStatus,
    NodeType,
)

_CASE_FOLD_TYPES = frozenset(
    {NodeType.IP, NodeType.HOST, NodeType.DOMAIN, NodeType.ASSET, NodeType.ENDPOINT}
)

_TYPE_CONFLICT = "type conflict: same value observed as different node types"
_DOWNGRADE_WITHOUT_EVIDENCE = "downgrade without evidence"
_UNJUSTIFIED_DOWNGRADE = "unjustified downgrade"

_CONFIDENCE_TOLERANCE = 0.2
"""Max confidence swing accepted on an update without evidence; beyond it -> conflict."""


@dataclass(frozen=True, slots=True)
class GraphMergeConflict:
    """A rejected mutation: what was proposed vs. what exists, and why."""

    edge_type: EdgeType | None
    node_value: str
    reason: str
    existing_confidence: float
    proposed_confidence: float


class GraphMergeError(Exception):
    """Raised when a GraphUpdate cannot be applied (e.g. missing edge endpoint)."""


class GraphMergeEngine:
    """Applies GraphUpdate proposals to an AttackGraphStore, recording conflicts."""

    def __init__(self, store: AttackGraphStore):
        self.store = store

    # -- public API -----------------------------------------------------------

    def apply(self, graph_update: GraphUpdate) -> list[GraphMergeConflict]:
        """Apply a proposed update; returns any conflicts.

        Node updates apply first, then edge updates. Conflicting mutations are
        skipped; non-conflicting ones in the same update are still applied.
        """
        conflicts: list[GraphMergeConflict] = []
        existing = self._index_nodes()
        proposed = {self._key(n): n for n in graph_update.node_updates}

        for node in graph_update.node_updates:
            conflict = self._check_node_conflict(node, existing, proposed)
            if conflict is not None:
                conflicts.append(conflict)
                continue
            self.store.upsert_node(node)
            existing[self._key(node)] = node

        for edge in graph_update.edge_updates:
            try:
                self.store.upsert_edge(edge)
            except ValueError as exc:
                raise GraphMergeError(str(exc)) from exc

        return conflicts

    def preview(self, update: GraphUpdate) -> list[GraphMergeConflict]:
        """Dry run: report conflicts without mutating the store."""
        existing = self._index_nodes()
        proposed = {self._key(n): n for n in update.node_updates}
        return [
            c
            for n in update.node_updates
            if (c := self._check_node_conflict(n, existing, proposed)) is not None
        ]

    # -- conflict detection ----------------------------------------------------

    def _check_node_conflict(
        self,
        node: GraphNode,
        existing: dict[tuple[str, str], GraphNode],
        proposed: dict[tuple[str, str], GraphNode],
    ) -> GraphMergeConflict | None:
        """Return a conflict for ``node`` or None if it is safe to apply."""
        key = self._key(node)
        cur = existing.get(key)
        # Same update carries two different types for one value -> conflict.
        if cur is None:
            other = proposed.get(key)
            if other is not None and other is not node and other.node_type != node.node_type:
                return self._conflict(node, _TYPE_CONFLICT, other.confidence)
            return None
        if cur.node_type != node.node_type:
            return self._conflict(node, _TYPE_CONFLICT, cur.confidence)
        if cur.status == NodeStatus.CONFIRMED and node.status == NodeStatus.REFUTED and not node.evidence_refs:
            return self._conflict(node, _DOWNGRADE_WITHOUT_EVIDENCE, cur.confidence)
        if abs(node.confidence - cur.confidence) > _CONFIDENCE_TOLERANCE and not node.evidence_refs:
            # ponytail: one reason covers both directions — a spike on a
            # low-confidence node is as unjustified as a drop without evidence.
            return self._conflict(node, _UNJUSTIFIED_DOWNGRADE, cur.confidence)
        return None

    # -- helpers -----------------------------------------------------------------

    def _index_nodes(self) -> dict[tuple[str, str], GraphNode]:
        return {self._key(n): n for n in self.store.to_graph_nodes()}

    @staticmethod
    def _key(node: GraphNode) -> tuple[str, str]:
        value = node.value.strip()
        if node.node_type in _CASE_FOLD_TYPES:
            value = value.lower()
        return (node.scope, value)

    @staticmethod
    def _conflict(node: GraphNode, reason: str, existing_confidence: float) -> GraphMergeConflict:
        return GraphMergeConflict(
            edge_type=None,
            node_value=node.value,
            reason=reason,
            existing_confidence=existing_confidence,
            proposed_confidence=node.confidence,
        )
