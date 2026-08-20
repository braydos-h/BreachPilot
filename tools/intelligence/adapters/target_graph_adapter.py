"""TargetGraphV2Adapter — value-based wiring over the legacy ``TargetGraph``.

Defect C1: ``agent_loop`` called ``TargetGraph.add_edge(value, value, ...)``
passing node *values* where the legacy API expects node *ids*, producing orphan
edges whose endpoints match no node. This adapter resolves endpoints by
(type, value) — auto-creating missing nodes — before calling ``add_edge`` with
real IDs, and dedups repeated (from, to, relation) wiring.
"""

from __future__ import annotations

from typing import Any


class TargetGraphV2Adapter:
    """Thin, stateless adapter: every method takes the target graph as an argument."""

    @staticmethod
    def resolve_node_id(target_graph: Any, node_type: str, value: str) -> str:
        """Return the node id for ``(node_type, value)``, creating the node if absent.

        Lookup is an exact-match scan over ``query_graph`` results; a LIKE-based
        ``value_pattern`` can over-match, so the returned node must match exactly.
        """
        value = str(value).strip()
        if not value:
            raise ValueError("node value must not be empty or whitespace-only")
        for node in target_graph.query_graph(node_type=node_type, value_pattern=value, limit=1000)["nodes"]:
            if node["value"] == value:
                return node["id"]
        return target_graph.add_node(node_type, value)

    @staticmethod
    def add_edge_by_value(
        target_graph: Any,
        from_type: str,
        from_value: str,
        to_type: str,
        to_value: str,
        relation: str = "related",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Wire an edge by (type, value) endpoints, auto-creating missing nodes.

        Idempotent: wiring the same (from, to, relation) twice returns the
        original edge id instead of inserting a duplicate row.
        """
        from_value = str(from_value).strip()
        to_value = str(to_value).strip()
        if not from_value or not to_value:
            raise ValueError("node values must not be empty or whitespace-only")
        from_id = TargetGraphV2Adapter.resolve_node_id(target_graph, from_type, from_value)
        to_id = TargetGraphV2Adapter.resolve_node_id(target_graph, to_type, to_value)
        for edge in target_graph.query_graph(relation=relation, limit=10000)["edges"]:
            if edge["from_node_id"] == from_id and edge["to_node_id"] == to_id:
                return edge["id"]
        return target_graph.add_edge(from_id, to_id, relation, metadata)

    @staticmethod
    def edges_summary(target_graph: Any) -> dict[str, int]:
        """Count edges per relation, for diagnostics."""
        counts: dict[str, int] = {}
        for edge in target_graph.query_graph(limit=10000)["edges"]:
            counts[edge["relation"]] = counts.get(edge["relation"], 0) + 1
        return counts
