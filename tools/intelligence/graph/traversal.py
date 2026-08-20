"""Pure, bounded graph traversal over AttackGraph v2 arrays.

The caller supplies the node/edge lists so this module stays importable
without the store layer (avoids circular imports). Every traversal takes an
optional scope filter and enforces ``max_*`` bounds to keep queries cheap.
"""

from __future__ import annotations

from collections import deque

from tools.intelligence.graph.types import EdgeType, GraphEdge, GraphNode, NodeType

BoundaryEdge = tuple[GraphNode, GraphEdge]
"""A boundary edge: a node outside the subgraph plus the edge touching it."""


class GraphTraversal:
    """Query helpers over caller-supplied node/edge arrays."""

    def __init__(self, nodes: list[GraphNode], edges: list[GraphEdge]):
        self._nodes = nodes
        self._edges = edges

    # -- adjacency ---------------------------------------------------------

    def _outgoing(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self._edges if e.source_node_id == node_id]

    def _incoming(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self._edges if e.target_node_id == node_id]

    def _node_by_id(self, node_id: str) -> GraphNode | None:
        for n in self._nodes:
            if n.node_id == node_id:
                return n
        return None

    # -- filtered lists ---------------------------------------------------------

    def nodes_of_type(self, node_type: NodeType, scope: str | None = None) -> list[GraphNode]:
        """Nodes of ``node_type``, optionally restricted to ``scope``."""
        out = []
        for n in self._nodes:
            if n.node_type != node_type:
                continue
            if scope is not None and n.scope != scope:
                continue
            out.append(n)
        return out

    def edges_of_type(self, edge_type: EdgeType, scope: str | None = None) -> list[GraphEdge]:
        """Edges of ``edge_type``, optionally restricted to ``scope``."""
        out = []
        for e in self._edges:
            if e.edge_type != edge_type:
                continue
            if scope is not None and e.scope != scope:
                continue
            out.append(e)
        return out

    # -- BFS / neighborhoods ----------------------------------------------------

    def neighbors(
        self,
        node_id: str,
        relation: EdgeType | None = None,
        max_hops: int = 1,
        max_nodes: int = 50,
    ) -> list[tuple[GraphNode, GraphEdge, int]]:
        """Bounded BFS outward from ``node_id``.

        Returns ``(node, edge, distance)`` tuples in discovery order (edge
        distance 1 first). ``relation`` restricts to edges of one type. Hard
        bound: exploration stops as soon as ``max_nodes`` nodes have been
        collected, so a dense graph cannot explode the result.
        """
        if self._node_by_id(node_id) is None:
            return []
        frontier: deque[tuple[str, int]] = deque([(node_id, 0)])
        seen: dict[str, int] = {node_id: 0}
        out: list[tuple[GraphNode, GraphEdge, int]] = []
        while frontier:
            current, dist = frontier.popleft()
            if dist >= max_hops:
                continue
            for e in self._outgoing(current):
                if relation is not None and e.edge_type != relation:
                    continue
                target = e.target_node_id
                if target in seen:
                    continue
                nxt = self._node_by_id(target)
                if nxt is None:
                    continue
                seen[target] = dist + 1
                out.append((nxt, e, dist + 1))
                if len(out) >= max_nodes:
                    return out
                frontier.append((target, dist + 1))
        return out

    # -- paths ------------------------------------------------------------------

    def paths(
        self,
        start_node_id: str,
        end_node_id: str,
        max_length: int = 4,
        max_paths: int = 10,
    ) -> list[list[tuple[GraphNode, GraphEdge, int]]]:
        """Enumerate simple paths from ``start_node_id`` to ``end_node_id``.

        Each path is a list of ``(node, edge, distance)`` steps (distance
        starting at 1). Bounded by ``max_length`` edges and ``max_paths``
        results; node visitation is deduplicated within a path, so a graph
        with cycles terminates.
        """
        if self._node_by_id(start_node_id) is None or self._node_by_id(end_node_id) is None:
            return []
        results: list[list[tuple[GraphNode, GraphEdge, int]]] = []
        visited = {start_node_id}

        def walk(current: str, dist: int, acc: list[tuple[GraphNode, GraphEdge, int]]) -> None:
            if len(results) >= max_paths:
                return
            if dist >= max_length:
                return
            for e in self._outgoing(current):
                target = e.target_node_id
                if target in visited:
                    continue
                nxt = self._node_by_id(target)
                if nxt is None:
                    continue
                visited.add(target)
                acc.append((nxt, e, dist + 1))
                if target == end_node_id:
                    results.append(list(acc))
                else:
                    walk(target, dist + 1, acc)
                acc.pop()
                visited.discard(target)
                if len(results) >= max_paths:
                    return

        walk(start_node_id, 0, [])
        return results

    def path_exists(self, node_id: str, other_id: str, max_hops: int = 3) -> bool:
        """True iff any simple path connects the two nodes within ``max_hops``."""
        for path in self.paths(node_id, other_id, max_length=max_hops, max_paths=1):
            return True
        return False

    # -- subgraphs ----------------------------------------------------------------

    def subgraph(self, node_ids: list[str], max_distance: int = 1) -> tuple[list[GraphNode], list[GraphEdge], list[BoundaryEdge]]:
        """Induced subgraph plus boundary edges around ``node_ids``.

        Returns ``(nodes, internal_edges, boundary_edges)`` where boundary
        edges connect an included node to one outside the set; the outside
        node is attached for context (without recursive expansion, so the
        result stays bounded by ``max_distance``). Raises nothing on missing
        ids; unknown ids are skipped.
        """
        wanted = set(node_ids)
        internal: list[GraphEdge] = []
        boundary: list[BoundaryEdge] = []
        for e in self._edges:
            src_in = e.source_node_id in wanted
            dst_in = e.target_node_id in wanted
            if src_in and dst_in:
                internal.append(e)
            elif src_in:
                out_node = self._node_by_id(e.target_node_id)
                if out_node is not None:
                    boundary.append((out_node, e))
            elif dst_in:
                out_node = self._node_by_id(e.source_node_id)
                if out_node is not None:
                    boundary.append((out_node, e))
        included = [n for n in self._nodes if n.node_id in wanted]
        return included, internal, boundary
