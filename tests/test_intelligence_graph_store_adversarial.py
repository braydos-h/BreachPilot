"""Adversarial tests for the AttackGraph v2 store + merge engine.

Covers contradictory-fingerprint detection, unjustified confidence changes,
evidence-backed upgrades, stale-edge protection, and orphan-edge cleanup.
"""

from tools.intelligence.graph.merge import GraphMergeEngine
from tools.intelligence.graph.store import AttackGraphStore
from tools.intelligence.graph.types import (
    EdgeType,
    GraphEdge,
    GraphNode,
    GraphUpdate,
    NodeStatus,
    NodeType,
)


def make_node(
    node_type: NodeType,
    value: str,
    scope: str = "",
    status: NodeStatus = NodeStatus.UNKNOWN,
    confidence: float = 0.5,
    evidence_refs: tuple[str, ...] = (),
    last_seen: str = "",
) -> GraphNode:
    return GraphNode(
        node_id="n_" + value.replace(".", "_").lower(),
        node_type=node_type,
        value=value,
        scope=scope,
        confidence=confidence,
        status=status,
        evidence_refs=evidence_refs,
        last_seen=last_seen,
    )


def make_edge(
    edge_id: str,
    source: str,
    target: str,
    edge_type: EdgeType = EdgeType.CONNECTED_TO,
    scope: str = "",
    last_seen: str = "",
    confidence: float = 0.5,
    evidence_refs: tuple[str, ...] = (),
) -> GraphEdge:
    return GraphEdge(
        edge_id=edge_id,
        source_node_id=source,
        target_node_id=target,
        edge_type=edge_type,
        scope=scope,
        last_seen=last_seen,
        confidence=confidence,
        evidence_refs=evidence_refs,
    )


def test_contradictory_fingerprint_same_value_different_types_conflicts(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    store.upsert_node(make_node(NodeType.IP, "10.0.0.1", confidence=0.8))
    engine = GraphMergeEngine(store)
    proposal = make_node(NodeType.HOST, "10.0.0.1", confidence=0.9)
    conflicts = engine.apply(GraphUpdate(node_updates=[proposal]))
    assert len(conflicts) == 1
    assert "type conflict" in conflicts[0].reason
    # No silent merge: the store still holds exactly one node of type IP.
    nodes = store.to_graph_nodes()
    assert len(nodes) == 1
    assert nodes[0].node_type == NodeType.IP


def test_unjustified_confidence_spike_conflicts(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    store.upsert_node(make_node(NodeType.FINDING, "find-1", confidence=0.3))
    engine = GraphMergeEngine(store)
    proposal = make_node(NodeType.FINDING, "find-1", confidence=0.95)
    conflicts = engine.apply(GraphUpdate(node_updates=[proposal]))
    assert len(conflicts) == 1
    assert conflicts[0].reason == "unjustified downgrade"
    assert store.get_node_by_value(NodeType.FINDING, "find-1").confidence == 0.3


def test_evidence_backed_upgrade_allowed(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    store.upsert_node(make_node(NodeType.FINDING, "find-1", confidence=0.3))
    engine = GraphMergeEngine(store)
    proposal = make_node(NodeType.FINDING, "find-1", confidence=0.95, evidence_refs=("ev:scanner:1:abc:2026",))
    conflicts = engine.apply(GraphUpdate(node_updates=[proposal]))
    assert conflicts == []
    got = store.get_node_by_value(NodeType.FINDING, "find-1")
    assert got.confidence == 0.95


def test_stale_edge_overwrite_keeps_max_last_seen(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    a = make_node(NodeType.HOST, "a.com")
    b = make_node(NodeType.HOST, "b.com")
    store.upsert_node(a)
    store.upsert_node(b)
    store.upsert_edge(make_edge("e1", a.node_id, b.node_id, last_seen="2026-08-20T10:00:00", confidence=0.7))
    store.upsert_edge(make_edge("e2", a.node_id, b.node_id, last_seen="2026-08-19T10:00:00", confidence=0.9))
    edges = store.query_edges()
    assert len(edges) == 1
    assert edges[0].last_seen == "2026-08-20T10:00:00"


def test_orphan_edge_cleanup_on_delete(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    a = make_node(NodeType.HOST, "a.com")
    b = make_node(NodeType.HOST, "b.com")
    store.upsert_node(a)
    store.upsert_node(b)
    store.upsert_edge(make_edge("e1", a.node_id, b.node_id))
    store.upsert_edge(make_edge("e2", b.node_id, a.node_id, edge_type=EdgeType.RELATED_TO))
    store.delete_node(a.node_id)
    assert store.query_edges() == []
    assert store.get_node(a.node_id) is None
