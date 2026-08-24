"""Tests for the AttackGraph v2 SQLite store and merge engine (no network)."""

import pytest

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
    node_id: str | None = None,
) -> GraphNode:
    return GraphNode(
        node_id=node_id or "n_" + value.replace(".", "_").lower(),
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
) -> GraphEdge:
    return GraphEdge(
        edge_id=edge_id,
        source_node_id=source,
        target_node_id=target,
        edge_type=edge_type,
        scope=scope,
        last_seen=last_seen,
        confidence=confidence,
    )


def test_upsert_dedup_same_node_twice(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    nid1 = store.upsert_node(make_node(NodeType.HOST, "example.com", confidence=0.6))
    nid2 = store.upsert_node(make_node(NodeType.HOST, "EXAMPLE.COM", confidence=0.9))
    assert nid1 == nid2
    assert store.summary()["total_nodes"] == 1
    got = store.get_node(nid1)
    assert got.confidence == 0.9
    assert got.value == "example.com"


def test_upsert_edge_missing_endpoint_raises(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    n = make_node(NodeType.HOST, "a.example")
    store.upsert_node(n)
    with pytest.raises(ValueError):
        store.upsert_edge(make_edge("e1", "n_unknown", n.node_id))


def test_edge_dedup_merge(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    a = make_node(NodeType.HOST, "a.com")
    b = make_node(NodeType.HOST, "b.com")
    store.upsert_node(a)
    store.upsert_node(b)
    eid1 = store.upsert_edge(make_edge("e1", a.node_id, b.node_id, confidence=0.5))
    eid2 = store.upsert_edge(make_edge("e2", a.node_id, b.node_id, confidence=0.9))
    assert eid1 == eid2
    assert store.summary()["total_edges"] == 1


def test_neighbors_bounded_by_max_nodes(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    nodes = [make_node(NodeType.HOST, f"n{i}.com") for i in range(60)]
    for n in nodes:
        store.upsert_node(n)
    for i in range(59):
        store.upsert_edge(make_edge(f"e{i}", nodes[i].node_id, nodes[i + 1].node_id))
    got = store.neighbors(nodes[0].node_id, max_hops=10, max_nodes=10)
    assert len(got) == 10
    assert got[0][2] == 1  # chain: first hop reaches exactly one node
    assert len({g[0].node_id for g in got}) == 10  # 10 distinct nodes, bounded


def test_paths_bounded_by_max_paths(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    nodes = [make_node(NodeType.HOST, f"p{i}.com") for i in range(8)]
    for n in nodes:
        store.upsert_node(n)
    for i in range(7):
        store.upsert_edge(make_edge(f"e{i}", nodes[i].node_id, nodes[i + 1].node_id))
    # two parallel branches to nodes[2]: chain and via node 3
    store.upsert_edge(make_edge("x", nodes[0].node_id, nodes[3].node_id))
    store.upsert_edge(make_edge("y", nodes[3].node_id, nodes[2].node_id))
    paths = store.paths(nodes[0].node_id, nodes[2].node_id, max_length=4, max_paths=1)
    assert len(paths) == 1


def test_scope_isolation(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    n1 = make_node(NodeType.HOST, "same-host.com", scope="scopeA", node_id="na")
    n2 = make_node(NodeType.HOST, "same-host.com", scope="scopeB", node_id="nb")
    store.upsert_node(n1)
    store.upsert_node(n2)
    assert store.summary()["total_nodes"] == 2
    assert store.get_node_by_value(NodeType.HOST, "SAME-HOST.COM", scope="scopeA") is not None


def test_summary_counts(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    a = make_node(NodeType.HOST, "h1.com")
    b = make_node(NodeType.IP, "1.2.3.4")
    store.upsert_node(a)
    store.upsert_node(b)
    store.upsert_edge(make_edge("e1", a.node_id, b.node_id))
    s = store.summary()
    assert s["total_nodes"] == 2
    assert s["total_edges"] == 1
    assert s["nodes"][NodeType.HOST.value] == 1
    assert s["edges"][EdgeType.CONNECTED_TO.value] == 1


def test_persistence_across_store_instances(tmp_path):
    db = tmp_path / "g.db"
    store = AttackGraphStore(db)
    store.upsert_node(make_node(NodeType.HOST, "persist.com"))
    store.close()
    store2 = AttackGraphStore(db)
    assert store2.summary()["total_nodes"] == 1
    assert store2.get_node_by_value(NodeType.HOST, "persist.com") is not None


def test_merge_engine_status_downgrade_without_evidence_conflicts(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    store.upsert_node(make_node(NodeType.HYPOTHESIS, "hyp-1", status=NodeStatus.CONFIRMED, confidence=0.9))
    engine = GraphMergeEngine(store)
    proposal = make_node(NodeType.HYPOTHESIS, "hyp-1", status=NodeStatus.REFUTED, confidence=0.9)
    conflicts = engine.apply(GraphUpdate(node_updates=[proposal]))
    assert len(conflicts) == 1
    assert conflicts[0].reason == "downgrade without evidence"
    assert store.get_node_by_value(NodeType.HYPOTHESIS, "hyp-1").status == NodeStatus.CONFIRMED


def test_merge_preview_is_dry(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    store.upsert_node(make_node(NodeType.HYPOTHESIS, "hp", status=NodeStatus.CONFIRMED, confidence=0.9))
    engine = GraphMergeEngine(store)
    proposal = make_node(NodeType.HYPOTHESIS, "hp", status=NodeStatus.REFUTED, confidence=0.9)
    conflicts = engine.preview(GraphUpdate(node_updates=[proposal]))
    assert len(conflicts) == 1
    assert store.summary()["total_nodes"] == 1


def test_merge_engine_bulk_skips_only_conflicts(tmp_path):
    store = AttackGraphStore(tmp_path / "g.db")
    store.upsert_node(make_node(NodeType.HYPOTHESIS, "bad", status=NodeStatus.CONFIRMED, confidence=0.9))
    engine = GraphMergeEngine(store)
    update = GraphUpdate(
        node_updates=[
            make_node(NodeType.HYPOTHESIS, "bad", status=NodeStatus.REFUTED, confidence=0.9),
            make_node(NodeType.HOST, "new-host.com", status=NodeStatus.LIKELY, confidence=0.7),
        ]
    )
    conflicts = engine.apply(update)
    assert len(conflicts) == 1
    assert store.summary()["total_nodes"] == 2
    assert store.get_node_by_value(NodeType.HOST, "new-host.com") is not None
