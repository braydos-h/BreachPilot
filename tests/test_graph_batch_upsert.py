"""P2-02: attack graph batch upsert parity + O(1) commits."""

from __future__ import annotations


def _node(i: int, scope: str = "s"):
    from tools.intelligence.graph.types import GraphNode, NodeStatus, NodeType

    return GraphNode(
        node_id=f"n{i:05d}",
        node_type=NodeType.HOST,
        value=f"host-{i}.example.com",
        scope=scope,
        properties={"idx": i},
        confidence=0.5 + (i % 5) * 0.1,
        status=NodeStatus.SUSPECTED,
        first_seen="2026-01-01T00:00:00Z",
        last_seen="2026-01-02T00:00:00Z",
        evidence_refs=(f"ev-{i}",),
        observation_count=1,
        contradiction_count=0,
        source="test",
    )


def _edge(a: str, b: str, i: int, scope: str = "s"):
    from tools.intelligence.graph.types import EdgeType, GraphEdge

    return GraphEdge(
        edge_id=f"e{i:05d}",
        source_node_id=a,
        target_node_id=b,
        edge_type=EdgeType.RELATED_TO,
        scope=scope,
        properties={"idx": i},
        confidence=0.6,
        source="test",
        first_seen="2026-01-01T00:00:00Z",
        last_seen="2026-01-02T00:00:00Z",
        evidence_refs=(f"eev-{i}",),
        observation_count=1,
        contradiction_count=0,
    )


def test_batch_upsert_parity_and_few_commits(tmp_path):
    from tools.intelligence.graph.store import AttackGraphStore

    nodes = [_node(i) for i in range(1000)]
    edges = [_edge(f"n{i % 1000:05d}", f"n{(i + 1) % 1000:05d}", i) for i in range(2000)]

    row_store = AttackGraphStore(tmp_path / "row.db")
    for n in nodes:
        row_store.upsert_node(n)
    for e in edges:
        row_store.upsert_edge(e)

    batch_store = AttackGraphStore(tmp_path / "batch.db")
    traced: list[str] = []
    batch_store._conn.set_trace_callback(traced.append)
    try:
        with batch_store.transaction():
            batch_store.upsert_nodes(nodes)
            batch_store.upsert_edges(edges)
    finally:
        batch_store._conn.set_trace_callback(None)
    commits = sum(1 for stmt in traced if stmt.strip().upper() == "COMMIT")
    assert commits <= 3, f"{commits} commits for one batch"

    assert batch_store.summary() == row_store.summary()
    for i in (0, 7, 999):
        assert batch_store.get_node(f"n{i:05d}").value == row_store.get_node(f"n{i:05d}").value  # type: ignore[union-attr]
        assert batch_store.get_node(f"n{i:05d}").evidence_refs == row_store.get_node(f"n{i:05d}").evidence_refs  # type: ignore[union-attr]

    # Re-merge overlapping batch: parity again (refs union, counts sum).
    overlap = [_node(i) for i in range(500, 1500)]
    for n in overlap:
        row_store.upsert_node(n)
    with batch_store.transaction():
        batch_store.upsert_nodes(overlap)
    assert batch_store.summary() == row_store.summary()
    assert batch_store.get_node("n00500").observation_count == 2  # type: ignore[union-attr]


def test_native_upsert_parity_on_merge_edges(tmp_path):
    """Native UPSERT == SELECT path on contradiction bump, refs union, props merge."""
    from tools.intelligence.graph.store import AttackGraphStore
    from tools.intelligence.graph.types import GraphEdge, GraphNode, NodeStatus, NodeType

    def base_node(**kw):
        d = {
            "node_id": "nx",
            "node_type": NodeType.HOST,
            "value": "merge.example.com",
            "scope": "s",
            "properties": {"a": 1, "nested": {"x": 1}},
            "confidence": 0.5,
            "status": NodeStatus.CONFIRMED,
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-02T00:00:00Z",
            "evidence_refs": ("r1", "r2"),
            "observation_count": 3,
            "contradiction_count": 0,
            "source": "orig",
        }
        d.update(kw)
        return GraphNode(**d)

    stores = {}
    for name in ("native", "select"):
        s = AttackGraphStore(tmp_path / f"{name}.db")
        if name == "select":
            s._nodes_upsert_ok = False
            s._edges_upsert_ok = False
        stores[name] = s

    for s in stores.values():
        s.upsert_node(base_node(node_id="n-base"))

    # Refuting merge: contradiction bump, refs union (overlap), props override,
    # confidence max, observation sum, last_seen max, empty source keeps old.
    refute = base_node(
        node_id="n-other-id",
        properties={"b": 2, "nested": {"y": 2}},
        confidence=0.9,
        status=NodeStatus.REFUTED,
        last_seen="2026-03-03T00:00:00Z",
        first_seen="2026-02-02T00:00:00Z",
        evidence_refs=("r2", "r3"),
        observation_count=2,
        source="",
    )
    for s in stores.values():
        s.upsert_node(refute)

    a, b = (
        stores["native"].get_node_by_value(NodeType.HOST, "merge.example.com", "s"),
        stores["select"].get_node_by_value(NodeType.HOST, "merge.example.com", "s"),
    )
    assert a is not None and b is not None
    assert a.to_dict() == b.to_dict(), f"{a.to_dict()} != {b.to_dict()}"
    assert a.contradiction_count == 1
    assert a.evidence_refs == ("r1", "r2", "r3")
    assert a.properties == {"a": 1, "b": 2, "nested": {"y": 2}}
    assert a.confidence == 0.9 and a.observation_count == 5
    assert a.first_seen == "2026-01-01T00:00:00Z" and a.last_seen == "2026-03-03T00:00:00Z"
    assert a.source == "orig"

    # Edge merge parity (refs union + contradiction sum, id stability).
    from tools.intelligence.graph.types import EdgeType

    def base_edge(**kw):
        d = {
            "edge_id": "ex",
            "source_node_id": "n-base",
            "target_node_id": "n-base",
            "edge_type": EdgeType.RELATED_TO,
            "scope": "s",
            "properties": {"k": "v1"},
            "confidence": 0.4,
            "source": "e1",
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-02T00:00:00Z",
            "evidence_refs": ("er1",),
            "observation_count": 1,
            "contradiction_count": 2,
        }
        d.update(kw)
        return GraphEdge(**d)

    ids = {}
    for name, s in stores.items():
        id1 = s.upsert_edge(base_edge(edge_id="e-first"))
        id2 = s.upsert_edge(base_edge(edge_id="e-second", confidence=0.8, evidence_refs=("er1", "er2")))
        ids[name] = (id1, id2)
    assert ids["native"] == ids["select"]
    assert ids["native"][0] == ids["native"][1] == "e-first"
    ea = stores["native"].summary()
    eb = stores["select"].summary()
    assert ea == eb
