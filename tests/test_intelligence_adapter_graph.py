"""Tests for ``TargetGraphV2Adapter`` — value-based edge wiring (defect C1).

Covers auto-creation of endpoints, defensive ``add_edge`` validation, backward
compat for valid IDs, per-relation edge counts, and the swarm-style
``add_edge_by_value(g, "host", ..., "service", "ssh", "exposes")`` regression.
"""

from __future__ import annotations

import pytest

from db import DatabaseManager, _new_id
from target_graph import TargetGraph
from tools.intelligence.adapters import TargetGraphV2Adapter


@pytest.fixture
def graph(tmp_path):
    path = tmp_path / "test_adapter_graph.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
        mid = _new_id("M")
        conn.execute(
            """INSERT INTO missions(id, program_name, objective, risk_profile, created_at, updated_at)
            VALUES(?,?,?,?,datetime('now'),datetime('now'))""",
            (mid, "Adapter Graph Test", "Map surface", "standard_authorized"),
        )
    return db, mid, TargetGraph(db, mid)


def _edge_count(db, mid):
    with db.connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM graph_edges WHERE mission_id=?", (mid,)).fetchone()[0]


def test_add_edge_by_value_auto_creates_both_nodes_and_links_them(graph):
    db, mid, g = graph
    eid = TargetGraphV2Adapter.add_edge_by_value(g, "host", "10.0.0.1", "service", "ssh", "exposes")
    result = g.query_graph()
    assert [n["type"] for n in result["nodes"]] == ["host", "service"]
    assert len(result["edges"]) == 1
    edge = result["edges"][0]
    assert edge["id"] == eid
    from_node = next(n for n in result["nodes"] if n["id"] == edge["from_node_id"])
    to_node = next(n for n in result["nodes"] if n["id"] == edge["to_node_id"])
    assert (from_node["type"], from_node["value"]) == ("host", "10.0.0.1")
    assert (to_node["type"], to_node["value"]) == ("service", "ssh")
    assert edge["relation"] == "exposes"


def test_add_edge_with_nonexistent_id_raises_value_error(graph):
    _, _, g = graph
    g.add_node("host", "10.0.0.5")
    with pytest.raises(ValueError, match="existing node ids"):
        g.add_edge("GN-DOES-NOT-EXIST", "GN-ALSO-MISSING", "exposes")


def test_add_edge_with_valid_ids_still_works(graph):
    _, _, g = graph
    n1 = g.add_node("host", "10.0.0.5")
    n2 = g.add_node("service", "ssh")
    eid = g.add_edge(n1, n2, "exposes")
    result = g.query_graph(relation="exposes")
    assert len(result["edges"]) == 1
    assert result["edges"][0]["id"] == eid


def test_edges_summary_counts_per_relation(graph):
    _, _, g = graph
    TargetGraphV2Adapter.add_edge_by_value(g, "host", "10.0.0.1", "service", "ssh", "exposes")
    TargetGraphV2Adapter.add_edge_by_value(g, "host", "10.0.0.1", "service", "http", "exposes")
    TargetGraphV2Adapter.add_edge_by_value(g, "host", "10.0.0.2", "service", "ssh", "related_to")
    assert TargetGraphV2Adapter.edges_summary(g) == {"exposes": 2, "related_to": 1}


def test_swarm_style_host_exposes_ssh_call_produces_real_edge(graph):
    db, mid, g = graph
    eid = TargetGraphV2Adapter.add_edge_by_value(g, "host", "10.0.0.1", "service", "ssh", "exposes")
    assert _edge_count(db, mid) == 1
    edge = g.query_graph(relation="exposes")["edges"][0]
    assert edge["id"] == eid
    ids = {n["id"] for n in g.query_graph()["nodes"]}
    assert edge["from_node_id"] in ids and edge["to_node_id"] in ids
