"""Tests for ``target_graph.py`` — attack-surface graph CRUD over SQLite.

Covers node/edge validation, add/query, ``find_untested_assets``,
``find_permission_boundaries``, ``find_object_id_candidates``,
``summarize_graph``, and the ``_row_to_node``/``_row_to_edge``/``_json_load``
helpers.
"""

from __future__ import annotations

import pytest

from db import DatabaseManager, _new_id
from target_graph import (
    EDGE_TYPES,
    NODE_TYPES,
    TargetGraph,
    _json_load,
    _row_to_edge,
    _row_to_node,
)

# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def temp_db(tmp_path):
    path = tmp_path / "test_graph.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
        mid = _new_id("M")
        conn.execute(
            """INSERT INTO missions(id, program_name, objective, risk_profile, created_at, updated_at)
            VALUES(?,?,?,?,datetime('now'),datetime('now'))""",
            (mid, "Graph Test", "Map surface", "standard_authorized"),
        )
        db._mid = mid
    return db


@pytest.fixture
def graph(temp_db):
    return TargetGraph(temp_db, getattr(temp_db, "_mid", "M-TEST"))


# ── Type sets ───────────────────────────────────────────────────────────────


def test_node_types_is_frozenset_with_known_types():
    assert isinstance(NODE_TYPES, frozenset)
    for t in ("host", "ip", "service", "web_app", "endpoint", "parameter", "finding", "evidence"):
        assert t in NODE_TYPES


def test_edge_types_is_frozenset_with_known_relations():
    assert isinstance(EDGE_TYPES, frozenset)
    for r in ("owns", "exposes", "serves", "tested_by", "related_to", "blocked_by_scope"):
        assert r in EDGE_TYPES


# ── add_node ────────────────────────────────────────────────────────────────


def test_add_node_returns_id_prefix(graph):
    nid = graph.add_node("host", "10.0.0.5")
    assert nid.startswith("GN-")


def test_add_node_with_explicit_id(graph):
    nid = graph.add_node("ip", "10.0.0.1", node_id="GN-CUSTOM")
    assert nid == "GN-CUSTOM"


def test_add_node_with_metadata(graph):
    graph.add_node("service", "ssh", metadata={"port": 22, "version": "OpenSSH 8.9"})
    result = graph.query_graph(node_type="service")
    node = result["nodes"][0]
    assert node["metadata"]["port"] == 22
    assert node["metadata"]["version"] == "OpenSSH 8.9"


def test_add_node_invalid_type_raises(graph):
    with pytest.raises(ValueError, match="Invalid node type"):
        graph.add_node("bogus_type", "value")


def test_add_node_empty_metadata_defaults_to_empty_dict(graph):
    graph.add_node("host", "10.0.0.5")
    result = graph.query_graph(node_type="host")
    assert result["nodes"][0]["metadata"] == {}


# ── add_edge ────────────────────────────────────────────────────────────────


def test_add_edge_returns_id_prefix(graph):
    n1 = graph.add_node("host", "10.0.0.5")
    n2 = graph.add_node("service", "ssh")
    eid = graph.add_edge(n1, n2, "exposes")
    assert eid.startswith("GE-")


def test_add_edge_with_explicit_id(graph):
    n1 = graph.add_node("host", "10.0.0.5")
    n2 = graph.add_node("service", "ssh")
    eid = graph.add_edge(n1, n2, "exposes", edge_id="GE-CUSTOM")
    assert eid == "GE-CUSTOM"


def test_add_edge_with_metadata(graph):
    n1 = graph.add_node("host", "10.0.0.5")
    n2 = graph.add_node("service", "ssh")
    graph.add_edge(n1, n2, "exposes", metadata={"discovered_by": "nmap"})
    result = graph.query_graph(relation="exposes")
    assert result["edges"][0]["metadata"]["discovered_by"] == "nmap"


def test_add_edge_invalid_relation_raises(graph):
    n1 = graph.add_node("host", "10.0.0.5")
    n2 = graph.add_node("service", "ssh")
    with pytest.raises(ValueError, match="Invalid edge relation"):
        graph.add_edge(n1, n2, "bogus_relation")


# ── query_graph ─────────────────────────────────────────────────────────────


def test_query_graph_empty(graph):
    result = graph.query_graph()
    assert result == {"nodes": [], "edges": []}


def test_query_graph_filter_by_node_type(graph):
    graph.add_node("host", "10.0.0.5")
    graph.add_node("service", "ssh")
    result = graph.query_graph(node_type="host")
    assert len(result["nodes"]) == 1
    assert result["nodes"][0]["type"] == "host"
    assert result["edges"] == []


def test_query_graph_filter_by_value_pattern(graph):
    graph.add_node("host", "10.0.0.5")
    graph.add_node("host", "10.0.0.6")
    graph.add_node("host", "192.168.1.1")
    result = graph.query_graph(value_pattern="10.0.0")
    assert len(result["nodes"]) == 2
    for n in result["nodes"]:
        assert "10.0.0" in n["value"]


def test_query_graph_filter_by_relation(graph):
    n1 = graph.add_node("host", "10.0.0.5")
    n2 = graph.add_node("service", "ssh")
    graph.add_edge(n1, n2, "exposes")
    graph.add_edge(n1, n2, "related_to")
    result = graph.query_graph(relation="exposes")
    assert len(result["edges"]) == 1
    assert result["edges"][0]["relation"] == "exposes"


def test_query_graph_respects_limit(graph):
    for i in range(10):
        graph.add_node("host", f"10.0.0.{i}")
    result = graph.query_graph(limit=3)
    assert len(result["nodes"]) == 3


def test_query_graph_node_shape(graph):
    nid = graph.add_node("host", "10.0.0.5", metadata={"k": "v"})
    result = graph.query_graph()
    node = result["nodes"][0]
    assert set(node.keys()) == {"id", "mission_id", "type", "value", "metadata", "created_at"}
    assert node["id"] == nid
    assert node["metadata"] == {"k": "v"}


def test_query_graph_edge_shape(graph):
    n1 = graph.add_node("host", "10.0.0.5")
    n2 = graph.add_node("service", "ssh")
    eid = graph.add_edge(n1, n2, "exposes")
    result = graph.query_graph()
    edge = result["edges"][0]
    assert set(edge.keys()) == {"id", "mission_id", "from_node_id", "to_node_id", "relation", "metadata", "created_at"}
    assert edge["id"] == eid
    assert edge["from_node_id"] == n1
    assert edge["to_node_id"] == n2


# ── find_untested_assets ────────────────────────────────────────────────────


def test_find_untested_assets_returns_all_when_none_tested(graph):
    graph.add_node("host", "10.0.0.5")
    graph.add_node("ip", "10.0.0.6")
    untested = graph.find_untested_assets()
    assert len(untested) == 2


def test_find_untested_assets_excludes_tested(graph):
    host = graph.add_node("host", "10.0.0.5")
    evidence = graph.add_node("evidence", "scan-output")
    graph.add_edge(host, evidence, "tested_by")
    untested = graph.find_untested_assets()
    # host now has a tested_by edge -> excluded
    assert all("10.0.0.5" not in u for u in untested)


def test_find_untested_assets_only_attack_surface_types(graph):
    # non-attack-surface types are not returned even if untested
    graph.add_node("parameter", "id")  # parameter is NOT in the IN-clause
    graph.add_node("technology", "nginx")  # technology NOT in the IN-clause
    graph.add_node("host", "10.0.0.5")  # host IS in the IN-clause
    untested = graph.find_untested_assets()
    assert len(untested) == 1
    assert "10.0.0.5" in untested[0]


def test_find_untested_assets_format_includes_truncated_id(graph):
    nid = graph.add_node("host", "10.0.0.5")
    untested = graph.find_untested_assets()
    assert untested[0].startswith("10.0.0.5 (")
    assert nid[:12] in untested[0]


# ── find_permission_boundaries ─────────────────────────────────────────────


def test_find_permission_boundaries_returns_only_boundary_nodes(graph):
    graph.add_node("permission_boundary", "admin role")
    graph.add_node("permission_boundary", "root")
    graph.add_node("host", "10.0.0.5")
    boundaries = graph.find_permission_boundaries()
    assert len(boundaries) == 2
    assert all("node_id" in b and "boundary" in b for b in boundaries)
    assert {b["boundary"] for b in boundaries} == {"admin role", "root"}


def test_find_permission_boundaries_empty(graph):
    assert graph.find_permission_boundaries() == []


# ── find_object_id_candidates ───────────────────────────────────────────────


def test_find_object_id_candidates_matches_id_uuid_user_etc(graph):
    graph.add_node("endpoint", "/api/users/{id}")
    graph.add_node("endpoint", "/api/orders/{order_id}")
    graph.add_node("parameter", "uuid")
    graph.add_node("endpoint", "/static/home")  # no id-like token
    graph.add_node("host", "10.0.0.5")  # wrong type
    candidates = graph.find_object_id_candidates()
    values = {c["value"] for c in candidates}
    assert "/api/users/{id}" in values
    assert "/api/orders/{order_id}" in values
    assert "uuid" in values
    assert "/static/home" not in values


def test_find_object_id_candidates_empty(graph):
    assert graph.find_object_id_candidates() == []


# ── summarize_graph ─────────────────────────────────────────────────────────


def test_summarize_graph_empty(graph):
    summary = graph.summarize_graph()
    assert "Target Graph Summary" in summary
    assert "(empty)" in summary


def test_summarize_graph_with_nodes_and_edges(graph):
    n1 = graph.add_node("host", "10.0.0.5")
    n2 = graph.add_node("service", "ssh")
    graph.add_edge(n1, n2, "exposes")
    summary = graph.summarize_graph()
    assert "host: 1" in summary
    assert "service: 1" in summary
    assert "exposes: 1" in summary
    assert graph._mission_id in summary


def test_summarize_graph_mission_id(graph):
    summary = graph.summarize_graph()
    assert "Mission:" in summary
    assert graph._mission_id in summary


# ── helpers ─────────────────────────────────────────────────────────────────


def test_row_to_node_complete():
    row = {
        "id": "GN-1",
        "mission_id": "M-1",
        "type": "host",
        "value": "10.0.0.5",
        "metadata_json": '{"k": "v"}',
        "created_at": "2024-01-01",
    }
    node = _row_to_node(row)
    assert node["id"] == "GN-1"
    assert node["metadata"] == {"k": "v"}


def test_row_to_node_missing_fields():
    node = _row_to_node({})
    assert node["id"] == ""
    assert node["metadata"] == {}


def test_row_to_edge_complete():
    row = {
        "id": "GE-1",
        "mission_id": "M-1",
        "from_node_id": "GN-1",
        "to_node_id": "GN-2",
        "relation": "exposes",
        "metadata_json": '{"k": "v"}',
        "created_at": "2024-01-01",
    }
    edge = _row_to_edge(row)
    assert edge["id"] == "GE-1"
    assert edge["from_node_id"] == "GN-1"
    assert edge["relation"] == "exposes"
    assert edge["metadata"] == {"k": "v"}


def test_json_load_dict_passthrough():
    assert _json_load({"a": 1}) == {"a": 1}


def test_json_load_list_passthrough():
    assert _json_load([1, 2]) == [1, 2]


def test_json_load_valid_string():
    assert _json_load('{"a": 1}') == {"a": 1}


def test_json_load_invalid_string_returns_default_empty_dict():
    assert _json_load("not json") == {}


def test_json_load_empty_string_returns_empty_dict():
    assert _json_load("") == {}


def test_json_load_invalid_with_explicit_default():
    assert _json_load("xx", default="fallback") == "fallback"


def test_json_load_none_returns_empty_dict():
    assert _json_load(None) == {}
