"""C5: FindingAdapter wiring tests — validation reachability + graph linking."""

from __future__ import annotations

import pytest

from db import DatabaseManager, _new_id
from finding_verifier import FindingVerifier
from target_graph import TargetGraph
from tools.intelligence.adapters.finding_adapter import FindingAdapter


@pytest.fixture
def temp_db(tmp_path):
    path = tmp_path / "adapter.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
        mid = _new_id("M")
        conn.execute(
            """INSERT INTO missions(id, program_name, objective, risk_profile, created_at, updated_at)
            VALUES(?,?,?,?,datetime('now'),datetime('now'))""",
            (mid, "Adapter Test", "Find vulns.", "standard_authorized"),
        )
        db._mid = mid
    return db


@pytest.fixture
def verifier(temp_db):
    return FindingVerifier(temp_db, temp_db._mid)


@pytest.fixture
def graph(temp_db):
    return TargetGraph(temp_db, temp_db._mid)


def test_ensure_reproduction_steps_derives_from_evidence():
    finding = {"reproduction_steps": [], "evidence_refs": ["E-1", "E-2"]}
    steps = FindingAdapter.ensure_reproduction_steps(finding)
    assert steps == ["Reproduce via evidence: E-1", "Reproduce via evidence: E-2"]


def test_ensure_reproduction_steps_keeps_existing():
    finding = {"reproduction_steps": ["step one"], "evidence_refs": []}
    assert FindingAdapter.ensure_reproduction_steps(finding) == ["step one"]


def test_ensure_reproduction_steps_accepts_explicit_refs():
    finding = {"reproduction_steps_json": "[]", "evidence_refs_json": "[]"}
    steps = FindingAdapter.ensure_reproduction_steps(finding, evidence_refs=["E-9"])
    assert steps == ["Reproduce via evidence: E-9"]


def test_validate_finding_auto_transitions_to_validated(verifier):
    """C5 regression: previously impossible because reproduction_steps never filled."""
    fid = verifier.create_candidate(
        title="IDOR on /api/user",
        affected_asset="example.com",
        summary="User can access other users' data by changing the ID parameter.",
        vuln_class="IDOR",
        impact="Unauthorized access to user data.",
        evidence_refs=["E-0001"],
    )
    result = verifier.validate_finding(fid)
    assert result["valid"] is True
    assert "reproduction_steps" not in result["missing"]
    assert verifier.get_finding(fid)["status"] == "validated"


def test_dedupe_findings_returns_existing_id(verifier):
    fid = verifier.create_candidate(
        title="First",
        affected_asset="example.com",
        summary="Summary of sufficient length for a candidate finding.",
        vuln_class="IDOR",
    )
    assert FindingAdapter.dedupe_findings(verifier, "example.com", "IDOR", None) == fid
    assert FindingAdapter.dedupe_findings(verifier, "example.com", "XSS", None) is None
    assert FindingAdapter.dedupe_findings(verifier, "other.com", "IDOR", None) is None


def test_link_to_graph_creates_finding_node_and_edges(verifier, graph):
    fid = verifier.create_candidate(
        title="IDOR on /api/user",
        affected_asset="example.com",
        summary="User can access other users' data by changing the ID parameter.",
        vuln_class="IDOR",
        impact="Unauthorized access to user data.",
        evidence_refs=["E-0001"],
    )
    finding = verifier.get_finding(fid)
    node_id = FindingAdapter.link_to_graph(verifier, graph, finding, node_map={})
    assert node_id is not None

    nodes = graph.query_graph(node_type="finding").get("nodes", [])
    assert any(n["id"] == node_id and n["value"] == "IDOR on /api/user" for n in nodes)

    edges = graph.query_graph().get("edges", [])
    assert any(e["from_node_id"] == node_id and e["relation"] == "related_to" for e in edges)
    assert any(e["from_node_id"] == node_id and e["relation"] == "produced_evidence" for e in edges)


def test_link_to_graph_is_idempotent(verifier, graph):
    fid = verifier.create_candidate(
        title="Repeated finding",
        affected_asset="example.com",
        summary="Summary of sufficient length for a candidate finding.",
        vuln_class="XSS",
        evidence_refs=["E-2"],
    )
    finding = verifier.get_finding(fid)
    first = FindingAdapter.link_to_graph(verifier, graph, finding, node_map={})
    second = FindingAdapter.link_to_graph(verifier, graph, finding, node_map={})
    assert first == second
    assert len(graph.query_graph(node_type="finding").get("nodes", [])) == 1


def test_link_to_graph_returns_none_without_finding_id(graph):
    assert FindingAdapter.link_to_graph(verifier=None, target_graph=graph, finding_row={}, node_map={}) is None
