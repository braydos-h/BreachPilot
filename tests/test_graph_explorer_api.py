"""Tests for the Attack Graph explorer API (tools/api/routes/graph_explorer.py).

Hermetic: no real network, no subprocesses. Builds a fake persistence + run
dir with a synthetic audit trail + enhanced report, then asserts the explorer
endpoints return bounded, scope-isolated graph data with the right shape.
Covers: default-off gating, summary, neighborhood bounds, path bounds, node
404s, scope isolation, conflicts, empty graph, and malformed params.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from starlette.testclient import TestClient

from tools.api.errors import install_error_handlers
from tools.api.routes import graph_explorer as graph_explorer_routes

# ── helpers ──────────────────────────────────────────────────────────────────


class _NoAuth:
    async def __call__(self, request):
        return "test"


class _FakePersistence:
    def __init__(self, reports_dir: Path, runs: dict[str, dict[str, Any]]):
        self.reports_dir = reports_dir
        self._runs = runs

    def get_run(self, run_id: str):
        return self._runs.get(run_id)


def _make_app(reports_dir: Path, runs: dict[str, dict[str, Any]], graph_enabled: bool = True):
    """Standalone app with only the explorer route + real error handlers."""
    app = FastAPI()
    install_error_handlers(app)
    router = graph_explorer_routes.create_router(
        auth=_NoAuth(),
        persistence=_FakePersistence(reports_dir, runs),
        config={"api": {"graph_route": graph_enabled}},
    )
    app.include_router(router)
    return app


def _sample_run() -> dict[str, Any]:
    return {
        "id": "run-1",
        "created_at": "2026-08-01T09:00:00Z",
        "updated_at": "2026-08-01T10:05:00Z",
        "request": {"target": "10.0.0.5", "mode": "attack"},
        "preview": {"target_ip": "10.0.0.5", "original_target": "10.0.0.5"},
    }


def _write_artifacts(run_dir: Path) -> None:
    """Write a realistic audit trail + enhanced report with one finding."""
    run_dir.mkdir(parents=True, exist_ok=True)
    audit = [
        {
            "timestamp": "2026-08-01T10:00:00Z",
            "target_ip": "10.0.0.5",
            "tool_name": "nmap",
            "status": "success",
            "attempt_id": "a1",
            "code_sha256": "abc",
        },
        {
            "timestamp": "2026-08-01T10:01:00Z",
            "target_ip": "10.0.0.5",
            "tool_name": "run_exploit_terminal",
            "status": "success",
            "attempt_id": "a2",
            "code_sha256": "def",
        },
    ]
    (run_dir / "exploit_audit.jsonl").write_text("\n".join(json.dumps(r) for r in audit), encoding="utf-8")
    enhanced = run_dir / "enhanced"
    enhanced.mkdir(parents=True, exist_ok=True)
    (enhanced / "enhanced_report.json").write_text(
        json.dumps(
            {
                "report_metadata": {"generated_at": "2026-08-01T10:05:00Z"},
                "technical_findings": [
                    {
                        "finding_id": "F-0001",
                        "title": "SQL injection in login",
                        "affected_asset": "10.0.0.5",
                        "vuln_class": "SQL Injection",
                        "severity": "high",
                        "cvss": {"base_score": 9.0, "severity": "critical"},
                        "confidence": 0.9,
                        "evidence_refs": ["ev:nmap:10.0.0.5:abc123:2026-08-01"],
                        "exploitation_result": "Exploit verified",
                        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                        "attack_chain": {"chain_id": "chain1"},
                    }
                ],
                "exploitation_chains": [
                    {
                        "chain_id": "chain1",
                        "target": "10.0.0.5",
                        "entries": [
                            {"module": "nmap", "result": "ports found"},
                            {"module": "sqlmap", "result": "injected"},
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _make(tmp_path: Path, runs: dict[str, dict[str, Any]] | None = None):
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    if runs is None:
        runs = {"run-1": _sample_run()}
        _write_artifacts(reports / "run-1")
    app = _make_app(reports, runs)
    return TestClient(app)


# ── default-off + run not found ──────────────────────────────────────────────


def test_explorer_default_off_returns_404(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    app = _make_app(reports, {"run-1": _sample_run()}, graph_enabled=False)
    resp = TestClient(app).get("/api/v1/graph/runs/run-1")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "graph_disabled"


def test_explorer_unknown_run_returns_404(tmp_path):
    client = _make(tmp_path, runs={})
    resp = client.get("/api/v1/graph/runs/nope")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "run_not_found"


# ── graph data ───────────────────────────────────────────────────────────────


def test_graph_returns_nodes_edges_and_real_types(tmp_path):
    client = _make(tmp_path)
    resp = client.get("/api/v1/graph/runs/run-1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["run_id"] == "run-1"
    types = {n["node_type"] for n in body["nodes"]}
    assert "ip" in types
    assert "finding" in types
    assert "observation" in types
    assert "evidence" in types
    assert "vulnerability_candidate" in types
    edge_types = {e["edge_type"] for e in body["edges"]}
    assert "observed_on" in edge_types
    assert "supported_by" in edge_types
    assert "affected_by" in edge_types
    # no fabricated tool/step/target legacy types
    assert not (types & {"tool", "target", "step"})


def test_graph_filters_by_type_status_and_search(tmp_path):
    client = _make(tmp_path)
    only_findings = client.get("/api/v1/graph/runs/run-1", params={"node_type": "finding"}).json()
    assert {n["node_type"] for n in only_findings["nodes"]} == {"finding"}
    confirmed = client.get("/api/v1/graph/runs/run-1", params={"status": "confirmed"}).json()
    assert {n["node_type"] for n in confirmed["nodes"]} == {"finding"}
    searched = client.get("/api/v1/graph/runs/run-1", params={"q": "sqlmap"}).json()
    assert searched["nodes"] and all("sqlmap" in n["value"].lower() for n in searched["nodes"])
    unknown_type = client.get("/api/v1/graph/runs/run-1", params={"node_type": "banana"}).json()
    assert unknown_type["nodes"]  # invalid filters are ignored, never 500


def test_graph_limit_is_bounded_and_truncation_flag(tmp_path):
    client = _make(tmp_path)
    tiny = client.get("/api/v1/graph/runs/run-1", params={"limit": 1}).json()
    assert len(tiny["nodes"]) <= 1
    assert tiny["truncated"] is True
    huge = client.get("/api/v1/graph/runs/run-1", params={"limit": 100000}).json()
    assert len(huge["nodes"]) <= 500  # clamped to the authoritative ceiling


def test_graph_empty_run_is_not_an_error(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "run-empty").mkdir()
    client = _make(
        tmp_path,
        runs={"run-empty": {"id": "run-empty", "created_at": "t", "updated_at": "t", "request": {}, "preview": {}}},
    )
    resp = client.get("/api/v1/graph/runs/run-empty")
    assert resp.status_code == 200
    body = resp.json()
    assert body["nodes"] == []
    assert body["edges"] == []
    assert body["truncated"] is False


# ── summary + conflicts ──────────────────────────────────────────────────────


def test_summary_counts_real_nodes(tmp_path):
    client = _make(tmp_path)
    resp = client.get("/api/v1/graph/runs/run-1/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["summary"]["total_nodes"] > 0
    assert body["stats"]["ips"] == 1
    assert body["stats"]["findings"] == 1
    assert body["stats"]["confirmed"] == 1
    assert body["stats"]["highest_degree_node"]["node_type"] == "ip"
    assert body["stats"]["conflict_count"] == 0


def test_conflicts_endpoint_returns_list(tmp_path):
    client = _make(tmp_path)
    resp = client.get("/api/v1/graph/runs/run-1/conflicts")
    assert resp.status_code == 200
    assert isinstance(resp.json()["conflicts"], list)


# ── node details + neighbors + paths ─────────────────────────────────────────


def _node_id_of(client: TestClient, node_type: str) -> str:
    body = client.get("/api/v1/graph/runs/run-1").json()
    return next(n["node_id"] for n in body["nodes"] if n["node_type"] == node_type)


def test_node_details_returns_connections(tmp_path):
    client = _make(tmp_path)
    fid = _node_id_of(client, "finding")
    resp = client.get(f"/api/v1/graph/runs/run-1/nodes/{fid}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["node"]["node_type"] == "finding"
    assert body["node"]["status"] == "confirmed"
    assert body["node"]["properties"]["cvss_score"] == 9.0
    assert body["edges"] and body["neighbors"]


def test_node_details_unknown_node_404(tmp_path):
    client = _make(tmp_path)
    resp = client.get("/api/v1/graph/runs/run-1/nodes/run:nope|ip|1-2-3-4")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "node_not_found"


def test_neighbors_bounded_and_clamped(tmp_path):
    client = _make(tmp_path)
    ip_id = _node_id_of(client, "ip")
    resp = client.get(
        f"/api/v1/graph/runs/run-1/nodes/{ip_id}/neighbors",
        params={"max_hops": 99, "max_nodes": 99999},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["nodes"]) <= 200  # clamped
    assert body["start_node"]["node_id"] == ip_id


def test_neighbors_unknown_node_404(tmp_path):
    client = _make(tmp_path)
    resp = client.get("/api/v1/graph/runs/run-1/nodes/run:nope|ip|1-2-3-4/neighbors")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "node_not_found"


def test_paths_bounded(tmp_path):
    client = _make(tmp_path)
    ip_id = _node_id_of(client, "ip")
    fid = _node_id_of(client, "finding")
    resp = client.get(
        "/api/v1/graph/runs/run-1/paths",
        params={"start": ip_id, "end": fid, "max_length": 4, "max_paths": 5},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["paths"]) <= 5
    for path in body["paths"]:
        assert path[-1]["node"]["node_id"] == fid  # each step ends at the target
        assert all(step["distance"] >= 1 for step in path)
        assert all(step["distance"] <= 4 for step in path)


def test_paths_unknown_endpoint_returns_empty(tmp_path):
    client = _make(tmp_path)
    resp = client.get(
        "/api/v1/graph/runs/run-1/paths",
        params={"start": "run:nope", "end": "run:nope2", "max_length": 3, "max_paths": 5},
    )
    assert resp.status_code == 200
    assert resp.json()["paths"] == []


# ── scope isolation ──────────────────────────────────────────────────────────


def test_scope_isolation_between_runs(tmp_path):
    """A node id from run A must never resolve inside run B."""
    reports = tmp_path / "reports"
    reports.mkdir()
    _write_artifacts(reports / "run-1")
    # run-2 has no artifacts; node ids are run-scoped by construction.
    (reports / "run-2").mkdir()
    runs = {
        "run-1": _sample_run(),
        "run-2": {
            "id": "run-2",
            "created_at": "t",
            "updated_at": "t",
            "request": {"target": "10.0.0.9"},
            "preview": {"target_ip": "10.0.0.9", "original_target": "10.0.0.9"},
        },
    }
    client = _make(tmp_path, runs=runs)
    run1_ids = {n["node_id"] for n in client.get("/api/v1/graph/runs/run-1").json()["nodes"]}
    run2_ids = {n["node_id"] for n in client.get("/api/v1/graph/runs/run-2").json()["nodes"]}
    assert run1_ids.isdisjoint(run2_ids)
    # Cross-run node lookup is 404.
    foreign_id = next(iter(run1_ids))
    resp = client.get(f"/api/v1/graph/runs/run-2/nodes/{foreign_id}")
    assert resp.status_code == 404


# ── builder unit tests ───────────────────────────────────────────────────────


def test_builder_records_merge_conflict_on_skipped_edge():
    """An edge referencing a missing node is recorded as a conflict, not fatal."""
    from tools.api.graph_builder import _safe_apply
    from tools.intelligence.graph.store import AttackGraphStore
    from tools.intelligence.graph.types import EdgeType, GraphEdge, GraphUpdate

    store = AttackGraphStore(":memory:", scope="run:x")
    update = GraphUpdate(
        edge_updates=[
            GraphEdge(
                edge_id="e1",
                source_node_id="missing-a",
                target_node_id="missing-b",
                edge_type=EdgeType.OBSERVED_ON,
                scope="run:x",
                first_seen="t",
                last_seen="t",
            )
        ]
    )
    conflicts: list[Any] = []
    _safe_apply(store, update, conflicts)
    assert len(conflicts) == 1
    assert "ingest skip" in conflicts[0].reason
    assert store.summary()["total_nodes"] == 0


def test_builder_surfaces_intrabatch_type_conflict():
    """Same value proposed as two types within one update -> merge conflict."""
    from tools.api.graph_builder import _safe_apply
    from tools.intelligence.graph.store import AttackGraphStore
    from tools.intelligence.graph.types import GraphNode, GraphUpdate, NodeStatus, NodeType

    store = AttackGraphStore(":memory:", scope="run:x")
    update = GraphUpdate(
        node_updates=[
            GraphNode(node_id="a", node_type=NodeType.HOST, value="10.0.0.5", scope="run:x", status=NodeStatus.UNKNOWN),
            GraphNode(node_id="b", node_type=NodeType.IP, value="10.0.0.5", scope="run:x", status=NodeStatus.UNKNOWN),
        ]
    )
    conflicts: list[Any] = []
    _safe_apply(store, update, conflicts)
    assert any("type conflict" in c.reason for c in conflicts)
