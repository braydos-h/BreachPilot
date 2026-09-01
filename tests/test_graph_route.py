"""Tests for the graph-viz API route (tools/api/routes/graph.py).

Hermetic: no real network, no real filesystem entry points. Builds a fake
persistence + run dir with a synthetic audit trail + enhanced report, then
asserts the route returns DAG JSON with the right node/edge shape. Verifies
the route is default-off (404 when api.graph_route=false).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from starlette.testclient import TestClient

from tools.api.routes import graph as graph_routes

# ── build_graph unit tests ───────────────────────────────────────────────────


def test_build_graph_empty_inputs():
    g = graph_routes.build_graph([], [])
    assert g["nodes"] == []
    assert g["edges"] == []


def test_build_graph_audit_records_create_tool_and_target_nodes():
    records = [
        {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"},
        {"tool_name": "dump_credentials", "target_ip": "10.0.0.5", "status": "completed"},
    ]
    g = graph_routes.build_graph(records, [])
    node_ids = {n["id"] for n in g["nodes"]}
    assert "tool:run_exploit_terminal" in node_ids
    assert "tool:dump_credentials" in node_ids
    assert "target:10.0.0.5" in node_ids


def test_build_graph_targets_edge_from_tool_to_target():
    records = [{"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"}]
    g = graph_routes.build_graph(records, [])
    targets_edges = [e for e in g["edges"] if e["relation"] == "targets"]
    assert any(e["source"] == "tool:run_exploit_terminal" and e["target"] == "target:10.0.0.5" for e in targets_edges)


def test_build_graph_temporal_enables_edge_between_consecutive_tools():
    records = [
        {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"},
        {"tool_name": "dump_credentials", "target_ip": "10.0.0.5", "status": "completed"},
    ]
    g = graph_routes.build_graph(records, [])
    enables_edges = [e for e in g["edges"] if e["relation"] == "enables"]
    assert any(
        e["source"] == "tool:run_exploit_terminal" and e["target"] == "tool:dump_credentials" for e in enables_edges
    )


def test_build_graph_skips_empty_tool_name():
    records = [{"tool_name": "", "target_ip": "10.0.0.5", "status": "completed"}]
    g = graph_routes.build_graph(records, [])
    assert g["nodes"] == []


def test_build_graph_handles_comma_joined_targets():
    records = [{"tool_name": "lateral_exec", "target_ip": "10.0.0.5,10.0.0.6", "status": "completed"}]
    g = graph_routes.build_graph(records, [])
    node_ids = {n["id"] for n in g["nodes"]}
    assert "target:10.0.0.5" in node_ids
    assert "target:10.0.0.6" in node_ids


def test_build_graph_chain_entries_become_step_nodes():
    chains = [
        {
            "chain_id": "CHAIN-1",
            "entries": [
                {"module": "recon", "result": "success"},
                {"module": "exploit", "result": "success"},
            ],
        },
    ]
    g = graph_routes.build_graph([], chains)
    step_nodes = [n for n in g["nodes"] if n["type"] == "step"]
    assert len(step_nodes) == 2
    enables = [e for e in g["edges"] if e["relation"] == "enables"]
    assert any(e["source"].endswith(":recon") and e["target"].endswith(":exploit") for e in enables)


def test_build_graph_no_self_edges():
    """A tool that targets itself never produces a self-loop."""
    records = [{"tool_name": "run_exploit_terminal", "target_ip": "run_exploit_terminal", "status": "completed"}]
    g = graph_routes.build_graph(records, [])
    for e in g["edges"]:
        assert e["source"] != e["target"]


def test_build_graph_node_shape():
    records = [{"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"}]
    g = graph_routes.build_graph(records, [])
    for node in g["nodes"]:
        assert "id" in node
        assert "type" in node
        assert "label" in node
    for edge in g["edges"]:
        assert "source" in edge
        assert "target" in edge
        assert "relation" in edge


# ── Route integration (default-off + enabled) ────────────────────────────────


class _FakePersistence:
    """Minimal persistence stub: reports_dir + get_run()."""

    def __init__(self, reports_dir: Path, runs: dict[str, dict[str, Any]]):
        self.reports_dir = reports_dir
        self._runs = runs

    def get_run(self, run_id: str):
        return self._runs.get(run_id)


def _make_app(reports_dir: Path, runs: dict[str, dict[str, Any]], graph_enabled: bool):
    """Build a FastAPI app with only the graph route mounted + a fake auth."""
    app = FastAPI()
    router = graph_routes.create_router(
        auth=_NoAuth(),
        persistence=_FakePersistence(reports_dir, runs),
        config={"api": {"graph_route": graph_enabled}},
    )
    app.include_router(router)
    return app


class _NoAuth:
    async def __call__(self, request):
        return "test"


def _write_audit(run_dir: Path, records: list[dict[str, Any]]):
    run_dir.mkdir(parents=True, exist_ok=True)
    audit = run_dir / "exploit_audit.jsonl"
    with audit.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def test_graph_route_default_off_returns_404(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    run_dir = reports / "run-1"
    _write_audit(run_dir, [{"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"}])
    app = _make_app(reports, {"run-1": {"run_id": "run-1"}}, graph_enabled=False)
    client = TestClient(app)
    resp = client.get("/api/v1/runs/run-1/graph")
    assert resp.status_code == 404


def test_graph_route_enabled_returns_dag(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    run_dir = reports / "run-1"
    _write_audit(
        run_dir,
        [
            {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"},
            {"tool_name": "dump_credentials", "target_ip": "10.0.0.5", "status": "completed"},
        ],
    )
    app = _make_app(reports, {"run-1": {"run_id": "run-1"}}, graph_enabled=True)
    client = TestClient(app)
    resp = client.get("/api/v1/runs/run-1/graph")
    assert resp.status_code == 200
    body = resp.json()
    assert body["run_id"] == "run-1"
    assert len(body["nodes"]) > 0
    assert len(body["edges"]) > 0
    node_ids = {n["id"] for n in body["nodes"]}
    assert "tool:run_exploit_terminal" in node_ids
    assert "tool:dump_credentials" in node_ids
    assert "target:10.0.0.5" in node_ids


def test_graph_route_unknown_run_returns_404(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    app = _make_app(reports, {}, graph_enabled=True)
    client = TestClient(app)
    resp = client.get("/api/v1/runs/no-such-run/graph")
    assert resp.status_code == 404


def test_graph_route_no_network(tmp_path):
    """The route reads local files only; no subprocess, no network."""
    reports = tmp_path / "reports"
    reports.mkdir()
    run_dir = reports / "run-1"
    _write_audit(run_dir, [{"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "completed"}])
    app = _make_app(reports, {"run-1": {"run_id": "run-1"}}, graph_enabled=True)
    client = TestClient(app)
    resp = client.get("/api/v1/runs/run-1/graph")
    assert resp.status_code == 200
    # empty audit + no enhanced report → empty graph (not an error)
    body = resp.json()
    assert "nodes" in body
    assert "edges" in body


def test_graph_route_reads_enhanced_chains(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    run_dir = reports / "run-1"
    _write_audit(run_dir, [])
    enhanced_dir = run_dir / "enhanced"
    enhanced_dir.mkdir(parents=True, exist_ok=True)
    (enhanced_dir / "enhanced_report.json").write_text(
        json.dumps(
            {
                "exploitation_chains": [
                    {"chain_id": "CHAIN-1", "entries": [{"module": "recon", "result": "success"}]},
                ],
            }
        ),
        encoding="utf-8",
    )
    app = _make_app(reports, {"run-1": {"run_id": "run-1"}}, graph_enabled=True)
    client = TestClient(app)
    resp = client.get("/api/v1/runs/run-1/graph")
    assert resp.status_code == 200
    body = resp.json()
    step_nodes = [n for n in body["nodes"] if n["type"] == "step"]
    assert len(step_nodes) == 1
    assert step_nodes[0]["label"] == "recon"
