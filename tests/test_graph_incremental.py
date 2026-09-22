"""P2-04: incremental graph ingest parity (incremental == fresh full build)."""

from __future__ import annotations

import json


def _rec(i: int, tool: str = "run_exploit_terminal", target: str = "10.0.0.5") -> dict:
    return {
        "tool_name": tool,
        "target_ip": target,
        "timestamp": f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}Z",
        "status": "success",
        "attempt_id": f"a{i}",
        "code_sha256": f"{i:064d}",
    }


def _run_row(run_id: str) -> dict:
    return {
        "id": run_id,
        "updated_at": "2026-01-01T00:00:00Z",
        "request": {"target": "10.0.0.5"},
        "preview": {"target_ip": "10.0.0.5", "original_target": "10.0.0.5"},
    }


def _snapshot(service, run: dict) -> dict:
    g = service.graph(run, limit=500)
    return {
        "total_nodes": g["total_nodes"],
        "nodes": sorted((n["node_id"], n["value"], n["observation_count"], n["status"]) for n in g["nodes"]),
        "edges": sorted((e["source_node_id"], e["target_node_id"], e["edge_type"]) for e in g["edges"]),
    }


def test_incremental_ingest_parity(tmp_path):
    from tools.api.graph_service import AttackGraphService

    reports = tmp_path / "reports"
    run_dir = reports / "run1"
    run_dir.mkdir(parents=True)
    audit = run_dir / "exploit_audit.jsonl"
    audit.write_text("\n".join(json.dumps(_rec(i)) for i in range(500)) + "\n", encoding="utf-8")

    service = AttackGraphService(persistence=None, reports_dir=reports)
    run = _run_row("run1")
    before = _snapshot(service, run)

    # Append 200 lines: incremental path must equal a fresh full build.
    with audit.open("a", encoding="utf-8") as f:
        for i in range(500, 700):
            f.write(json.dumps(_rec(i, tool="run_web_scan" if i % 2 else "run_exploit_terminal")) + "\n")

    # Cost proof: count node upserts during the refresh. A full rebuild
    # replays all 700 records; incremental ingest touches O(new) only.
    import tools.intelligence.graph.store as st

    calls = {"n": 0}
    real_upsert = st.AttackGraphStore.upsert_node

    def counting_upsert(self, node):
        calls["n"] += 1
        return real_upsert(self, node)

    st.AttackGraphStore.upsert_node = counting_upsert  # type: ignore[method-assign]
    try:
        incremental = _snapshot(service, run)
    finally:
        st.AttackGraphStore.upsert_node = real_upsert  # type: ignore[method-assign]
    assert calls["n"] < 500, f"re-ingested {calls['n']} nodes for 200 new records (full rebuild?)"

    fresh_reports = tmp_path / "reports_fresh"
    fresh_dir = fresh_reports / "run1"
    fresh_dir.mkdir(parents=True)
    (fresh_dir / "exploit_audit.jsonl").write_text(audit.read_text(encoding="utf-8"), encoding="utf-8")
    fresh_service = AttackGraphService(persistence=None, reports_dir=fresh_reports)
    rebuilt = _snapshot(fresh_service, _run_row("run1"))

    assert incremental == rebuilt
    assert incremental["total_nodes"] > before["total_nodes"]
