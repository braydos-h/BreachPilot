"""Graph visualization API route: read-only attack-path DAG.

Exposes ``GET /api/v1/runs/{run_id}/graph`` returning a DAG JSON the WebUI
renders with reactflow. Nodes = findings/creds/access/tools; edges = "enables"
(temporal tool-execution order + exploitation_chain entry links). Read-only:
no target touch. Default-off via ``api.graph_route`` (config).

The DAG is built from the run's ``exploit_audit.jsonl`` (Flow A's append-only
audit trail) plus the enhanced report's ``exploitation_chains`` when present.
This avoids depending on Flow B's SQLite ``target_graph.py`` (which is mission-
scoped, not run-scoped) — Flow A runs don't always have a mission DB.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from tools.api.auth import BearerAuth
from tools.api.persistence import ApiPersistence

router = APIRouter(prefix="/api/v1", tags=["graph"])

# Set by create_app.
_AUTH: BearerAuth | None = None
_PERSISTENCE: ApiPersistence | None = None
_CONFIG: dict[str, Any] = {}
_GRAPH_ROUTE_ENABLED: bool = False


def configure(auth: BearerAuth, persistence: ApiPersistence, config: dict[str, Any]) -> None:
    global _AUTH, _PERSISTENCE, _CONFIG, _GRAPH_ROUTE_ENABLED
    _AUTH = auth
    _PERSISTENCE = persistence
    _CONFIG = config
    api_cfg = config.get("api", {}) or {}
    _GRAPH_ROUTE_ENABLED = bool(api_cfg.get("graph_route", False))


async def _require_auth(request: Request) -> str:
    if _AUTH is None:
        raise RuntimeError("API auth not configured.")
    return await _AUTH(request)


def _run_dir(run_id: str) -> Path:
    """Resolve reports/<run_id>/, refusing path escapes (mirrors runs.py)."""
    if _PERSISTENCE is None:
        raise RuntimeError("Persistence not configured.")
    base = _PERSISTENCE.reports_dir.resolve()
    candidate = (base / run_id).resolve()
    if base not in candidate.parents and candidate != base:
        raise HTTPException(status_code=400, detail="Invalid run id")
    return candidate


def _read_audit(run_dir: Path) -> list[dict[str, Any]]:
    """Read the run's exploit_audit.jsonl (tries two locations). Tolerant."""
    for candidate in (run_dir / "exploit_audit.jsonl", run_dir / "exploit_workspace" / "exploit_audit.jsonl"):
        if not candidate.is_file():
            continue
        records: list[dict[str, Any]] = []
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                records.append(rec)
        return records
    return []


def _read_enhanced_chains(run_dir: Path) -> list[dict[str, Any]]:
    """Read exploitation_chains from enhanced/enhanced_report.json if present."""
    path = run_dir / "enhanced" / "enhanced_report.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    chains = data.get("exploitation_chains") or []
    return chains if isinstance(chains, list) else []


def build_graph(records: list[dict[str, Any]], chains: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a DAG JSON from audit records + exploitation chains.

    Nodes: one per distinct tool_name (type ``tool``), per distinct target_ip
    (type ``target``), and per chain entry (type ``step`` with chain_id).
    Edges: temporal ``enables`` between consecutive tool executions on the
    same target; ``enables`` between chain entries (chain order); ``targets``
    between a tool and its target_ip.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    edge_seen: set[str] = set()

    def add_node(node_id: str, node_type: str, label: str, **extra: Any) -> None:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": node_type, "label": label, **extra}

    def add_edge(source: str, target: str, relation: str = "enables") -> None:
        key = f"{source}->{target}:{relation}"
        if key in edge_seen or source == target:
            return
        edge_seen.add(key)
        edges.append({"source": source, "target": target, "relation": relation})

    # Audit records → tool + target nodes + temporal edges per target.
    last_tool_per_target: dict[str, str] = {}
    for rec in records:
        tool = str(rec.get("tool_name") or "").strip()
        if not tool:
            continue
        tool_id = f"tool:{tool}"
        add_node(tool_id, "tool", tool, status=str(rec.get("status") or ""))
        targets = str(rec.get("target_ip") or "")
        for t in targets.split(","):
            t = t.strip()
            if not t:
                continue
            target_id = f"target:{t}"
            add_node(target_id, "target", t)
            add_edge(tool_id, target_id, "targets")
            # temporal edge: previous tool on this target enables this one
            prev = last_tool_per_target.get(t)
            if prev and prev != tool_id:
                add_edge(prev, tool_id, "enables")
            last_tool_per_target[t] = tool_id

    # Exploitation chains → step nodes + chain-order edges.
    for chain in chains:
        chain_id = str(chain.get("chain_id") or "")
        entries = chain.get("entries") or []
        prev_step: str | None = None
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            module = str(entry.get("module") or entry.get("tool") or f"step-{i}")
            step_id = f"step:{chain_id}:{i}:{module}"
            add_node(
                step_id,
                "step",
                module,
                chain_id=chain_id,
                result=str(entry.get("result") or ""),
            )
            if prev_step:
                add_edge(prev_step, step_id, "enables")
            prev_step = step_id

    return {"nodes": list(nodes.values()), "edges": edges}


@router.get("/runs/{run_id}/graph", response_model=None)
async def get_run_graph(
    run_id: str,
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    """Return the attack-path DAG for a run (nodes + edges).

    Read-only. Default-off: returns 404 when ``api.graph_route`` is false. The
    DAG is built from the run's exploit_audit.jsonl + enhanced_report.json
    exploitation_chains when present. No target touch, no network.
    """
    if not _GRAPH_ROUTE_ENABLED:
        raise HTTPException(status_code=404, detail="Graph route disabled (api.graph_route=false)")
    if _PERSISTENCE is None or _PERSISTENCE.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="Run not found")
    run_dir = _run_dir(run_id)
    records = _read_audit(run_dir)
    chains = _read_enhanced_chains(run_dir)
    graph = build_graph(records, chains)
    return {"run_id": run_id, "nodes": graph["nodes"], "edges": graph["edges"]}
