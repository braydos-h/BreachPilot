"""Attack Graph explorer API: read-only interactive investigation surface.

Exposes the per-run AttackGraph v2 store built by ``graph_builder``:

- ``GET /api/v1/graph/runs/{run_id}``               filtered nodes + edges
- ``GET /api/v1/graph/runs/{run_id}/summary``     counts + stats chips
- ``GET /api/v1/graph/runs/{run_id}/conflicts``   merge-engine conflicts
- ``GET /api/v1/graph/runs/{run_id}/nodes/{id}``  node details + connections
- ``GET /api/v1/graph/runs/{run_id}/nodes/{id}/neighbors``  bounded BFS
- ``GET /api/v1/graph/runs/{run_id}/paths``       bounded path discovery

Every query is bounded (node/edge limits, hop/path caps), rejects unknown
node ids with 404, validates enum filters, and is scope-isolated per run.
Gated behind ``api.graph_route`` (same flag as the legacy DAG route).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from tools.api.auth import BearerAuth
from tools.api.errors import APIError
from tools.api.graph_service import AttackGraphService
from tools.api.persistence import ApiPersistence

router = APIRouter(prefix="/api/v1/graph", tags=["graph-explorer"])

# Set by create_app.
_AUTH: BearerAuth | None = None
_PERSISTENCE: ApiPersistence | None = None
_CONFIG: dict[str, Any] = {}
_SERVICE: AttackGraphService | None = None
_GRAPH_ROUTE_ENABLED: bool = False

# Bounds (clamped client-side too; these are the authoritative ceilings).
_MAX_LIMIT = 500
_MAX_NEIGHBOR_HOPS = 4
_MAX_NEIGHBOR_NODES = 200
_MAX_PATH_LENGTH = 8
_MAX_PATH_COUNT = 8


def configure(auth: BearerAuth, persistence: ApiPersistence, config: dict[str, Any]) -> None:
    global _AUTH, _PERSISTENCE, _CONFIG, _SERVICE, _GRAPH_ROUTE_ENABLED
    _AUTH = auth
    _PERSISTENCE = persistence
    _CONFIG = config
    _SERVICE = AttackGraphService(persistence)
    api_cfg = config.get("api", {}) or {}
    _GRAPH_ROUTE_ENABLED = bool(api_cfg.get("graph_route", False))


async def _require_auth(request: Request) -> str:
    if _AUTH is None:
        raise RuntimeError("API auth not configured.")
    return await _AUTH(request)


def _gate() -> None:
    if not _GRAPH_ROUTE_ENABLED:
        raise APIError("graph_disabled", "Graph route disabled (api.graph_route=false)", status_code=404)


def _service() -> AttackGraphService:
    if _SERVICE is None or _PERSISTENCE is None:
        raise RuntimeError("Graph explorer not configured.")
    return _SERVICE


def _get_run(run_id: str) -> dict[str, Any]:
    run = _PERSISTENCE.get_run(run_id) if _PERSISTENCE else None
    if run is None:
        raise APIError("run_not_found", f"Run {run_id} not found", status_code=404)
    return run


def _clamp(value: Any, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(int(value), hi))
    except (TypeError, ValueError):
        return default


@router.get("/runs/{run_id}", response_model=None)
async def get_graph(
    run_id: str,
    node_type: list[str] = Query(default=[], alias="node_type"),
    status: list[str] = Query(default=[], alias="status"),
    q: str = Query(default=""),
    limit: int = Query(default=300),
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    """Filtered nodes + edges for a run. ``truncated`` true when ``limit`` hit."""
    _gate()
    run = _get_run(run_id)
    limit = _clamp(limit, 300, 1, _MAX_LIMIT)
    return _service().graph(run, node_types=node_type, statuses=status, search=q, limit=limit)


@router.get("/runs/{run_id}/summary", response_model=None)
async def get_summary(
    run_id: str,
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    _gate()
    return _service().summary(_get_run(run_id))


@router.get("/runs/{run_id}/conflicts", response_model=None)
async def get_conflicts(
    run_id: str,
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    _gate()
    return {"run_id": run_id, "conflicts": _service().conflicts(_get_run(run_id))}


@router.get("/runs/{run_id}/nodes/{node_id}", response_model=None)
async def get_node(
    run_id: str,
    node_id: str,
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    _gate()
    detail = _service().node(_get_run(run_id), node_id)
    if detail is None:
        raise APIError("node_not_found", f"Node {node_id} not found in run {run_id}", status_code=404)
    return {"run_id": run_id, **detail}


@router.get("/runs/{run_id}/nodes/{node_id}/neighbors", response_model=None)
async def get_neighbors(
    run_id: str,
    node_id: str,
    max_hops: int = Query(default=1),
    max_nodes: int = Query(default=50),
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    _gate()
    service = _service()
    result = service.neighbors(
        _get_run(run_id),
        node_id,
        max_hops=_clamp(max_hops, 1, 1, _MAX_NEIGHBOR_HOPS),
        max_nodes=_clamp(max_nodes, 50, 1, _MAX_NEIGHBOR_NODES),
    )
    if result["start_node"] is None:
        raise APIError("node_not_found", f"Node {node_id} not found in run {run_id}", status_code=404)
    return {"run_id": run_id, **result}


@router.get("/runs/{run_id}/paths", response_model=None)
async def get_paths(
    run_id: str,
    start: str,
    end: str,
    max_length: int = Query(default=4),
    max_paths: int = Query(default=5),
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    _gate()
    result = _service().paths(
        _get_run(run_id),
        start,
        end,
        max_length=_clamp(max_length, 4, 1, _MAX_PATH_LENGTH),
        max_paths=_clamp(max_paths, 5, 1, _MAX_PATH_COUNT),
    )
    return {"run_id": run_id, **result}
