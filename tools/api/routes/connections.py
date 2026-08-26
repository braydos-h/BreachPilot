"""Connections / Access API — persisted operator connection state.

Exposes the ConnectionManager (tools/operator_connection/manager.py) via
authenticated REST endpoints under /api/v1.  The manager is the single source
of truth; this module never reads/writes operator_connections.json directly.
Listener output goes through PersistentSessionManager so the API reuses the
same tmux/nohup/nc back-end that the operator implants use.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from tools.api.auth import BearerAuth

router = APIRouter(prefix="/api/v1", tags=["connections"])

_AUTH: BearerAuth | None = None
_CONFIG: dict[str, Any] = {}
_CONFIG_PATH: Path = Path("config.yaml")

# Connection ID pattern: conn- + 8 hex chars (from manager._conn_id)
_CONN_ID_RE = re.compile(r"^conn-[0-9a-f]{8}$")
# Allowlist of valid statuses
_VALID_STATUSES = {"active", "stale", "removed", "error"}


def configure(auth: BearerAuth, config: dict[str, Any], config_path: Path) -> None:
    global _AUTH, _CONFIG, _CONFIG_PATH
    _AUTH = auth
    _CONFIG = config
    _CONFIG_PATH = config_path


async def _require_auth(request: Request) -> str:
    if _AUTH is None:
        raise RuntimeError("API not configured.")
    return await _AUTH(request)


def _workspace() -> Path:
    """Resolve the operator_connection workspace directory."""
    oc_cfg = _CONFIG.get("operator_connection", {}) or {}
    ws_raw = oc_cfg.get("workspace_dir") or ""
    if not ws_raw:
        # Fallback to exploit workspace_dir
        ws_raw = (_CONFIG.get("exploit", {}) or {}).get("workspace_dir", "exploit_workspace")
    p = Path(str(ws_raw))
    if not p.is_absolute():
        p = (_CONFIG_PATH.parent / p).resolve()
    else:
        p = p.resolve()
    return p


def _get_manager():
    from tools.operator_connection.manager import get_connection_manager

    ws = _workspace()
    ws.mkdir(parents=True, exist_ok=True)
    return get_connection_manager(ws)


def _get_session_manager():
    from tools.persistent_session_manager import get_session_manager

    ws = _workspace()
    ws.mkdir(parents=True, exist_ok=True)
    return get_session_manager(ws)


def _validate_connection_id(cid: str) -> str:
    cid = (cid or "").strip()
    if not cid:
        raise HTTPException(status_code=400, detail="Invalid connection id")
    # Accept conn-xxxxxxxx but also tolerate other ids that manager may have created
    # without being overly strict — still block path traversal.
    if "/" in cid or "\\" in cid or ".." in cid or len(cid) > 64:
        raise HTTPException(status_code=400, detail="Invalid connection id")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", cid):
        raise HTTPException(status_code=400, detail="Invalid connection id")
    return cid


# -- Pydantic response models ---------------------------------------------


class ConnectionResponse(BaseModel):
    connection_id: str
    target_ip: str
    method: str
    callback_host: str
    callback_port: int
    listener_name: str
    status: str
    created_at: float
    created_at_iso: str | None = None
    last_beacon: float | None = None
    last_beacon_iso: str | None = None
    last_check: float | None = None
    last_check_iso: str | None = None
    check_output: str = ""
    implant_path: str = ""
    mitre_technique: str = ""
    os_family: str = ""
    notes: str = ""


class ConnectionsListResponse(BaseModel):
    connections: list[ConnectionResponse]
    total: int
    active: int
    stale: int
    removed: int
    error: int


class ListenerOutputResponse(BaseModel):
    connection_id: str
    listener_name: str
    output: str
    updated_at: str
    running: bool = False
    status: str = ""


class RemoveResponse(BaseModel):
    connection: ConnectionResponse
    removed: bool = True
    listener_stopped: bool = False


# -- Helpers ---------------------------------------------------------------


def _to_response_dict(rec: Any) -> dict[str, Any]:
    """Convert ConnectionRecord to API dict via to_dict()."""
    return rec.to_dict()


def _counts(conns: list[Any]) -> dict[str, int]:
    total = len(conns)
    active = sum(1 for c in conns if c.status == "active")
    stale = sum(1 for c in conns if c.status == "stale")
    removed = sum(1 for c in conns if c.status == "removed")
    error = sum(1 for c in conns if c.status == "error")
    return {"total": total, "active": active, "stale": stale, "removed": removed, "error": error}


# -- Routes ----------------------------------------------------------------


@router.get("/connections", response_model=ConnectionsListResponse)
async def list_connections(
    status: str | None = Query(None, description="Filter by status: active|stale|removed|error"),
    target: str | None = Query(None, description="Filter by target IP"),
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    mgr = _get_manager()
    # Validate status
    if status is not None:
        status = status.strip().lower()
        if status and status not in _VALID_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status {status!r}. Must be one of: {', '.join(sorted(_VALID_STATUSES))}",
            )
    else:
        status = ""
    target_ip = (target or "").strip()
    # Use manager's target filter if provided, else all
    if target_ip:
        # Use manager filtering then apply status filter
        recs = mgr.list_connections(target_ip=target_ip)
    else:
        recs = mgr.list_connections()
    if status:
        recs = [r for r in recs if r.status == status]
    # Build response
    conn_dicts = [_to_response_dict(r) for r in recs]
    # For counts: if filtering, show counts for filtered set? Provide overall counts from full
    # unfiltered set so KPI cards reflect global state even when filtered.
    # But spec says counts in response should be for the returned set? We provide both:
    # total etc reflect filtered counts; frontend can also compute.
    # To also satisfy "Active 3" KPI when filtered to Active, we return filtered counts.
    cnt = _counts(recs)
    return {"connections": conn_dicts, **cnt}


@router.get("/connections/{connection_id}", response_model=ConnectionResponse)
async def get_connection(
    connection_id: str,
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    cid = _validate_connection_id(connection_id)
    mgr = _get_manager()
    rec = mgr.get(cid)
    if rec is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    return _to_response_dict(rec)


@router.post("/connections/{connection_id}/check", response_model=ConnectionResponse)
async def check_connection(
    connection_id: str,
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    cid = _validate_connection_id(connection_id)
    mgr = _get_manager()
    rec = mgr.get(cid)
    if rec is None:
        raise HTTPException(status_code=404, detail="Connection not found")

    # Perform health check via PersistentSessionManager listener state.
    # This reuses the same session abstractions as the implant infrastructure.
    output = ""
    healthy = False
    listener_running = False
    try:
        sess_mgr = _get_session_manager()
        # Read listener output (bounded, never unlimited)
        try:
            # Use read_listener_output for the listener associated with this connection
            result = sess_mgr.read_listener_output(rec.listener_name, lines=100)
            if isinstance(result, dict):
                output = str(result.get("output", ""))
                listener_running = bool(result.get("running", False))
                # If output starts with LOG_NOT_FOUND or INVALID_NAME, treat as not healthy
                if output.startswith("LOG_NOT_FOUND") or output.startswith("INVALID_NAME"):
                    healthy = False
                    # Keep output as is for check_output so operator sees reason
                else:
                    healthy = listener_running
                    # If output is empty but listener running, still healthy (no beacons yet)
            else:
                output = str(result)
                healthy = False
        except Exception as exc:
            output = f"listener check error: {exc}"
            healthy = False
            listener_running = False

        # Also consider the record's own state: if listener not running, stale
        # If exception, mark as error later.
        if not listener_running:
            healthy = False
            if not output or output.startswith("LOG_NOT_FOUND"):
                # Try list_all_sessions as fallback to detect running
                try:
                    all_sessions = sess_mgr.list_all_sessions()
                    if any(s.get("name") == rec.listener_name and s.get("running") for s in all_sessions):
                        healthy = True
                        listener_running = True
                        if not output or output.startswith("LOG_NOT_FOUND"):
                            output = "listener running (no recent output)"
                except Exception:
                    pass
                if not healthy and not output:
                    output = f"listener {rec.listener_name!r} not running"

    except Exception as exc:
        output = f"health check failed: {exc}"
        healthy = False

    # Update manager state: active | stale | error
    # Use mark_check for active/stale, and override to error if needed.
    try:
        # Use existing mark_check which does active/stale and truncates output to 2000
        mgr.mark_check(cid, output, healthy)
        updated = mgr.get(cid)
        if updated is None:
            raise HTTPException(status_code=404, detail="Connection not found")
        # If we detected a hard error (e.g. exception), promote to error status
        if not healthy and output.startswith("health check failed"):
            updated.status = "error"
            updated.check_output = output[:2000]
            updated.last_check = time.time()
            # Persist
            try:
                mgr._save()  # type: ignore[attr-defined]
            except Exception:
                pass
        return _to_response_dict(updated)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Health check error: {exc}")


@router.post("/connections/{connection_id}/remove", response_model=RemoveResponse)
async def remove_connection(
    connection_id: str,
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    cid = _validate_connection_id(connection_id)
    mgr = _get_manager()
    rec = mgr.get(cid)
    if rec is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    listener_name = rec.listener_name

    # Prefer graceful state transition: mark_removed preserves record for audit.
    success = mgr.mark_removed(cid)
    if not success:
        raise HTTPException(status_code=404, detail="Connection not found")

    updated = mgr.get(cid)
    if updated is None:
        raise HTTPException(status_code=404, detail="Connection not found")

    # Best-effort listener cleanup via PersistentSessionManager.
    # The UI action should not fail if listener already stopped.
    listener_stopped = False
    try:
        sess_mgr = _get_session_manager()
        # Try stop_listener, then fallback to stop_background_job
        res = sess_mgr.stop_listener(listener_name)
        if isinstance(res, dict) and res.get("success"):
            listener_stopped = True
        else:
            # Try background job fallback
            try:
                res2 = sess_mgr.stop_background_job(listener_name)
                if isinstance(res2, dict) and res2.get("success"):
                    listener_stopped = True
            except Exception:
                pass
    except Exception:
        # Never fail removal because listener stop failed
        pass

    return {
        "connection": _to_response_dict(updated),
        "removed": True,
        "listener_stopped": listener_stopped,
    }


@router.get("/connections/{connection_id}/listener", response_model=ListenerOutputResponse)
async def get_listener_output(
    connection_id: str,
    lines: int = Query(100, ge=1, le=500, description="Number of lines to return (bounded)"),
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    cid = _validate_connection_id(connection_id)
    mgr = _get_manager()
    rec = mgr.get(cid)
    if rec is None:
        raise HTTPException(status_code=404, detail="Connection not found")

    listener_name = rec.listener_name
    if not listener_name:
        raise HTTPException(status_code=404, detail="No listener associated with this connection")

    try:
        sess_mgr = _get_session_manager()
        result = sess_mgr.read_listener_output(listener_name, lines=lines)
        if isinstance(result, dict):
            output = str(result.get("output", ""))
            running = bool(result.get("running", False))
            # Truncate output to bounded size (max ~ 16k characters)
            if len(output) > 16384:
                output = output[-16384:]
            status_val = "running" if running else "stopped"
            # Detect LOG_NOT_FOUND style
            if output.startswith("LOG_NOT_FOUND") or output.startswith("INVALID_NAME"):
                status_val = "not_found"
                running = False
        else:
            output = str(result)
            running = False
            status_val = "unknown"
            if len(output) > 16384:
                output = output[-16384:]
    except Exception as exc:
        # Handle missing/stopped listener cleanly — don't 500
        output = f"listener unavailable: {exc}"
        running = False
        status_val = "error"
        if len(output) > 16384:
            output = output[-16384:]

    # Bound output only, never unlimited log.
    return {
        "connection_id": cid,
        "listener_name": listener_name,
        "output": output,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "running": running,
        "status": status_val,
    }
