"""Assessment run routes: POST /runs, GET /runs, GET /runs/{id}, cancel, resume, tools."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from tools.api.auth import BearerAuth
from tools.api.persistence import ApiPersistence
from tools.api.run_manager import RunManager
from tools.run_service.models import RunKind, RunRequest

router = APIRouter(prefix="/api/v1", tags=["runs"])

# Set by create_app.
_AUTH: BearerAuth | None = None
_PERSISTENCE: ApiPersistence | None = None
_RUN_MANAGER: RunManager | None = None


def configure(auth: BearerAuth, persistence: ApiPersistence, run_manager: RunManager) -> None:
    global _AUTH, _PERSISTENCE, _RUN_MANAGER
    _AUTH = auth
    _PERSISTENCE = persistence
    _RUN_MANAGER = run_manager


async def _require_auth(request: Request) -> str:
    if _AUTH is None:
        raise RuntimeError("API not configured.")
    return await _AUTH(request)


def _rm() -> RunManager:
    if _RUN_MANAGER is None:
        raise RuntimeError("Run manager not configured.")
    return _RUN_MANAGER


def _ps() -> ApiPersistence:
    if _PERSISTENCE is None:
        raise RuntimeError("Persistence not configured.")
    return _PERSISTENCE


# ── Request models ──────────────────────────────────────────────────────────

class RunCreateRequest(BaseModel):
    target: str = Field(..., description="Target IP or domain")
    mode: str = Field("attack", pattern="^(recon|attack)$")
    goal: str = ""
    custom_goal: str = ""
    recon_first: bool | None = None
    model: str | None = None
    swarm: bool = False
    parallel_swarm: bool = False
    critic: bool = False
    reflection: bool = False
    adaptive_exploits: bool = False
    long_session: bool = False
    multi_model_consult: bool | None = None
    observer_mode: str = "hybrid"
    ultrathink: bool = False
    skills: str | None = None
    skills_include: list[str] = Field(default_factory=list)
    skills_exclude: list[str] = Field(default_factory=list)
    resume: str = ""
    kind: str = Field("agent", pattern="^(agent|manual)$")
    yes: bool = False


class DecisionAnswerRequest(BaseModel):
    answer: str


class ToolCallRequest(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)


# ── Routes ──────────────────────────────────────────────────────────────────

@router.post("/runs", status_code=201)
async def create_run(body: RunCreateRequest, auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Create a run (preview + start_confirm decision). Does not execute yet."""
    request = RunRequest(
        target=body.target, mode=body.mode, goal_name=body.goal,
        custom_goal=body.custom_goal, recon_first=body.recon_first,
        model_alias=body.model or "", swarm=body.swarm,
        parallel_swarm=body.parallel_swarm, critic=body.critic,
        reflection=body.reflection, adaptive_exploits=body.adaptive_exploits,
        long_session=body.long_session, multi_model_consult=body.multi_model_consult,
        observer_mode=body.observer_mode, ultrathink=body.ultrathink,
        skills_mode=body.skills, skills_include=body.skills_include,
        skills_exclude=body.skills_exclude, resume_source=body.resume,
        kind=RunKind(body.kind), yes=body.yes,
    )
    run_id, preview, decision = await _rm().create_run(request)
    result: dict[str, Any] = {
        "run_id": run_id,
        "preview": {
            "run_id": preview.run_id,
            "target_ip": preview.target_ip,
            "mode": preview.mode,
            "goal_name": preview.goal_name,
            "model_alias": preview.model_alias,
            "permission": preview.permission,
            "destructive": preview.destructive,
            "required_confirmation_text": preview.required_confirmation_text,
            "budgets": preview.budgets,
            "swarm": preview.swarm,
        },
        "state": "awaiting_confirmation" if decision else "queued",
    }
    if decision:
        result["decision"] = {
            "id": decision.id,
            "kind": decision.kind.value,
            "required_text": decision.required_text,
            "prompt_text": decision.prompt_text,
        }
    return result


@router.get("/runs")
async def list_runs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    """List run history."""
    runs = _ps().list_runs(limit=limit, offset=offset)
    return {"runs": [{"id": r["id"], "state": r["state"], "created_at": r["created_at"]} for r in runs]}


@router.get("/runs/{run_id}")
async def get_run(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Get run details: effective state, progress, pending decisions, artifacts, result, errors."""
    run = _ps().get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    decisions = _ps().list_decisions(run_id)
    return {
        "id": run["id"],
        "state": run["state"],
        "created_at": run["created_at"],
        "updated_at": run["updated_at"],
        "request": run.get("request_json", {}),
        "preview": run.get("preview_json", {}),
        "result": run.get("result_json", {}),
        "error": run.get("error", ""),
        "cancelled_at": run.get("cancelled_at", ""),
        "resumed_from": run.get("resumed_from", ""),
        "decisions": [{"id": d["id"], "kind": d["kind"], "status": d["status"], "answer": d["answer"]} for d in decisions],
    }


@router.post("/runs/{run_id}/cancel")
async def cancel_run(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Cooperative cancellation + guaranteed MCP/swarm child cleanup."""
    await _rm().cancel_run(run_id)
    return {"run_id": run_id, "state": "cancelled"}


@router.post("/runs/{run_id}/resume")
async def resume_run(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Create a new execution record linked by resumed_from, reusing existing report/session state."""
    original = _ps().get_run(run_id)
    if original is None:
        raise HTTPException(status_code=404, detail="Original run not found")
    req_data = original.get("request_json", {})
    request_fields = {
        key: value
        for key, value in req_data.items()
        if key in RunRequest.__dataclass_fields__
    }
    request_fields.update(
        resume_source=run_id,
        kind=RunKind(req_data.get("kind", "agent")),
        yes=False,
    )
    request = RunRequest(**request_fields)
    new_id, preview, decision = await _rm().create_run(request)
    return {"run_id": new_id, "resumed_from": run_id, "preview": {"run_id": preview.run_id, "target_ip": preview.target_ip}}


@router.get("/runs/{run_id}/tools")
async def get_tools(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Return the live MCP tool schemas (including plugin-contributed tools)."""
    schemas = _rm().get_tool_schemas(run_id)
    return {"tools": schemas}


@router.post("/runs/{run_id}/tools/{tool_name}/calls")
async def call_tool(run_id: str, tool_name: str, body: ToolCallRequest, auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Policy-gated REST bridge for manual WebUI tool calls."""
    return await _rm().call_tool(run_id, tool_name, body.arguments)
