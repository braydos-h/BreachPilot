"""Decision routes: list decisions, answer a decision, get one decision."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from tools.api.auth import BearerAuth
from tools.api.run_manager import RunManager

router = APIRouter(prefix="/api/v1", tags=["decisions"])

_AUTH: BearerAuth | None = None
_RUN_MANAGER: RunManager | None = None


def configure(auth: BearerAuth, run_manager: RunManager) -> None:
    global _AUTH, _RUN_MANAGER
    _AUTH = auth
    _RUN_MANAGER = run_manager


async def _require_auth(request: Request) -> str:
    if _AUTH is None:
        raise RuntimeError("API not configured.")
    return await _AUTH(request)


def _rm() -> RunManager:
    if _RUN_MANAGER is None:
        raise RuntimeError("Run manager not configured.")
    return _RUN_MANAGER


class DecisionAnswer(BaseModel):
    answer: str


class DecisionOut(BaseModel):
    """Typed decision shape for OpenAPI codegen."""

    id: str
    run_id: str
    kind: str
    prompt_text: str = ""
    required_text: str = ""
    options: list[dict[str, Any]] = Field(default_factory=list)
    status: str
    answer: str = ""
    created_at: str
    answered_at: str = ""


@router.get("/runs/{run_id}/decisions", response_model=None)
async def list_decisions(run_id: str, auth: str = Depends(_require_auth)) -> dict:
    """List pending/answered decisions for a run."""
    decisions = await _rm().list_decisions(run_id)
    return {"decisions": decisions}


@router.get("/runs/{run_id}/decisions/{decision_id}", response_model=DecisionOut)
async def get_decision(run_id: str, decision_id: str, auth: str = Depends(_require_auth)) -> DecisionOut:
    """Get a single decision by id (full row: prompt_text, required_text, options)."""
    from tools.api.persistence import ApiPersistence

    # Reach the persistence layer through the run manager's owned reference.
    persistence: ApiPersistence | None = getattr(_rm(), "_persistence", None)
    if persistence is None:
        raise HTTPException(status_code=500, detail="Persistence not configured.")
    decision = persistence.get_decision(decision_id)
    if decision is None:
        raise HTTPException(status_code=404, detail="Decision not found")
    if decision.get("run_id") != run_id:
        raise HTTPException(status_code=404, detail="Decision not found")
    return DecisionOut(
        id=decision["id"],
        run_id=decision["run_id"],
        kind=decision["kind"],
        prompt_text=decision.get("prompt_text", ""),
        required_text=decision.get("required_text", ""),
        options=decision.get("options_json", []),
        status=decision["status"],
        answer=decision.get("answer", ""),
        created_at=decision.get("created_at", ""),
        answered_at=decision.get("answered_at", ""),
    )


@router.post("/runs/{run_id}/decisions/{decision_id}", response_model=None)
async def answer_decision(
    run_id: str, decision_id: str, body: DecisionAnswer, auth: str = Depends(_require_auth)
) -> dict:
    """Answer a pending decision (start_confirm, goal_select, or tool_approval)."""
    return await _rm().answer_decision(run_id, decision_id, body.answer)
