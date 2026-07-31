"""Decision routes: list decisions, answer a decision."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

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


@router.get("/runs/{run_id}/decisions", response_model=None)
async def list_decisions(run_id: str, auth: str = Depends(_require_auth)) -> dict:
    """List pending/answered decisions for a run."""
    decisions = await _rm().list_decisions(run_id)
    return {"decisions": decisions}


@router.post("/runs/{run_id}/decisions/{decision_id}", response_model=None)
async def answer_decision(run_id: str, decision_id: str, body: DecisionAnswer, auth: str = Depends(_require_auth)) -> dict:
    """Answer a pending decision (start_confirm, goal_select, or tool_approval)."""
    return await _rm().answer_decision(run_id, decision_id, body.answer)
