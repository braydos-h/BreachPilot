"""System routes: preset listing plus persisted custom goals.

Split of ``tools/api/routes/system.py`` (p2-02) — endpoint paths, auth,
and bodies unchanged; former ``create_router`` closures now read ``ctx``.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from ._shared import SystemContext

__all__ = ["register"]


# ── Custom goals helpers ─────────────────────────────────────────────────

_CUSTOM_GOAL_NAME_MAX = 100
_CUSTOM_GOAL_OBJECTIVE_MAX = 2000


def _validate_custom_goal_name(name: Any) -> str:
    from tools.api.errors import APIError

    if not isinstance(name, str):
        raise APIError("invalid_goal", "name must be a string.", status_code=400)
    cleaned = name.strip()
    if not cleaned:
        raise APIError("invalid_goal", "name must be non-empty.", status_code=400)
    if len(cleaned) > _CUSTOM_GOAL_NAME_MAX:
        raise APIError("invalid_goal", f"name must be at most {_CUSTOM_GOAL_NAME_MAX} characters.", status_code=400)
    return cleaned


def _validate_custom_goal_objective(objective: Any) -> str:
    from tools.api.errors import APIError

    if not isinstance(objective, str):
        raise APIError("invalid_goal", "objective must be a string.", status_code=400)
    cleaned = objective.strip()
    if not cleaned:
        raise APIError("invalid_goal", "objective must be non-empty.", status_code=400)
    if len(cleaned) > _CUSTOM_GOAL_OBJECTIVE_MAX:
        raise APIError(
            "invalid_goal",
            f"objective must be at most {_CUSTOM_GOAL_OBJECTIVE_MAX} characters.",
            status_code=400,
        )
    return cleaned


def _check_duplicate_custom_goal_name(ctx: SystemContext, name: str, exclude_id: str | None = None) -> None:
    from tools.api.errors import APIError
    from tools.goal_engine import PRESET_GOALS

    lower = name.lower()
    for preset_name in PRESET_GOALS:
        if preset_name.lower() == lower:
            raise APIError("duplicate_goal", f"A built-in goal with name '{name}' already exists.", status_code=409)

    persistence = ctx.get_persistence()
    if persistence is None:
        return
    existing = persistence.get_custom_goal_by_name(name)
    if existing and (exclude_id is None or existing["id"] != exclude_id):
        raise APIError("duplicate_goal", f"A custom goal with name '{name}' already exists.", status_code=409)


def register(router: APIRouter, ctx: SystemContext) -> None:
    """Mount the goals endpoints (paths/auth unchanged)."""

    @router.get("/goals")
    async def list_goals(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """List all preset goals with full descriptions and risk requirement tags.

        ``compatible`` reflects the conservative baseline risk profile
        (``standard_authorized``): safe and gated goals are selectable, while
        high-risk goals report ``compatible: false`` until the profile is raised to
        ``high_authorized_testing`` (attack runs). The WebUI renders that as an
        "Unavailable" state; it never bypasses the backend goal gates.

        Custom goals (persisted in ``custom_goals``) are returned alongside presets
        in ``custom_goals`` — a clearly separated array so the frontend never
        confuses a user-authored objective with a static ``safe``/``gated``/``high``
        preset. Each entry carries ``source`` for explicit discrimination.
        """
        from tools.goal_engine import GoalEngine

        engine = GoalEngine()
        out: list[dict[str, Any]] = []
        for name, goal in engine.presets.items():
            out.append(
                {
                    "name": name,
                    "description": goal.description,
                    "risk": goal.risk_requirement,
                    "compatible": engine.is_compatible(name, "standard_authorized"),
                    "source": "preset",
                }
            )
        custom_goals: list[dict[str, Any]] = []
        persistence = ctx.get_persistence()
        if persistence is not None:
            try:
                rows = persistence.list_custom_goals()
                for row in rows:
                    custom_goals.append(
                        {
                            "id": row["id"],
                            "name": row["name"],
                            "objective": row["objective"],
                            "created_at": row["created_at"],
                            "updated_at": row["updated_at"],
                            "source": "custom",
                        }
                    )
            except Exception:
                custom_goals = []
        return {"goals": out, "custom_goals": custom_goals}

    @router.post("/goals", status_code=201)
    async def create_custom_goal(request: Request, auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Create a persisted custom goal.

        Distinct from built-in presets: the objective is free-text stored as
        ``custom_goal`` on run creation. Validates name/objective, enforces
        case-insensitive uniqueness (including against preset names), and returns
        201 with the created row. 409 on duplicate, 400 on invalid input.
        """
        from tools.api.errors import APIError

        body = await request.json()
        if not isinstance(body, dict):
            raise APIError("invalid_body", "Expected a JSON object.", status_code=400)
        name = _validate_custom_goal_name(body.get("name"))
        objective = _validate_custom_goal_objective(body.get("objective"))
        _check_duplicate_custom_goal_name(ctx, name)

        persistence = ctx.get_persistence()
        if persistence is None:
            raise APIError("internal_error", "Persistence not configured.", status_code=500)
        try:
            row = persistence.create_custom_goal(name, objective)
        except ValueError as exc:
            raise APIError("duplicate_goal", str(exc), status_code=409) from exc
        return {
            "id": row["id"],
            "name": row["name"],
            "objective": row["objective"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "source": "custom",
        }

    @router.patch("/goals/{goal_id}")
    async def update_custom_goal(
        goal_id: str, request: Request, auth: str = Depends(ctx.require_auth)
    ) -> dict[str, Any]:
        """Update a persisted custom goal (name and/or objective).

        Built-in presets are immutable — only rows in ``custom_goals`` can be
        updated. Returns 200 with the updated row, 404 if the id does not exist,
        409 on duplicate name, 400 on invalid input.
        """
        from tools.api.errors import APIError

        persistence = ctx.get_persistence()
        if persistence is None:
            raise APIError("internal_error", "Persistence not configured.", status_code=500)
        existing = persistence.get_custom_goal(goal_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Custom goal not found")

        body = await request.json()
        if not isinstance(body, dict):
            raise APIError("invalid_body", "Expected a JSON object.", status_code=400)
        has_name = "name" in body
        has_objective = "objective" in body
        if not has_name and not has_objective:
            raise APIError("invalid_body", "Provide at least one of: name, objective.", status_code=400)

        new_name = _validate_custom_goal_name(body["name"]) if has_name else existing["name"]
        new_objective = _validate_custom_goal_objective(body["objective"]) if has_objective else existing["objective"]

        if new_name.lower() != existing["name"].lower():
            _check_duplicate_custom_goal_name(ctx, new_name, exclude_id=goal_id)

        try:
            updated = persistence.update_custom_goal(goal_id, new_name, new_objective)
        except ValueError as exc:
            raise APIError("duplicate_goal", str(exc), status_code=409) from exc
        if updated is None:
            raise HTTPException(status_code=404, detail="Custom goal not found")
        return {
            "id": updated["id"],
            "name": updated["name"],
            "objective": updated["objective"],
            "created_at": updated["created_at"],
            "updated_at": updated["updated_at"],
            "source": "custom",
        }

    @router.delete("/goals/{goal_id}")
    async def delete_custom_goal(goal_id: str, auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Delete a persisted custom goal.

        Built-in presets cannot be deleted. Returns 200 with ``{deleted: true}``,
        404 if the id does not exist.
        """
        from tools.api.errors import APIError

        persistence = ctx.get_persistence()
        if persistence is None:
            raise APIError("internal_error", "Persistence not configured.", status_code=500)
        existing = persistence.get_custom_goal(goal_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Custom goal not found")
        ok = persistence.delete_custom_goal(goal_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Custom goal not found")
        return {"deleted": True, "id": goal_id}

    # ── Config schema (B5) ──────────────────────────────────────────────────────
