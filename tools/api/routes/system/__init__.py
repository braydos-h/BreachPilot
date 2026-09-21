"""System and administration routes (package split of ``system.py``, p2-02).

Top-level :func:`create_router` aggregates the per-domain sub-routers with
zero URL/auth change: ``/health``, ``/capabilities``, ``/config``,
``/secrets``, ``/models``, ``/plugins``, ``/skills``, ``/diagnostics``,
``/goals``, ``/config/schema``, ``/models/live``, ``/skills/{name}``.
``tools.api.routes.system`` still exposes ``create_router`` plus the former
module-level helpers, so existing import paths keep working.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter

from tools.api.auth import BearerAuth

from . import config as _config_mod
from . import core as _core_mod
from . import diagnostics as _diagnostics_mod
from . import goals as _goals_mod
from . import models as _models_mod
from . import skills as _skills_mod
from ._shared import (
    _SKILL_NAME_RE,
    SystemContext,
    _chatgpt_status_sync,
    _load_memory_sync,
    _merge_config,
    _opencode_go_status_sync,
    _plugin_skill_dirs,
    _read_attack_memory_db,
    _resolve_skill_dir,
    _run_doctor_sync,
    _safe_json,
    _validate_skill_name,
    browser_capability_status,
)

__all__ = [
    "SystemContext",
    "_SKILL_NAME_RE",
    "_chatgpt_status_sync",
    "_load_memory_sync",
    "_merge_config",
    "_opencode_go_status_sync",
    "_plugin_skill_dirs",
    "_read_attack_memory_db",
    "_resolve_skill_dir",
    "_run_doctor_sync",
    "_safe_json",
    "_validate_skill_name",
    "browser_capability_status",
    "create_router",
]


def create_router(
    auth: BearerAuth,
    config: dict[str, Any],
    config_path: Path,
    run_manager: Any = None,
    persistence: Any = None,
) -> APIRouter:
    """Create a system router with isolated dependencies."""
    router = APIRouter(prefix="/api/v1", tags=["system"])
    ctx = SystemContext(
        auth=auth,
        config=config,
        config_path=config_path,
        run_manager=run_manager,
        persistence=persistence,
    )
    _core_mod.register(router, ctx)
    _config_mod.register(router, ctx)
    _models_mod.register(router, ctx)
    _diagnostics_mod.register(router, ctx)
    _goals_mod.register(router, ctx)
    _skills_mod.register(router, ctx)
    return router
