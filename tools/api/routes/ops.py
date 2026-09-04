"""Ops summary route: one read-only status rollup for dormant backends.

Covers the backends that previously had settings toggles but no operational
surface: killchain, snapshots (+ counterfactual), eval baseline, browser, and
the active chat provider. Read-only by design — enabling stays in
``PATCH /api/v1/config`` (Settings page); this route only reports.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request

from tools.api.auth import BearerAuth


def create_router(auth: BearerAuth, config: dict[str, Any]) -> APIRouter:
    """Create an ops-summary router with isolated dependencies."""
    router = APIRouter(prefix="/api/v1/ops", tags=["ops"])

    async def _require_auth(request: Request) -> str:
        return await auth(request)

    @router.get("/summary")
    async def ops_summary(auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Read-only rollup: killchain/snapshots/eval/browser/provider status."""
        kill = (config.get("killchain") or {}) if isinstance(config.get("killchain"), dict) else {}
        snap = (config.get("snapshots") or {}) if isinstance(config.get("snapshots"), dict) else {}
        replay = (config.get("replay_simulator") or {}) if isinstance(config.get("replay_simulator"), dict) else {}
        evaluation = (config.get("eval") or {}) if isinstance(config.get("eval"), dict) else {}
        browser = (config.get("browser") or {}) if isinstance(config.get("browser"), dict) else {}
        models = (config.get("models") or {}) if isinstance(config.get("models"), dict) else {}

        baseline_path = str(evaluation.get("baseline_path") or "reports/eval/baseline.json")
        return {
            "killchain": {
                "enabled": bool(kill.get("enabled", False)),
                "goal_state": str(kill.get("goal_state") or "shell_as_root"),
                "require_verification": bool(kill.get("require_verification", True)),
            },
            "snapshots": {
                "enabled": bool(snap.get("enabled", False)),
                "provider": str(snap.get("provider") or "docker"),
                "counterfactual": bool(replay.get("counterfactual", False)),
            },
            "eval": {
                "enabled": bool(evaluation.get("enabled", True)),
                "baseline_path": baseline_path,
                "baseline_exists": Path(baseline_path).exists(),
            },
            "browser": {
                "enabled": bool(browser.get("enabled", False)),
                "backend": str(browser.get("backend") or "none"),
            },
            "provider": {"active": str(models.get("provider") or "ollama")},
        }

    return router
