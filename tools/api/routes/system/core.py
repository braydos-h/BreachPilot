"""System routes: health, capabilities, plugins, attack modules, and full reset.

Split of ``tools/api/routes/system.py`` (p2-02) — endpoint paths, auth,
and bodies unchanged; former ``create_router`` closures now read ``ctx``.
"""

from __future__ import annotations

import shutil
from typing import Any

from fastapi import APIRouter, Depends, Request

from ._shared import (
    SystemContext,
    browser_capability_status,
)

__all__ = ["register"]


def register(router: APIRouter, ctx: SystemContext) -> None:
    """Mount the core endpoints (paths/auth unchanged)."""

    @router.get("/health", tags=["system"])
    async def health() -> dict[str, Any]:
        """Health check — no authentication required."""
        return {"version": "v1", "ready": True}

    @router.get("/capabilities")
    async def capabilities(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """API features, supported run options, constraints, and tool groups.

        ``max_concurrent_runs`` is read from the live ``api.max_concurrent_runs``
        config key (default 1 = legacy single-run behavior). The ``features`` list
        advertises both REST surfaces and advisory MCP tool families so the WebUI
        can gate each panel on its feature flag (an absent feature renders an empty
        state, never a 404 loop).
        """
        api_cfg = ctx.config.get("api", {}) or {}
        # Browser status is advertised so the WebUI (and API clients) can gate
        # the browser panel: metadata always, ``available`` only when browser
        # execution is actually runnable (enabled + registered backend + host
        # SDK or sandbox worker). See docs/browser-agent-design.md.
        browser_cfg = ctx.config.get("browser", {}) or {}
        try:
            from tools.browser.capabilities import browser_available as _browser_available

            browser_is_available = bool(_browser_available(ctx.config))
        except Exception:  # noqa: BLE001 — status metadata is best-effort, never breaks the route
            browser_is_available = False
        return {
            "api_version": "v1",
            "browser": {
                "enabled": bool(browser_cfg.get("enabled", False)),
                "backend": str(browser_cfg.get("backend", "none") or "none"),
                "available": browser_is_available,
                "capabilities": browser_capability_status(ctx.config),
            },
            "features": [
                "runs",
                "decisions",
                "events",
                "websocket",
                "tool_gateway",
                "config",
                "secrets",
                "goals",
                "config_schema",
                "artifacts",
                "audit",
                "swarm_state",
                "campaign_state",
                "logs",
                "credentials",
                "loot",
                "live_models",
                "skill_detail",
                "run_delete",
                "sse",
                "single_decision",
                "diagnostics_output",
                "sandbox_status",
                "run_sandbox",
                # ── commit fc0af19 ── advisory/local MCP tool families + new surfaces.
                # Each name keys a WebUI panel off capabilities.features so a disabled
                # backend feature renders an empty state, not a 404 loop.
                "graph_route",
                "ops_summary",
                "poc_verification",
                "replay_simulator",
                "peer_review",
                "mitre",
                "threat_intel",
                "ticketing",
                "witness",
                "negotiation_rounds",
                "ics_write",
                "ctf",
            ],
            "constraints": {
                "max_concurrent_runs": int(api_cfg.get("max_concurrent_runs", 1) or 1),
                "loopback_only": True,
                "manual_tool_calls": True,
            },
            "run_options": {
                "modes": ["recon", "attack", "fast"],
                "kinds": ["agent"],
                "flags": [
                    "swarm",
                    "parallel_swarm",
                    "critic",
                    "reflection",
                    "adaptive_exploits",
                    "long_session",
                    "multi_model_consult",
                    "ultrathink",
                    "recon_first",
                ],
            },
        }

    @router.post("/system/reset")
    async def reset_system(request: Request, auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Wipe all past work: run history, reports/, exploit_workspace/,
        research_workspace/, and swarm_workspace/.

        Refuses while any run is active (running/queued/awaiting_input). The
        api_runtime.db file itself is kept (its schema is the live persistence
        instance's state); all rows are deleted. Users/annotations are removed
        with the runs they belong to; user accounts are kept.
        """
        from tools.api.errors import APIError

        if ctx.run_manager is None:
            raise RuntimeError("Run manager not configured.")
        if ctx.run_manager.has_active:
            raise APIError(
                "conflict",
                "Cannot reset while a run is active. Cancel or wait for it to finish first.",
                status_code=409,
            )

        reports_dir = ctx.run_manager._persistence.reports_dir.resolve()
        # The api_runtime.db file lives inside reports_dir and is held open by the
        # live ApiPersistence instance, so clear its rows first and keep the file.
        runs_deleted = ctx.run_manager._persistence.reset_all()
        removed: list[str] = []
        for target in [
            reports_dir,
            (reports_dir.parent / "exploit_workspace").resolve(),
            (reports_dir.parent / "swarm_workspace").resolve(),
        ]:
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
                removed.append(str(target))
        # Recreate reports/ with a fresh (empty) api_runtime.db so the live
        # persistence instance keeps working.
        reports_dir.mkdir(parents=True, exist_ok=True)
        ctx.run_manager._persistence._init_db()

        # research_workspace: research.db is held open by the Flow B singleton's
        # thread-local connections (Windows locks open files, and the conn lives on
        # a different thread than this request), so the file cannot be deleted.
        # Wipe its tables in place and delete everything else in the dir.
        research_dir = (reports_dir.parent / "research_workspace").resolve()
        research_cleared = False
        if research_dir.exists():
            try:
                import sqlite3

                conn = sqlite3.connect(str(research_dir / "research.db"))
                try:
                    tables = [
                        r[0]
                        for r in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table' "
                            "AND name NOT LIKE 'sqlite_%' AND name != '_migrations'"
                        )
                    ]
                    for table in tables:
                        conn.execute(f'DELETE FROM "{table}"')
                    conn.commit()
                finally:
                    conn.close()
                research_cleared = True
            except Exception:
                pass
            for child in research_dir.iterdir():
                if child.name == "research.db":
                    continue
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    try:
                        child.unlink()
                    except OSError:
                        pass

        return {
            "status": "ok",
            "runs_deleted": runs_deleted,
            "removed": removed,
            "research_cleared": research_cleared,
        }

    @router.get("/plugins")
    async def list_plugins(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """List discovered plugins."""
        try:
            from tools.plugins import list_discovered_plugins

            return {"plugins": list_discovered_plugins()}
        except Exception:
            return {"plugins": []}

    @router.get("/attack/modules")
    async def list_attack_modules(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """List the pre-packaged attack module catalog (metadata only, read-only)."""
        from tools.attack_modules.registry import list_modules

        out: list[dict[str, Any]] = []
        for mod in list_modules():
            family = mod.__class__.__module__.split(".")[-1]
            out.append(
                {
                    "name": mod.name,
                    "description": mod.description,
                    "family": family,
                    "target_services": list(mod.target_services),
                    "target_ports": list(mod.target_ports),
                    "required_cves": list(mod.required_cves),
                    "destructive_ics": bool(getattr(mod, "destructive_ics", False)),
                }
            )
        return {"modules": out}

    # ── Goals (B4) ──────────────────────────────────────────────────────────────

    # ── Custom goals helpers ─────────────────────────────────────────────────
