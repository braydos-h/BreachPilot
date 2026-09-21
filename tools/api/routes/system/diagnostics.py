"""System routes: doctor/self-test plus system info/telemetry/memory/sandbox/browser.

Split of ``tools/api/routes/system.py`` (p2-02) — endpoint paths, auth,
and bodies unchanged; former ``create_router`` closures now read ``ctx``.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ._shared import (
    SystemContext,
    _load_memory_sync,
    _run_doctor_sync,
)

__all__ = ["register"]


def register(router: APIRouter, ctx: SystemContext) -> None:
    """Mount the diagnostics endpoints (paths/auth unchanged)."""

    @router.get("/system/info")
    async def get_system_info(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Host info: hostname, OS, Python, local IPs, public IP (best-effort).

        The public-IP lookup hits an external service (api.ipify.org) with a short
        timeout and never fails the request — it degrades to ``null`` offline.
        """
        import platform
        import socket
        import sys

        def _local_ips() -> list[str]:
            ips: list[str] = []
            try:
                for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                    ip = info[4][0]
                    if ip not in ips:
                        ips.append(ip)
            except OSError:
                pass
            return ips

        def _public_ip() -> str:
            import urllib.request

            try:
                with urllib.request.urlopen("https://api.ipify.org", timeout=3.0) as resp:
                    return resp.read().decode("utf-8").strip()
            except Exception:
                return ""

        public_ip = await asyncio.to_thread(_public_ip)
        return {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "os": platform.system(),
            "python": sys.version.split()[0],
            "local_ips": _local_ips(),
            "public_ip": public_ip or None,
        }

    @router.get("/system/telemetry")
    async def get_telemetry(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """LLM usage telemetry summary + recent records (numeric/categorical only).

        Reads ``research_workspace/logs/llm_usage.jsonl`` via tools/model_telemetry.
        No prompts, responses, or raw provider payloads are ever persisted or returned.
        """
        from tools.model_telemetry import read_usage_records, usage_summary, workspace_root_from_sources

        def _load() -> dict[str, Any]:
            workspace_root = workspace_root_from_sources(ctx.config_path)
            return {
                "summary": usage_summary(workspace_root),
                "recent": read_usage_records(workspace_root, limit=50),
            }

        return await asyncio.to_thread(_load)

    @router.get("/system/memory")
    async def get_memory(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Attack memory + experience-store learnings (cross-mission, no secrets)."""
        return await asyncio.to_thread(_load_memory_sync, ctx.config_path, ctx.config)

    @router.get("/system/sandbox")
    async def get_sandbox_status(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Disposable-sandbox status for the System UI (read-only, no Docker controls).

        Reports sandbox.enabled/backend/image, Docker reachability, network policy
        posture, and resource limits. Never exposes container exec/remove controls:
        sandbox lifecycle is owned by the run engine, not the WebUI.
        """
        from tools.sandbox import status_report

        return await asyncio.to_thread(status_report, ctx.config)

    @router.get("/system/browser")
    async def get_browser_status(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Browser-agent status for the System UI (read-only, never launches).

        Reports config (enabled/backend/bounds), the runtime availability
        verdict, and the Playwright SDK/Chromium probes with distinct detail
        strings so the UI can tell "disabled" from "SDK missing" from
        "chromium missing" from "ready". Live sessions live in the MCP server
        process and are intentionally not listed here.
        """
        from tools.browser._pw_probe import browser_health
        from tools.browser.capabilities import browser_capabilities, browser_runtime_available

        browser_cfg = ctx.config.get("browser", {}) or {}
        try:
            available = bool(browser_runtime_available(ctx.config))
        except Exception:  # noqa: BLE001 — status metadata is best-effort
            available = False
        try:
            health = browser_health(ctx.config)
        except Exception:  # noqa: BLE001 — status metadata is best-effort
            health = {"name": "browser_backend_playwright", "ok": False, "detail": "probe failed"}
        try:
            capabilities = browser_capabilities(ctx.config)
        except Exception:  # noqa: BLE001 — status metadata is best-effort
            capabilities = []
        return {
            "enabled": bool(browser_cfg.get("enabled", False)),
            "backend": str(browser_cfg.get("backend", "none") or "none"),
            "available": available,
            "health": health,
            "capabilities": capabilities,
            "config": {
                "headless": bool(browser_cfg.get("headless", True)),
                "max_sessions": browser_cfg.get("max_sessions", 2),
                "allow_mutating_actions": bool(browser_cfg.get("allow_mutating_actions", False)),
                "capture_screenshots": bool(browser_cfg.get("capture_screenshots", True)),
                "capture_network": bool(browser_cfg.get("capture_network", True)),
                "capture_console": bool(browser_cfg.get("capture_console", False)),
            },
        }

    @router.get("/system/sandbox/fix/plan")
    async def get_sandbox_fix_plan(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Read-only remediation plan for the Docker sandbox.

        Returns enough detail for the WebUI to explain exactly what would happen
        before any host-changing commands run. No side effects, localhost/auth
        protected like the rest of /system/sandbox.
        """
        from tools.sandbox.remediation import build_plan

        return await asyncio.to_thread(build_plan, ctx.config)

    @router.post("/system/sandbox/fix")
    async def start_sandbox_fix(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Start the Docker sandbox remediation (localhost/auth protected).

        Narrow, enum-like endpoint: the browser requests a fix job, not arbitrary
        commands. No body params are accepted – the server's known project path
        (docker/sandbox) is used, and the job is identified by a server-generated id.
        Returns the initial job record; poll GET /system/sandbox/fix/{job_id} for
        progress.
        """
        from tools.api.errors import APIError
        from tools.sandbox import remediation as _rem
        from tools.sandbox.models import SandboxConfig
        from tools.sandbox.remediation import _job_to_dict, _start_background_job, create_job

        # Do not treat disabled as success – refuse to "fix" an intentional choice.
        cfg = SandboxConfig.from_config(ctx.config)
        if not cfg.enabled:
            raise APIError(
                "sandbox_disabled",
                "Sandbox is intentionally disabled (sandbox.enabled: false). Enable it in config.yaml instead.",
                status_code=400,
            )

        # Fail closed on concurrent running job: one fix at a time.
        with _rem._JOBS_LOCK:
            for j in _rem._JOBS.values():
                if j.status in ("pending", "running"):
                    raise APIError("conflict", "A sandbox fix is already running.", status_code=409)

        job = await create_job(ctx.config)
        # Start background execution (does not block the HTTP response).
        _start_background_job(job.job_id, ctx.config)
        return _job_to_dict(job)

    @router.get("/system/sandbox/fix/{job_id}")
    async def get_sandbox_fix_status(job_id: str, auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Poll the fix job for structured step progress."""
        from tools.sandbox.remediation import _job_to_dict, get_job

        # Sanitize job_id: only hex ids we generate are valid – reject path traversal / injection.
        if not re.fullmatch(r"[0-9a-fA-F]{6,32}", job_id):
            raise HTTPException(status_code=404, detail="Fix job not found")
        job = await get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Fix job not found")
        return _job_to_dict(job)

    @router.post("/diagnostics/doctor")
    async def run_doctor(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Run the environment self-check and capture its stdout output."""
        code, output = await asyncio.to_thread(_run_doctor_sync, ctx.config_path)
        return {"exit_code": code, "output": output}

    @router.post("/diagnostics/self-test")
    async def run_self_test(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Run the safe localhost smoke test and capture its stdout output."""
        import contextlib
        import io

        from tools.self_test import run_self_test as _run

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = await _run(None)
        return {"exit_code": code, "output": buf.getvalue()}

    # ── Attack modules catalog ──────────────────────────────────────────────────
