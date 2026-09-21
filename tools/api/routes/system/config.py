"""System routes: redacted config, atomic patches, write-only secrets, config schema.

Split of ``tools/api/routes/system.py`` (p2-02) — endpoint paths, auth,
and bodies unchanged; former ``create_router`` closures now read ``ctx``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request

from tools.api.errors import sanitize

from ._shared import SystemContext

__all__ = ["register"]


def register(router: APIRouter, ctx: SystemContext) -> None:
    """Mount the config endpoints (paths/auth unchanged)."""

    @router.get("/config")
    async def get_config(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Return redacted configuration."""
        return sanitize(ctx.config)

    @router.patch("/config")
    async def patch_config(
        request: Request,
        auth: str = Depends(ctx.require_auth),
    ) -> dict[str, Any]:
        """Apply config changes atomically through ConfigValidator."""
        body = await request.json()
        if not isinstance(body, dict):
            from tools.api.errors import APIError

            raise APIError("invalid_body", "Expected a JSON object.", status_code=400)
        merged = ctx.apply_config_patch(body)
        return {"status": "ok", "config": sanitize(merged)}

    @router.get("/secrets")
    async def get_secrets(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Expose only configured/missing provider-key status; secret values are write-only."""
        import os

        from tools.api_key_store import (
            DEFAULT_API_KEY_FILE,
            configured_api_key_env_names,
            load_api_key_file,
        )

        names = configured_api_key_env_names(ctx.config)
        path = Path(os.environ.get("BREACHPILOT_API_KEY_FILE", DEFAULT_API_KEY_FILE))
        loaded = load_api_key_file(path)
        status = {}
        for name in names:
            import os as _os

            status[name] = "configured" if (name in loaded or _os.environ.get(name)) else "missing"
        return {"keys": status}

    @router.put("/secrets")
    async def put_secrets(
        request: Request,
        auth: str = Depends(ctx.require_auth),
    ) -> dict[str, Any]:
        """Write-only secret storage (values never returned)."""
        from tools.api.errors import APIError

        body = await request.json()
        if not isinstance(body, dict) or not isinstance(body.get("secrets"), dict):
            raise APIError("invalid_body", "Expected {secrets: {name: value}}", status_code=400)
        import os

        from tools.api_key_store import (
            DEFAULT_API_KEY_FILE,
            configured_api_key_env_names,
            save_api_keys,
        )

        secrets = body["secrets"]
        allowed = set(configured_api_key_env_names(ctx.config))
        if any(
            name not in allowed or not isinstance(value, str) or not value.strip() for name, value in secrets.items()
        ):
            raise APIError(
                "invalid_secrets",
                "Secret names must be configured provider environment variables and values must be non-empty strings.",
                status_code=400,
            )
        path = Path(os.environ.get("BREACHPILOT_API_KEY_FILE", DEFAULT_API_KEY_FILE))
        written = save_api_keys(path, secrets)
        for name in written:
            os.environ[name] = secrets[name].strip()
        return {"status": "ok", "written": written}

    @router.get("/config/schema")
    async def get_config_schema(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Return the full default config schema (CONFIG_SCHEMA) for typed form rendering."""
        from tools.config_manager import CONFIG_SCHEMA

        return {"schema": CONFIG_SCHEMA}

    # ── Live Ollama models (C1) ─────────────────────────────────────────────────
