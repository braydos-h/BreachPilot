"""System routes: model registry, live discovery, and provider status/controls.

Split of ``tools/api/routes/system.py`` (p2-02) — endpoint paths, auth,
and bodies unchanged; former ``create_router`` closures now read ``ctx``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from ._shared import (
    SystemContext,
    _chatgpt_status_sync,
    _opencode_go_status_sync,
)

__all__ = ["register"]


def register(router: APIRouter, ctx: SystemContext) -> None:
    """Mount the models endpoints (paths/auth unchanged)."""

    @router.get("/models")
    async def list_models(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """List configured model aliases + metadata (provider-aware)."""
        from tools.config_manager import get_ai_provider, get_chatgpt_config, get_opencode_go_config

        models = ctx.config.get("models", {})
        provider = get_ai_provider(ctx.config)
        response: dict[str, Any] = {
            "provider": provider,
            "default_alias": models.get("default_alias", "glm"),
            "registry": models.get("registry", {}),
            "info": models.get("info", {}),
        }
        # Generic active-provider block: default + configured models resolved
        # through the registered adapter, so provider #4 needs no route change.
        # (Absent only when the active id names no registered adapter.)
        try:
            from tools.providers.registry import get_provider as _get_adapter
            from tools.providers.registry import resolve_default_model as _resolve_default

            _adapter = _get_adapter(provider)
            _pcfg = _adapter.provider_config(ctx.config)
            _configured = [str(m) for m in (_pcfg.get("models") or []) if str(m).strip()]
            if provider == "ollama":
                _configured = [str(v) for v in (models.get("registry", {}) or {}).values() if v]
            _default = _resolve_default(ctx.config, provider)
            if _default and _default not in _configured:
                _configured.append(_default)
            response["active_provider"] = {
                "id": provider,
                "default_model": _default,
                "configured_models": _configured,
            }
        except Exception:
            pass
        if provider == "chatgpt":
            chatgpt_cfg = get_chatgpt_config(ctx.config)
            response["chatgpt"] = {
                "default_model": chatgpt_cfg.get("default_model", "gpt-5.2"),
                "context_window": chatgpt_cfg.get("context_window", 128000),
                "configured_models": list(chatgpt_cfg.get("models") or []),
            }
        if provider == "opencode_go":
            og_cfg = get_opencode_go_config(ctx.config)
            response["opencode_go"] = {
                "base_url": og_cfg.get("base_url", "https://opencode.ai/zen/go/v1"),
                "default_model": og_cfg.get("default_model", "muse-spark-1.2-contributor"),
                "context_window": og_cfg.get("context_window", 128000),
                "configured_models": list(og_cfg.get("models") or []),
                "enabled": bool(og_cfg.get("enabled", False)),
            }
        return response

    @router.post("/models")
    async def add_model(request: Request, auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Add a model alias to ``models.registry`` (writes through config validation)."""
        from tools.api.errors import APIError

        body = await request.json()
        if not isinstance(body, dict):
            raise APIError("invalid_body", "Expected a JSON object.", status_code=400)
        alias = str(body.get("alias") or "").strip()
        model = str(body.get("model") or "").strip()
        if not alias or not model:
            raise APIError("invalid_body", "alias and model must be non-empty strings.", status_code=400)
        if len(alias) > 64 or len(model) > 256:
            raise APIError("invalid_body", "alias or model too long.", status_code=400)
        merged = ctx.apply_config_patch({"models": {"registry": {alias: model}}})
        return {
            "status": "ok",
            "alias": alias,
            "model": model,
            "registry": merged.get("models", {}).get("registry", {}),
        }

    @router.delete("/models/{alias}")
    async def remove_model(alias: str, auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Remove a model alias from ``models.registry`` (and its ``info`` entry)."""
        import copy

        from tools.api.errors import APIError

        alias = alias.strip()
        merged = copy.deepcopy(ctx.config)
        models = merged.setdefault("models", {})
        registry = models.setdefault("registry", {})
        if alias not in registry:
            raise HTTPException(status_code=404, detail=f"Model alias '{alias}' not found")
        if models.get("default_alias") == alias:
            raise APIError("invalid_model", f"Cannot remove the default alias '{alias}'.", status_code=400)
        del registry[alias]
        models.setdefault("info", {}).pop(alias, None)
        ctx.write_config(merged)
        return {"status": "ok", "alias": alias, "deleted": True}

    @router.post("/models/provider")
    async def set_model_provider(request: Request, auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Switch the active chat/generate provider.

        Validity is resolved through the provider registry (``resolve_known_provider_ids``
        — provider #4 needs no route change). The active provider's legacy config
        block is auto-enabled on switch (``chatgpt``/``opencode_go`` top-level
        blocks, ``providers.<id>`` for newer providers).
        """
        from tools.api.errors import APIError
        from tools.config_manager import resolve_known_provider_ids

        body = await request.json()
        if not isinstance(body, dict):
            raise APIError("invalid_body", "Expected a JSON object.", status_code=400)
        provider = str(body.get("provider") or "").strip().lower()
        known = resolve_known_provider_ids()
        if provider not in known:
            raise APIError(
                "invalid_provider",
                f"provider must be one of: {', '.join(known)}.",
                status_code=400,
            )
        patch: dict[str, Any] = {"models": {"provider": provider}}
        # Auto-enable the provider block when switching to it (mirrors chatgpt behaviour)
        if provider == "opencode_go":
            patch["opencode_go"] = {"enabled": True}
        elif provider == "chatgpt":
            patch["chatgpt"] = {"enabled": True}
        else:
            patch["providers"] = {provider: {"enabled": True}}
        merged = ctx.apply_config_patch(patch)
        return {"status": "ok", "provider": provider, "registered_providers": sorted(known)}

    @router.post("/models/refresh")
    async def refresh_models(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Sync ``models.registry`` to the newest same-family versions on the Ollama API.

        Hits ``ollama.host`` ``GET /api/tags`` off-thread (bearer-auth like the
        doctor), bumps every alias with a strictly newer same-family version
        (``glm-5.2:cloud`` -> ``glm-5.3:cloud``), and persists via the validated
        config-write path. ``503`` when the Ollama API is unreachable;
        ``400 invalid_provider`` when ``models.provider`` is not ``ollama``.
        See ``tools/ollama_models.py``.
        """
        from tools.api.errors import APIError
        from tools.config_manager import get_ai_provider
        from tools.ollama_models import refresh_model_registry

        if get_ai_provider(ctx.config) != "ollama":
            raise APIError("invalid_provider", "Model refresh applies to the ollama provider only.", status_code=400)
        result = await asyncio.to_thread(
            refresh_model_registry,
            ctx.config,
            config_path=ctx.config_path,
            persist=False,
        )
        if not result.get("ok"):
            result.pop("available", None)
            from fastapi import Response

            return Response(content=json.dumps(result), status_code=503, media_type="application/json")
        updates = result.get("updates") or {}
        if updates:
            merged = ctx.apply_config_patch(
                {"models": {"registry": {alias: upd["new"] for alias, upd in updates.items()}}}
            )
            result["registry"] = merged.get("models", {}).get("registry", {})
            result["persisted"] = True
        return result

    @router.get("/models/live")
    async def list_live_models(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """List models actually installed in the configured backend (provider-neutral).

        Single registry-dispatch path: the active provider adapter
        (``tools.providers.registry.get_provider``) owns its own live discovery
        (``adapter.list_models(config)`` — off-thread so slow probes never block
        the event loop) and raises :class:`ProviderDiscoveryError` on failure with
        the registry-mode fallback. The route never branches on provider id —
        adding provider #4 requires no route change. On discovery failure the
        response degrades to ``{"source": "registry"}`` with a 503 and the
        provider's fallback models.
        """
        from fastapi import Response

        from tools.config_manager import get_ai_provider
        from tools.providers.registry import get_provider
        from tools.providers.types import ProviderDiscoveryError

        provider = get_ai_provider(ctx.config)
        registry_fallback = [str(v) for v in (ctx.config.get("models", {}).get("registry", {}) or {}).values() if v]

        def _provider_fallback() -> list[str]:
            """Provider-specific fallback models (never another provider's ids).

            Ollama degrades to the static ``models.registry`` values; every
            other provider degrades to its adapter's configured models +
            default_model. Unknown/unregistered ids keep the registry list.
            """
            if provider == "ollama":
                return registry_fallback
            try:
                pcfg = get_provider(provider).provider_config(ctx.config)
            except Exception:
                return registry_fallback
            configured = [str(m) for m in (pcfg.get("models") or []) if str(m).strip()]
            default = str(pcfg.get("default_model") or "")
            ordered = ([default] + [m for m in configured if m != default]) if default else configured
            return ordered or registry_fallback

        try:
            adapter = get_provider(provider)
        except Exception as exc:  # unknown provider id — surface, don't crash
            return Response(
                content=json.dumps(
                    {
                        "models": registry_fallback,
                        "source": "registry",
                        "error": f"Unknown provider '{provider}': {exc}",
                    }
                ),
                status_code=503,
                media_type="application/json",
            )
        try:
            infos = await asyncio.to_thread(adapter.list_models, ctx.config)
            models = [i.id for i in infos if i.id]
            if not models:
                raise ProviderDiscoveryError(f"{provider} reported no models")
            return {"models": models, "source": provider}
        except ProviderDiscoveryError as exc:
            return Response(
                content=json.dumps(
                    {
                        "models": exc.fallback_models or _provider_fallback(),
                        "source": "registry",
                        "error": exc.message,
                    }
                ),
                status_code=503,
                media_type="application/json",
            )
        except Exception as exc:  # defensive: never 500 the models panel
            return Response(
                content=json.dumps(
                    {
                        "models": _provider_fallback(),
                        "source": "registry",
                        "error": f"{provider} discovery failed: {exc}",
                    }
                ),
                status_code=503,
                media_type="application/json",
            )

    # ── AI providers (ChatGPT / openai-oauth) ────────────────────────────────────

    @router.get("/providers")
    async def get_providers(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Registry-driven provider metadata + status (no secrets).

        ``providers`` lists every registered adapter's metadata (id, display name,
        ``ProviderCapabilities``, configured/default-model) off-thread per adapter
        so provider #4 appears without route changes. ``active`` mirrors
        ``provider``; ``chatgpt``/``opencode_go`` legacy status blocks stay for the
        existing WebUI consumers.
        """
        from tools.config_manager import get_ai_provider, get_chatgpt_config, get_opencode_go_config
        from tools.providers.chatgpt_provider import ChatGptProxyManager
        from tools.providers.registry import PROVIDERS

        provider = get_ai_provider(ctx.config)
        chatgpt_cfg = get_chatgpt_config(ctx.config)
        og_cfg = get_opencode_go_config(ctx.config)
        manager = ChatGptProxyManager.get()
        authenticated, proxy_running = await asyncio.to_thread(_chatgpt_status_sync, chatgpt_cfg)
        og_status = await asyncio.to_thread(_opencode_go_status_sync, og_cfg)
        provider_rows: list[dict[str, Any]] = []
        for adapter in sorted(PROVIDERS.all(), key=lambda a: a.id):
            try:
                meta = await asyncio.to_thread(adapter.metadata, ctx.config)
                provider_rows.append(meta)
            except Exception as exc:  # one bad adapter must not kill the panel
                provider_rows.append({"id": adapter.id, "provider": adapter.id, "error": str(exc)})
        return {
            "provider": provider,
            "active": provider,
            "providers": provider_rows,
            "chatgpt": {
                "enabled": bool(chatgpt_cfg.get("enabled", False)),
                "authenticated": authenticated,
                "proxy_running": proxy_running,
                "host": chatgpt_cfg.get("host", "127.0.0.1"),
                "port": chatgpt_cfg.get("port", 10531),
                "default_model": chatgpt_cfg.get("default_model", "gpt-5.2"),
                "we_started": manager._we_started,
            },
            "opencode_go": og_status,
        }

    @router.post("/providers/chatgpt/login")
    async def chatgpt_login(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Start a ChatGPT OAuth login (browser flow) and return the login URL.

        Tokens stay in openai-oauth's ~/.codex/auth.json — they never enter the
        request/response/config. Returns ``{ok, url?, reason?}``.
        """
        from tools.config_manager import get_chatgpt_config
        from tools.providers.chatgpt_provider import ChatGptProxyManager

        chatgpt_cfg = get_chatgpt_config(ctx.config)
        result = await asyncio.to_thread(ChatGptProxyManager.get().run_login, chatgpt_cfg)
        return result

    @router.post("/providers/chatgpt/proxy/start")
    async def chatgpt_proxy_start(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Ensure the local openai-oauth proxy is running."""
        from tools.config_manager import get_chatgpt_config
        from tools.providers.chatgpt_provider import ChatGptProxyManager

        chatgpt_cfg = get_chatgpt_config(ctx.config)
        return await asyncio.to_thread(ChatGptProxyManager.get().ensure_running, chatgpt_cfg)

    @router.post("/providers/chatgpt/proxy/stop")
    async def chatgpt_proxy_stop(auth: str = Depends(ctx.require_auth)) -> dict[str, Any]:
        """Stop the proxy only if BreachPilot started it."""
        from tools.config_manager import get_chatgpt_config
        from tools.providers.chatgpt_provider import ChatGptProxyManager

        chatgpt_cfg = get_chatgpt_config(ctx.config)
        manager = ChatGptProxyManager.get()
        we_started = manager._we_started
        await asyncio.to_thread(manager.shutdown, chatgpt_cfg)
        return {"ok": True, "stopped": we_started}

    # ── Skill detail (C2) ──────────────────────────────────────────────────────
