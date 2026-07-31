"""System and administration routes: /health, /capabilities, /config, /secrets, /models, /plugins, /skills, /diagnostics, /goals, /config/schema, /models/live, /skills/{name}."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request

from tools.api.auth import BearerAuth
from tools.api.errors import sanitize

router = APIRouter(prefix="/api/v1", tags=["system"])

# These are set by create_app at startup.
_AUTH: BearerAuth | None = None
_CONFIG: dict[str, Any] = {}
_CONFIG_PATH: Path = Path("config.yaml")


def configure(auth: BearerAuth, config: dict[str, Any], config_path: Path) -> None:
    global _AUTH, _CONFIG, _CONFIG_PATH
    _AUTH = auth
    _CONFIG = config
    _CONFIG_PATH = config_path


def _merge_config(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_config(merged[key], value)
        else:
            merged[key] = value
    return merged


async def _require_auth(request: Request) -> str:
    """FastAPI dependency: validate bearer token via BearerAuth.__call__."""
    if _AUTH is None:
        raise RuntimeError("API auth not configured.")
    return await _AUTH(request)


@router.get("/health", tags=["system"])
async def health() -> dict[str, Any]:
    """Health check — no authentication required."""
    return {"version": "v1", "ready": True}


@router.get("/capabilities")
async def capabilities(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """API features, supported run options, constraints, and tool groups."""
    return {
        "api_version": "v1",
        "features": ["runs", "decisions", "events", "websocket", "tool_gateway", "config", "secrets",
                     "goals", "config_schema", "artifacts", "audit", "swarm_state", "campaign_state",
                     "logs", "credentials", "loot", "live_models", "skill_detail", "run_delete",
                     "sse", "single_decision", "diagnostics_output"],
        "constraints": {
            "max_concurrent_runs": 1,
            "loopback_only": True,
            "manual_tool_calls": True,
        },
        "run_options": {
            "modes": ["recon", "attack"],
            "kinds": ["agent", "manual"],
            "flags": ["swarm", "parallel_swarm", "critic", "reflection", "adaptive_exploits",
                       "long_session", "multi_model_consult", "ultrathink", "recon_first"],
        },
    }


@router.get("/config")
async def get_config(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Return redacted configuration."""
    return sanitize(_CONFIG)


@router.patch("/config")
async def patch_config(
    request: Request,
    auth: str = Depends(_require_auth),
) -> dict[str, Any]:
    """Apply config changes atomically through ConfigValidator."""
    body = await request.json()
    if not isinstance(body, dict):
        from tools.api.errors import APIError
        raise APIError("invalid_body", "Expected a JSON object.", status_code=400)
    # Merge + validate.
    from tools.api.auth import is_loopback_origin
    from tools.config_manager import ConfigValidator
    merged = _merge_config(_CONFIG, body)
    origins = (merged.get("api", {}) or {}).get("allowed_origins", [])
    if isinstance(origins, list) and any(
        isinstance(origin, str) and not is_loopback_origin(origin, origins)
        for origin in origins
    ):
        from tools.api.errors import APIError
        raise APIError(
            "config_invalid",
            "api.allowed_origins may contain only loopback HTTP(S) origins.",
            status_code=400,
        )
    validator = ConfigValidator(_CONFIG_PATH)
    validator._config = merged
    result = validator.validate()
    if not result.is_valid:
        from tools.api.errors import APIError
        raise APIError("config_invalid", "Config validation failed", status_code=400,
                       details={"errors": result.errors})
    # Atomic write.
    import os
    from uuid import uuid4

    import yaml
    tmp = _CONFIG_PATH.with_name(f".{_CONFIG_PATH.name}.{uuid4().hex}.tmp")
    try:
        tmp.write_text(yaml.safe_dump(merged, default_flow_style=False, sort_keys=False, allow_unicode=True), encoding="utf-8")
        os.replace(tmp, _CONFIG_PATH)
    finally:
        if tmp.exists():
            tmp.unlink()
    _CONFIG.clear()
    _CONFIG.update(merged)
    return {"status": "ok", "config": sanitize(merged)}


@router.get("/secrets")
async def get_secrets(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Expose only configured/missing provider-key status; secret values are write-only."""
    import os

    from tools.api_key_store import (
        DEFAULT_API_KEY_FILE,
        configured_api_key_env_names,
        load_api_key_file,
    )
    names = configured_api_key_env_names(_CONFIG)
    path = Path(os.environ.get("NETATTACKAI_API_KEY_FILE", DEFAULT_API_KEY_FILE))
    loaded = load_api_key_file(path)
    status = {}
    for name in names:
        import os as _os
        status[name] = "configured" if (name in loaded or _os.environ.get(name)) else "missing"
    return {"keys": status}


@router.put("/secrets")
async def put_secrets(
    request: Request,
    auth: str = Depends(_require_auth),
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
    allowed = set(configured_api_key_env_names(_CONFIG))
    if any(
        name not in allowed or not isinstance(value, str) or not value.strip()
        for name, value in secrets.items()
    ):
        raise APIError(
            "invalid_secrets",
            "Secret names must be configured provider environment variables and values must be non-empty strings.",
            status_code=400,
        )
    path = Path(os.environ.get("NETATTACKAI_API_KEY_FILE", DEFAULT_API_KEY_FILE))
    written = save_api_keys(path, secrets)
    for name in written:
        os.environ[name] = secrets[name].strip()
    return {"status": "ok", "written": written}


@router.get("/models")
async def list_models(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """List configured model aliases + metadata."""
    models = _CONFIG.get("models", {})
    return {
        "default_alias": models.get("default_alias", "glm"),
        "registry": models.get("registry", {}),
        "info": models.get("info", {}),
    }


@router.get("/plugins")
async def list_plugins(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """List discovered plugins."""
    try:
        from tools.plugins import list_discovered_plugins
        return {"plugins": list_discovered_plugins()}
    except Exception:
        return {"plugins": []}


@router.get("/skills")
async def list_skills(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """List runtime skills catalog."""
    try:
        from tools.skill_registry_cache import get_registry
        reg = get_registry(_CONFIG)
        skills = []
        for s in reg.all_skills():
            skills.append({"name": s.name, "description": s.description, "tags": list(s.tags or [])})
        return {"skills": skills}
    except Exception:
        return {"skills": []}


@router.get("/skills/search")
async def search_skills(q: str = "", auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Search runtime skills by query."""
    try:
        from tools.skill_registry_cache import get_registry
        reg = get_registry(_CONFIG)
        results = reg.search(q) if q else reg.all_skills()
        return {"results": [{"name": s.name, "description": s.description} for s in results[:20]]}
    except Exception:
        return {"results": []}


@router.post("/diagnostics/doctor")
async def run_doctor(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Run the environment self-check and capture its stdout output."""
    import contextlib
    import io
    from tools.doctor import run_doctor as _run
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = _run(_CONFIG_PATH)
    return {"exit_code": code, "output": buf.getvalue()}


@router.post("/diagnostics/self-test")
async def run_self_test(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Run the safe localhost smoke test and capture its stdout output."""
    import contextlib
    import io
    from tools.self_test import run_self_test as _run
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = await _run(None)
    return {"exit_code": code, "output": buf.getvalue()}


# ── Goals (B4) ──────────────────────────────────────────────────────────────

@router.get("/goals")
async def list_goals(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """List all preset goals with full descriptions and risk requirement tags."""
    from tools.goal_engine import GoalEngine
    engine = GoalEngine()
    out: list[dict[str, Any]] = []
    for name, goal in engine.presets.items():
        out.append({
            "name": name,
            "description": goal.description,
            "risk": goal.risk_requirement,
            "compatible": True,
        })
    return {"goals": out}


# ── Config schema (B5) ──────────────────────────────────────────────────────

@router.get("/config/schema")
async def get_config_schema(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Return the full default config schema (CONFIG_SCHEMA) for typed form rendering."""
    from tools.config_manager import CONFIG_SCHEMA
    return {"schema": CONFIG_SCHEMA}


# ── Live Ollama models (C1) ─────────────────────────────────────────────────

@router.get("/models/live")
async def list_live_models(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """List models actually installed in the local Ollama instance.

    Hits ``ollama.host`` ``/api/tags`` live each call. Falls back to the
    configured registry with a 503 when Ollama is unreachable.
    """
    ollama_host = _CONFIG.get("ollama", {}).get("host", "http://localhost:11434")
    registry = _CONFIG.get("models", {}).get("registry", {})
    try:
        import httpx
        from fastapi import Response
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{ollama_host}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            models = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
            return {"models": models, "source": "ollama"}
    except Exception as exc:
        return Response(
            content=json.dumps({"models": list(registry.values()), "source": "registry", "error": f"Ollama unreachable: {exc}"}),
            status_code=503,
            media_type="application/json",
        )


# ── Skill detail (C2) ──────────────────────────────────────────────────────

@router.get("/skills/{name}")
async def get_skill(name: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Return a single runtime skill's sanitized body + sections + references."""
    from fastapi import HTTPException
    try:
        from tools.skill_registry_cache import get_registry
        reg = get_registry(_CONFIG)
        skill = reg.get(name)
        if skill is None:
            raise HTTPException(status_code=404, detail="Skill not found")
        return {
            "name": skill.name,
            "description": skill.description,
            "body": skill.body,
            "sections": skill.sections,
            "tags": list(skill.metadata.tags or []),
            "references": [str(r) for r in skill.metadata.references],
            "nist_csf": list(skill.metadata.nist_csf or []),
            "mitre_attack": list(skill.metadata.mitre_attack or []),
            "domain": skill.metadata.domain,
            "subdomain": skill.metadata.subdomain,
            "version": skill.metadata.version,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not load skill: {exc}")
