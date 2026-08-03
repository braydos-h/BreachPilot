"""System and administration routes: /health, /capabilities, /config, /secrets, /models, /plugins, /skills, /diagnostics, /goals, /config/schema, /models/live, /skills/{name}."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

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
        skills = [
            {"name": s.name, "description": s.metadata.description, "tags": list(s.metadata.tags or [])}
            for s in reg.list_skills()
        ]
        return {"skills": skills}
    except Exception as exc:
        return {"skills": [], "error": f"{type(exc).__name__}: {exc}"}


@router.get("/skills/search")
async def search_skills(q: str = "", auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Search runtime skills by query."""
    try:
        from tools.skill_registry_cache import get_registry
        reg = get_registry(_CONFIG)
        results = reg.search(q) if q else reg.list_skills()
        return {"results": [{"name": s.name, "description": s.metadata.description} for s in results[:20]]}
    except Exception as exc:
        return {"results": [], "error": f"{type(exc).__name__}: {exc}"}


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
    """List models actually installed in the configured Ollama backend.

    Hits ``ollama.host`` ``/api/tags`` live each call (cloud host requires
    ``Authorization: Bearer $OLLAMA_API_KEY``). Falls back to the configured
    registry with a 503 when the backend is unreachable.
    """
    ollama_host = _CONFIG.get("ollama", {}).get("host", "https://api.ollama.com")
    registry = _CONFIG.get("models", {}).get("registry", {})
    try:
        import httpx
        from fastapi import Response
        headers = {}
        api_key = (os.environ.get("OLLAMA_API_KEY", "") or "").strip()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        async with httpx.AsyncClient(timeout=5.0, headers=headers) as client:
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


# ── Skill install / remove (write path) ──────────────────────────────────────
# Skills are advisory-only markdown guidance imported into the LLM system prompt.
# Install writes a new SKILL.md under the first configured skills.roots dir;
# remove deletes the skill's directory. Both paths guard against path traversal
# (regex on the name + resolve()-based containment under the chosen root) and
# refuse to touch plugin-contributed skill dirs (only configured roots are
# writable). parse_skill_file validates on write so malformed skills never land
# on disk; the registry cache is cleared so the next read reloads from disk.

_SKILL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")


def _skill_writable_root() -> Path:
    """Return the first configured skills.roots entry, resolved against the repo base.

    The repo base is the config file's parent dir (matches how load_config and
    skill_registry_cache resolve relative roots). Raises 400 if no root is
    configured or it is not a writable directory.
    """
    from tools.api.errors import APIError

    skills_cfg = _CONFIG.get("skills", {}) or {}
    roots = skills_cfg.get("roots") or ["skills"]
    if not isinstance(roots, list) or not roots:
        raise APIError("invalid_config", "skills.roots is empty.", status_code=400)
    first = Path(str(roots[0]))
    if not first.is_absolute():
        first = _CONFIG_PATH.parent / first
    try:
        first = first.resolve()
    except OSError as exc:
        raise APIError("invalid_config", f"Cannot resolve skills root: {exc}", status_code=400)
    if not first.is_dir():
        raise APIError("invalid_config", f"Skills root is not a directory: {first}", status_code=400)
    return first


def _validate_skill_name(name: str) -> str:
    from tools.api.errors import APIError

    cleaned = str(name or "").strip()
    if not _SKILL_NAME_RE.match(cleaned):
        raise APIError(
            "invalid_skill_name",
            "Skill name must be 2-64 chars, lowercase alphanumeric and hyphens, starting with a letter or digit.",
            status_code=400,
        )
    return cleaned


def _resolve_skill_dir(name: str, root: Path) -> Path:
    """Resolve the skill directory for a name and confirm it stays under root."""
    from tools.api.errors import APIError

    target = (root / name).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise APIError("invalid_skill_name", "Skill name escapes the skills root.", status_code=400)
    return target


def _plugin_skill_dirs() -> set[str]:
    """Return the set of plugin-contributed skill dir paths (read-only, never writable)."""
    try:
        from tools.plugins import PLUGIN_REGISTRY
        return {str(p) for p in PLUGIN_REGISTRY.skill_dirs}
    except Exception:
        return set()


@router.post("/skills")
async def install_skill(request: Request, auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Install a new skill by writing SKILL.md under the writable skills root.

    Body: {name: str, markdown: str}. The name is validated and the markdown is
    parsed on write -- a malformed skill (bad front matter, empty name, etc.)
    is rejected and the created directory is cleaned up so nothing broken
    lands on disk. The registry cache is cleared so the next /skills read
    reflects the new file.
    """
    from tools.api.errors import APIError
    from tools.skill_registry import parse_skill_file
    from tools.skill_registry_cache import clear_cache

    body = await request.json()
    if not isinstance(body, dict):
        raise APIError("invalid_body", "Expected a JSON object.", status_code=400)
    name = _validate_skill_name(str(body.get("name") or ""))
    markdown = body.get("markdown")
    if not isinstance(markdown, str) or not markdown.strip():
        raise APIError("invalid_body", "markdown must be a non-empty string.", status_code=400)

    root = _skill_writable_root()
    target_dir = _resolve_skill_dir(name, root)
    if target_dir.exists():
        raise APIError("skill_exists", f"Skill '{name}' already exists.", status_code=409)

    skill_file = target_dir / "SKILL.md"
    tmp_file = target_dir.with_name(f".{target_dir.name}.tmp")
    created_dir = False
    try:
        target_dir.mkdir(parents=True)
        created_dir = True
        # Write via temp file then atomic replace, mirroring config write style.
        tmp_file.write_text(markdown, encoding="utf-8")
        os.replace(tmp_file, skill_file)
        # Validate on write: parse the file we just wrote. On failure, clean up.
        try:
            parsed = parse_skill_file(skill_file, root=root)
        except Exception as exc:
            raise APIError("invalid_skill", f"Skill markdown is invalid: {exc}", status_code=400)
        # Enforce dir name == front-matter name so the registry (which keys on
        # the front-matter name) indexes the skill under the same name the
        # client used -- otherwise DELETE /skills/{name} and config toggles
        # would target the wrong identifier.
        if parsed.name != name:
            raise APIError(
                "invalid_skill",
                f"Front-matter name '{parsed.name}' does not match the requested name '{name}'.",
                status_code=400,
            )
        clear_cache()
        return {
            "name": parsed.name,
            "description": parsed.metadata.description,
            "tags": list(parsed.metadata.tags or []),
        }
    except APIError:
        # Clean up any partial state on validation/config errors.
        if created_dir and target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)
        if tmp_file.exists():
            try:
                tmp_file.unlink()
            except OSError:
                pass
        raise
    except Exception as exc:
        if created_dir and target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)
        if tmp_file.exists():
            try:
                tmp_file.unlink()
            except OSError:
                pass
        raise APIError("install_failed", f"Could not install skill: {exc}", status_code=500)


@router.delete("/skills/{name}")
async def remove_skill(name: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Delete a skill's directory from the writable skills root.

    Refuses to delete skills that resolve to plugin-contributed roots (those
    are read-only). Path traversal is blocked by _resolve_skill_dir's
    containment check. Clears the registry cache so the next /skills read
    reflects the deletion.
    """
    from tools.api.errors import APIError
    from tools.skill_registry_cache import clear_cache

    cleaned = _validate_skill_name(name)
    root = _skill_writable_root()
    target_dir = _resolve_skill_dir(cleaned, root)
    if not target_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skill '{cleaned}' not found")
    # Reject deletion of plugin-contributed skill dirs (defence in depth).
    plugin_dirs = _plugin_skill_dirs()
    if any(str(target_dir).startswith(pd) for pd in plugin_dirs):
        raise APIError(
            "skill_not_writable",
            "Cannot delete skills from plugin-contributed directories.",
            status_code=400,
        )
    try:
        shutil.rmtree(target_dir)
    except OSError as exc:
        raise APIError("remove_failed", f"Could not delete skill: {exc}", status_code=500)
    clear_cache()
    return {"name": cleaned, "deleted": True}
