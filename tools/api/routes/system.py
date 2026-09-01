"""System and administration routes: /health, /capabilities, /config, /secrets, /models, /plugins, /skills, /diagnostics, /goals, /config/schema, /models/live, /skills/{name}."""

from __future__ import annotations

import asyncio
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
_RUN_MANAGER: Any = None


def configure(auth: BearerAuth, config: dict[str, Any], config_path: Path) -> None:
    global _AUTH, _CONFIG, _CONFIG_PATH
    _AUTH = auth
    _CONFIG = config
    _CONFIG_PATH = config_path


def browser_capability_status(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Capability-status metadata for /capabilities (never available here).

    Lazy import: tools.browser is dependency-free, but the system routes stay
    importable even if the browser seam is absent (bundled wheel edge case).
    """
    try:
        from tools.browser.capabilities import browser_capabilities

        return browser_capabilities(config)
    except Exception:  # noqa: BLE001 — status metadata is best-effort, never breaks the route
        return []


def configure_run_manager(run_manager: Any) -> None:
    global _RUN_MANAGER
    _RUN_MANAGER = run_manager


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
    """API features, supported run options, constraints, and tool groups.

    ``max_concurrent_runs`` is read from the live ``api.max_concurrent_runs``
    config key (default 1 = legacy single-run behavior). The ``features`` list
    advertises both REST surfaces and advisory MCP tool families so the WebUI
    can gate each panel on its feature flag (an absent feature renders an empty
    state, never a 404 loop).
    """
    api_cfg = _CONFIG.get("api", {}) or {}
    # Browser status is advertised so the WebUI (and API clients) can detect
    # that browser capabilities exist but are unavailable — capability-status
    # metadata only; there are no browser endpoints to pretend otherwise.
    # See docs/browser-agent-design.md §WebUI event model.
    browser_cfg = _CONFIG.get("browser", {}) or {}
    return {
        "api_version": "v1",
        "browser": {
            "enabled": bool(browser_cfg.get("enabled", False)),
            "backend": str(browser_cfg.get("backend", "none") or "none"),
            "available": False,
            "capabilities": browser_capability_status(_CONFIG),
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


@router.get("/config")
async def get_config(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Return redacted configuration."""
    return sanitize(_CONFIG)


def _write_config(merged: dict[str, Any]) -> dict[str, Any]:
    """Validate + atomically write ``merged`` as the new live config.

    Shared by PATCH /config and the model-registry write endpoints so the
    loopback-origin guard, ConfigValidator, and atomic write stay in one place.
    """
    from tools.api.auth import is_loopback_origin
    from tools.api.errors import APIError
    from tools.config_manager import ConfigValidator

    origins = (merged.get("api", {}) or {}).get("allowed_origins", [])
    if isinstance(origins, list) and any(
        isinstance(origin, str) and not is_loopback_origin(origin, origins) for origin in origins
    ):
        raise APIError(
            "config_invalid",
            "api.allowed_origins may contain only loopback HTTP(S) origins.",
            status_code=400,
        )
    validator = ConfigValidator(_CONFIG_PATH)
    validator._config = merged
    result = validator.validate()
    if not result.is_valid:
        raise APIError("config_invalid", "Config validation failed", status_code=400, details={"errors": result.errors})
    import os
    from uuid import uuid4

    import yaml

    tmp = _CONFIG_PATH.with_name(f".{_CONFIG_PATH.name}.{uuid4().hex}.tmp")
    try:
        tmp.write_text(
            yaml.safe_dump(merged, default_flow_style=False, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
        os.replace(tmp, _CONFIG_PATH)
    finally:
        if tmp.exists():
            tmp.unlink()
    _CONFIG.clear()
    _CONFIG.update(merged)
    return merged


def _apply_config_patch(patch: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge ``patch`` into the live config and write it."""
    return _write_config(_merge_config(_CONFIG, patch))


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
    merged = _apply_config_patch(body)
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
    if any(name not in allowed or not isinstance(value, str) or not value.strip() for name, value in secrets.items()):
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


@router.get("/models")
async def list_models(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """List configured model aliases + metadata (provider-aware)."""
    from tools.config_manager import get_ai_provider, get_chatgpt_config, get_opencode_go_config

    models = _CONFIG.get("models", {})
    provider = get_ai_provider(_CONFIG)
    response: dict[str, Any] = {
        "provider": provider,
        "default_alias": models.get("default_alias", "glm"),
        "registry": models.get("registry", {}),
        "info": models.get("info", {}),
    }
    if provider == "chatgpt":
        chatgpt_cfg = get_chatgpt_config(_CONFIG)
        response["chatgpt"] = {
            "default_model": chatgpt_cfg.get("default_model", "gpt-5.2"),
            "context_window": chatgpt_cfg.get("context_window", 128000),
            "configured_models": list(chatgpt_cfg.get("models") or []),
        }
    if provider == "opencode_go":
        og_cfg = get_opencode_go_config(_CONFIG)
        response["opencode_go"] = {
            "base_url": og_cfg.get("base_url", "https://opencode.ai/zen/go/v1"),
            "default_model": og_cfg.get("default_model", "muse-spark-1.2-contributor"),
            "context_window": og_cfg.get("context_window", 128000),
            "configured_models": list(og_cfg.get("models") or []),
            "enabled": bool(og_cfg.get("enabled", False)),
        }
    return response


@router.post("/models")
async def add_model(request: Request, auth: str = Depends(_require_auth)) -> dict[str, Any]:
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
    merged = _apply_config_patch({"models": {"registry": {alias: model}}})
    return {"status": "ok", "alias": alias, "model": model, "registry": merged.get("models", {}).get("registry", {})}


@router.delete("/models/{alias}")
async def remove_model(alias: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Remove a model alias from ``models.registry`` (and its ``info`` entry)."""
    import copy

    from tools.api.errors import APIError

    alias = alias.strip()
    merged = copy.deepcopy(_CONFIG)
    models = merged.setdefault("models", {})
    registry = models.setdefault("registry", {})
    if alias not in registry:
        raise HTTPException(status_code=404, detail=f"Model alias '{alias}' not found")
    if models.get("default_alias") == alias:
        raise APIError("invalid_model", f"Cannot remove the default alias '{alias}'.", status_code=400)
    del registry[alias]
    models.setdefault("info", {}).pop(alias, None)
    _write_config(merged)
    return {"status": "ok", "alias": alias, "deleted": True}


@router.post("/models/provider")
async def set_model_provider(request: Request, auth: str = Depends(_require_auth)) -> dict[str, Any]:
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
    merged = _apply_config_patch(patch)
    return {"status": "ok", "provider": provider, "registered_providers": sorted(known)}


@router.post("/models/refresh")
async def refresh_models(auth: str = Depends(_require_auth)) -> dict[str, Any]:
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

    if get_ai_provider(_CONFIG) != "ollama":
        raise APIError("invalid_provider", "Model refresh applies to the ollama provider only.", status_code=400)
    result = await asyncio.to_thread(
        refresh_model_registry,
        _CONFIG,
        config_path=_CONFIG_PATH,
        persist=False,
    )
    if not result.get("ok"):
        result.pop("available", None)
        from fastapi import Response

        return Response(content=json.dumps(result), status_code=503, media_type="application/json")
    updates = result.get("updates") or {}
    if updates:
        merged = _apply_config_patch({"models": {"registry": {alias: upd["new"] for alias, upd in updates.items()}}})
        result["registry"] = merged.get("models", {}).get("registry", {})
        result["persisted"] = True
    return result


@router.get("/system/info")
async def get_system_info(auth: str = Depends(_require_auth)) -> dict[str, Any]:
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
async def get_telemetry(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """LLM usage telemetry summary + recent records (numeric/categorical only).

    Reads ``research_workspace/logs/llm_usage.jsonl`` via tools/model_telemetry.
    No prompts, responses, or raw provider payloads are ever persisted or returned.
    """
    from tools.model_telemetry import read_usage_records, usage_summary, workspace_root_from_sources

    def _load() -> dict[str, Any]:
        workspace_root = workspace_root_from_sources(_CONFIG_PATH)
        return {
            "summary": usage_summary(workspace_root),
            "recent": read_usage_records(workspace_root, limit=50),
        }

    return await asyncio.to_thread(_load)


def _safe_json(raw: Any) -> dict[str, Any]:
    try:
        data = json.loads(raw or "{}")
        return data if isinstance(data, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


def _read_attack_memory_db(db_path: Path) -> list[dict[str, Any]]:
    """Read items from one ``attack_memory.db`` (best-effort, never raises)."""
    import sqlite3

    items: list[dict[str, Any]] = []
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT id, session_id, target_ip, category, item_key, item_value, "
                "source_tool, success, metadata_json, first_seen_at, last_seen_at, seen_count "
                "FROM attack_memory_items ORDER BY last_seen_at DESC LIMIT 200"
            ).fetchall()
        finally:
            conn.close()
    except Exception:
        return items
    for row in rows:
        items.append(
            {
                "id": row["id"],
                "session_id": row["session_id"],
                "target_ip": row["target_ip"],
                "category": row["category"],
                "item_key": row["item_key"],
                "item_value": row["item_value"],
                "source_tool": row["source_tool"],
                "success": bool(row["success"]),
                "metadata": _safe_json(row["metadata_json"]),
                "first_seen_at": row["first_seen_at"],
                "last_seen_at": row["last_seen_at"],
                "seen_count": int(row["seen_count"]),
            }
        )
    return items


def _load_memory_sync(config_path: Path, config: dict[str, Any]) -> dict[str, Any]:
    """Read experience-store lessons + attack-memory items (best-effort).

    Lessons come from the default research DB (``lessons`` table); attack
    memory comes from any ``attack_memory.db`` under the reports dir. Both are
    read-only and tolerate a fresh install (empty tables / no files).
    """
    lessons: list[dict[str, Any]] = []
    confidence: list[dict[str, Any]] = []
    try:
        from db import get_default_db

        db = get_default_db()
        with db.connection() as conn:
            cur = conn.execute(
                "SELECT id, target_signature, action_type, outcome, confidence, created_at, metadata_json "
                "FROM lessons WHERE embedding_json = '[]' ORDER BY created_at DESC LIMIT 100"
            )
            for row in cur.fetchall():
                lessons.append(
                    {
                        "id": row["id"],
                        "target_signature": row["target_signature"],
                        "action_type": row["action_type"],
                        "outcome": row["outcome"],
                        "confidence": row["confidence"],
                        "created_at": row["created_at"],
                        "metadata": _safe_json(row["metadata_json"]),
                    }
                )
            cur = conn.execute(
                "SELECT action_type, COUNT(*) AS n, "
                "SUM(CASE WHEN outcome='success' THEN 1 ELSE 0 END) AS successes, "
                "SUM(CASE WHEN outcome='failure' THEN 1 ELSE 0 END) AS failures, "
                "SUM(CASE WHEN outcome='partial' THEN 1 ELSE 0 END) AS partials, "
                "MAX(created_at) AS last_seen "
                "FROM lessons WHERE embedding_json = '[]' "
                "GROUP BY action_type ORDER BY last_seen DESC"
            )
            for row in cur.fetchall():
                n = int(row["n"])
                s = int(row["successes"])
                f = int(row["failures"])
                p = int(row["partials"])
                # Beta(1,1) posterior mean. ponytail: no time decay here — the
                # viewer shows raw counts; add decay if it ever misleads.
                alpha = 1.0 + s + p
                beta = 1.0 + f + p
                confidence.append(
                    {
                        "action_type": row["action_type"],
                        "observations": n,
                        "successes": s,
                        "failures": f,
                        "partials": p,
                        "confidence": round(alpha / (alpha + beta), 4),
                        "last_seen": row["last_seen"],
                    }
                )
    except Exception:
        lessons, confidence = [], []

    attack_memory: list[dict[str, Any]] = []
    try:
        reports_dir = Path(str(config.get("reports_dir", "reports") or "reports"))
        if not reports_dir.is_absolute():
            reports_dir = config_path.parent / reports_dir
        for db_path in sorted(reports_dir.rglob("attack_memory.db")):
            attack_memory.extend(_read_attack_memory_db(db_path))
    except Exception:
        attack_memory = []

    return {"lessons": lessons, "confidence": confidence, "attack_memory": attack_memory}


@router.get("/system/memory")
async def get_memory(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Attack memory + experience-store learnings (cross-mission, no secrets)."""
    return await asyncio.to_thread(_load_memory_sync, _CONFIG_PATH, _CONFIG)


@router.get("/system/sandbox")
async def get_sandbox_status(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Disposable-sandbox status for the System UI (read-only, no Docker controls).

    Reports sandbox.enabled/backend/image, Docker reachability, network policy
    posture, and resource limits. Never exposes container exec/remove controls:
    sandbox lifecycle is owned by the run engine, not the WebUI.
    """
    from tools.sandbox import status_report

    return await asyncio.to_thread(status_report, _CONFIG)


@router.get("/system/sandbox/fix/plan")
async def get_sandbox_fix_plan(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Read-only remediation plan for the Docker sandbox.

    Returns enough detail for the WebUI to explain exactly what would happen
    before any host-changing commands run. No side effects, localhost/auth
    protected like the rest of /system/sandbox.
    """
    from tools.sandbox.remediation import build_plan

    return await asyncio.to_thread(build_plan, _CONFIG)


@router.post("/system/sandbox/fix")
async def start_sandbox_fix(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Start the Docker sandbox remediation (localhost/auth protected).

    Narrow, enum-like endpoint: the browser requests a fix job, not arbitrary
    commands. No body params are accepted – the server's known project path
    (docker/sandbox) is used, and the job is identified by a server-generated id.
    Returns the initial job record; poll GET /system/sandbox/fix/{job_id} for
    progress.
    """
    from tools.api.errors import APIError
    from tools.sandbox.models import SandboxConfig
    from tools.sandbox.remediation import _job_to_dict, _start_background_job, create_job
    from tools.sandbox import remediation as _rem

    # Do not treat disabled as success – refuse to "fix" an intentional choice.
    cfg = SandboxConfig.from_config(_CONFIG)
    if not cfg.enabled:
        raise APIError(
            "sandbox_disabled",
            "Sandbox is intentionally disabled (sandbox.enabled: false). Enable it in config.yaml instead.",
            status_code=400,
        )

    # Fail closed on concurrent running job: one fix at a time.
    async with _rem._JOBS_LOCK:
        for j in _rem._JOBS.values():
            if j.status in ("pending", "running"):
                raise APIError("conflict", "A sandbox fix is already running.", status_code=409)

    job = await create_job(_CONFIG)
    # Start background execution (does not block the HTTP response).
    _start_background_job(job.job_id, _CONFIG)
    return _job_to_dict(job)


@router.get("/system/sandbox/fix/{job_id}")
async def get_sandbox_fix_status(job_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Poll the fix job for structured step progress."""
    from tools.sandbox.remediation import _job_to_dict, get_job

    # Sanitize job_id: only hex ids we generate are valid – reject path traversal / injection.
    if not re.fullmatch(r"[0-9a-fA-F]{6,32}", job_id):
        raise HTTPException(status_code=404, detail="Fix job not found")
    job = await get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Fix job not found")
    return _job_to_dict(job)


@router.post("/system/reset")
async def reset_system(request: Request, auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Wipe all past work: run history, reports/, exploit_workspace/,
    research_workspace/, and swarm_workspace/.

    Refuses while any run is active (running/queued/awaiting_input). The
    api_runtime.db file itself is kept (its schema is the live persistence
    instance's state); all rows are deleted. Users/annotations are removed
    with the runs they belong to; user accounts are kept.
    """
    from tools.api.errors import APIError

    if _RUN_MANAGER is None:
        raise RuntimeError("Run manager not configured.")
    if _RUN_MANAGER.has_active:
        raise APIError(
            "conflict",
            "Cannot reset while a run is active. Cancel or wait for it to finish first.",
            status_code=409,
        )

    reports_dir = _RUN_MANAGER._persistence.reports_dir.resolve()
    # The api_runtime.db file lives inside reports_dir and is held open by the
    # live ApiPersistence instance, so clear its rows first and keep the file.
    runs_deleted = _RUN_MANAGER._persistence.reset_all()
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
    _RUN_MANAGER._persistence._init_db()

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


def _run_doctor_sync(config_path: Path) -> tuple[int, str]:
    """Run the environment self-check off-thread and capture its stdout."""
    import contextlib
    import io

    from tools.doctor import run_doctor as _run

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = _run(config_path)
    return code, buf.getvalue()


@router.post("/diagnostics/doctor")
async def run_doctor(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Run the environment self-check and capture its stdout output."""
    code, output = await asyncio.to_thread(_run_doctor_sync, _CONFIG_PATH)
    return {"exit_code": code, "output": output}


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


# ── Attack modules catalog ──────────────────────────────────────────────────


@router.get("/attack/modules")
async def list_attack_modules(auth: str = Depends(_require_auth)) -> dict[str, Any]:
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


@router.get("/goals")
async def list_goals(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """List all preset goals with full descriptions and risk requirement tags.

    ``compatible`` reflects the conservative baseline risk profile
    (``standard_authorized``): safe and gated goals are selectable, while
    high-risk goals report ``compatible: false`` until the profile is raised to
    ``high_authorized_testing`` (attack runs). The WebUI renders that as an
    "Unavailable" state; it never bypasses the backend goal gates.
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
            }
        )
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

    provider = get_ai_provider(_CONFIG)
    registry_fallback = [str(v) for v in (_CONFIG.get("models", {}).get("registry", {}) or {}).values() if v]
    try:
        adapter = get_provider(provider)
    except Exception as exc:  # unknown provider id — surface, don't crash
        return Response(
            content=json.dumps(
                {"models": registry_fallback, "source": "registry", "error": f"Unknown provider '{provider}': {exc}"}
            ),
            status_code=503,
            media_type="application/json",
        )
    try:
        infos = await asyncio.to_thread(adapter.list_models, _CONFIG)
        models = [i.id for i in infos if i.id]
        if not models:
            raise ProviderDiscoveryError(f"{provider} reported no models")
        return {"models": models, "source": provider}
    except ProviderDiscoveryError as exc:
        return Response(
            content=json.dumps(
                {
                    "models": exc.fallback_models or registry_fallback,
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
                {"models": registry_fallback, "source": "registry", "error": f"{provider} discovery failed: {exc}"}
            ),
            status_code=503,
            media_type="application/json",
        )


# ── AI providers (ChatGPT / openai-oauth) ────────────────────────────────────


def _chatgpt_status_sync(chatgpt_cfg: dict[str, Any]) -> tuple[bool, bool]:
    """Read ChatGPT auth + proxy health off-thread (health check does HTTP)."""
    from tools.providers.chatgpt_provider import ChatGptProxyManager

    manager = ChatGptProxyManager.get()
    return manager.is_authenticated(chatgpt_cfg), manager._health_ok(chatgpt_cfg)


def _opencode_go_status_sync(og_cfg: dict[str, Any]) -> dict[str, Any]:
    """Return OpenCode Go reachable/online status without exposing secrets.

    Never returns the API key.  Probes ``GET {base_url}/models`` with a short
    timeout when a key is present; otherwise reachable stays False.
    """
    import os

    env_name = str(og_cfg.get("api_key_env") or "OPENCODE_GO_API_KEY")
    api_key = (os.environ.get(env_name, "") or "").strip()
    api_key_present = bool(api_key)
    base_url = str(og_cfg.get("base_url") or "https://opencode.ai/zen/go/v1").rstrip("/")
    default_model = str(og_cfg.get("default_model") or "muse-spark-1.2-contributor")
    enabled = bool(og_cfg.get("enabled", False))

    reachable = False
    available_models: list[str] = list(og_cfg.get("models") or [])
    error: str | None = None

    if not api_key_present:
        error = f"API key not set ({env_name})"
    else:
        # Lightweight probe: GET /models with bearer auth, short timeout.
        try:
            import httpx

            headers = {"Authorization": f"Bearer {api_key}"}
            with httpx.Client(timeout=3.0, headers=headers) as client:
                resp = client.get(f"{base_url}/models")
                if resp.status_code < 400:
                    reachable = True
                    try:
                        data = resp.json()
                        raw = data.get("data") if isinstance(data, dict) else None
                        if isinstance(raw, list):
                            parsed = [str(m.get("id", "")) for m in raw if isinstance(m, dict) and m.get("id")]
                            if parsed:
                                available_models = parsed
                    except Exception:
                        pass
                else:
                    error = f"HTTP {resp.status_code}"
        except Exception as exc:
            txt = str(exc)
            if api_key and api_key in txt:
                txt = txt.replace(api_key, "[REDACTED]")
            error = txt[:500]

    result: dict[str, Any] = {
        "enabled": enabled,
        "base_url": base_url,
        "default_model": default_model,
        "api_key_present": api_key_present,
        "reachable": reachable,
        "available_models": available_models,
        "configured_models": list(og_cfg.get("models") or []),
        "context_window": og_cfg.get("context_window", 128000),
    }
    if error:
        result["error"] = error
    return result


@router.get("/providers")
async def get_providers(auth: str = Depends(_require_auth)) -> dict[str, Any]:
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

    provider = get_ai_provider(_CONFIG)
    chatgpt_cfg = get_chatgpt_config(_CONFIG)
    og_cfg = get_opencode_go_config(_CONFIG)
    manager = ChatGptProxyManager.get()
    authenticated, proxy_running = await asyncio.to_thread(_chatgpt_status_sync, chatgpt_cfg)
    og_status = await asyncio.to_thread(_opencode_go_status_sync, og_cfg)
    provider_rows: list[dict[str, Any]] = []
    for adapter in sorted(PROVIDERS.all(), key=lambda a: a.id):
        try:
            meta = await asyncio.to_thread(adapter.metadata, _CONFIG)
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
async def chatgpt_login(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Start a ChatGPT OAuth login (browser flow) and return the login URL.

    Tokens stay in openai-oauth's ~/.codex/auth.json — they never enter the
    request/response/config. Returns ``{ok, url?, reason?}``.
    """
    from tools.config_manager import get_chatgpt_config
    from tools.providers.chatgpt_provider import ChatGptProxyManager

    chatgpt_cfg = get_chatgpt_config(_CONFIG)
    result = await asyncio.to_thread(ChatGptProxyManager.get().run_login, chatgpt_cfg)
    return result


@router.post("/providers/chatgpt/proxy/start")
async def chatgpt_proxy_start(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Ensure the local openai-oauth proxy is running."""
    from tools.config_manager import get_chatgpt_config
    from tools.providers.chatgpt_provider import ChatGptProxyManager

    chatgpt_cfg = get_chatgpt_config(_CONFIG)
    return await asyncio.to_thread(ChatGptProxyManager.get().ensure_running, chatgpt_cfg)


@router.post("/providers/chatgpt/proxy/stop")
async def chatgpt_proxy_stop(auth: str = Depends(_require_auth)) -> dict[str, Any]:
    """Stop the proxy only if BreachPilot started it."""
    from tools.config_manager import get_chatgpt_config
    from tools.providers.chatgpt_provider import ChatGptProxyManager

    chatgpt_cfg = get_chatgpt_config(_CONFIG)
    manager = ChatGptProxyManager.get()
    we_started = manager._we_started
    await asyncio.to_thread(manager.shutdown, chatgpt_cfg)
    return {"ok": True, "stopped": we_started}


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
