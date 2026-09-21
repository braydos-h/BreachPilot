"""Shared context + helpers for the system routes package (p2-02 split).

Single source of truth for ``SystemContext`` (the per-router ``auth`` /
``config`` / ``config_path`` / ``run_manager`` / ``persistence`` bundle plus
the config-write/persistence closures) and the former module-level helpers
(``_safe_json``, ``_load_memory_sync``, provider-status probes, skill path
validators, ``_merge_config``). Moved verbatim out of
``tools/api/routes/system.py`` — zero behavior change.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import Request

from tools.api.auth import BearerAuth

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
]


_SKILL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")


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
    """Read experience-store lessons + attack-memory items (best-effort)."""
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


def _chatgpt_status_sync(chatgpt_cfg: dict[str, Any]) -> tuple[bool, bool]:
    """Read ChatGPT auth + proxy health off-thread (health check does HTTP)."""
    from tools.providers.chatgpt_provider import ChatGptProxyManager

    manager = ChatGptProxyManager.get()
    return manager.is_authenticated(chatgpt_cfg), manager._health_ok(chatgpt_cfg)


def _opencode_go_status_sync(og_cfg: dict[str, Any]) -> dict[str, Any]:
    """Return OpenCode Go reachable/online status without exposing secrets."""
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
        try:
            import httpx

            from tools.providers.opencode_go_provider import _SESSION_HEADER, opencode_session_id

            headers = {"Authorization": f"Bearer {api_key}", _SESSION_HEADER: opencode_session_id()}
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


def _run_doctor_sync(config_path: Path) -> tuple[int, str]:
    """Run the environment self-check off-thread and capture its stdout."""
    import contextlib
    import io

    from tools.doctor import run_doctor as _run

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = _run(config_path)
    return code, buf.getvalue()


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


def _merge_config(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_config(merged[key], value)
        else:
            merged[key] = value
    return merged


@dataclass
class SystemContext:
    """Per-router dependency bundle (replaces the create_router closures).

    Holds the exact objects the old closures captured so endpoint behavior
    (live-config mutation via ``write_config``, persistence fallback,
    loopback bearer auth) is unchanged.
    """

    auth: BearerAuth
    config: dict[str, Any]
    config_path: Path
    run_manager: Any = None
    persistence: Any = None

    async def require_auth(self, request: Request) -> str:
        """FastAPI dependency: validate bearer token via BearerAuth.__call__."""
        return await self.auth(request)

    def get_persistence(self) -> Any:
        """Return the active persistence, falling back to run_manager's persistence."""
        if self.persistence is not None:
            return self.persistence
        if self.run_manager is not None and hasattr(self.run_manager, "_persistence"):
            return self.run_manager._persistence
        return None

    def write_config(self, merged: dict[str, Any]) -> dict[str, Any]:
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
        validator = ConfigValidator(self.config_path)
        validator._config = merged
        result = validator.validate()
        if not result.is_valid:
            raise APIError(
                "config_invalid", "Config validation failed", status_code=400, details={"errors": result.errors}
            )
        import os
        from uuid import uuid4

        import yaml

        tmp = self.config_path.with_name(f".{self.config_path.name}.{uuid4().hex}.tmp")
        try:
            tmp.write_text(
                yaml.safe_dump(merged, default_flow_style=False, sort_keys=False, allow_unicode=True), encoding="utf-8"
            )
            os.replace(tmp, self.config_path)
        finally:
            if tmp.exists():
                tmp.unlink()
        self.config.clear()
        self.config.update(merged)
        return merged

    def apply_config_patch(self, patch: dict[str, Any]) -> dict[str, Any]:
        """Deep-merge ``patch`` into the live config and write it."""
        return self.write_config(_merge_config(self.config, patch))
