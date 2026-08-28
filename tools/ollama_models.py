"""Ollama model-catalog sync — keep ``models.registry`` on the newest versions.

Fetches the live model list from the Ollama API (``GET {host}/api/tags`` — the
same endpoint ``tools/doctor.py`` probes) and bumps every ``models.registry``
alias whose configured spec has a strictly newer same-family version available
(e.g. ``glm-5.2:cloud`` -> ``glm-5.3:cloud``), including when the configured
version has disappeared from the catalog entirely.

Rules:
- Family matching: ``glm-5.2`` and ``glm-5.3`` share family ``glm``;
  ``kimi-k2.6`` / ``kimi-k3`` share ``kimi-k``. Specs without a trailing
  version token (``nomic-embed-text``, ``deepseek-v4-pro``) are never touched.
- Tag preference: when several specs share the newest version, the one with the
  same tag as the configured spec (``:cloud``, ``:8b``, ...) wins.
- No pulls: the registry only stores model ids, and for Ollama Cloud hosts a
  ``pull`` merely registers a pointer (see ``tools/doctor.py``) — rewriting the
  id is the whole update.
- ``models.info`` metadata (labels, context windows) is operator-managed and
  deliberately left untouched.

Config gate: ``models.auto_update`` (default true). The daemon runs this once
at boot (``main._run_daemon``) and ``POST /api/v1/models/refresh`` exposes it
on demand; ``tools/api/routes/system.py`` persists through the validated
config-write path when triggered via the API.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Trailing version token: optional separator + optional 'v' + digits/dots at the
# end of the base name. "glm-5.2" -> ("glm", (5, 2)); "kimi-k2.6" ->
# ("kimi-k", (2, 6)); "minimax-m3" -> ("minimax-m", (3,)); "gpt-oss" -> ("gpt-oss", None).
_VERSION_RE = re.compile(r"[-._]?v?(?P<ver>\d+(?:\.\d+)*)$")


def parse_model_spec(spec: str) -> tuple[str, tuple[int, ...] | None]:
    """Split a model spec into ``(family, version)``.

    ``version`` is a tuple of ints for numeric comparison (``(5, 2)`` <
    ``(5, 10)``), or ``None`` when the spec carries no trailing version token.
    Only the base name (before any ``:tag``) is considered.
    """
    base = (spec or "").split(":", 1)[0].strip()
    match = _VERSION_RE.search(base)
    if not match:
        return base, None
    version = tuple(int(part) for part in match.group("ver").split("."))
    family = base[: match.start()] or base
    return family, version


def fetch_available_models(host: str, api_key_env: str = "OLLAMA_API_KEY", timeout: float = 5.0) -> list[str]:
    """Return every model name listed by the Ollama API (``GET /api/tags``).

    Cloud hosts require ``Authorization: Bearer $OLLAMA_API_KEY``; local
    daemons ignore the header, so sending it unconditionally is safe (same
    convention as ``tools/doctor.py``). Raises on any network/HTTP error.
    """
    url = f"{host.rstrip('/')}/api/tags"
    req = urllib.request.Request(url)
    api_key = (os.environ.get(api_key_env, "") or "").strip()
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 -- scheme from config (loopback/cloud)
        data = json.loads(resp.read().decode("utf-8"))
    return [str(m.get("name", "")) for m in data.get("models", []) if m.get("name")]


def compute_registry_updates(registry: dict[str, str], available: list[str]) -> dict[str, dict[str, str]]:
    """Compute ``{alias: {old, new}}`` spec bumps for a registry.

    Only same-family strictly-newer versions are proposed; versionless specs
    and families with no candidates are left untouched.
    """
    family_index: dict[str, list[tuple[tuple[int, ...], str, str]]] = {}
    for name in available:
        family, version = parse_model_spec(name)
        if version is None or not family:
            continue
        tag = name.split(":", 1)[1] if ":" in name else ""
        family_index.setdefault(family, []).append((version, tag, name))

    updates: dict[str, dict[str, str]] = {}
    for alias, spec in (registry or {}).items():
        family, version = parse_model_spec(spec)
        if version is None:
            continue
        candidates = family_index.get(family)
        if not candidates:
            continue
        best = max(candidates, key=lambda c: c[0])
        if best[0] <= version:
            continue
        tag = spec.split(":", 1)[1] if ":" in spec else ""
        same_tag = [c for c in candidates if c[0] == best[0] and c[1] == tag]
        new_spec = same_tag[0][2] if same_tag else best[2]
        if new_spec != spec:
            updates[alias] = {"old": spec, "new": new_spec}
    return updates


def refresh_model_registry(
    config: dict[str, Any],
    host: str | None = None,
    api_key_env: str = "OLLAMA_API_KEY",
    timeout: float = 5.0,
    config_path: str | Path = "config.yaml",
    persist: bool = True,
) -> dict[str, Any]:
    """One-shot registry sync against the Ollama API.

    Fetches the live catalog, computes same-family version bumps for
    ``models.registry`` and (when ``persist``) writes the updated config atomically
    through ``ConfigValidator``. Never mutates the caller's ``config`` dict.
    Returns ``{ok, host, available_count, updates, registry[, error]}``;
    ``ok=False`` + ``error`` when the catalog is unreachable.
    """
    ollama_cfg = config.get("ollama") if isinstance(config, dict) else None
    ohost = host or (
        str(ollama_cfg.get("host"))
        if isinstance(ollama_cfg, dict) and ollama_cfg.get("host")
        else "https://api.ollama.com"
    )
    registry = dict((config.get("models") or {}).get("registry") or {})
    try:
        available = fetch_available_models(ohost, api_key_env=api_key_env, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 -- any transport failure is a soft error
        return {
            "ok": False,
            "host": ohost,
            "available_count": 0,
            "updates": {},
            "error": f"{type(exc).__name__}: {exc}",
        }

    updates = compute_registry_updates(registry, available)
    result: dict[str, Any] = {
        "ok": True,
        "host": ohost,
        "available_count": len(available),
        "updates": updates,
        "registry": registry,
        "persisted": False,
    }
    if updates:
        new_config = copy.deepcopy(config)
        models = new_config.setdefault("models", {})
        reg = models.setdefault("registry", {})
        for alias, upd in updates.items():
            reg[alias] = upd["new"]
        if persist:
            _persist_config(new_config, config_path)
            result["persisted"] = True
        result["registry"] = dict(reg)
    return result


def _persist_config(config: dict[str, Any], config_path: str | Path) -> None:
    """Validate + atomically write ``config`` (mirrors system.py ``_write_config``)."""
    import os
    import uuid

    import yaml

    from tools.config_manager import ConfigValidator

    path = Path(config_path)
    validator = ConfigValidator(path)
    validator._config = config
    result = validator.validate()
    if not result.is_valid:
        raise ValueError(f"Config validation failed: {result.errors}")
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        tmp.write_text(
            yaml.safe_dump(config, default_flow_style=False, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def auto_refresh_on_startup(config: dict[str, Any], config_path: str | Path = "config.yaml") -> dict[str, Any] | None:
    """Boot-time best-effort registry sync. ``None`` when skipped.

    Skips silently (returns ``None``) for non-Ollama providers, when
    ``models.auto_update`` is false, or on any error — startup must never
    fail because the model catalog was unreachable.
    """
    try:
        from tools.config_manager import get_ai_provider

        if get_ai_provider(config) != "ollama":
            return None
        models_cfg = config.get("models") or {}
        if not models_cfg.get("auto_update", True):
            return None
    except Exception as exc:  # noqa: BLE001 -- never block boot on config introspection
        logger.warning("Model auto-update skipped: %s: %s", type(exc).__name__, exc)
        return None
    try:
        result = refresh_model_registry(config, config_path=config_path, persist=True, timeout=5.0)
    except Exception as exc:  # noqa: BLE001 -- advisory only
        logger.warning("Model auto-update failed: %s: %s", type(exc).__name__, exc)
        return None
    if result.get("ok") and result.get("updates"):
        # Mirror the bumps into the caller's config dict so an in-memory
        # consumer (e.g. the WebUI daemon's ``create_app(config=config)``)
        # sees the refreshed registry without a restart.
        reg = (config.get("models") or {}).setdefault("registry", {})
        for alias, upd in result["updates"].items():
            reg[alias] = upd["new"]
    return result
