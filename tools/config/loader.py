"""Configuration loader — file I/O + provider helpers."""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import Any

from .schema import CONFIG_SCHEMA
from .validator import ConfigValidationResult, ConfigValidator

logger = logging.getLogger(__name__)


def validate_config_file(path: Path | str = "config.yaml") -> ConfigValidationResult:
    """Quick validation of a config file. Returns the result."""
    validator = ConfigValidator(path)
    _, result = validator.load_and_validate()
    return result


def load_validated_config(path: Path | str = "config.yaml") -> dict[str, Any]:
    """Load config with validation and defaults applied. Raises on errors."""
    validator = ConfigValidator(path)
    config, result = validator.load_and_validate()

    if not result.is_valid:
        error_msg = "; ".join(result.errors)
        raise ValueError(f"Config validation failed: {error_msg}")

    if result.has_warnings:
        for w in result.warnings:
            logger.warning("Config warning: %s", w)
        for uk in result.unknown_keys:
            logger.warning("Unknown config key: %s", uk)

    return validator.apply_defaults()


def get_ai_provider(config: dict[str, Any] | None = None) -> str:
    """Return the active chat/generate provider (``ollama`` | ``chatgpt`` | ``opencode_go``).

    Reads ``models.provider``; defaults to ``ollama`` so an absent key (the
    common case) is unchanged. Tolerates a None config.
    """
    cfg = config or {}
    models = cfg.get("models") if isinstance(cfg, dict) else None
    if isinstance(models, dict):
        provider = models.get("provider")
        if provider:
            return str(provider).lower()
    return "ollama"


def get_chatgpt_config(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the ``chatgpt`` block with schema defaults applied.

    The merge is shallow-over-defaults; used by the model-router and proxy
    manager. Never returns None.
    """

    base = copy.deepcopy(CONFIG_SCHEMA.get("chatgpt", {}))
    cfg = config or {}
    overlay = cfg.get("chatgpt") if isinstance(cfg, dict) else None
    if isinstance(overlay, dict):
        for key, value in overlay.items():
            if value is not None:
                base[key] = value
    return base


def get_opencode_go_config(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the ``opencode_go`` block with schema defaults applied.

    The merge is shallow-over-defaults; used by the model-router and discovery.
    Never returns None.
    """

    base = copy.deepcopy(CONFIG_SCHEMA.get("opencode_go", {}))
    cfg = config or {}
    overlay = cfg.get("opencode_go") if isinstance(cfg, dict) else None
    if isinstance(overlay, dict):
        for key, value in overlay.items():
            if value is not None:
                base[key] = value
    return base


def get_ollama_host(config: dict[str, Any] | None = None) -> str:
    """Return ``ollama.host`` from a config dict (module-level convenience)."""
    cfg = config or {}
    ollama = cfg.get("ollama") if isinstance(cfg, dict) else None
    if isinstance(ollama, dict):
        return str(ollama.get("host", "https://api.ollama.com"))
    return "https://api.ollama.com"


# ---------------------------------------------------------------------------
# Provider architecture accessors (single normalization layer)
# ---------------------------------------------------------------------------


def get_provider_config(config: dict[str, Any] | None = None, provider_id: str = "") -> dict[str, Any]:
    """Return provider ``provider_id``'s merged config block (never None).

    Single normalization layer for the provider architecture:

    1. Modern ``providers.<provider_id>`` block wins when present;
    2. Otherwise falls back to the provider's legacy top-level block
       (``ollama`` / ``chatgpt`` / ``opencode_go``) with schema defaults
       applied — so existing config.yaml files stay byte-compatible;
    3. Unknown providers get an empty block (schema defaults not applied —
       third-party adapters supply their own ``_coalesce`` defaults).

    Returns a fresh dict; callers may mutate freely.
    """
    cfg = config or {}
    pid = str(provider_id or "").strip().lower()

    providers_block = cfg.get("providers") if isinstance(cfg, dict) else None
    modern = providers_block.get(pid) if isinstance(providers_block, dict) else None
    if isinstance(modern, dict):
        if pid == "chatgpt":
            base = get_chatgpt_config(cfg)
        elif pid == "opencode_go":
            base = get_opencode_go_config(cfg)
        elif pid == "ollama":
            base = copy.deepcopy(CONFIG_SCHEMA.get("ollama", {}))
            overlay = cfg.get("ollama") if isinstance(cfg, dict) else None
            if isinstance(overlay, dict):
                for key, value in overlay.items():
                    if value is not None:
                        base[key] = value
        else:
            return copy.deepcopy(modern)
        for key, value in modern.items():
            if value is not None:
                base[key] = value
        return base

    if pid == "chatgpt":
        return get_chatgpt_config(cfg)
    if pid == "opencode_go":
        return get_opencode_go_config(cfg)
    if pid == "ollama":
        ollama = copy.deepcopy(CONFIG_SCHEMA.get("ollama", {}))
        overlay = cfg.get("ollama") if isinstance(cfg, dict) else None
        if isinstance(overlay, dict):
            for key, value in overlay.items():
                if value is not None:
                    ollama[key] = value
        return ollama
    if not pid:
        return {}
    raise ValueError(f"Unknown model provider '{provider_id}'. Expected one of: ollama, chatgpt, opencode_go.")


def get_embeddings_config(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the ``embeddings`` block with schema defaults applied (never None)."""
    base = copy.deepcopy(CONFIG_SCHEMA.get("embeddings", {}))
    cfg = config or {}
    overlay = cfg.get("embeddings") if isinstance(cfg, dict) else None
    if isinstance(overlay, dict):
        for key, value in overlay.items():
            if value is not None:
                base[key] = value
    # Legacy backcompat: when the modern block is untouched but the legacy
    # ollama block exists, inherit its embedding knobs (host/model).
    if dict(overlay or {}).get("provider") is None:
        ollama_cfg = cfg.get("ollama") if isinstance(cfg, dict) else None
        if isinstance(ollama_cfg, dict):
            if base.get("provider") == "ollama":
                host = ollama_cfg.get("embed_host") or ollama_cfg.get("host")
                if host and not base.get("host"):
                    base["host"] = str(host)
                api_key_env = ollama_cfg.get("api_key_env")
                if api_key_env and not base.get("api_key_env"):
                    base["api_key_env"] = str(api_key_env)
        memory_cfg = cfg.get("memory") if isinstance(cfg, dict) else None
        if isinstance(memory_cfg, dict) and memory_cfg.get("embedding_model") and not base.get("model"):
            base["model"] = str(memory_cfg["embedding_model"])
    return base


def get_model_host(config: dict[str, Any] | None = None, provider_id: str | None = None) -> str:
    """The chat host for ``provider_id`` (default: active provider).

    Only the Ollama provider has a host concept (cloud endpoint or local
    daemon); other providers configure their endpoint inside their own
    block and this returns an empty string for them. Callers use it for
    display/log purposes and pass host straight to the ollama factory.
    """
    cfg = config or {}
    pid = str(provider_id or get_ai_provider(cfg)).strip().lower()
    if pid != "ollama":
        return ""
    provider_block = get_provider_config(cfg, "ollama")
    return str(provider_block.get("host") or get_ollama_host(cfg))
