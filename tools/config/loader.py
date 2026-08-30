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
