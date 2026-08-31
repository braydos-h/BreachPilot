"""Config manager shim — re-exports from tools.config package."""

from __future__ import annotations

from tools.config.loader import (
    get_ai_provider,
    get_chatgpt_config,
    get_embeddings_config,
    get_model_host,
    get_ollama_host,
    get_opencode_go_config,
    get_provider_config,
    load_validated_config,
    validate_config_file,
)
from tools.config.schema import CONFIG_SCHEMA, DEFAULT_CONFIG, KNOWN_TOP_KEYS
from tools.config.validator import ConfigValidationResult, ConfigValidator


def resolve_known_provider_ids() -> list[str]:
    """Registered chat-provider ids (registry-driven; import-safe fallback).

    Used by the config validator's ``models.provider`` whitelist so adding
    provider #4 doesn't require touching the validator. If the providers
    package can't be imported (e.g. mid-refactor), falls back to the
    built-in three.
    """
    try:
        from tools.providers.ollama_provider import OllamaProvider

        del OllamaProvider  # importing the module is what forces registration
        from tools.providers.registry import _LazyDefaultRegistry, PROVIDERS

        _LazyDefaultRegistry._ensure()
        return sorted(PROVIDERS.ids())
    except Exception:  # noqa: BLE001 -- validation must never crash on provider import
        return ["chatgpt", "ollama", "opencode_go"]


__all__ = [
    "CONFIG_SCHEMA",
    "DEFAULT_CONFIG",
    "KNOWN_TOP_KEYS",
    "ConfigValidationResult",
    "ConfigValidator",
    "get_ai_provider",
    "get_chatgpt_config",
    "get_embeddings_config",
    "get_model_host",
    "get_ollama_host",
    "get_opencode_go_config",
    "get_provider_config",
    "load_validated_config",
    "resolve_known_provider_ids",
    "validate_config_file",
]