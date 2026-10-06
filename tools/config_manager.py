"""Config manager shim — re-exports from tools.config package."""

from __future__ import annotations

from typing import Any

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
from tools.config.profiles import (
    PROFILE_DESCRIPTIONS,
    PROFILES,
    apply_profile,
    describe_profiles,
    get_profile,
    list_profiles,
)
from tools.config.schema import CONFIG_SCHEMA, DEFAULT_CONFIG, DEPRECATED_TOP_KEYS, KNOWN_TOP_KEYS
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
        from tools.providers.registry import PROVIDERS, _LazyDefaultRegistry

        _LazyDefaultRegistry._ensure()
        return sorted(PROVIDERS.ids())
    except Exception:  # noqa: BLE001 -- validation must never crash on provider import
        return ["chatgpt", "ollama", "opencode_go"]


def resolve_default_model_alias(config: dict[str, Any]) -> str:
    """Return the model alias selected by the active provider configuration.

    OpenCode Go uses its provider-specific ``default_model`` as the router
    alias. ``models.default_alias`` remains the selection source for Ollama
    and ChatGPT. Keeping this resolution shared prevents benchmark execution
    and provenance from silently falling back to a stale Ollama alias.
    """
    if get_ai_provider(config) == "opencode_go":
        provider_config = get_opencode_go_config(config)
        model = str(provider_config.get("default_model", "") or "").strip()
        if model:
            return model
    models = config.get("models", {}) if isinstance(config, dict) else {}
    if isinstance(models, dict):
        alias = str(models.get("default_alias", "") or "").strip()
        if alias:
            return alias
    return "glm"


__all__ = [
    "CONFIG_SCHEMA",
    "DEFAULT_CONFIG",
    "DEPRECATED_TOP_KEYS",
    "KNOWN_TOP_KEYS",
    "PROFILE_DESCRIPTIONS",
    "PROFILES",
    "ConfigValidationResult",
    "ConfigValidator",
    "apply_profile",
    "describe_profiles",
    "get_ai_provider",
    "get_chatgpt_config",
    "get_embeddings_config",
    "get_model_host",
    "get_ollama_host",
    "get_opencode_go_config",
    "get_profile",
    "get_provider_config",
    "list_profiles",
    "load_validated_config",
    "resolve_known_provider_ids",
    "resolve_default_model_alias",
    "validate_config_file",
]
