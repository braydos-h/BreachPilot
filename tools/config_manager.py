"""Config manager shim — re-exports from tools.config package."""

from __future__ import annotations

from tools.config.loader import (
    get_ai_provider,
    get_chatgpt_config,
    get_ollama_host,
    load_validated_config,
    validate_config_file,
)
from tools.config.schema import CONFIG_SCHEMA, DEFAULT_CONFIG, KNOWN_TOP_KEYS
from tools.config.validator import ConfigValidationResult, ConfigValidator

__all__ = [
    "CONFIG_SCHEMA",
    "DEFAULT_CONFIG",
    "KNOWN_TOP_KEYS",
    "ConfigValidationResult",
    "ConfigValidator",
    "get_ai_provider",
    "get_chatgpt_config",
    "get_ollama_host",
    "load_validated_config",
    "validate_config_file",
]
