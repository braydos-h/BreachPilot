"""tools.config package — re-exports for compat."""

from __future__ import annotations

from .loader import get_ai_provider, get_chatgpt_config, get_ollama_host, load_validated_config, validate_config_file
from .schema import CONFIG_SCHEMA, DEFAULT_CONFIG, KNOWN_TOP_KEYS
from .validator import ConfigValidationResult, ConfigValidator

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
