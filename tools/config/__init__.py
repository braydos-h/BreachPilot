"""tools.config package — re-exports for compat."""

from __future__ import annotations

from .loader import (
    get_ai_provider,
    get_chatgpt_config,
    get_ollama_host,
    get_opencode_go_config,
    load_validated_config,
    validate_config_file,
)
from .profiles import (
    PROFILE_DESCRIPTIONS,
    PROFILES,
    apply_profile,
    describe_profiles,
    get_profile,
    list_profiles,
)
from .schema import CONFIG_SCHEMA, DEFAULT_CONFIG, DEPRECATED_TOP_KEYS, KNOWN_TOP_KEYS
from .validator import ConfigValidationResult, ConfigValidator

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
    "get_ollama_host",
    "get_opencode_go_config",
    "get_profile",
    "list_profiles",
    "load_validated_config",
    "validate_config_file",
]
