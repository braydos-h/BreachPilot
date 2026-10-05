"""Benchmark model selection through the shared provider registry."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def resolve_model_alias(config: Mapping[str, Any], requested: str = "") -> str:
    """Resolve an explicit or configured model to the active provider's model ID."""
    selected = requested.strip()
    if selected:
        return selected

    from tools.config.loader import get_ai_provider
    from tools.providers.registry import resolve_default_model

    provider_id = get_ai_provider(config)
    model_id = resolve_default_model(config, provider_id).strip()
    if model_id:
        return model_id

    # Keep compatibility with minimal legacy Ollama test/config inputs that
    # omit a registry model while still making the provider resolver primary.
    models = config.get("models")
    default_alias = models.get("default_alias") if isinstance(models, Mapping) else None
    return str(default_alias or "glm")
