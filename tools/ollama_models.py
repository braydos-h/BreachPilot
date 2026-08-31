"""Compat shim — Ollama model-catalog sync moved into the provider architecture.

The implementation now lives in ``tools/providers/ollama_provider.py`` (all
Ollama API behavior is owned by the OllamaProvider adapter alongside the SDK
isolation and host handling).  This shim re-exports the same callables for the
existing import sites (``main.py``, ``tools/api/routes/system.py``, tests).

Note for tests that monkeypatch: patch the implementation module
(``tools.providers.ollama_provider.<fn>``) rather than this shim, since the
functions resolve their siblings from the provider module's globals.
"""

from __future__ import annotations

from tools.providers.ollama_provider import (  # noqa: F401 -- re-export
    DEFAULT_MODEL_REGISTRY,
    auto_refresh_on_startup,
    compute_registry_updates,
    fetch_available_models,
    parse_model_spec,
    refresh_model_registry,
)
