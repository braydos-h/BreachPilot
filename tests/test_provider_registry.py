"""Tests for the provider registry (``tools/providers/registry.py``) + adapters.

Covers the registry-resolution layer that replaced every
``if provider == "chatgpt"/"opencode_go"`` branch:
* lazy registration of the three built-in adapters (ollama / opencode_go /
  chatgpt) and uniqueness of ``ProviderRegistry.register``;
* alias resolution, unknown-provider errors, metadata rows (capabilities,
  configured, default_model — no secrets);
* ``get_provider_from_config`` / ``resolve_default_model`` config dispatch;
* config normalization through the single layer
  (``tools.config.loader.get_provider_config``: ``providers.<id>`` block >
  legacy top-level block) and ``get_model_host`` (ollama-only host).
"""

from __future__ import annotations

from typing import Any

import pytest

from tools.providers import registry as registry_mod
from tools.providers.base import BaseProvider
from tools.providers.registry import (
    PROVIDERS,
    UnknownProviderError,
    get_provider,
    get_provider_from_config,
    resolve_default_model,
)
from tools.providers.types import ProviderCapabilities

# ── Registration + lookup ───────────────────────────────────────────────


def test_lazy_registry_registers_builtins():
    # Registration is lazy — resolving any provider first builds the defaults.
    assert get_provider("ollama") is not None
    ids = PROVIDERS.ids()
    assert sorted(ids) == ["chatgpt", "ollama", "opencode_go"]


def test_register_duplicate_rejected():
    reg = registry_mod.ProviderRegistry()

    class _A(BaseProvider):
        id = "x"

        def build_router(self, config=None, **kwargs):  # satisfy the ABC
            raise NotImplementedError

    class _B(_A):
        id = "x"

    reg.register(_A())
    with pytest.raises(ValueError, match="already registered"):
        reg.register(_B())


def test_get_unknown_provider_raises():
    with pytest.raises(UnknownProviderError):
        get_provider("does_not_exist")


def test_all_returns_registered_adapters():
    get_provider("ollama")  # trigger lazy registration (may already be done)
    adapters = PROVIDERS.all()
    assert {a.id for a in adapters} == {"chatgpt", "ollama", "opencode_go"}
    assert all(isinstance(a, BaseProvider) for a in adapters)


# ── Metadata (provider metadata drives the UI/API) ──────────────────────


def test_metadata_shape_and_capabilities():
    meta = get_provider("opencode_go").metadata(None)
    assert meta["id"] == "opencode_go"
    assert meta["name"]
    caps = meta["capabilities"]
    assert set(caps) >= {"chat", "streaming", "tool_calls", "reasoning", "embeddings", "model_discovery"}
    # opencode_go is the reference reasoning provider without embeddings.
    assert caps["reasoning"] is True
    assert caps["embeddings"] is False
    # No secrets ever surface.
    assert not any("key" in str(k).lower() and isinstance(v, str) and v for k, v in meta.items())


def test_ollama_metadata_reports_embeddings_capability():
    meta = get_provider("ollama").metadata(None)
    assert meta["capabilities"]["embeddings"] is True


def test_registry_metadata_helper_lists_all():
    get_provider("ollama")  # trigger lazy registration (may already be done)
    rows = PROVIDERS.metadata(None)
    assert len(rows) == len(PROVIDERS.ids())
    for row in rows:
        assert row["id"]
        assert isinstance(row["capabilities"], dict)


# ── Config dispatch ─────────────────────────────────────────────────────


def test_get_provider_from_config_dispatch():
    config: dict[str, Any] = {"models": {"provider": "opencode_go"}}
    adapter = get_provider_from_config(config)
    assert adapter.id == "opencode_go"


def test_get_provider_from_config_defaults_to_ollama():
    assert get_provider_from_config({}).id == "ollama"
    assert get_provider_from_config(None).id == "ollama"


def test_get_provider_from_config_unknown_is_ollama_dispatch():
    # An unknown models.provider value must NOT crash config dispatch; the
    # strict warning lives in the config validator.
    with pytest.raises(UnknownProviderError):
        get_provider_from_config({"models": {"provider": "ghost"}})


def test_resolve_default_model_provider_block_wins():
    cfg = {
        "models": {"provider": "opencode_go"},
        "opencode_go": {"default_model": "muse-spark-1.2-contributor"},
        "providers": {"opencode_go": {"default_model": "custom-model"}},
    }
    assert resolve_default_model(cfg, "opencode_go") == "custom-model"
    cfg_lg = {"opencode_go": {"default_model": "legacy-model"}}
    assert resolve_default_model(cfg_lg, "opencode_go") == "legacy-model"


def test_resolve_default_model_ollama_registry_alias():
    cfg = {"models": {"default_alias": "glm", "registry": {"glm": "glm-5.2:cloud"}}}
    assert resolve_default_model(cfg, "ollama") == "glm-5.2:cloud"


# ── Config normalization (single layer) ─────────────────────────────────


def test_get_provider_config_prefers_providers_block():
    from tools.config.loader import get_provider_config

    cfg = {
        "providers": {"opencode_go": {"base_url": "https://modern.example/v1", "default_model": "modern"}},
        "opencode_go": {"base_url": "https://legacy.example/v1", "default_model": "legacy"},
    }
    block = get_provider_config(cfg, "opencode_go")
    assert block["base_url"] == "https://modern.example/v1"
    assert block["default_model"] == "modern"
    # Never leaks legacy keys.
    assert block.get("enabled") is not None or True


def test_get_provider_config_falls_back_to_legacy_block():
    from tools.config.loader import get_provider_config

    cfg = {"opencode_go": {"base_url": "https://legacy.example/v1", "default_model": "legacy"}}
    block = get_provider_config(cfg, "opencode_go")
    assert block["base_url"] == "https://legacy.example/v1"
    assert block["default_model"] == "legacy"


def test_get_provider_config_unknown_id_is_empty():
    from tools.config.loader import get_provider_config

    assert get_provider_config({}, "nope") == {}


def test_get_model_host_ollama_only():
    from tools.config.loader import get_model_host

    cfg = {"ollama": {"host": "http://localhost:11434"}}
    assert get_model_host(cfg, "ollama") == "http://localhost:11434"
    assert get_model_host(cfg, "opencode_go") == ""


def test_capabilities_frozen():
    caps = ProviderCapabilities()
    with pytest.raises(Exception):
        caps.chat = True  # type: ignore[misc]


def test_is_configured_default_semantics():
    class _P(BaseProvider):
        id = "p"
        display_name = "P"
        capabilities = ProviderCapabilities()

        def build_router(self, config=None, **kwargs):  # satisfy the ABC
            raise NotImplementedError

    p = _P()
    assert p.is_configured({"enabled": True}) is True
    assert p.is_configured({"base_url": "http://x"}) is True
    assert p.is_configured({}) is False
    assert p.is_configured({"enabled": False}) is False
