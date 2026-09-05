"""Alias -> concrete registry resolution (ollama provider)."""

from __future__ import annotations


def test_build_client_resolves_alias_to_concrete():
    from tools.providers.ollama_provider import OllamaProvider

    provider = OllamaProvider()
    config = {"models": {"registry": {"kimi": "kimi-k2.6:cloud"}, "default_alias": "kimi"}}
    client = provider.build_client(config, "kimi")
    assert client.model_id == "kimi-k2.6:cloud"


def test_build_router_no_double_alias():
    from tools.providers.ollama_provider import OllamaProvider

    provider = OllamaProvider()
    config = {
        "models": {
            "registry": {"kimi": "kimi-k2.6:cloud", "glm": "glm-5.2:cloud"},
            "default_alias": "glm",
        }
    }
    router = provider.build_router(config)
    assert router.get_client("kimi").model_id == "kimi-k2.6:cloud"
    assert router.get_client("glm").model_id == "glm-5.2:cloud"
