"""Provider contract tests — every registered provider must satisfy the same
surface, regardless of backend.

These tests are the enforcement arm of the provider architecture:
* identity + capability metadata is complete and secret-free;
* ``health`` degrades to structured doctor-compatible checks, never raises;
* ``title_model`` resolves without network;
* ``list_models`` fails into the structured ``ProviderDiscoveryError`` (never a
  leaky network error) and ``build_client`` either works locally or raises an
  actionable provider error;
* the canonical BreachPilot model response format helpers produce the
  documented shape;
* a synthetic provider #4 can be implemented + registered + dispatched with
  ZERO edits outside its adapter (the pluggability proof).
"""

from __future__ import annotations

from typing import Any

import pytest

from tools.providers.base import CANONICAL_CHAT_KWARGS, BaseProvider
from tools.providers.registry import PROVIDERS, get_provider, get_provider_from_config
from tools.providers.types import (
    ModelClient,
    ProviderCapabilities,
    ProviderDiscoveryError,
    ProviderError,
    ProviderHealth,
    chat_response,
    stream_chunk,
    stream_tool_chunk,
    tool_call,
    usage_report,
)

BUILTIN_IDS = sorted(["ollama", "opencode_go", "chatgpt"])


def _registered_ids() -> list[str]:
    get_provider("ollama")  # trigger lazy registration
    return sorted(PROVIDERS.ids())


def test_builtins_registered():
    assert _registered_ids() == BUILTIN_IDS


@pytest.mark.parametrize("provider_id", BUILTIN_IDS)
class TestProviderInterfaceContract:
    def test_identity_and_capabilities(self, provider_id: str):
        adapter = get_provider(provider_id)
        assert isinstance(adapter, BaseProvider)
        assert adapter.id == provider_id
        assert adapter.display_name
        assert isinstance(adapter.capabilities, ProviderCapabilities)
        caps = adapter.capabilities.as_dict()
        assert set(caps) >= {"chat", "streaming", "tool_calls", "reasoning", "embeddings", "model_discovery"}
        # Every provider must at least declare chat support.
        assert caps["chat"] is True
        # Ollama is the only one with the embedding endpoint today.
        assert caps["embeddings"] is (provider_id == "ollama")

    def test_metadata_shape_no_secrets(self, provider_id: str):
        adapter = get_provider(provider_id)
        meta = adapter.metadata(None)
        assert meta["id"] == provider_id
        assert meta["name"] == adapter.display_name
        assert isinstance(meta["capabilities"], dict)
        assert isinstance(meta["configured"], bool)
        assert set(meta) >= {"id", "name", "capabilities", "configured", "default_model"}
        # No secret-bearing values leak into metadata.
        for key, value in meta.items():
            if "key" in str(key).lower() or "token" in str(key).lower():
                assert not value, f"metadata surfaced a secret under {key!r}"

    def test_provider_config_returns_mapping(self, provider_id: str):
        assert isinstance(get_provider(provider_id).provider_config({}), dict)

    def test_health_never_raises(self, provider_id: str, monkeypatch: pytest.MonkeyPatch):
        if provider_id == "ollama":
            # Ollama's adapter delegates probes to doctor helpers — keep the
            # contract offline by stubbing them (they are call-time imports).
            monkeypatch.setattr(
                "tools.doctor._check_ollama",
                lambda host: {"name": "ollama", "ok": False, "error": "mocked", "hint": ""},
            )
            monkeypatch.setattr(
                "tools.doctor._check_models",
                lambda host, configured, **kw: {"name": "models", "ok": False, "error": "mocked", "hint": ""},
            )
        health: ProviderHealth = get_provider(provider_id).health({})
        assert isinstance(health, ProviderHealth)
        assert health.checks
        for check in health.checks:
            assert check.get("name")
            assert isinstance(check.get("ok"), bool)
        # Compaction must work for the doctor.
        compact = health.as_check(f"{provider_id}_health")
        assert compact["name"] == f"{provider_id}_health"
        assert isinstance(compact["ok"], bool)

    def test_title_model_resolves_without_network(self, provider_id: str):
        model_id = get_provider(provider_id).title_model(None)
        assert isinstance(model_id, str) and model_id

    def test_list_models_degrades_to_discovery_error(self, provider_id: str, monkeypatch: pytest.MonkeyPatch):
        """With nothing reachable/configured, list_models raises the structured
        ProviderDiscoveryError (carrying a registry-mode fallback) — never a
        bare network error, and it must not spawn infrastructure in a contract
        test (the manager seam is stubbed for chatgpt)."""
        from tools.providers.chatgpt_provider import ChatGptProxyManager

        adapter = get_provider(provider_id)
        if provider_id == "ollama":
            monkeypatch.setattr(
                "tools.providers.ollama_provider.fetch_available_models",
                lambda *a, **k: (_ for _ in ()).throw(ConnectionError("mocked unreachable")),
            )
            config: dict[str, Any] = {"models": {"registry": {"glm": "glm-5.2:cloud"}}}
        elif provider_id == "chatgpt":
            # Unconfigured + not signed in (file check stubbed to False; the
            # manager is never constructed for real, so nothing can spawn).
            monkeypatch.setattr(ChatGptProxyManager, "get", lambda: _UnavailableManager())
            config = {}
        else:  # opencode_go — no key in env, no endpoint reachable
            monkeypatch.delenv("OPENCODE_GO_API_KEY", raising=False)
            config = {}
        with pytest.raises(ProviderDiscoveryError) as excinfo:
            adapter.list_models(config)
        assert excinfo.value.message
        assert isinstance(excinfo.value.fallback_models, list)

    def test_build_client_works_or_raises_actionable(self, provider_id: str, monkeypatch: pytest.MonkeyPatch):
        """build_client either returns a ModelClient using only local
        construction, or raises a clean provider error naming the problem."""
        from tools.providers.chatgpt_provider import ChatGptProxyManager

        adapter = get_provider(provider_id)
        if provider_id == "chatgpt":
            monkeypatch.setattr(ChatGptProxyManager, "get", lambda: _UnavailableManager())
            with pytest.raises(RuntimeError, match="ChatGPT provider unavailable"):
                adapter.build_client({})
            return
        if provider_id == "ollama":
            config: dict[str, Any] = {"ollama": {"host": "http://127.0.0.1:1"}}
        else:
            monkeypatch.delenv("OPENCODE_GO_API_KEY", raising=False)
            config = {}
        client = adapter.build_client(config, adapter.title_model(config))
        assert client.model_id == adapter.title_model(config)
        assert callable(client.chat) and callable(client.stream)


# ── BreachPilot model response format helpers ───────────────────────────


def test_response_format_helpers_shape():
    resp = chat_response(
        "gpt-x",
        "hi",
        thinking="why",
        tool_calls=[tool_call("run_exploit_terminal", {"cmd": "id"}, call_id="c1")],
        usage=usage_report(10, 3),
    )
    assert resp["model"] == "gpt-x"
    assert resp["message"]["role"] == "assistant"
    assert resp["message"]["content"] == "hi"
    assert resp["message"]["thinking"] == "why"
    tc = resp["message"]["tool_calls"][0]
    assert tc["id"] == "c1" and tc["type"] == "function"
    assert tc["function"]["name"] == "run_exploit_terminal"
    assert tc["function"]["arguments"] == '{"cmd": "id"}'
    assert resp["usage"] == {"input_tokens": 10, "output_tokens": 3, "total_tokens": 13}


def test_tool_call_argument_normalization():
    # dict -> JSON string; string passes through; None -> "{}".
    assert tool_call("f", {"a": 1})["function"]["arguments"] == '{"a": 1}'
    assert tool_call("f", '{"a": 1}')["function"]["arguments"] == '{"a": 1}'
    assert tool_call("f", None)["function"]["arguments"] == "{}"


def test_stream_chunk_helpers():
    text = stream_chunk("delta text")
    assert text["message"]["content"] == "delta text"
    assert text["message"]["role"] == "assistant"
    final = stream_tool_chunk([tool_call("f", {})], usage=usage_report(1, 1))
    assert final["message"]["tool_calls"][0]["function"]["name"] == "f"
    assert final["usage"]["total_tokens"] == 2


def test_usage_total_tokens_computed():
    assert usage_report(7, 2)["total_tokens"] == 9


# ── ModelClient contract (provider-neutral) ─────────────────────────────


def _noop_stream(*args: Any, **kwargs: Any) -> Any:
    return iter(())


def test_model_client_defaults():
    mc = ModelClient(name="m", chat=lambda *a, **k: {}, stream=_noop_stream)
    assert mc.model_id == "m"
    assert mc.provider == "ollama"  # documented backcompat default


def test_model_client_provider_neutral_chat_passthrough():
    seen: dict[str, Any] = {}

    def chat(*args: Any, **kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return chat_response("m", "ok")

    mc = ModelClient(name="m", chat=chat, stream=_noop_stream, model_id="m", provider="acme")
    out = mc.chat(messages=[{"role": "user", "content": "x"}], context_window_tokens=123)
    assert out["message"]["content"] == "ok"
    assert seen["context_window_tokens"] == 123  # canonical kwarg reaches the raw client


def test_canonical_chat_kwargs_only_context_window():
    assert CANONICAL_CHAT_KWARGS == ("context_window_tokens",)


def test_provider_error_family_is_shared():
    # All provider-level failures derive from one catchable base so generic
    # code handles "provider said no" without knowing the backend.
    assert issubclass(ProviderDiscoveryError, ProviderError)
    assert issubclass(ProviderError, RuntimeError)


# ── Synthetic provider #4 (pluggability proof) ─────────────────────────


class _AcmeRaw:
    """A minimal raw backend: speaks the BreachPilot response format."""

    def chat(self, **kwargs: Any) -> dict[str, Any]:
        model = str(kwargs.get("model", ""))
        return chat_response(model, "acme")


class _AcmeProvider(BaseProvider):
    """A fourth provider written exactly the way docs/provider-development.md
    describes: implement the adapter, register it, done."""

    id = "acme"
    display_name = "Acme Cloud (test)"

    def build_router(self, config=None, *, request_timeout_seconds=None, provider_config=None):
        from tools.providers.base import make_model_client

        cfg = dict(provider_config) if provider_config is not None else self.provider_config(config)
        model = str(cfg.get("default_model") or "acme-mini")
        client = make_model_client(model, alias=model, raw_client=_AcmeRaw(), provider=self.id)
        router = _AcmeRouter()
        router.register(model, client)
        return router

    def build_client(self, config=None, alias="", *, request_timeout_seconds=None):
        return self.build_router(config, request_timeout_seconds=request_timeout_seconds).get_client(alias)


class _AcmeRouter:
    """Minimal ModelRouter surface (get_client) for the synthetic provider."""

    def __init__(self) -> None:
        self._clients: dict[str, Any] = {}

    def register(self, alias: str, client: Any) -> None:
        self._clients[alias] = client

    def get_client(self, alias: str) -> Any:
        return self._clients[alias]


def test_provider_number_four_plug_in_proof():
    PROVIDERS.register(_AcmeProvider())
    try:
        # 1) registry dispatch knows it
        adapter = get_provider("acme")
        assert adapter.display_name == "Acme Cloud (test)"
        # 2) config dispatch knows it
        assert get_provider_from_config({"models": {"provider": "acme"}}).id == "acme"
        # 3) build_router/build_client need no edits anywhere else
        router = adapter.build_router({"providers": {"acme": {"default_model": "acme-mini"}}})
        out = router.get_client("acme-mini").chat(model="acme-mini", messages=[{"role": "user", "content": "hi"}])
        assert out["message"]["content"] == "acme"
        # 4) metadata surfaces in the registry rows like the built-ins do
        assert "acme" in _registered_ids()
        meta = adapter.metadata({"providers": {"acme": {"default_model": "acme-mini"}}})
        assert meta["id"] == "acme"
        assert meta["default_model"] == "acme-mini"
    finally:
        PROVIDERS._providers.pop("acme", None)


# ── Fake manager used by the chatgpt contract stubs ─────────────────────


class _UnavailableManager:
    """Manager stand-in reporting 'not authenticated' without any lifecycle."""

    def ensure_running(self, cfg: Any) -> dict[str, Any]:
        return {"ok": False, "reason": "not_authenticated"}

    def is_authenticated(self, cfg: Any) -> bool:
        return False
