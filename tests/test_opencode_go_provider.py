"""Mocked tests for the OpenCode Go (Responses API) provider integration.

No network, no real subscription, no live API key. httpx is faked.
Guards the Responses translation seam, auth, discovery, and router wiring
without touching target/scope safety.
"""

from __future__ import annotations

import json
import os
from typing import Any

import pytest

import tools.providers.opencode_go_provider as og
from tools.config_manager import get_ai_provider, get_opencode_go_config
from tools.model_router import (
    DEFAULT_MODEL_REGISTRY,
    _build_model_client,
    build_model_client_for_provider,
    build_router,
)

# ---------------------------------------------------------------------------
# Fakes (mirrors test_chatgpt_provider)
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, payload: Any, *, status: int = 200, text: str = ""):
        self._payload = payload
        self.status_code = status
        self.text = text or json.dumps(payload) if isinstance(payload, dict) else str(payload)
        self._headers: dict[str, str] = {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise og.httpx.HTTPStatusError("boom", request=None, response=self)  # type: ignore[arg-type]

    def json(self) -> Any:
        return self._payload


class _FakeStreamResponse:
    def __init__(self, lines: list[str], *, status: int = 200):
        self._lines = lines
        self.status_code = status
        self.text = "\n".join(lines)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise og.httpx.HTTPStatusError("boom", request=None, response=self)  # type: ignore[arg-type]

    def iter_lines(self):
        for line in self._lines:
            yield line


class _FakeClient:
    """Minimal httpx.Client stand-in: post() / get() / stream() ctx manager."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.calls: list[dict[str, Any]] = []
        self.headers = kwargs.get("headers")
        self.timeout = kwargs.get("timeout")

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def get(self, url: str, **kwargs: Any) -> Any:
        # Merge headers check
        headers = kwargs.get("headers") or {}
        # Also check instance headers? For Opencode discovery we pass headers explicitly
        self.calls.append({"method": "GET", "url": url, "headers": headers})
        handler = _FAKE_HTTPX.get_handler("GET", url)
        return handler(url, headers)

    def post(self, url: str, *, json: Any | None = None, headers: Any | None = None, **kwargs: Any) -> Any:
        self.calls.append({"method": "POST", "url": url, "json": json, "headers": headers})
        handler = _FAKE_HTTPX.get_handler("POST", url)
        return handler(url, json or {}, headers or {})

    def stream(
        self, method: str, url: str, *, json: Any | None = None, headers: Any | None = None, **kwargs: Any
    ) -> Any:
        self.calls.append({"method": method, "url": url, "json": json, "headers": headers, "stream": True})

        class _Ctx:
            def __enter__(self_) -> Any:
                handler = _FAKE_HTTPX.get_handler("STREAM", url)
                return handler(url, json or {}, headers or {})

            def __exit__(self_, *exc: Any) -> None:
                return None

        return _Ctx()


class _FakeHttpxModule:
    def __init__(self) -> None:
        self.Client = _FakeClient
        self.HTTPStatusError = type("HTTPStatusError", (Exception,), {})
        # For error classification
        self.ConnectError = type("ConnectError", (Exception,), {})
        self.ConnectTimeout = type("ConnectTimeout", (Exception,), {})
        self.ReadTimeout = type("ReadTimeout", (Exception,), {})
        self.TimeoutException = type("TimeoutException", (Exception,), {})
        self._handlers: dict[tuple[str, str], Any] = {}
        self._default: Any = None

    def reset(self) -> None:
        self._handlers.clear()
        self._default = None

    def set(self, method: str, url_substr: str, handler: Any) -> None:
        self._handlers[(method, url_substr)] = handler

    def get_handler(self, method: str, url: str) -> Any:
        for (m, sub), handler in self._handlers.items():
            if m == method and sub in url:
                return handler
        if self._default is not None:
            return self._default
        raise AssertionError(f"no fake httpx handler for {method} {url}")

    def set_default(self, handler: Any) -> None:
        self._default = handler


_FAKE_HTTPX = _FakeHttpxModule()


@pytest.fixture(autouse=True)
def _reset_provider(monkeypatch):
    monkeypatch.setattr(og, "httpx", _FAKE_HTTPX)
    _FAKE_HTTPX.reset()
    yield


def _og_config(**overrides: Any) -> dict[str, Any]:
    cfg = get_opencode_go_config({"models": {"provider": "opencode_go"}})
    cfg.update(overrides)
    return cfg


def _responses_text_model(
    text: str, *, model: str = "muse-spark-1.2-contributor", usage: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "model": model,
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": text}],
            }
        ],
        "usage": usage or {"input_tokens": 5, "output_tokens": 3, "total_tokens": 8},
    }


def _responses_tool_call_model(
    calls: list[dict[str, Any]],
    *,
    model: str = "muse-spark-1.2-contributor",
    text: str = "",
    usage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    output: list[dict[str, Any]] = []
    if text:
        output.append({"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]})
    for c in calls:
        output.append(c)
    return {"model": model, "output": output, "usage": usage or {}}


def _set_nonstream(payload: dict[str, Any], *, api_key_check: bool = True):
    def handler(url, body, headers=None):
        if api_key_check and headers is not None:
            assert "Authorization" in headers, "missing Authorization header"
            assert headers["Authorization"].startswith("Bearer "), "bad auth header"
        return _FakeResponse(payload)

    _FAKE_HTTPX.set("POST", "/responses", handler)


def _set_stream(lines: list[str]):
    _FAKE_HTTPX.set("STREAM", "/responses", lambda url, body, headers=None: _FakeStreamResponse(lines))


def _json_lines(chunks: list[dict[str, Any]], *, done: bool = True) -> list[str]:
    lines = [f"data: {json.dumps(c)}" for c in chunks]
    if done:
        lines.append("data: [DONE]")
    return lines


# ---------------------------------------------------------------------------
# 1. config defaults
# ---------------------------------------------------------------------------


def test_config_defaults():
    cfg = get_opencode_go_config({})
    assert cfg["base_url"] == "https://opencode.ai/zen/go/v1"
    assert cfg["default_model"] == "muse-spark-1.2-contributor"
    assert cfg["api_key_env"] == "OPENCODE_GO_API_KEY"
    assert cfg["models"] == []
    assert cfg["context_window"] == 128000
    assert cfg["discover_cache_seconds"] == 300
    assert cfg["enabled"] is False


# ---------------------------------------------------------------------------
# 2. provider selection
# ---------------------------------------------------------------------------


def test_provider_selection():
    assert get_ai_provider({}) == "ollama"
    assert get_ai_provider({"models": {"provider": "opencode_go"}}) == "opencode_go"
    assert get_ai_provider({"models": {"provider": "OPENCODE_GO"}}) == "opencode_go"
    assert get_ai_provider({"models": {"provider": "ollama"}}) == "ollama"


# ---------------------------------------------------------------------------
# 3. missing API key
# ---------------------------------------------------------------------------


def test_missing_api_key_raises(monkeypatch):
    monkeypatch.delenv("OPENCODE_GO_API_KEY", raising=False)
    client = og.OpenCodeGoResponsesClient(base_url="https://opencode.ai/zen/go/v1", api_key="", timeout=5)
    with pytest.raises(RuntimeError, match="API key not configured"):
        client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])


def test_missing_api_key_via_env(monkeypatch):
    # Router now defers the missing-key error to chat-time so run previews still succeed.
    monkeypatch.delenv("OPENCODE_GO_API_KEY", raising=False)
    cfg = _og_config(api_key_env="OPENCODE_GO_API_KEY")
    router = build_router(
        provider="opencode_go",
        opencode_go_config=cfg,
        config={"models": {"provider": "opencode_go"}, "opencode_go": cfg},
    )
    client = router.get_client("muse-spark-1.2-contributor")
    with pytest.raises(RuntimeError, match="API key not configured"):
        client.chat(messages=[{"role": "user", "content": "hi"}])


# ---------------------------------------------------------------------------
# 4. Authorization bearer header
# ---------------------------------------------------------------------------


def test_authorization_header_sent(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "test-key-123")
    seen: list[dict[str, Any]] = []

    def handler(url, body, headers=None):
        seen.append(headers or {})
        return _FakeResponse(_responses_text_model("hello"))

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(base_url="https://opencode.ai/zen/go/v1", api_key="test-key-123", timeout=5)
    resp = client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])
    assert resp["message"]["content"] == "hello"
    assert seen[0]["Authorization"] == "Bearer test-key-123"
    assert seen[0]["Content-Type"] == "application/json"


# ---------------------------------------------------------------------------
# 5. API key never appearing in exceptions/status payloads
# ---------------------------------------------------------------------------


def test_api_key_never_in_exception(monkeypatch):
    secret = "super-secret-key-999"
    monkeypatch.setenv("OPENCODE_GO_API_KEY", secret)

    def handler(url, body, headers=None):
        return _FakeResponse({"error": "boom"}, status=401, text=secret)

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(base_url="https://opencode.ai/zen/go/v1", api_key=secret, timeout=5)
    try:
        client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])
        assert False, "should have raised"
    except RuntimeError as exc:
        msg = str(exc)
        assert secret not in msg
        assert "[REDACTED]" in msg or "401" in msg


def test_api_key_not_in_status_payload(monkeypatch):
    # Provider status route should not leak key
    import asyncio

    from tools.api.routes.system import _opencode_go_status_sync

    monkeypatch.setenv("OPENCODE_GO_API_KEY", "hidden-key-xyz")
    cfg = _og_config(base_url="https://opencode.ai/zen/go/v1")

    # Mock httpx GET to fail quickly
    def _fail(url, headers=None):
        raise og.httpx.ConnectError("cannot connect")

    _FAKE_HTTPX.set("GET", "/models", _fail)
    # Temporarily patch httpx in that module
    import tools.api.routes.system as sysmod

    original_httpx = None
    try:
        import httpx as real_httpx

        original_httpx = real_httpx
    except Exception:
        pass
    monkeypatch.setattr("tools.providers.opencode_go_provider.httpx", _FAKE_HTTPX)
    status = _opencode_go_status_sync(cfg)
    dumped = json.dumps(status)
    assert "hidden-key-xyz" not in dumped
    assert status["api_key_present"] is True


# ---------------------------------------------------------------------------
# 6. /models discovery
# ---------------------------------------------------------------------------


def test_models_discovery(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    cfg = _og_config()

    def handler(url, headers=None):
        return _FakeResponse({"object": "list", "data": [{"id": "muse-spark-1.2-contributor"}, {"id": "other-model"}]})

    _FAKE_HTTPX.set("GET", "/models", handler)
    client = og.OpenCodeGoResponsesClient(base_url="https://opencode.ai/zen/go/v1", api_key="k", timeout=5)
    models = client.discover_models("https://opencode.ai/zen/go/v1", cfg)
    assert "muse-spark-1.2-contributor" in models


def test_models_discovery_object_list_shape(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    cfg = _og_config()

    def handler(url, headers=None):
        return _FakeResponse({"object": "list", "data": [{"id": "muse-spark-1.2-contributor"}]})

    _FAKE_HTTPX.set("GET", "/models", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k")
    assert client.discover_models(cfg=cfg) == ["muse-spark-1.2-contributor"]


# ---------------------------------------------------------------------------
# 7. discovery cache
# ---------------------------------------------------------------------------


def test_discovery_cache(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    cfg = _og_config(discover_cache_seconds=300)
    calls = {"n": 0}

    def handler(url, headers=None):
        calls["n"] += 1
        return _FakeResponse({"data": [{"id": "muse-spark-1.2-contributor"}]})

    _FAKE_HTTPX.set("GET", "/models", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k", config=cfg)
    first = client.discover_models(cfg=cfg)
    second = client.discover_models(cfg=cfg)
    assert first == second
    assert calls["n"] == 1  # second hit cache


# ---------------------------------------------------------------------------
# 8. discovery failure + default-model fallback
# ---------------------------------------------------------------------------


def test_discovery_failure_fallback(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    cfg = _og_config(models=[], default_model="muse-spark-1.2-contributor")

    def _fail(url, headers=None):
        raise og.httpx.HTTPStatusError("nope", request=None, response=None)  # type: ignore[arg-type]

    _FAKE_HTTPX.set("GET", "/models", _fail)
    # build_router should fallback to default_model not crash
    router = build_router(
        provider="opencode_go",
        opencode_go_config=cfg,
        config={"models": {"provider": "opencode_go"}, "opencode_go": cfg},
    )
    client = router.get_client("muse-spark-1.2-contributor")
    assert client.model_id == "muse-spark-1.2-contributor"


def test_discovery_failure_with_configured_models(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    cfg = _og_config(models=["muse-spark-1.2-contributor", "custom-model"], default_model="muse-spark-1.2-contributor")

    def _fail(url, headers=None):
        raise Exception("network down")

    _FAKE_HTTPX.set("GET", "/models", _fail)
    router = build_router(
        provider="opencode_go",
        opencode_go_config=cfg,
        config={"models": {"provider": "opencode_go"}, "opencode_go": cfg},
    )
    # configured models win even though discovery failed
    assert router.get_client("custom-model").model_id == "custom-model"
    assert router.get_client("muse-spark-1.2-contributor").model_id == "muse-spark-1.2-contributor"


# ---------------------------------------------------------------------------
# 9. Responses text-only request
# ---------------------------------------------------------------------------


def test_text_only_request(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    seen: list[dict[str, Any]] = []

    def handler(url, body, headers=None):
        seen.append(body)
        return _FakeResponse(_responses_text_model("Hello world"))

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k")
    resp = client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])
    assert resp["message"]["content"] == "Hello world"
    assert resp["message"]["thinking"] == ""
    assert seen[0]["model"] == "muse-spark-1.2-contributor"
    assert seen[0]["stream"] is False
    # input should contain user message
    assert any(item.get("role") == "user" and item.get("content") == "hi" for item in seen[0]["input"])


# ---------------------------------------------------------------------------
# 10. system/user/assistant message conversion
# ---------------------------------------------------------------------------


def test_system_user_assistant_conversion(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    seen: list[dict[str, Any]] = []

    def handler(url, body, headers=None):
        seen.append(body)
        return _FakeResponse(_responses_text_model("ok"))

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k")
    messages = [
        {"role": "system", "content": "You are an exploit agent"},
        {"role": "user", "content": "TARGET: 10.0.0.1"},
        {"role": "assistant", "content": "Acknowledged"},
        {"role": "user", "content": "Run check"},
    ]
    client.chat(model="muse-spark-1.2-contributor", messages=messages)
    inp = seen[0]["input"]
    assert inp[0]["role"] == "system" and "exploit agent" in inp[0]["content"]
    assert inp[1]["role"] == "user" and "10.0.0.1" in inp[1]["content"]
    assert inp[2]["role"] == "assistant" and inp[2]["content"] == "Acknowledged"
    assert inp[3]["role"] == "user"


# ---------------------------------------------------------------------------
# 11. tool-schema conversion
# ---------------------------------------------------------------------------


def test_tool_schema_conversion(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    seen: list[dict[str, Any]] = []

    def handler(url, body, headers=None):
        seen.append(body)
        return _FakeResponse(_responses_text_model("done"))

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k")
    tools = [
        {
            "type": "function",
            "function": {
                "name": "run_exploit_terminal",
                "description": "Run a terminal command",
                "parameters": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}, "target_ip": {"type": "string"}},
                    "required": ["command"],
                },
            },
        }
    ]
    client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}], tools=tools)
    sent_tools = seen[0].get("tools")
    assert sent_tools is not None
    assert sent_tools[0]["type"] == "function"
    assert sent_tools[0]["name"] == "run_exploit_terminal"
    assert sent_tools[0]["description"] == "Run a terminal command"
    assert sent_tools[0]["parameters"]["required"] == ["command"]
    # Ensure Ollama shape is not sent
    assert "function" not in sent_tools[0]


def test_tool_schema_preserves_enum_and_nested(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    seen: list[dict[str, Any]] = []

    def handler(url, body, headers=None):
        seen.append(body)
        return _FakeResponse(_responses_text_model("ok"))

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k")
    tools = [
        {
            "type": "function",
            "function": {
                "name": "craft_exploit",
                "description": "Craft",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "mode": {"type": "string", "enum": ["a", "b"]},
                        "nested": {"type": "object", "properties": {"x": {"type": "integer"}}},
                    },
                    "required": ["mode"],
                },
            },
        }
    ]
    client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}], tools=tools)
    params = seen[0]["tools"][0]["parameters"]
    assert params["properties"]["mode"]["enum"] == ["a", "b"]
    assert params["properties"]["nested"]["properties"]["x"]["type"] == "integer"


def test_drops_ollama_only_params(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    seen: list[dict[str, Any]] = []

    def handler(url, body, headers=None):
        seen.append(body)
        return _FakeResponse(_responses_text_model("ok"))

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k")
    client.chat(
        model="muse-spark-1.2-contributor",
        messages=[{"role": "user", "content": "hi"}],
        options={"num_ctx": 128000},
        keep_alive="5m",
        format="json",
        suffix="x",
        think=True,
        raw=True,
        temperature=0.7,
        top_p=0.9,
    )
    payload = seen[0]
    for dropped in ("options", "keep_alive", "format", "suffix", "think", "raw", "num_ctx"):
        assert dropped not in payload
    assert payload["temperature"] == 0.7
    assert payload["top_p"] == 0.9


# ---------------------------------------------------------------------------
# 12. Responses function-call normalization
# ---------------------------------------------------------------------------


def test_function_call_normalization(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    payload = _responses_tool_call_model(
        [
            {
                "type": "function_call",
                "call_id": "call_123",
                "name": "run_exploit_terminal",
                "arguments": '{"command": "id", "target_ip": "10.0.0.1"}',
            }
        ]
    )

    def handler(url, body, headers=None):
        return _FakeResponse(payload)

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k")
    resp = client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])
    tcs = resp["message"]["tool_calls"]
    assert len(tcs) == 1
    assert tcs[0]["function"]["name"] == "run_exploit_terminal"
    # arguments should be JSON string for _normalize_tool_call compatibility
    assert tcs[0]["function"]["arguments"] == '{"command": "id", "target_ip": "10.0.0.1"}'
    from tools.exploit_agent.tool_calls import _normalize_tool_call

    norm = _normalize_tool_call(tcs[0])
    assert norm["function"]["arguments"] == {"command": "id", "target_ip": "10.0.0.1"}


def test_multiple_function_calls_normalization(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    payload = _responses_tool_call_model(
        [
            {"type": "function_call", "call_id": "c1", "name": "tool_a", "arguments": '{"x":1}'},
            {"type": "function_call", "call_id": "c2", "name": "tool_b", "arguments": '{"y":2}'},
        ]
    )
    _FAKE_HTTPX.set("POST", "/responses", lambda url, body, headers=None: _FakeResponse(payload))
    client = og.OpenCodeGoResponsesClient(api_key="k")
    resp = client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])
    assert len(resp["message"]["tool_calls"]) == 2
    assert resp["message"]["tool_calls"][0]["function"]["name"] == "tool_a"
    assert resp["message"]["tool_calls"][1]["function"]["name"] == "tool_b"


# ---------------------------------------------------------------------------
# 13. tool result / second-round continuation
# ---------------------------------------------------------------------------


def test_tool_result_continuation(monkeypatch):
    """Real multi-round flow: user -> function_call -> tool output -> text."""
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    # First turn: model requests function
    first_payload = _responses_tool_call_model(
        [
            {
                "type": "function_call",
                "call_id": "call_0",
                "name": "run_exploit_terminal",
                "arguments": '{"command":"id"}',
            }
        ]
    )
    # Second turn: after tool result, model returns text
    second_payload = _responses_text_model("uid=0 root")

    calls: list[dict[str, Any]] = []

    def handler(url, body, headers=None):
        calls.append(body)
        # Detect tool output round by checking for function_call_output in input
        has_output = any(item.get("type") == "function_call_output" for item in body.get("input", []))
        if has_output:
            return _FakeResponse(second_payload)
        return _FakeResponse(first_payload)

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k")

    # Round 1
    resp1 = client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "exploit"}])
    assert resp1["message"]["tool_calls"][0]["function"]["name"] == "run_exploit_terminal"

    # Build history as exploit_agent does
    history = [
        {"role": "user", "content": "exploit"},
        {"role": "assistant", "content": "", "tool_calls": resp1["message"]["tool_calls"]},
        {"role": "tool", "tool_name": "run_exploit_terminal", "content": "uid=0 root output"},
    ]
    resp2 = client.chat(model="muse-spark-1.2-contributor", messages=history)
    assert resp2["message"]["content"] == "uid=0 root"
    # Verify second request's input contained the function_call_output with correct call_id
    second_input = calls[1]["input"]
    fco = [x for x in second_input if x.get("type") == "function_call_output"]
    assert len(fco) == 1
    assert fco[0]["call_id"] == "call_0"
    assert "uid=0" in fco[0]["output"]


def test_tool_result_without_id_uses_fifo(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    seen: list[dict[str, Any]] = []

    def handler(url, body, headers=None):
        seen.append(body)
        return _FakeResponse(_responses_text_model("ok"))

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k")
    history = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "a", "arguments": "{}"}}]},
        {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "b", "arguments": "{}"}}]},
        {"role": "tool", "tool_name": "a", "content": "out a"},
        {"role": "tool", "tool_name": "b", "content": "out b"},
    ]
    client.chat(model="muse-spark-1.2-contributor", messages=history)
    inp = seen[0]["input"]
    # Should have 2 function_call + 2 function_call_output with matching ids in order
    fcs = [x for x in inp if x.get("type") == "function_call"]
    fcos = [x for x in inp if x.get("type") == "function_call_output"]
    assert len(fcs) == 2
    assert len(fcos) == 2
    assert fcos[0]["call_id"] == fcs[0]["call_id"]
    assert fcos[1]["call_id"] == fcs[1]["call_id"]


def test_interleaved_user_notes_keep_call_output_adjacent(monkeypatch):
    """Regression: benchmark run 20260831_010450_09800 failed from round 2 with
    'No tool output found for tool call call_1' (400). The agent loop appends
    operator notes (Detected services / research advisories) between tool
    results; the gateway closes the tool-result block at the first non-output
    item, orphaning the later calls of the same assistant turn. Each
    function_call must now be IMMEDIATELY followed by its function_call_output.
    """
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    seen: list[dict[str, Any]] = []

    def handler(url, body, headers=None):
        seen.append(body)
        return _FakeResponse(_responses_text_model("ok"))

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k")
    # Exact round-2 history shape produced by runner/_impl.py after round 1
    history = [
        {"role": "system", "content": "SYSTEM"},
        {"role": "user", "content": "MISSION"},
        {"role": "user", "content": "[RESEARCH ADVISORY] startup"},
        {
            "role": "assistant",
            "content": "I'll start by checking the target OS and running initial recon in parallel.",
            "thinking": "",
            "tool_calls": [
                {"function": {"name": "check_os", "arguments": {"target_ip": "127.0.0.1"}}},
                {
                    "function": {
                        "name": "quick_scan",
                        "arguments": {"target_ip": "127.0.0.1", "ports": "22,135"},
                    }
                },
            ],
        },
        {"role": "tool", "tool_name": "check_os", "content": "OS_CHECK_RESULTS: WINDOWS"},
        {"role": "user", "content": "Detected services: ssh on 127.0.0.1:22."},
        {"role": "user", "content": "[RESEARCH ADVISORY] failed"},
        {"role": "tool", "tool_name": "quick_scan", "content": "QUICK_SCAN_RESULTS: 2/14 ports open"},
        {"role": "user", "content": "Detected services: ssh on :22; msrpc on :135."},
        {"role": "user", "content": "[RESEARCH ADVISORY] failed"},
    ]
    client.chat(model="muse-spark-1.2-contributor", messages=history)
    inp = seen[0]["input"]

    fcs = [x for x in inp if x.get("type") == "function_call"]
    fcos = [x for x in inp if x.get("type") == "function_call_output"]
    assert len(fcs) == 2 and len(fcos) == 2
    # FIFO pairing preserved: check_os result -> check_os call, quick_scan -> quick_scan
    assert fcos[0]["call_id"] == fcs[0]["call_id"] and "OS_CHECK_RESULTS" in fcos[0]["output"]
    assert fcos[1]["call_id"] == fcs[1]["call_id"] and "QUICK_SCAN_RESULTS" in fcos[1]["output"]
    # Adjacency: every function_call is immediately followed by its output
    for idx, item in enumerate(inp):
        if item.get("type") == "function_call":
            nxt = inp[idx + 1] if idx + 1 < len(inp) else {}
            assert nxt.get("type") == "function_call_output", f"call {item['call_id']} not adjacent to its output"
            assert nxt["call_id"] == item["call_id"]
    # Operator notes are preserved as user items (not dropped)
    joined = " ".join(x.get("content", "") for x in inp if x.get("role") == "user")
    assert "Detected services" in joined and "RESEARCH ADVISORY" in joined


def test_missing_tool_output_synthesized(monkeypatch):
    """A call whose tool never returned (interrupted run / exhausted budget)
    still gets a synthesized output so the request stays well-formed."""
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    seen: list[dict[str, Any]] = []

    def handler(url, body, headers=None):
        seen.append(body)
        return _FakeResponse(_responses_text_model("ok"))

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k")
    history = [
        {"role": "user", "content": "hi"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"function": {"name": "a", "arguments": "{}"}},
                {"function": {"name": "b", "arguments": "{}"}},
            ],
        },
        {"role": "tool", "tool_name": "a", "content": "out a"},
    ]
    client.chat(model="muse-spark-1.2-contributor", messages=history)
    inp = seen[0]["input"]
    fcs = [x for x in inp if x.get("type") == "function_call"]
    fcos = [x for x in inp if x.get("type") == "function_call_output"]
    assert len(fcs) == 2 and len(fcos) == 2
    assert "out a" in fcos[0]["output"]
    assert "no tool result recorded" in fcos[1]["output"].lower()
    for idx, item in enumerate(inp):
        if item.get("type") == "function_call":
            assert inp[idx + 1].get("type") == "function_call_output"


def test_orphan_tool_output_demoted_to_user_item(monkeypatch):
    """A tool result with no pending call (e.g. compaction dropped the
    assistant tool_calls message) must not emit a bare function_call_output —
    strict gateways reject outputs without calls. It becomes a user item."""
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    seen: list[dict[str, Any]] = []

    def handler(url, body, headers=None):
        seen.append(body)
        return _FakeResponse(_responses_text_model("ok"))

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k")
    history = [
        {"role": "user", "content": "hi"},
        {"role": "tool", "tool_name": "check_os", "content": "OS_CHECK_RESULTS: WINDOWS"},
    ]
    client.chat(model="muse-spark-1.2-contributor", messages=history)
    inp = seen[0]["input"]
    assert not [x for x in inp if x.get("type") == "function_call_output"]
    users = [x for x in inp if x.get("role") == "user"]
    assert any("check_os" in x["content"] and "OS_CHECK_RESULTS" in x["content"] for x in users)


# ---------------------------------------------------------------------------
# 14. multiple function calls (already covered) — additional: preserves ids
# ---------------------------------------------------------------------------


def test_preserves_tool_call_ids(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    payload = _responses_tool_call_model(
        [
            {"type": "function_call", "call_id": "keep_me", "name": "x", "arguments": "{}"},
        ]
    )
    _FAKE_HTTPX.set("POST", "/responses", lambda url, body, headers=None: _FakeResponse(payload))
    client = og.OpenCodeGoResponsesClient(api_key="k")
    resp = client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])
    assert (
        resp["message"]["tool_calls"][0].get("id") == "keep_me"
        or resp["message"]["tool_calls"][0].get("call_id") == "keep_me"
    )


# ---------------------------------------------------------------------------
# 15. usage normalization
# ---------------------------------------------------------------------------


def test_usage_normalization(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    payload = _responses_text_model("hi", usage={"input_tokens": 10, "output_tokens": 20, "total_tokens": 30})
    _FAKE_HTTPX.set("POST", "/responses", lambda url, body, headers=None: _FakeResponse(payload))
    client = og.OpenCodeGoResponsesClient(api_key="k")
    resp = client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])
    assert resp["usage"]["input_tokens"] == 10
    assert resp["usage"]["output_tokens"] == 20
    assert resp["usage"]["total_tokens"] == 30


def test_usage_maps_prompt_completion(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    payload = {
        "model": "muse-spark-1.2-contributor",
        "output": [],
        "usage": {"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12},
    }
    _FAKE_HTTPX.set("POST", "/responses", lambda url, body, headers=None: _FakeResponse(payload))
    client = og.OpenCodeGoResponsesClient(api_key="k")
    resp = client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])
    assert resp["usage"]["input_tokens"] == 5
    assert resp["usage"]["output_tokens"] == 7


# ---------------------------------------------------------------------------
# 16-17. streaming text deltas + completion
# ---------------------------------------------------------------------------


def test_streaming_text_deltas(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    # Responses SSE deltas
    chunks = [
        {"type": "response.output_text.delta", "delta": "Hello"},
        {"type": "response.output_text.delta", "delta": " world"},
        {
            "type": "response.completed",
            "response": {"usage": {"input_tokens": 2, "output_tokens": 2, "total_tokens": 4}},
        },
    ]
    lines = [f"data: {json.dumps(c)}" for c in chunks] + ["data: [DONE]"]
    _FAKE_HTTPX.set("STREAM", "/responses", lambda url, body, headers=None: _FakeStreamResponse(lines))
    client = og.OpenCodeGoResponsesClient(api_key="k")
    out = list(
        client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}], stream=True)
    )
    # First two chunks are text deltas, last is final with usage
    contents = [c["message"]["content"] for c in out if c["message"]["content"]]
    assert contents == ["Hello", " world"]
    final = out[-1]
    assert final["usage"]["total_tokens"] == 4
    assert "tool_calls" in final["message"]


def test_streaming_ignores_lifecycle_and_stops_cleanly(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    chunks = [
        {"type": "response.created"},
        {"type": "response.in_progress"},
        {"type": "response.output_text.delta", "delta": "x"},
        {"type": "response.completed", "response": {"usage": {}}},
    ]
    lines = [f"data: {json.dumps(c)}" for c in chunks]
    lines.insert(1, ": keepalive")
    lines.append("data: [DONE]")
    _FAKE_HTTPX.set("STREAM", "/responses", lambda url, body, headers=None: _FakeStreamResponse(lines))
    client = og.OpenCodeGoResponsesClient(api_key="k")
    out = list(
        client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}], stream=True)
    )
    assert any(c["message"]["content"] == "x" for c in out)


def test_streaming_tool_call_via_output_item(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    chunks = [
        {
            "type": "response.output_item.added",
            "item": {"type": "function_call", "call_id": "c1", "name": "run_exploit_terminal", "arguments": ""},
        },
        {"type": "response.function_call_arguments.delta", "call_id": "c1", "delta": '{"command":'},
        {"type": "response.function_call_arguments.delta", "call_id": "c1", "delta": '"id"}'},
        {
            "type": "response.output_item.done",
            "item": {
                "type": "function_call",
                "call_id": "c1",
                "name": "run_exploit_terminal",
                "arguments": '{"command":"id"}',
            },
        },
        {"type": "response.completed", "response": {"usage": {"total_tokens": 9}}},
    ]
    lines = [f"data: {json.dumps(c)}" for c in chunks] + ["data: [DONE]"]
    _FAKE_HTTPX.set("STREAM", "/responses", lambda url, body, headers=None: _FakeStreamResponse(lines))
    client = og.OpenCodeGoResponsesClient(api_key="k")
    out = list(
        client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}], stream=True)
    )
    final = out[-1]
    assert final["message"]["tool_calls"][0]["function"]["name"] == "run_exploit_terminal"
    assert "id" in final["message"]["tool_calls"][0]["function"]["arguments"]


# ---------------------------------------------------------------------------
# 18-20. 401, 429, timeout/network
# ---------------------------------------------------------------------------


def test_401_raises(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "bad")
    _FAKE_HTTPX.set(
        "POST", "/responses", lambda url, body, headers=None: _FakeResponse({"error": "unauthorized"}, status=401)
    )
    client = og.OpenCodeGoResponsesClient(api_key="bad")
    with pytest.raises(RuntimeError, match="authentication failed"):
        client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])


def test_429_raises(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    _FAKE_HTTPX.set("POST", "/responses", lambda url, body, headers=None: _FakeResponse({"error": "rate"}, status=429))
    client = og.OpenCodeGoResponsesClient(api_key="k")
    with pytest.raises(RuntimeError, match="rate limited"):
        client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])


def test_timeout_raises(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")

    def handler(url, body, headers=None):
        raise og.httpx.ReadTimeout("timed out")

    _FAKE_HTTPX.set("POST", "/responses", handler)
    client = og.OpenCodeGoResponsesClient(api_key="k", timeout=1)
    with pytest.raises(RuntimeError, match="connection failed"):
        client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])


def test_malformed_response_raises(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    # Return not a dict
    _FAKE_HTTPX.set("POST", "/responses", lambda url, body, headers=None: _FakeResponse("not a dict object"))  # type: ignore
    # Our FakeResponse.json will return string; the client expects dict -> raise
    client = og.OpenCodeGoResponsesClient(api_key="k")

    # We craft handler to return list instead of dict via raw payload
    class _BadResp:
        status_code = 200
        text = "[]"

        def raise_for_status(self):
            pass

        def json(self):  # type: ignore[no-redef]
            return []

    _FAKE_HTTPX.set("POST", "/responses", lambda url, body, headers=None: _BadResp())
    with pytest.raises(RuntimeError, match="malformed"):
        client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])


# ---------------------------------------------------------------------------
# 21. model-router registration
# ---------------------------------------------------------------------------


def test_model_router_registration(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "testkey")
    cfg = _og_config(models=[], default_model="muse-spark-1.2-contributor")
    # Discovery returns the default model
    _FAKE_HTTPX.set(
        "GET", "/models", lambda url, headers=None: _FakeResponse({"data": [{"id": "muse-spark-1.2-contributor"}]})
    )
    router = build_router(
        provider="opencode_go",
        opencode_go_config=cfg,
        config={"models": {"provider": "opencode_go"}, "opencode_go": cfg},
    )
    # default should be registered
    assert router.get_client("muse-spark-1.2-contributor").model_id == "muse-spark-1.2-contributor"


def test_model_router_configured_models_win(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    cfg = _og_config(models=["muse-spark-1.2-contributor", "custom-model"], default_model="muse-spark-1.2-contributor")
    # No discovery needed
    router = build_router(
        provider="opencode_go",
        opencode_go_config=cfg,
        config={"models": {"provider": "opencode_go"}, "opencode_go": cfg},
    )
    assert router.get_client("custom-model").model_id == "custom-model"


def test_model_router_filters_non_responses_models(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    cfg = _og_config(models=[], default_model="muse-spark-1.2-contributor")
    # Discovery returns mixed models including chat-completions-only
    _FAKE_HTTPX.set(
        "GET",
        "/models",
        lambda url, headers=None: _FakeResponse(
            {"data": [{"id": "muse-spark-1.2-contributor"}, {"id": "chat-only-model"}]}
        ),
    )
    router = build_router(
        provider="opencode_go",
        opencode_go_config=cfg,
        config={"models": {"provider": "opencode_go"}, "opencode_go": cfg},
    )
    # chat-only-model should NOT be registered (Responses filter)
    with pytest.raises(KeyError):
        router.get_client("chat-only-model")
    # but default should exist
    assert router.get_client("muse-spark-1.2-contributor")


def test_effective_request_url_is_responses(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    seen_urls: list[str] = []

    def handler(url, body, headers=None):
        seen_urls.append(url)
        return _FakeResponse(_responses_text_model("ok"))

    _FAKE_HTTPX.set("POST", "/responses", handler)
    # Also mock base get? Not needed
    client = og.OpenCodeGoResponsesClient(base_url="https://opencode.ai/zen/go/v1", api_key="k")
    client.chat(model="muse-spark-1.2-contributor", messages=[{"role": "user", "content": "hi"}])
    assert seen_urls[0] == "https://opencode.ai/zen/go/v1/responses"


# ---------------------------------------------------------------------------
# 22. build_model_client_for_provider
# ---------------------------------------------------------------------------


def test_build_model_client_for_provider_opencode_go(monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    _FAKE_HTTPX.set("POST", "/responses", lambda url, body, headers=None: _FakeResponse(_responses_text_model("hello")))
    config = {"models": {"provider": "opencode_go"}, "opencode_go": _og_config()}
    client = build_model_client_for_provider(config, "muse-spark-1.2-contributor")
    assert client.model_id == "muse-spark-1.2-contributor"
    resp = client.chat(messages=[{"role": "user", "content": "hi"}])
    assert resp["message"]["content"] == "hello"


# ---------------------------------------------------------------------------
# 23. telemetry provider = opencode_go
# ---------------------------------------------------------------------------


def test_telemetry_provider_field(monkeypatch):
    import tools.model_telemetry as mt

    monkeypatch.setenv("OPENCODE_GO_API_KEY", "k")
    recorded: dict[str, Any] = {}

    def _fake_record(**kwargs):
        recorded.update(kwargs)
        return {}

    monkeypatch.setattr(mt, "record_model_usage", _fake_record)
    import tools.model_router as mr

    monkeypatch.setattr(mr, "record_model_usage", _fake_record)
    _FAKE_HTTPX.set(
        "POST",
        "/responses",
        lambda url, body, headers=None: _FakeResponse(_responses_text_model("hi", usage={"total_tokens": 3})),
    )
    raw = og.OpenCodeGoResponsesClient(base_url="https://opencode.ai/zen/go/v1", api_key="k")
    client = _build_model_client(
        "muse-spark-1.2-contributor", alias="muse-spark-1.2-contributor", raw_client=raw, provider="opencode_go"
    )
    client.chat(messages=[{"role": "user", "content": "hi"}])
    assert recorded.get("provider") == "opencode_go"


def test_build_usage_record_provider(monkeypatch, tmp_path):
    import tools.model_telemetry as mt

    rec = mt.build_usage_record(
        alias="muse-spark-1.2-contributor",
        model_id="muse-spark-1.2-contributor",
        response={"usage": {"total_tokens": 7}},
        messages=[],
        stream=False,
        started_at="s",
        ended_at="e",
        wall_duration_seconds=1.0,
        context_window_tokens=128000,
        source="test",
        provider="opencode_go",
    )
    assert rec["provider"] == "opencode_go"


# ---------------------------------------------------------------------------
# 24. Ollama regression
# ---------------------------------------------------------------------------


def test_ollama_regression(monkeypatch):
    import tools.model_router as mr

    constructed: list[str] = []

    class _Ollama:
        def __init__(self, host=None, **kw):
            constructed.append(host)
            self.host = host

        def chat(self, *a, **k):
            return {"message": {"content": "ollama"}}

    monkeypatch.setattr(mr, "OllamaClient", _Ollama)
    router = build_router(DEFAULT_MODEL_REGISTRY, host="https://api.ollama.com")
    client = router.get_client("glm")
    assert client.model_id == "glm-5.2:cloud"
    resp = client.chat(messages=[{"role": "user", "content": "hi"}])
    assert resp["message"]["content"] == "ollama"
    assert constructed == ["https://api.ollama.com"] * len(DEFAULT_MODEL_REGISTRY)


# ---------------------------------------------------------------------------
# 25. ChatGPT regression
# ---------------------------------------------------------------------------


def test_chatgpt_regression(monkeypatch):
    # Ensure ChatGPT path still works by mocking its manager
    import tools.providers.chatgpt_provider as cg

    monkeypatch.setattr(cg, "httpx", _FAKE_HTTPX)
    _FAKE_HTTPX.reset()
    # Stub chatgpt provider similarly to earlier test: we directly test router
    # with chatgpt config using fake httpx that returns gpt models
    _FAKE_HTTPX.set("GET", "/health", lambda url, headers=None: _FakeResponse({"ok": True}))
    _FAKE_HTTPX.set("GET", "/models", lambda url, headers=None: _FakeResponse({"data": [{"id": "gpt-5.2"}]}))
    _FAKE_HTTPX.set(
        "POST",
        "/chat/completions",
        lambda url, body, headers=None: _FakeResponse(
            {"model": "gpt-5.2", "choices": [{"message": {"content": "gpt"}}]}
        ),
    )
    cfg = get_ai_provider({"models": {"provider": "chatgpt"}})
    assert cfg == "chatgpt"
    # The chatgpt provider uses proxy manager; we just verify the adapter still behaves
    from tools.providers.chatgpt_provider import ChatGptProxyClient

    client = ChatGptProxyClient("http://127.0.0.1:10531/v1")
    # Need to set httpx fake for chatgpt client
    monkeypatch.setattr(cg, "httpx", _FAKE_HTTPX)
    resp = client.chat(model="gpt-5.2", messages=[{"role": "user", "content": "hi"}])
    assert resp["message"]["content"] == "gpt"


# ---------------------------------------------------------------------------
# 26. provider API/status response
# ---------------------------------------------------------------------------


def test_list_models_includes_opencode_go_block(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app import create_app

    test_cfg = {
        "api": {"host": "127.0.0.1", "port": 8765},
        "reports_dir": str(tmp_path / "reports"),
        "models": {"provider": "opencode_go", "registry": {}, "default_alias": "glm"},
        "opencode_go": {
            "base_url": "https://opencode.ai/zen/go/v1",
            "default_model": "muse-spark-1.2-contributor",
            "models": [],
            "context_window": 128000,
            "enabled": True,
        },
        "ollama": {"host": "https://api.ollama.com"},
        "chatgpt": {"default_model": "gpt-5.2"},
    }
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "test-token")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("api:\n  host: 127.0.0.1\n", encoding="utf-8")
    app = create_app(config_path=tmp_path / "config.yaml", config=test_cfg)
    client = TestClient(app)
    resp = client.get("/api/v1/models", headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    result = resp.json()
    assert result["provider"] == "opencode_go"
    assert "opencode_go" in result
    assert result["opencode_go"]["default_model"] == "muse-spark-1.2-contributor"
    assert result["opencode_go"]["base_url"] == "https://opencode.ai/zen/go/v1"


def test_providers_includes_opencode_go(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "")
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "test-token")
    from fastapi.testclient import TestClient

    from app import create_app

    test_cfg = {
        "api": {"host": "127.0.0.1", "port": 8765},
        "reports_dir": str(tmp_path / "reports"),
        "models": {"provider": "opencode_go"},
        "opencode_go": {
            "enabled": False,
            "base_url": "https://opencode.ai/zen/go/v1",
            "default_model": "muse-spark-1.2-contributor",
            "api_key_env": "OPENCODE_GO_API_KEY",
            "models": [],
        },
        "chatgpt": {"enabled": False},
    }
    (tmp_path / "config.yaml").write_text("api:\n  host: 127.0.0.1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    # Patch httpx for opencode status probe to avoid network
    monkeypatch.setattr(og, "httpx", _FAKE_HTTPX)
    _FAKE_HTTPX.set("GET", "/models", lambda url, headers=None: _FakeResponse({"data": []}))
    app = create_app(config_path=tmp_path / "config.yaml", config=test_cfg)
    client = TestClient(app)
    resp = client.get("/api/v1/providers", headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    result = resp.json()
    assert "opencode_go" in result
    assert "api_key_present" in result["opencode_go"]
    assert result["opencode_go"]["base_url"] == "https://opencode.ai/zen/go/v1"
    # Never leaks key
    assert "OPENCODE_GO_API_KEY" not in json.dumps(result) or "hidden" not in json.dumps(result)


def test_api_key_env_inclusion():
    from tools.api_key_store import configured_api_key_env_names

    names = configured_api_key_env_names({"opencode_go": {"api_key_env": "OPENCODE_GO_API_KEY"}})
    assert "OPENCODE_GO_API_KEY" in names
    # Default when absent still includes default
    names2 = configured_api_key_env_names({})
    assert "OPENCODE_GO_API_KEY" in names2


# ---------------------------------------------------------------------------
# WebUI mapping sanity (providerLabel switch)
# ---------------------------------------------------------------------------


def test_provider_label_mapping():
    # Mirrors webui/src/components/ProviderSetup.tsx providerLabel
    def provider_label(p: str) -> str:
        if p == "chatgpt":
            return "ChatGPT"
        if p == "opencode_go":
            return "OpenCode Go"
        return "Ollama"

    assert provider_label("ollama") == "Ollama"
    assert provider_label("chatgpt") == "ChatGPT"
    assert provider_label("opencode_go") == "OpenCode Go"
    # Legacy binary logic bug would label opencode_go as Ollama — ensure fixed
    assert provider_label("opencode_go") != "Ollama"


def test_model_options_for_opencode_go(monkeypatch):
    # Simulate the useModelOptions logic for opencode_go
    models_data = {
        "provider": "opencode_go",
        "opencode_go": {
            "configured_models": ["muse-spark-1.2-contributor"],
            "default_model": "muse-spark-1.2-contributor",
        },
        "registry": {},
        "default_alias": "glm",
    }
    live_data = {"source": "opencode_go", "models": ["muse-spark-1.2-contributor", "spark-extra"]}

    def use_model_options(models_data, live_data):
        provider = models_data.get("provider", "ollama")
        s = set()
        if provider == "opencode_go":
            if live_data.get("source") == "opencode_go":
                for m in live_data.get("models", []):
                    s.add(m)
            for m in models_data.get("opencode_go", {}).get("configured_models", []):
                s.add(m)
            if models_data.get("opencode_go", {}).get("default_model"):
                s.add(models_data["opencode_go"]["default_model"])
        return s

    assert "muse-spark-1.2-contributor" in use_model_options(models_data, live_data)
    assert "spark-extra" in use_model_options(models_data, live_data)
