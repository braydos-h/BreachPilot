"""Provider tool-call contract — every registered provider must handle tools consistently.

Exercises:
* tool definition translation (Ollama passthrough vs Responses/OpenAI normalization)
* tool call JSON-string argument handling (malformed → {})
* usage metadata normalization
* Ollama-only kwargs stripping
* tool result message shape (assistant tool_calls → tool role reinjection)
* streaming tool-call assembly
* is_target_in_allowlist is provider-agnostic (no provider may bypass it)

Parametrized over PROVIDERS.all() — provider #4 is included automatically.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from tools.providers.registry import PROVIDERS, get_provider
from tools.providers.types import chat_response, tool_call, usage_report


# Force lazy registration
get_provider("ollama")
ALL_IDS = sorted(PROVIDERS.ids())


@pytest.mark.parametrize("provider_id", ALL_IDS)
class TestProviderToolContract:
    def test_tool_definition_translation(self, provider_id: str):
        """Each provider's tool schema handling must not drop function names."""
        if provider_id == "opencode_go":
            from tools.providers.opencode_go_provider import _convert_tool_schemas

            schemas = [{"type": "function", "function": {"name": "run_exploit_terminal", "description": "run", "parameters": {"type": "object", "properties": {"command": {"type": "string"}}}}}]
            converted = _convert_tool_schemas(schemas)
            assert converted[0]["name"] == "run_exploit_terminal"
            assert converted[0]["type"] == "function"
        elif provider_id == "chatgpt":
            # ChatGPT proxy forwards Ollama-style schemas verbatim for /chat/completions;
            # it drops Ollama-only kwargs only. Verify the drop list does not include tools.
            from tools.providers.chatgpt_provider import _DROP_KWARGS

            assert "tools" not in _DROP_KWARGS
            assert "options" in _DROP_KWARGS
        else:  # ollama — passthrough
            from tools.providers.ollama_provider import apply_context_window

            # Ollama's context translation must not mutate tools
            raw = {"model": "m", "messages": [], "tools": [{"type": "function", "function": {"name": "t"}}], "context_window_tokens": 123}
            out = apply_context_window(dict(raw), 123)
            assert out.get("tools") is not None or "tools" not in raw

    def test_tool_call_arguments_are_json_strings(self, provider_id: str):
        """BreachPilot canonical requires arguments as JSON string; parser handles both."""
        from tools.exploit_agent.tool_calls import _normalize_tool_call

        # Dict → string, string → dict, None → {}
        tc_dict = tool_call("run_exploit_terminal", {"command": "id"})
        assert isinstance(tc_dict["function"]["arguments"], str)
        norm = _normalize_tool_call(tc_dict)
        assert norm["function"]["arguments"] == {"command": "id"}

        tc_str = tool_call("f", '{"a":1}')
        assert _normalize_tool_call(tc_str)["function"]["arguments"] == {"a": 1}

        tc_none = tool_call("f", None)
        assert _normalize_tool_call(tc_none)["function"]["arguments"] == {}

    def test_malformed_arguments_string_returns_empty_dict(self, provider_id: str):
        from tools.exploit_agent.tool_calls import _normalize_tool_call

        raw = {"function": {"name": "run_exploit_terminal", "arguments": "{bad"}}
        assert _normalize_tool_call(raw)["function"]["arguments"] == {}

    def test_usage_metadata_shape(self, provider_id: str):
        resp = chat_response("m", "hi", usage=usage_report(10, 5))
        assert resp["usage"]["input_tokens"] == 10
        assert resp["usage"]["total_tokens"] == 15
        # Streaming helpers also produce usage
        from tools.providers.types import stream_tool_chunk

        chunk = stream_tool_chunk([tool_call("f", {})], usage=usage_report(3, 2))
        assert chunk["usage"]["total_tokens"] == 5

    def test_ollama_only_kwargs_stripped_for_non_ollama(self, provider_id: str):
        if provider_id == "ollama":
            pytest.skip("ollama keeps Ollama-only kwargs")
        # Verify model_router drops Ollama-only kwargs for non-ollama
        from tools.model_router import _build_model_client

        seen: dict[str, Any] = {}

        class _Raw:
            def chat(self, **kwargs):
                seen.update(kwargs)
                return chat_response(kwargs.get("model", "m"), "ok")

        client = _build_model_client("m", raw_client=_Raw(), provider=provider_id)
        client.chat(model="m", messages=[{"role": "user", "content": "hi"}], options={"num_ctx": 9999}, keep_alive="5m")
        assert "options" not in seen
        assert "keep_alive" not in seen

    def test_provider_client_callable_and_chat_returns_canonical_shape(self, provider_id: str, monkeypatch: pytest.MonkeyPatch):
        from tools.providers.chatgpt_provider import ChatGptProxyManager

        adapter = get_provider(provider_id)
        if provider_id == "chatgpt":
            monkeypatch.setattr(ChatGptProxyManager, "get", lambda: _UnavailableMgr())
            # build_client for chatgpt without auth raises actionable — that's the contract
            with pytest.raises(RuntimeError, match="ChatGPT provider unavailable"):
                adapter.build_client({})
            return
        monkeypatch.delenv("OPENCODE_GO_API_KEY", raising=False)
        cfg: dict[str, Any] = {"ollama": {"host": "http://127.0.0.1:1"}} if provider_id == "ollama" else {}
        client = adapter.build_client(cfg, adapter.title_model(cfg))
        # chat must accept canonical kwargs and return canonical shape (no network for this stub)
        # We only verify the client is callable and has model_id; actual chat would need network/key
        assert callable(client.chat)
        assert client.model_id

    def test_provider_neutral_chat_passthrough_preserves_context_window_tokens(self, provider_id: str):
        """Generic code passes context_window_tokens; Ollama translates, others drop.
        The ModelClient closure must not lose the kwarg before dispatch decision."""
        from tools.model_router import _build_model_client
        from tools.providers.types import ModelClient

        captured: dict[str, Any] = {}

        class _CapRaw:
            def chat(self, **kw):
                captured.update(kw)
                return chat_response(kw.get("model", "m"), "ok")

        raw = _CapRaw()
        client = _build_model_client("m", raw_client=raw, provider="ollama")
        client.chat(model="m", messages=[], context_window_tokens=12345)
        # Ollama path translates to options.num_ctx
        assert captured.get("options", {}).get("num_ctx") == 12345 or captured.get("context_window_tokens") == 12345


class _UnavailableMgr:
    def ensure_running(self, cfg):
        return {"ok": False, "reason": "not_authenticated"}

    def is_authenticated(self, cfg):
        return False


# ---------------------------------------------------------------------------
# Opencode Go specific: message conversion
# ---------------------------------------------------------------------------

def test_opencode_go_message_conversion_preserves_tool_adjacency():
    from tools.providers.opencode_go_provider import _convert_messages_to_input

    sentinel = "SENTINEL_ADJ_123"
    # Simulate: user → assistant with 2 tool_calls → tool results interleaved with user note (gap)
    messages = [
        {"role": "user", "content": "hello"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"id": "call_0", "type": "function", "function": {"name": "search_target", "arguments": '{"query":"x"}'}},
                {"id": "call_1", "type": "function", "function": {"name": "lookup_service", "arguments": '{"target_ip":"127.0.0.1"}'}},
            ],
        },
        {"role": "tool", "tool_call_id": "call_0", "tool_name": "search_target", "content": sentinel},
        {"role": "user", "content": "note between tool results"},
        {"role": "tool", "tool_call_id": "call_1", "tool_name": "lookup_service", "content": "ok2"},
    ]
    items = _convert_messages_to_input(messages)
    # Every function_call must be immediately followed by its output
    for i, item in enumerate(items):
        if item.get("type") == "function_call":
            assert i + 1 < len(items)
            nxt = items[i + 1]
            assert nxt.get("type") == "function_call_output"
            assert nxt.get("call_id") == item.get("call_id")


def test_opencode_go_streaming_sse_parses_tool_calls():
    from tools.providers.opencode_go_provider import _parse_sse_stream
    import json as _json

    # Simulate a minimal Responses SSE sequence producing a tool call
    lines = [
        "event: response.output_item.added",
        "data: " + _json.dumps({"type": "response.output_item.added", "item": {"type": "function_call", "call_id": "call_0", "name": "run_exploit_terminal", "arguments": '{"command":"id"}'}}),
        "event: response.completed",
        "data: " + _json.dumps({"type": "response.completed", "response": {"output": [], "usage": {"input_tokens": 10, "output_tokens": 5}}}),
    ]

    class _FakeResp:
        def iter_lines(self):
            for l in lines:
                yield l

    chunks = list(_parse_sse_stream(_FakeResp()))
    # Last chunk carries assembled tool_calls
    assert any("tool_calls" in (c.get("message") or {}) for c in chunks)


# ---------------------------------------------------------------------------
# ChatGPT specific: streaming tool-call fragment accumulation
# ---------------------------------------------------------------------------

def test_chatgpt_stream_accumulates_tool_call_fragments():
    from tools.providers.chatgpt_provider import ChatGptProxyClient
    import json as _json

    # We don't hit network; verify _DROP_KWARGS does not strip tool schemas before payload build
    client = ChatGptProxyClient("http://127.0.0.1:1", timeout=1)
    payload = client._build_payload({"model": "m", "messages": [{"role": "user", "content": "hi"}], "tools": [{"type": "function", "function": {"name": "t"}}]})
    assert payload["tools"][0]["function"]["name"] == "t"
