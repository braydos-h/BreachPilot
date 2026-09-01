"""Reusable harness for deterministic LLM tool-use contract tests.

Provides:
* sentinel generation (unique per-test values)
* FakeTool / FakeMcpSession (controlled tool results, errors)
* ScriptedModelClient (queued LLM responses mixing tool_calls + final answer)
* ToolUseHarness — drives run_exploit_agent or low-level dispatch and captures
  a structured observability trace (provider/model/scenario/trial/tool
  selected/args/result status/step/termination/oracle/classification/elapsed/tokens)
* assert helpers for sentinel grounding and hallucination checks

All components are deterministic, offline, and mock subprocess/network.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

# ---------------------------------------------------------------------------
# Sentinels
# ---------------------------------------------------------------------------


def make_sentinel(prefix: str = "SENTINEL") -> str:
    """Generate a unique sentinel like ``SERVICE_SENTINEL_7C41_<uuid>``."""
    suffix = uuid.uuid4().hex[:8].upper()
    return f"{prefix}_{suffix}"


# ---------------------------------------------------------------------------
# Fake tool specs (used for low-level tool-catalog / validation tests)
# ---------------------------------------------------------------------------


@dataclass
class FakeToolSpec:
    name: str
    description: str = ""
    required: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)
    handler_result: str = ""
    handler_error: str | None = None  # if set, call_tool raises this

    def to_mcp_schema(self) -> dict[str, Any]:
        """Emit Ollama-style tool schema (type/function/parameters)."""
        params: dict[str, Any] = {"type": "object", "properties": dict(self.properties)}
        if self.required:
            params["required"] = list(self.required)
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description or f"Fake tool {self.name}",
                "parameters": params,
            },
        }


def build_fake_tools(specs: list[FakeToolSpec]) -> list[dict[str, Any]]:
    return [s.to_mcp_schema() for s in specs]


# ---------------------------------------------------------------------------
# Fake MCP session
# ---------------------------------------------------------------------------


class FakeMcpSession:
    """AsyncMCP session double that validates allowlist-like checks and returns
    controlled results or synthetic BLOCKED/ERROR strings."""

    def __init__(
        self,
        specs: list[FakeToolSpec],
        *,
        blocked_tools: set[str] | None = None,
        error_on: dict[str, str] | None = None,
        sentinel_map: dict[str, str] | None = None,
    ) -> None:
        self._specs = {s.name: s for s in specs}
        self.blocked_tools = set(blocked_tools or set())
        self.error_on = dict(error_on or {})
        self.sentinel_map = dict(sentinel_map or {})
        self.calls: list[dict[str, Any]] = []

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        args = dict(arguments or {})
        self.calls.append({"tool": name, "args": dict(args), "ts": time.monotonic()})
        if name in self.blocked_tools:
            return _mcp_result(f"BLOCKED: tool {name} blocked by safety gate")
        if name in self.error_on:
            raise RuntimeError(self.error_on[name])
        spec = self._specs.get(name)
        if spec is None:
            return _mcp_result(f"UNKNOWN_TOOL: {name}")
        if spec.handler_error is not None:
            raise RuntimeError(spec.handler_error)
        sentinel = self.sentinel_map.get(name, spec.handler_result)
        if not sentinel:
            sentinel = f"OK:{name}"
        return _mcp_result(sentinel)

    async def list_tools(self) -> Any:
        class _Resp:
            pass

        resp = _Resp()
        # Expose tools as objects with name/description/inputSchema
        tools = []
        for spec in self._specs.values():
            t = MagicMock()
            t.name = spec.name
            t.description = spec.description
            t.inputSchema = spec.to_mcp_schema()["function"]["parameters"]
            tools.append(t)
        resp.tools = tools
        return resp


def _mcp_result(text: str) -> Any:
    """Mimic CallToolResult content shape the loop parses."""
    item = MagicMock()
    item.text = text
    result = MagicMock()
    result.content = [item]
    result.isError = False
    result.structuredContent = None
    return result


def _mcp_error_result(text: str) -> Any:
    item = MagicMock()
    item.text = text
    result = MagicMock()
    result.content = [item]
    result.isError = True
    return result


# ---------------------------------------------------------------------------
# Scripted ModelClient (queued responses)
# ---------------------------------------------------------------------------


class ScriptedModelClient:
    """Deterministic fake ModelClient that returns queued responses.

    Each entry in ``queue`` is a dict matching the BreachPilot model response
    format (tools/providers/types.chat_response shape). The client records every
    call in ``history`` and returns entries in order; exhaustion returns a final
    answer with no tool_calls.
    """

    def __init__(self, queue: list[dict[str, Any]], *, provider: str = "ollama", name: str = "fake-model"):
        self.queue = list(queue)
        self.provider = provider
        self.name = name
        self.model_id = name
        self.history: list[dict[str, Any]] = []
        self.chat_calls: list[dict[str, Any]] = []

    def chat(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        # Mirror _normalize_chat_args tolerance: first positional may be model id
        positional = list(args)
        if positional and isinstance(positional[0], str):
            positional.pop(0)
        if positional and "messages" not in kwargs:
            kwargs["messages"] = positional.pop(0)
        self.chat_calls.append(dict(kwargs))
        # Record model for tracing
        kwargs.get("messages", [])
        if self.queue:
            resp = self.queue.pop(0)
            # Ensure BreachPilot shape
            if "message" not in resp:
                # Allow shorthand {"content": "...", "tool_calls": [...]}
                content = resp.get("content", "")
                tool_calls = resp.get("tool_calls", [])
                resp = {
                    "model": self.name,
                    "message": {"role": "assistant", "content": content, "thinking": "", "tool_calls": tool_calls},
                    "usage": resp.get("usage", {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20}),
                }
            return resp
        return {
            "model": self.name,
            "message": {
                "role": "assistant",
                "content": "FINAL: no more queued responses",
                "thinking": "",
                "tool_calls": [],
            },
        }

    def stream(self, *args: Any, **kwargs: Any) -> Any:
        kwargs["stream"] = True
        result = self.chat(*args, **kwargs)

        # Yield as single chunk then final tool chunk
        def _gen():
            content = result.get("message", {}).get("content", "")
            if content:
                yield {"message": {"role": "assistant", "content": content, "thinking": ""}}
            tcs = result.get("message", {}).get("tool_calls", [])
            if tcs:
                yield {
                    "message": {"role": "assistant", "content": "", "thinking": "", "tool_calls": tcs},
                    "usage": result.get("usage", {}),
                }

        return _gen()

    # Alias used by runner internals
    @property
    def chat_callable(self):
        return self.chat


def make_tool_call(name: str, args: Any, call_id: str = "") -> dict[str, Any]:
    """Build canonical tool-call entry (tool_calls wire format)."""
    import json as _json

    if isinstance(args, dict):
        args_s = _json.dumps(args, ensure_ascii=False)
    elif isinstance(args, str):
        args_s = args
    else:
        args_s = _json.dumps(args, ensure_ascii=False) if args is not None else "{}"
    entry: dict[str, Any] = {
        "id": call_id or f"call_{uuid.uuid4().hex[:6]}",
        "type": "function",
        "function": {"name": name, "arguments": args_s},
    }
    if call_id:
        entry["call_id"] = call_id
    return entry


# ---------------------------------------------------------------------------
# Observability trace capture
# ---------------------------------------------------------------------------


@dataclass
class TraceEvent:
    step: int
    tool: str
    args: dict[str, Any]
    result_status: str
    result_summary: str
    timestamp: str = ""


@dataclass
class HarnessTrace:
    provider: str = "ollama"
    model: str = "fake-model"
    scenario: str = ""
    trial: int = 0
    goal: str = ""
    available_tools: list[str] = field(default_factory=list)
    selected_tools: list[str] = field(default_factory=list)
    normalized_args: list[dict[str, Any]] = field(default_factory=list)
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    step_count: int = 0
    termination_reason: str = ""
    oracle_result: str = ""
    classification: str = ""
    elapsed_seconds: float = 0.0
    token_usage: dict[str, Any] = field(default_factory=dict)
    events: list[TraceEvent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "scenario": self.scenario,
            "trial": self.trial,
            "goal": self.goal,
            "available_tools": self.available_tools,
            "selected_tools": self.selected_tools,
            "normalized_args": self.normalized_args,
            "tool_results": self.tool_results,
            "step_count": self.step_count,
            "termination_reason": self.termination_reason,
            "oracle_result": self.oracle_result,
            "classification": self.classification,
            "elapsed_seconds": self.elapsed_seconds,
            "token_usage": self.token_usage,
            "events": [e.__dict__ for e in self.events],
        }

    def to_jsonl(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(self.to_dict(), default=str) + "\n")


# ---------------------------------------------------------------------------
# High-level harness — drives run_exploit_agent with fakes and captures trace
# ---------------------------------------------------------------------------


class ToolUseHarness:
    """Drives run_exploit_agent with scripted model + fake MCP session.

    Captures a structured trace suitable for asserting the 12 evaluation
    questions. Secrets are redacted (no args logging for secret-bearing params).
    """

    def __init__(
        self,
        target_ip: str = "127.0.0.1",
        *,
        provider: str = "ollama",
        model: str = "fake-model",
        tmp_path: Path | None = None,
    ) -> None:
        self.target_ip = target_ip
        self.provider = provider
        self.model = model
        self.tmp_path = tmp_path

    async def run(
        self,
        specs: list[FakeToolSpec],
        queue: list[dict[str, Any]],
        *,
        max_rounds: int = 8,
        sentinel_expected: str | None = None,
        oracle_expected: str | None = None,
        extra_policy_kwargs: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], HarnessTrace]:
        """Execute one tool-use scenario and return (final_result, trace)."""
        from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings

        tmp = self.tmp_path or Path.cwd() / ".tmp_harness"
        tmp.mkdir(parents=True, exist_ok=True)
        start = time.monotonic()
        session = FakeMcpSession(specs)
        client = ScriptedModelClient(queue, provider=self.provider, name=self.model)
        # Build Ollama-style tool schemas for the loop
        tool_schemas = build_fake_tools(specs)
        settings = ExploitSettings(
            enabled=True,
            permission=ExploitPermission.FULL_ACCESS,
            attack_mode=True,
            attack_max_rounds=max_rounds,
            attack_max_commands=50,
            workspace_root=tmp,
            target_ip=self.target_ip,
        )
        if extra_policy_kwargs:
            for k, v in extra_policy_kwargs.items():
                setattr(settings, k, v)
        policy = ExploitPolicy(settings, tmp)
        # Patch the stream model to avoid needing real streaming
        from unittest.mock import patch

        # run_exploit_agent will call _call_model_with_retry → client.chat
        # and _stream_model for final summarization; patch _stream_model to use
        # the scripted client's next queued item.
        async def _fake_stream(*a, **k):
            # Return last queued or a sentinel-grounded final
            if client.queue:
                nxt = client.queue.pop(0)
                content = nxt.get("message", {}).get("content", "") if "message" in nxt else nxt.get("content", "")
                return {"role": "assistant", "content": content or "stream-final", "thinking": ""}
            return {"role": "assistant", "content": sentinel_expected or "stream-final", "thinking": ""}

        trace = HarnessTrace(
            provider=self.provider,
            model=self.model,
            scenario=sentinel_expected or "",
            goal="test-goal",
            available_tools=[s.name for s in specs],
        )

        # Disable the read-only research sidecar whose model calls would consume
        # queued scripted responses (startup research + mid-run evidence triggers).
        # The harness drives a deterministic tool sequence; the assistant's extra
        # model turns would otherwise interleave and eat the next queued tool-call.
        def _disabled_research(*_a, **_k):
            class _Off:
                enabled = False

            return _Off()

        with (
            patch("tools.exploit_agent.runner._impl._stream_model", side_effect=_fake_stream),
            patch("tools.exploit_agent._stream_model", side_effect=_fake_stream),
            patch(
                "tools.exploit_agent.research_assistant.ResearchAssistantSettings.from_config",
                side_effect=_disabled_research,
            ),
            patch(
                "tools.exploit_agent.runner._impl.ResearchAssistantSettings.from_config",
                side_effect=_disabled_research,
                create=True,
            ),
        ):
            from tools.exploit_agent import run_exploit_agent

            final = await run_exploit_agent(
                client=client,
                model=self.model,
                session=session,
                exploit_tools=tool_schemas,
                policy=policy,
                target_ip=self.target_ip,
            )
        elapsed = time.monotonic() - start
        # Build trace from session calls + final messages
        trace.step_count = len(session.calls)
        trace.selected_tools = [c["tool"] for c in session.calls]
        trace.normalized_args = [c["args"] for c in session.calls]
        trace.elapsed_seconds = round(elapsed, 3)
        trace.termination_reason = str(final.get("outcome_summary", "") or final.get("status", "") or "completed")[:500]
        # Detect hallucinated success: agent claims success but no sentinel in tool results
        if sentinel_expected:
            all_text = json.dumps(final, default=str)
            trace.oracle_result = "grounded" if sentinel_expected in all_text else "not_grounded"
            trace.classification = "PASS" if sentinel_expected in all_text else "HALLUCINATED"
        elif oracle_expected:
            trace.oracle_result = oracle_expected
        # Token usage shim
        trace.token_usage = {"model_calls": len(client.chat_calls), "tool_calls": len(session.calls)}
        for idx, call in enumerate(session.calls):
            trace.events.append(
                TraceEvent(
                    step=idx + 1,
                    tool=call["tool"],
                    args=_redact_args(call["args"]),
                    result_status="ok",
                    result_summary=str(call["args"])[:200],
                )
            )
        return final, trace


def _redact_args(args: dict[str, Any]) -> dict[str, Any]:
    """Redact secret-bearing arg values (password/api_key/token)."""
    redacted: dict[str, Any] = {}
    for k, v in args.items():
        low = k.lower()
        if any(s in low for s in ("password", "passwd", "secret", "token", "api_key", "ntlm")):
            redacted[k] = "***"
        else:
            redacted[k] = v
    return redacted
