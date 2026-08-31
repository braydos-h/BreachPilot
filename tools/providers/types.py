"""BreachPilot-native provider types.

This module defines the canonical model-client contract of the engine.  The
``ModelClient`` dataclass (previously owned by ``tools/model_router.py``) and
the "Ollama-shaped dict" it returned have been formally adopted as the
**BreachPilot model response format**:

.. code-block:: python

    {
        "model": "<concrete model id>",
        "message": {
            "role": "assistant",
            "content": "<text>",
            "thinking": "<reasoning, '' when not supported>",
            "tool_calls": [  # optional
                {"id": "...", "type": "function",
                 "function": {"name": "...", "arguments": "<json string>"}},
            ],
        },
        "usage": {  # optional, normalized
            "input_tokens": int, "output_tokens": int, "total_tokens": int,
        },
    }

Streaming yields chunk dicts of the same shape, one per text delta, with a
final chunk carrying ``tool_calls`` / ``usage`` when present.

Providers translate between this format and their external API.  No provider
is required to emulate Ollama - Ollama is just one adapter (see
``tools/providers/ollama_provider.py``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

# ---------------------------------------------------------------------------
# Canonical response format helpers
# ---------------------------------------------------------------------------


def tool_call(name: str, arguments: Any, call_id: str = "") -> dict[str, Any]:
    """Build a canonical tool-call entry.

     ``arguments`` is normalized to a JSON string (the shape
     ``tools/exploit_agent/tool_calls._normalize_tool_call`` parses).  A non-dict
    /string value is JSON-encoded or stringified.
    """
    import json

    if isinstance(arguments, str):
        args_str = arguments
    elif arguments is None:
        args_str = "{}"
    elif isinstance(arguments, Mapping):
        try:
            args_str = json.dumps(arguments, ensure_ascii=False)
        except Exception:
            args_str = "{}"
    else:
        try:
            args_str = json.dumps(arguments, ensure_ascii=False)
        except Exception:
            args_str = str(arguments)
    entry: dict[str, Any] = {
        "id": str(call_id or ""),
        "type": "function",
        "function": {"name": str(name), "arguments": args_str},
    }
    if call_id:
        entry["call_id"] = str(call_id)
    return entry


def usage_report(
    input_tokens: Any = None,
    output_tokens: Any = None,
    total_tokens: Any = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build a normalized usage dict (token counts; missing fields derived)."""
    out: dict[str, Any] = {}
    if input_tokens is not None:
        out["input_tokens"] = input_tokens
    if output_tokens is not None:
        out["output_tokens"] = output_tokens
    if total_tokens is None and isinstance(out.get("input_tokens"), int) and isinstance(out.get("output_tokens"), int):
        total_tokens = out["input_tokens"] + out["output_tokens"]
    if total_tokens is not None:
        out["total_tokens"] = total_tokens
    for k, v in extra.items():
        if v is not None:
            out[k] = v
    return out


def chat_response(
    model: str,
    content: str,
    *,
    tool_calls: list[dict[str, Any]] | None = None,
    thinking: str = "",
    usage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a canonical (non-stream) chat response dict."""
    response: dict[str, Any] = {
        "model": str(model),
        "message": {
            "role": "assistant",
            "content": str(content or ""),
            "thinking": str(thinking or ""),
        },
    }
    if tool_calls is not None:
        response["message"]["tool_calls"] = list(tool_calls)
    if usage is not None:
        response["usage"] = dict(usage)
    return response


def stream_chunk(content: str, *, thinking: str = "") -> dict[str, Any]:
    """Build a canonical streaming text-delta chunk."""
    return {"message": {"role": "assistant", "content": str(content or ""), "thinking": str(thinking or "")}}


def stream_tool_chunk(tool_calls: list[dict[str, Any]], *, usage: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Build the canonical final streaming chunk (assembled tool calls + usage)."""
    chunk: dict[str, Any] = {
        "message": {"role": "assistant", "content": "", "thinking": "", "tool_calls": list(tool_calls)}
    }
    if usage is not None:
        chunk["usage"] = dict(usage)
    return chunk


# ---------------------------------------------------------------------------
# Core client / provider metadata types
# ---------------------------------------------------------------------------


@dataclass
class ModelClient:
    """BreachPilot's canonical model client.

    A thin wrapper around a raw provider callable.  Consumers call
    ``.chat(model, **kwargs)`` / ``.stream(...)``; the closure inside the
    provider adapter performs telemetry, argument normalization, and any
    provider-specific translation.  ``provider`` identifies the adapter for
    telemetry and retry-log attribution — it is set explicitly, never inferred
    from the model name.
    """

    name: str
    chat: Callable[..., Any]
    stream: Callable[..., Any]
    model_id: str = ""
    provider: str = ""

    def __post_init__(self) -> None:
        if not self.model_id:
            self.model_id = self.name
        if not self.provider:
            self.provider = "ollama"


@dataclass(frozen=True)
class ProviderCapabilities:
    """What a provider actually supports.

    Capabilities are explicit rather than inferred from provider names; UI and
    consumers must consult these instead of hard-coding per-provider `if`s.
    """

    chat: bool = True
    streaming: bool = True
    tool_calls: bool = True
    embeddings: bool = False
    model_discovery: bool = False
    reasoning: bool = False

    def as_dict(self) -> dict[str, bool]:
        return {
            "chat": self.chat,
            "streaming": self.streaming,
            "tool_calls": self.tool_calls,
            "embeddings": self.embeddings,
            "model_discovery": self.model_discovery,
            "reasoning": self.reasoning,
        }


@dataclass
class ModelInfo:
    """A model exposed by a provider (what ``list_models`` returns)."""

    id: str
    label: str = ""
    context_window: int | None = None
    description: str = ""
    default: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label or self.id,
            "context_window": self.context_window,
            "description": self.description,
            "default": self.default,
        }


class ProviderError(RuntimeError):
    """Base error for provider health/config problems (safe operator-facing)."""


class ProviderMissingDependencyError(ProviderError):
    """Raised when a selected provider's third-party SDK is not installed.

    The message MUST be actionable (name the extra / the alternative), per the
    provider-optional-dependency contract.
    """


class ProviderDiscoveryError(ProviderError):
    """Raised when a provider cannot enumerate live models right now.

    Carries the operator-safe ``message`` (shown verbatim by the API's
    ``GET /models/live`` fallback) and a ``fallback_models`` list (the
    provider's configured/default ids) so the UI can degrade to "registry"
    mode. The original exception text is embedded in ``message`` with secrets
    already redacted by the raising provider.
    """

    def __init__(
        self,
        message: str,
        *,
        fallback_models: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.fallback_models = [str(m) for m in (fallback_models or [])]


@dataclass
class ProviderHealth:
    """Provider health/config validation result (doctor-compatible checks).

    ``checks`` items use the doctor check shape: ``{name, ok, error?, hint?, subchecks?}``.
    """

    checks: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(bool(c.get("ok")) for c in self.checks)

    def as_check(self, name: str) -> dict[str, Any]:
        """Compact into a single doctor check entry."""
        failures = [c for c in self.checks if not c.get("ok")]
        return {
            "name": name,
            "ok": self.ok,
            "checks": self.checks,
            "error": "; ".join(str(c.get("error") or c.get("hint") or "") for c in failures).strip("; "),
        }
