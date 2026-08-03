"""Multi-model abstraction layer for Ollama backends.

Provides:
- ModelClient: unified interface for any Ollama model
- ModelRouter: manages multiple backends and distributes calls
- build_router(): factory to get a pre-configured router with the default model registry
- MODEL_INFO: per-alias metadata (context window, description) so the UI
  can show operators what they're picking and the context compactor can
  size itself correctly.

Usage:
    router = build_router()
    client = router.get_client("deepseek")
    response = client.chat(messages=[...], tools=[...])
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from tools.model_telemetry import (
    infer_source,
    now_iso,
    record_model_usage,
)

try:
    from ollama import Client as OllamaClient
except ImportError:
    OllamaClient = None  # type: ignore


# Per-alias model metadata. The ``context_window`` value is the contract
# the adaptive context compactor (``tools.exploit_agent``) uses to
# decide when to summarize; ``description`` is what the UI shows the
# operator when they pick a model. Keep both in sync with config.yaml's
# ``models.info`` block — that file's values are loaded at runtime and
# override the defaults here when present.
MODEL_INFO: dict[str, dict[str, Any]] = {
    "kimi": {
        "label": "Kimi K2.6",
        "context_window": 256_000,
        "description": "Moonshot Kimi K2.6 — strong long-form reasoning, 256K context.",
    },
    "deepseek": {
        "label": "DeepSeek V4 Pro",
        "context_window": 1_000_000,
        "description": "DeepSeek V4 Pro — 1M token context, deep code reasoning.",
    },
    "deepseek_flash": {
        "label": "DeepSeek V4 Flash",
        "context_window": 1_000_000,
        "description": "DeepSeek V4 Flash - 1M token context, fast DeepSeek option for lower-latency work.",
    },
    "glm": {
        "label": "GLM-5.2",
        "context_window": 976_000,
        "description": "Zhipu GLM-5.2 — 976K context, the smartest/newest GLM for deep reasoning + coding.",
    },
    "minimax": {
        "label": "Minimax M3",
        "context_window": 512_000,
        "description": "Minimax M3 (cloud) — 512K context, balanced coding + reasoning.",
    },
}

DEFAULT_MODEL_REGISTRY: dict[str, str] = {
    "kimi": "kimi-k2.6:cloud",
    "deepseek": "deepseek-v4-pro:cloud",
    "deepseek_flash": "deepseek-v4-flash:cloud",
    "glm": "glm-5.2:cloud",
    "minimax": "minimax-m3:cloud",
}


def get_model_info(alias: str, registry_info: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return metadata for a model alias.

    ``registry_info`` is the ``models.info`` block from config.yaml; when
    present, its entries override the in-code defaults so the operator
    can edit context windows and descriptions without code changes.
    Falls back to the in-code default if the alias is unknown.
    """
    default = {
        "label": alias,
        "context_window": 128_000,
        "description": f"Unknown alias '{alias}' - using 128K default context window.",
    }
    override = (registry_info or {}).get(alias)
    if isinstance(override, Mapping):
        base = dict(MODEL_INFO.get(alias, default))
        base.update({k: v for k, v in override.items() if v is not None})
        return base
    return dict(MODEL_INFO.get(alias, default))


def format_context_window(context_window: Any) -> str:
    """Format a token context window for compact operator-facing picker labels."""
    try:
        tokens = int(context_window)
    except (TypeError, ValueError):
        return "?"
    if tokens <= 0:
        return "?"
    if tokens >= 1_000_000:
        if tokens % 1_000_000 == 0:
            return f"{tokens // 1_000_000}M"
        label = f"{tokens / 1_000_000:.1f}".rstrip("0").rstrip(".")
        return f"{label}M"
    if tokens >= 1_000:
        if tokens % 1_000 == 0:
            return f"{tokens // 1_000}K"
        label = f"{tokens / 1_000:.1f}".rstrip("0").rstrip(".")
        return f"{label}K"
    return str(tokens)


def format_model_choice(
    alias: str,
    *,
    registry: Mapping[str, str] | None = None,
    registry_info: Mapping[str, Any] | None = None,
) -> str:
    """Return a consistent model-picker label with alias, label, context, id, and description."""
    info = get_model_info(alias, registry_info)
    label = str(info.get("label") or alias)
    ctx = format_context_window(info.get("context_window"))
    description = str(info.get("description") or "").strip()
    model_id = ""
    if isinstance(registry, Mapping):
        model_id = str(registry.get(alias) or "").strip()

    parts = [f"{alias:<15} | {label:<20} | {ctx:>5} ctx"]
    if model_id:
        parts.append(model_id)
    if description:
        parts.append(description)
    return " | ".join(parts)


def model_choice_items(
    registry: Mapping[str, str] | None = None,
    registry_info: Mapping[str, Any] | None = None,
) -> list[tuple[str, str]]:
    """Return ``(display, alias)`` items for configured model pickers."""
    effective_registry: Mapping[str, str] = registry or DEFAULT_MODEL_REGISTRY
    return [
        (format_model_choice(str(alias), registry=effective_registry, registry_info=registry_info), str(alias))
        for alias in effective_registry.keys()
    ]


@dataclass
class ModelClient:
    """Thin wrapper around a raw model callable."""
    name: str
    chat: Callable[..., Any]
    stream: Callable[..., Any]
    model_id: str = ""

    def __post_init__(self):
        if not self.model_id:
            self.model_id = self.name


class ModelRouter:
    """Manages multiple Ollama model backends."""

    def __init__(self):
        self._clients: dict[str, ModelClient] = {}

    def register(self, alias: str, client: ModelClient) -> None:
        self._clients[alias] = client

    def get_client(self, alias: str) -> ModelClient:
        # Tolerate callers that pass a concrete model id (e.g. "glm-5.2:cloud")
        # instead of its alias. Reverse-lookup by model_id, then by name, so a
        # stray --model glm-5.2:cloud resolves to the registered "glm" client
        # instead of hard-failing the whole boot.
        if alias in self._clients:
            return self._clients[alias]
        for client in self._clients.values():
            if client.model_id == alias or client.name == alias:
                return client
        raise KeyError(
            f"Model alias '{alias}' not registered. "
            f"Available: {list(self._clients)!r}"
        )

    def clients(self) -> list[ModelClient]:
        return list(self._clients.values())

    def random_client(self) -> ModelClient:
        if not self._clients:
            raise RuntimeError("No model clients registered in router.")
        return random.choice(list(self._clients.values()))


def _registry_info_from_config() -> Mapping[str, Any]:
    try:
        from tools.config_manager import load_validated_config

        config = load_validated_config()
    except Exception:
        return {}
    models_cfg = config.get("models", {}) if isinstance(config, Mapping) else {}
    info = models_cfg.get("info", {}) if isinstance(models_cfg, Mapping) else {}
    return info if isinstance(info, Mapping) else {}


def _context_window_for(alias: str, model_name: str) -> int | None:
    info = _registry_info_from_config()
    for key in (alias, model_name):
        model_info = get_model_info(str(key), info)
        context_window = model_info.get("context_window")
        if isinstance(context_window, int) and context_window > 0:
            return context_window
    return None


def _normalize_chat_args(args: tuple[Any, ...], kwargs: dict[str, Any], model_name: str) -> dict[str, Any]:
    raw_kwargs = dict(kwargs)
    positional = list(args)

    # Existing call sites use both client.chat(model, messages=...) and
    # client.chat(messages=...). The wrapped Ollama client always receives the
    # concrete configured model id.
    if positional and isinstance(positional[0], str):
        positional.pop(0)
    if positional and "messages" not in raw_kwargs:
        raw_kwargs["messages"] = positional.pop(0)
    if "model" in raw_kwargs:
        raw_kwargs.pop("model", None)
    raw_kwargs.setdefault("messages", [])
    if not raw_kwargs.get("tools"):
        raw_kwargs.pop("tools", None)
    raw_kwargs["model"] = model_name
    return raw_kwargs


def _stream_with_telemetry(
    stream: Any,
    *,
    alias: str,
    model_name: str,
    messages: Any,
    started_at: str,
    started_monotonic: float,
    context_window_tokens: int | None,
    source: str,
):
    last_chunk: Any | None = None
    error = ""
    try:
        for chunk in stream:
            last_chunk = chunk
            yield chunk
    except Exception as exc:
        error = str(exc)
        raise
    finally:
        record_model_usage(
            alias=alias,
            model_id=model_name,
            response=last_chunk,
            messages=messages,
            stream=True,
            started_at=started_at,
            ended_at=now_iso(),
            wall_duration_seconds=time.monotonic() - started_monotonic,
            context_window_tokens=context_window_tokens,
            source=source,
            error=error,
        )


# ponytail: cloud-only. The host (default https://api.ollama.com) is set
# from config.yaml's ``ollama.host`` at every call site; the ollama Python
# client auto-attaches ``Authorization: Bearer $OLLAMA_API_KEY`` to every
# request, so pointing the same Client at the cloud host is the whole
# wiring. No reachability probe, no local→cloud fallback — the cloud IS
# the default. A local-only install overrides ``ollama.host`` to point at
# a local daemon and the same code path runs against that.
OLLAMA_CLOUD_HOST = "https://api.ollama.com"


def _build_model_client(
    model_name: str,
    host: str = OLLAMA_CLOUD_HOST,
    *,
    alias: str = "",
    request_timeout_seconds: float | None = None,
) -> ModelClient:
    """Factory to build a ModelClient for an Ollama model.

    Cloud-only by default: ``host`` is ``https://api.ollama.com`` unless
    overridden by config or a caller. The ollama Python client reads
    ``OLLAMA_API_KEY`` from the env on init and adds ``Authorization: Bearer
    <key>`` to every request, so a host swap is sufficient — no extra auth
    plumbing. Override ``ollama.host`` in config.yaml to point at a local
    daemon if you have one; the same code path runs against it.
    """
    if OllamaClient is None:
        raise RuntimeError("ollama package not installed")

    # ponytail: pass timeout straight to the httpx-backed Ollama client. A hung
    # generation raises httpx.ReadTimeout, already matched by
    # exploit_agent._is_retryable_error → 3x retry → synthetic error dict, so
    # the attack loop survives without a new error path. None = httpx default.
    if request_timeout_seconds is not None:
        raw_client = OllamaClient(host=host, timeout=request_timeout_seconds)
    else:
        raw_client = OllamaClient(host=host)

    telemetry_alias = alias or model_name
    context_window_tokens = _context_window_for(telemetry_alias, model_name)

    def chat(*args: Any, **kwargs: Any) -> Any:
        source = str(kwargs.pop("telemetry_source", "") or "") or infer_source()
        raw_kwargs = _normalize_chat_args(args, kwargs, model_name)
        messages = raw_kwargs.get("messages", [])
        stream = bool(raw_kwargs.get("stream", False))
        started_at = now_iso()
        started_monotonic = time.monotonic()
        error = ""
        try:
            response = raw_client.chat(**raw_kwargs)
            if stream:
                return _stream_with_telemetry(
                    response,
                    alias=telemetry_alias,
                    model_name=model_name,
                    messages=messages,
                    started_at=started_at,
                    started_monotonic=started_monotonic,
                    context_window_tokens=context_window_tokens,
                    source=source,
                )
            record_model_usage(
                alias=telemetry_alias,
                model_id=model_name,
                response=response,
                messages=messages,
                stream=False,
                started_at=started_at,
                ended_at=now_iso(),
                wall_duration_seconds=time.monotonic() - started_monotonic,
                context_window_tokens=context_window_tokens,
                source=source,
            )
            return response
        except Exception as exc:
            error = str(exc)
            record_model_usage(
                alias=telemetry_alias,
                model_id=model_name,
                response=None,
                messages=messages,
                stream=stream,
                started_at=started_at,
                ended_at=now_iso(),
                wall_duration_seconds=time.monotonic() - started_monotonic,
                context_window_tokens=context_window_tokens,
                source=source,
                error=error,
            )
            raise

    def stream_chat(*args: Any, **kwargs: Any) -> Any:
        kwargs["stream"] = True
        kwargs.setdefault("tools", None)
        return chat(*args, **kwargs)

    return ModelClient(name=model_name, chat=chat, stream=stream_chat, model_id=model_name)


def build_router(
    registry: Mapping[str, str] | None = None,
    host: str = OLLAMA_CLOUD_HOST,
    *,
    request_timeout_seconds: float | None = None,
) -> ModelRouter:
    """Build and return a router from alias -> Ollama model name."""
    registry = registry or DEFAULT_MODEL_REGISTRY
    router = ModelRouter()
    for alias, model_name in registry.items():
        router.register(str(alias), _build_model_client(
            str(model_name), host=host, alias=str(alias),
            request_timeout_seconds=request_timeout_seconds,
        ))
    return router
