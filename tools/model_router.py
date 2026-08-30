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


# Model roles recognized for role-aware routing (models.roles.<role> -> alias).
# Every role defaults to the default alias, so an unconfigured roles block is
# byte-identical to today's behavior; operators point a role at a stronger
# alias only when one is available.
MODEL_ROLES: tuple[str, ...] = (
    "planner",
    "executor",
    "interpreter",
    "code_generator",
    "critic",
    "summarizer",
)


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
        raise KeyError(f"Model alias '{alias}' not registered. Available: {list(self._clients)!r}")

    def get_client_for_role(
        self,
        role: str,
        *,
        config: Mapping[str, Any] | None = None,
        fallback_alias: str | None = None,
    ) -> ModelClient:
        """Resolve a model client for a functional role.

        Reads ``config['models']['roles'][role]`` (an alias or model id) and
        resolves it through ``get_client`` (which tolerates concrete model
        ids). Missing role config falls back to ``fallback_alias`` and then to
        the ``models.default_alias`` value in config. Role resolution failures
        fall back the same way -- a typo in a role mapping must never hard-fail
        a run. ``config=None`` and no fallback returns the only client when
        exactly one is registered, else raises (mirrors get_client semantics).
        """
        roles: Mapping[str, Any] = {}
        default_alias: str = ""
        if isinstance(config, Mapping):
            models_cfg = config.get("models", {})
            if isinstance(models_cfg, Mapping):
                roles_raw = models_cfg.get("roles", {})
                roles = roles_raw if isinstance(roles_raw, Mapping) else {}
                default_alias = str(models_cfg.get("default_alias", "") or "")
        candidates = [str(roles.get(role, "") or ""), fallback_alias or "", default_alias]
        for alias in candidates:
            if not alias:
                continue
            try:
                return self.get_client(alias)
            except KeyError:
                continue
        if len(self._clients) == 1:
            return next(iter(self._clients.values()))
        raise KeyError(f"No model client resolvable for role '{role}'.")

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
    provider: str = "ollama",
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
            provider=provider,
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
    raw_client: Any = None,
    provider: str = "ollama",
) -> ModelClient:
    """Factory to build a ModelClient for a chat/generate backend.

    Cloud-only by default: ``host`` is ``https://api.ollama.com`` unless
    overridden by config or a caller. The ollama Python client reads
    ``OLLAMA_API_KEY`` from the env on init and adds ``Authorization: Bearer
    <key>`` to every request, so a host swap is sufficient — no extra auth
    plumbing. Override ``ollama.host`` in config.yaml to point at a local
    daemon if you have one; the same code path runs against it.

    Provider seam: pass ``raw_client`` (any object with a ``chat(**kwargs)``
    method returning an Ollama-shaped dict / stream iterable) to route through
    a non-Ollama backend. When ``raw_client is None`` the Ollama client is
    constructed exactly as before — byte-identical, so every test that
    monkeypatches ``model_router.OllamaClient`` keeps working. ``provider`` is
    threaded into telemetry so records attribute by provider (additive; default
    ``"ollama"`` keeps old records valid).
    """
    if raw_client is None:
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
                    provider=provider,
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
                provider=provider,
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
                provider=provider,
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
    provider: str = "ollama",
    chatgpt_config: Mapping[str, Any] | None = None,
    opencode_go_config: Mapping[str, Any] | None = None,
    config: Mapping[str, Any] | None = None,
) -> ModelRouter:
    """Build and return a router from alias -> model name.

    ``provider`` selects the backend. ``"ollama"`` (default) is the unchanged
    per-registry-alias path. ``"chatgpt"`` routes through the local
    openai-oauth proxy (``127.0.0.1:10531/v1``): it ensures the proxy is
    running, discovers models from ``/v1/models`` (falling back to the
    ``chatgpt.default_model`` / configured ``chatgpt.models`` list), and
    registers one ``ModelClient`` per discovered GPT model — each backed by a
    single shared ``ChatGptProxyClient``. ``"opencode_go"`` routes through the
    hosted Responses endpoint (``https://opencode.ai/zen/go/v1/responses``).
    ``alias`` == ``model_id`` for the chatgpt / opencode_go paths (no alias
    namespace).
    """
    if provider == "chatgpt":
        return _build_chatgpt_router(
            chatgpt_config or {},
            request_timeout_seconds=request_timeout_seconds,
        )
    if provider == "opencode_go":
        cfg = opencode_go_config
        if cfg is None and isinstance(config, Mapping):
            from tools.config.loader import get_opencode_go_config

            cfg = get_opencode_go_config(config)
        return _build_opencode_go_router(
            cfg or {},
            request_timeout_seconds=request_timeout_seconds,
        )

    registry = registry or DEFAULT_MODEL_REGISTRY
    router = ModelRouter()
    for alias, model_name in registry.items():
        router.register(
            str(alias),
            _build_model_client(
                str(model_name),
                host=host,
                alias=str(alias),
                request_timeout_seconds=request_timeout_seconds,
            ),
        )
    return router


def _build_chatgpt_router(
    chatgpt_config: Mapping[str, Any],
    *,
    request_timeout_seconds: float | None = None,
) -> ModelRouter:
    """Build a router backed by the local openai-oauth ChatGPT proxy."""
    from tools.providers.chatgpt_provider import ChatGptProxyClient, ChatGptProxyManager

    cfg = dict(chatgpt_config)
    manager = ChatGptProxyManager.get()
    running = manager.ensure_running(cfg)
    if not running.get("ok"):
        reason = running.get("reason") or "unavailable"
        raise RuntimeError(
            f"ChatGPT provider unavailable: {reason}. "
            f"Run 'python main.py --doctor' or sign in via the interactive menu."
        )
    base_url = running["base_url"]

    # Resolve the model list: explicit config override → discover → fallback.
    configured = cfg.get("models") or []
    if configured:
        model_ids = [str(m) for m in configured if str(m).strip()]
    else:
        model_ids = manager.discover_models(base_url, cfg)
    if not model_ids:
        default_model = str(cfg.get("default_model") or "gpt-5.2")
        model_ids = [default_model]

    timeout = cfg.get("request_timeout_seconds")
    client_timeout = request_timeout_seconds
    if client_timeout is None and timeout is not None:
        try:
            client_timeout = float(timeout)
        except (TypeError, ValueError):
            client_timeout = None
    shared = ChatGptProxyClient(base_url, timeout=client_timeout)

    router = ModelRouter()
    for model_id in model_ids:
        router.register(
            model_id,
            _build_model_client(
                model_id,
                alias=model_id,
                request_timeout_seconds=client_timeout,
                raw_client=shared,
                provider="chatgpt",
            ),
        )
    return router


def _is_opencode_responses_model(
    model_id: str,
    raw_item: Mapping[str, Any] | None,
    cfg: Mapping[str, Any] | None = None,
) -> bool:
    """True if a discovered model is safe to route through the Responses adapter.

    The hosted catalog mixes providers/protocols.  Our Responses adapter must
    NOT blindly expose ``/chat/completions``-only or Anthropic ``/messages``-only
    models via ``/responses``.  The reliable signal (when present) is an
    explicit protocol hint in the discovery payload (e.g. ``supported_api``,
    ``endpoints``, ``capabilities`` containing ``responses``).  When no hint
    exists we conservatively allow only the known Responses family and the
    configured default.
    """
    cleaned = str(model_id or "").strip()
    if not cleaned:
        return False
    # Always allow the configured default
    default = str((cfg or {}).get("default_model") or "muse-spark-1.2-contributor")
    if cleaned == default:
        return True
    # Known Responses family
    if cleaned == "muse-spark-1.2-contributor":
        return True
    # Heuristic for spark family (future spark releases stay on Responses)
    if "muse-spark" in cleaned or "spark" in cleaned.lower():
        return True
    if raw_item is not None:
        # Look for explicit protocol metadata
        for key in ("supported_api", "api", "protocol", "endpoints", "capabilities", "supported_endpoints", "type"):
            val = raw_item.get(key)  # type: ignore[attr-defined]
            if val is None:
                continue
            text = str(val).lower() if not isinstance(val, list) else " ".join(str(v).lower() for v in val)
            if "response" in text:
                return True
        # Some catalogs nest under metadata
        meta = raw_item.get("metadata") if isinstance(raw_item.get("metadata"), Mapping) else None  # type: ignore[attr-defined]
        if isinstance(meta, Mapping):
            for key in ("supported_api", "protocol", "endpoints"):
                val = meta.get(key)
                if val is None:
                    continue
                text = str(val).lower() if not isinstance(val, list) else " ".join(str(v).lower() for v in val)
                if "response" in text:
                    return True
    return False


def _build_opencode_go_router(
    opencode_config: Mapping[str, Any],
    *,
    request_timeout_seconds: float | None = None,
) -> ModelRouter:
    """Build a router backed by the hosted OpenCode Go Responses API.

    The API key is resolved from ``api_key_env`` (default ``OPENCODE_GO_API_KEY``)
    but a missing key does NOT block router construction — the resulting
    ``OpenCodeGoResponsesClient`` will surface a clear ``API key not configured``
    error on the first ``chat`` call, matching the Ollama Cloud behaviour
    (preview succeeds, auth fails on first generation). This prevents a silent
    ``500`` on ``POST /runs`` when the operator has switched provider but not
    yet set the key.
    """
    from tools.providers.opencode_go_provider import OpenCodeGoResponsesClient

    cfg = dict(opencode_config)
    import os

    env_name = str(cfg.get("api_key_env") or "OPENCODE_GO_API_KEY").strip() or "OPENCODE_GO_API_KEY"
    api_key = (os.environ.get(env_name, "") or "").strip()
    # Do NOT raise here — defer to chat-time so run previews still succeed.
    base_url = str(cfg.get("base_url") or "https://opencode.ai/zen/go/v1").rstrip("/")
    timeout = request_timeout_seconds
    if timeout is None and cfg.get("request_timeout_seconds") is not None:
        try:
            timeout = float(cfg["request_timeout_seconds"])
        except (TypeError, ValueError):
            timeout = None
    if timeout is None:
        timeout = 300.0

    shared = OpenCodeGoResponsesClient(
        base_url=base_url,
        api_key=api_key,
        timeout=float(timeout),
        default_model=str(cfg.get("default_model") or "muse-spark-1.2-contributor"),
        config=cfg,
    )

    # Resolve model list: explicit -> discover (filtered) -> fallback
    configured = cfg.get("models") or []
    if configured:
        model_ids = [str(m).strip() for m in configured if str(m).strip()]
    else:
        model_ids = []
        try:
            discovered = shared.discover_models(base_url, cfg)
        except Exception:
            discovered = []
        if discovered:
            # If discovery returned ids but we have no raw metadata, filter by id heuristic
            filtered = [mid for mid in discovered if _is_opencode_responses_model(mid, None, cfg)]
            if filtered:
                model_ids = filtered
            else:
                # Discovery contained only non-Responses models; fall back to default
                model_ids = []

    if not model_ids:
        default_model = str(cfg.get("default_model") or "muse-spark-1.2-contributor")
        model_ids = [default_model]

    # De-duplicate preserving order and ensure default present
    seen: set[str] = set()
    unique: list[str] = []
    for mid in model_ids:
        if mid not in seen:
            seen.add(mid)
            unique.append(mid)
    default_model = str(cfg.get("default_model") or "muse-spark-1.2-contributor")
    if default_model not in seen:
        unique.append(default_model)

    router = ModelRouter()
    for model_id in unique:
        router.register(
            model_id,
            _build_model_client(
                model_id,
                alias=model_id,
                request_timeout_seconds=float(timeout) if timeout is not None else None,
                raw_client=shared,
                provider="opencode_go",
            ),
        )
    return router


def build_model_client_for_provider(
    config: Mapping[str, Any] | None,
    alias: str,
    *,
    request_timeout_seconds: float | None = None,
) -> ModelClient:
    """Build a single ``ModelClient`` for ``alias`` under the configured provider.

    Root-cause replacement for the duplicated ``_build_model_client(alias,
    host=...)`` fallback call sites: reads ``models.provider`` +
    ``ollama.host`` / the ``chatgpt``/``opencode_go`` block from config and
    builds the right client. For ``ollama`` this is byte-identical to the old
    direct call. For ``chatgpt`` it ensures the proxy and wraps a
    ``ChatGptProxyClient``. For ``opencode_go`` it wraps an
    ``OpenCodeGoResponsesClient``.
    """
    cfg = config or {}
    from tools.config_manager import get_ai_provider, get_chatgpt_config, get_ollama_host, get_opencode_go_config

    provider = get_ai_provider(cfg)
    if provider == "chatgpt":
        chatgpt_config = get_chatgpt_config(cfg)
        from tools.providers.chatgpt_provider import ChatGptProxyClient, ChatGptProxyManager

        manager = ChatGptProxyManager.get()
        running = manager.ensure_running(chatgpt_config)
        if not running.get("ok"):
            raise RuntimeError(f"ChatGPT provider unavailable: {running.get('reason') or 'unavailable'}.")
        timeout = request_timeout_seconds
        if timeout is None and chatgpt_config.get("request_timeout_seconds") is not None:
            try:
                timeout = float(chatgpt_config["request_timeout_seconds"])
            except (TypeError, ValueError):
                timeout = None
        shared = ChatGptProxyClient(running["base_url"], timeout=timeout)
        return _build_model_client(
            alias,
            alias=alias,
            request_timeout_seconds=timeout,
            raw_client=shared,
            provider="chatgpt",
        )
    if provider == "opencode_go":
        og_cfg = get_opencode_go_config(cfg)
        import os

        env_name = str(og_cfg.get("api_key_env") or "OPENCODE_GO_API_KEY").strip() or "OPENCODE_GO_API_KEY"
        api_key = (os.environ.get(env_name, "") or "").strip()
        # Do not raise here — let the chat-time missing-key error surface on first generation,
        # matching Ollama behaviour (preview succeeds, auth fails later).
        timeout = request_timeout_seconds
        if timeout is None and og_cfg.get("request_timeout_seconds") is not None:
            try:
                timeout = float(og_cfg["request_timeout_seconds"])
            except (TypeError, ValueError):
                timeout = None
        base_url = str(og_cfg.get("base_url") or "https://opencode.ai/zen/go/v1").rstrip("/")
        from tools.providers.opencode_go_provider import OpenCodeGoResponsesClient

        shared = OpenCodeGoResponsesClient(
            base_url=base_url,
            api_key=api_key,
            timeout=float(timeout) if timeout is not None else 300.0,
            default_model=str(og_cfg.get("default_model") or alias or "muse-spark-1.2-contributor"),
            config=og_cfg,
        )
        return _build_model_client(
            alias,
            alias=alias,
            request_timeout_seconds=timeout,
            raw_client=shared,
            provider="opencode_go",
        )

    host = get_ollama_host(cfg)
    return _build_model_client(
        alias,
        host=host,
        alias=alias,
        request_timeout_seconds=request_timeout_seconds,
    )
