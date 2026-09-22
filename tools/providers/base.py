"""Provider adapter base class.

Every chat/generate provider implements :class:`BaseProvider` and registers an
instance with the registry (``tools/providers/registry.py``).  Application
code (exploit agent, swarm, run service, session titler, eval harness, ...)
never references a concrete provider: it resolves one through the registry and
talks to the canonical :class:`tools.providers.types.ModelClient` contract.

Adding a provider therefore means: implement one adapter, register it, add
config metadata, add tests -- no edits to agent/swarm/run-service code.

Contract methods:

- ``build_router``       -> a ``ModelRouter`` of registered clients for this provider
- ``build_client``       -> one client for a concrete alias/model id
- ``list_models``        -> discoverable/configured models (``list[ModelInfo]``)
- ``title_model``        -> the cheap model used for session titling (may be the default)
- ``health``             -> doctor-compatible validation checks
- ``is_configured``      -> secrets/endpoint present enough to attempt a call

API-specific translation lives ENTIRELY inside the adapter (see
``docs/provider-development.md``).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Mapping

from .types import ModelInfo, ProviderCapabilities, ProviderHealth

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tools.model_router import ModelRouter

    from .types import ModelClient


# Canonical chat kwargs that are BreachPilot concepts rather than Ollama ones.
# Generic code may pass ``context_window_tokens`` on any provider; adapters
# translate it to their backend's mechanism (Ollama's ``options.num_ctx``) or
# drop it when the backend has no such knob.
CANONICAL_CHAT_KWARGS = ("context_window_tokens",)

#: Ollama-only chat kwargs with no meaning on other backends. Dropped
#: centrally (see ``prepare_chat_kwargs``) so the ChatGPT / OpenCode Go raw
#: clients and ``model_router`` stop maintaining three copies of the list.
OLLAMA_ONLY_CHAT_KWARGS = ("options", "keep_alive", "format", "suffix", "think", "raw", "num_ctx")

#: Data-residency values for :meth:`BaseProvider.privacy_boundary`.
#: ``local`` = prompts stay on this host; ``cloud`` = prompts egress off-box.
DATA_RESIDENCY_LOCAL = "local"
DATA_RESIDENCY_CLOUD = "cloud"


def is_loopback_url(url: str) -> bool:
    """True when ``url`` addresses this host (loopback only, no secrets read).

    Matches ``localhost``, ``*.localhost``, IPv4 ``127.0.0.0/8``, and IPv6
    ``::1``. Anything else — LAN IPs, tailnets, public hosts — is NOT
    loopback: only an operator-confirmed loopback URL keeps prompts on-box.
    """
    import ipaddress
    from urllib.parse import urlparse

    try:
        host = (urlparse(str(url or "")).hostname or "").strip().lower()
    except Exception:  # noqa: BLE001 -- unparseable host is not loopback
        return False
    if not host:
        return False
    host = host.strip("[]")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class BaseProvider(ABC):
    """Abstract base for a chat/generate provider adapter."""

    #: Stable provider id (matches ``models.provider`` / ``providers.<id>``).
    id: str = ""
    display_name: str = ""
    capabilities: ProviderCapabilities = ProviderCapabilities()

    # ── Identity / metadata ────────────────────────────────────────────

    def metadata(self, config: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Serializable provider metadata for the API/UI (no secrets)."""
        cfg = self.provider_config(config)
        privacy = self.privacy_boundary(config)
        return {
            "id": self.id,
            "name": self.display_name,
            "capabilities": self.capabilities.as_dict(),
            "configured": self.is_configured(self.provider_config(config)),
            "default_model": str(cfg.get("default_model", "")),
            "data_residency": privacy["data_residency"],
            "egress_target": privacy["egress_target"],
        }

    def privacy_boundary(self, config: Mapping[str, Any] | None = None) -> dict[str, str]:
        """Where prompts go: ``{"data_residency": local|cloud, "egress_target": str}``.

        Derived from the effective host/base_url at call time; never carries
        secrets (hosts/URLs only, no keys/tokens). The default is ``cloud``
        with an empty target — concrete adapters override with their real
        destination. UI renders badge + notice from these two fields only
        (zero per-provider branching).
        """
        del config  # default: no host to inspect
        return {"data_residency": DATA_RESIDENCY_CLOUD, "egress_target": ""}

    def is_configured(self, cfg: Mapping[str, Any]) -> bool:
        """Whether the provider has enough config to attempt a call.

        Default: ``enabled`` flag or non-empty ``base_url``.  Providers with
        secrets (API keys) override to also require the key/env var.
        """
        return bool(cfg) and (bool(cfg.get("enabled")) or bool(cfg.get("base_url")))

    # ── Config resolution ──────────────────────────────────────────────

    def provider_config(self, config: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Return this provider's merged config block (schema defaults applied).

        Delegates to the single config-normalization layer
        (``tools.config.loader.get_provider_config``) which reads the modern
        ``providers.<id>`` block first, then falls back to the provider's
        legacy top-level block.  Never returns None.
        """
        from tools.config.loader import get_provider_config

        return get_provider_config(config or {}, self.id)

    # ── Client / router construction ───────────────────────────────────

    @abstractmethod
    def build_router(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        request_timeout_seconds: float | None = None,
        provider_config: Mapping[str, Any] | None = None,
    ) -> "ModelRouter":
        """Build a ``ModelRouter`` of clients backed by this provider."""

    def build_client(
        self,
        config: Mapping[str, Any] | None = None,
        alias: str = "",
        *,
        request_timeout_seconds: float | None = None,
    ) -> "ModelClient":
        """Build a single ``ModelClient`` for ``alias`` (default: default model)."""
        raise NotImplementedError(f"Provider '{self.id}' does not implement build_client")

    # Optional: injectable raw client seam (set by tests to a fake backend).
    _raw_client_factory: Any = None

    def use_raw_client_factory(self, factory: Any) -> None:
        """Inject a ``build_raw_client(provider_config, timeout)`` factory (tests)."""
        self._raw_client_factory = factory

    # ── Models / roles ─────────────────────────────────────────────────

    def list_models(self, config: Mapping[str, Any] | None = None) -> list[ModelInfo]:
        """Enumerate available models.  Default: the configured/default model."""
        cfg = self.provider_config(config)
        model_ids = [str(m) for m in (cfg.get("models") or []) if str(m).strip()]
        default_model = str(cfg.get("default_model", "") or "")
        if default_model and default_model not in model_ids:
            model_ids.append(default_model)
        context_window = cfg.get("context_window")
        return [
            ModelInfo(
                id=model_id,
                label=model_id,
                context_window=int(context_window) if isinstance(context_window, (int, float)) else None,
                default=(model_id == default_model),
            )
            for model_id in model_ids
        ]

    def title_model(self, config: Mapping[str, Any] | None = None) -> str:
        """Model id used for cheap session titling.  Default: default_model."""
        return str(self.provider_config(config).get("default_model", "") or "")

    # ── Health / config validation (doctor) ────────────────────────────

    def health(self, config: Mapping[str, Any] | None = None) -> ProviderHealth:
        """Validate config/secrets/endpoint for doctor.

        Default implementation verifies the config block exists and is
        enabled; concrete providers add endpoint/auth/model sub-checks.
        """
        del config  # default: nothing provider-specific to validate
        return ProviderHealth()


# ---------------------------------------------------------------------------
# Shared provider helpers (consolidation point).
#
# Retry / streaming / telemetry / context-window handling used to live in
# three places (``model_router._build_model_client``, each adapter's
# ``_normalize_usage`` / ``_coalesce`` / timeout block, and
# ``exploit_agent.model_client._is_retryable_error``). They now live here so
# adapters stay thin and provider #4 reuses them with zero new branches.
# ---------------------------------------------------------------------------


def coalesce_config(defaults: Mapping[str, Any], cfg: Mapping[str, Any] | None) -> dict[str, Any]:
    """Merge ``cfg`` over ``defaults`` (non-None values win; missing keys filled)."""
    merged = dict(defaults)
    if cfg:
        for key, value in cfg.items():
            if value is not None:
                merged[key] = value
    for key, default in defaults.items():
        if key not in merged:
            merged[key] = default
    return merged


def resolve_request_timeout(
    explicit: float | None,
    cfg_value: Any,
    default: float | None = None,
) -> float | None:
    """Single timeout resolution: explicit kwarg wins, else config value, else default."""
    if explicit is not None:
        return explicit
    if cfg_value is None:
        return default
    try:
        return float(cfg_value)
    except (TypeError, ValueError):
        return default


def provider_model_infos(
    ids: list[str],
    default_model: str,
    context_window: Any,
) -> list[ModelInfo]:
    """Single ``list_models`` record builder (deduped, default-flagged)."""
    ctx = int(context_window) if isinstance(context_window, (int, float)) else None
    infos: list[ModelInfo] = []
    seen: set[str] = set()
    for model_id in ids or [default_model]:
        if not model_id or model_id in seen:
            continue
        seen.add(model_id)
        infos.append(ModelInfo(id=model_id, label=model_id, context_window=ctx, default=(model_id == default_model)))
    return infos


def normalize_provider_usage(raw: Any) -> dict[str, Any]:
    """Single usage-payload normalizer (OpenAI/Responses shapes -> canonical).

    Thin wrapper over ``types.usage_report`` so the ChatGPT and OpenCode Go
    adapters share one mapping instead of two hand-rolled copies.
    """
    from .types import usage_report

    if not isinstance(raw, dict) or not raw:
        return {}
    return usage_report(
        raw.get("prompt_tokens", raw.get("input_tokens")),
        raw.get("completion_tokens", raw.get("output_tokens")),
        raw.get("total_tokens"),
    )


def strip_ollama_only_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``kwargs`` without Ollama-only keys (never mutates)."""
    return {k: v for k, v in kwargs.items() if k not in OLLAMA_ONLY_CHAT_KWARGS}


def prepare_chat_kwargs(raw_kwargs: dict[str, Any], provider_id: str) -> dict[str, Any]:
    """Pop canonical ``context_window_tokens`` and translate/drop it per provider.

    Ollama translates to ``options.num_ctx`` (only when > 0, never mutating
    the caller's dict); every other provider drops it plus any Ollama-only
    keys. Returns a new dict.
    """
    kwargs = dict(raw_kwargs)
    canonical_ctx = kwargs.pop("context_window_tokens", None)
    if provider_id == "ollama":
        if canonical_ctx is None:
            return kwargs
        try:
            tokens = int(canonical_ctx)
        except (TypeError, ValueError):
            return kwargs
        if tokens > 0:
            options = dict(kwargs.get("options") or {})
            options["num_ctx"] = tokens
            return {**kwargs, "options": options}
        return kwargs
    for dropped in OLLAMA_ONLY_CHAT_KWARGS:
        kwargs.pop(dropped, None)
    return kwargs


def normalize_chat_args(args: tuple[Any, ...], kwargs: dict[str, Any], model_name: str) -> dict[str, Any]:
    """Single chat-arg normalizer (positional model/messages tolerance).

    Moved here from ``model_router._normalize_chat_args`` so adapters and the
    router share one implementation. Behavior is byte-identical.
    """
    raw_kwargs = dict(kwargs)
    positional = list(args)
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


def is_retryable_error(exc: BaseException) -> bool:
    """Single transient-error classifier shared by agent retry loops."""
    name = type(exc).__name__
    if name in (
        "RemoteProtocolError",
        "ConnectError",
        "ConnectionError",
        "TimeoutError",
        "ReadTimeout",
        "ConnectTimeout",
        "WriteTimeout",
        "PoolTimeout",
        "TimeoutException",
    ):
        return True
    module = getattr(type(exc), "__module__", "") or ""
    for marker in ("httpx", "httpcore", "anyio", "asyncio"):
        if marker in module:
            return True
    return False


def retry_delay_seconds(attempt: int) -> float:
    """Exponential backoff with jitter for model retry loops (``2**n + U[0,1)``)."""
    import random as _random

    return 2**attempt + _random.uniform(0, 1)


def wrap_raw_client_with_telemetry(
    *,
    model_name: str,
    raw_client: Any,
    alias: str = "",
    provider: str = "ollama",
    context_window_tokens: int | None = None,
) -> "ModelClient":
    """Single telemetry/streaming chat closure for every provider.

    Owns arg normalization, canonical context-window handling, timing,
    ``telemetry_source`` attribution, streaming final-chunk accounting, and
    error-path telemetry. ``model_router._build_model_client`` delegates here
    so adapters (via ``make_model_client``) and the router share one path.
    """
    import time as _time

    from tools.model_telemetry import infer_source, now_iso, record_model_usage

    from .types import ModelClient as _ModelClient

    telemetry_alias = alias or model_name

    def chat(*args: Any, **kwargs: Any) -> Any:
        source = str(kwargs.pop("telemetry_source", "") or "") or infer_source()
        raw_kwargs = prepare_chat_kwargs(normalize_chat_args(args, kwargs, model_name), provider)
        messages = raw_kwargs.get("messages", [])
        stream = bool(raw_kwargs.get("stream", False))
        started_at = now_iso()
        started_monotonic = _time.monotonic()
        error = ""
        try:
            response = raw_client.chat(**raw_kwargs)
            if stream:

                def _gen() -> Any:
                    last: Any | None = None
                    stream_error = ""
                    try:
                        for chunk in response:
                            last = chunk
                            yield chunk
                    except Exception as exc:
                        stream_error = str(exc)
                        raise
                    finally:
                        record_model_usage(
                            alias=telemetry_alias,
                            model_id=model_name,
                            response=last,
                            messages=messages,
                            stream=True,
                            started_at=started_at,
                            ended_at=now_iso(),
                            wall_duration_seconds=_time.monotonic() - started_monotonic,
                            context_window_tokens=context_window_tokens,
                            source=source,
                            error=stream_error,
                            provider=provider,
                        )

                return _gen()
            record_model_usage(
                alias=telemetry_alias,
                model_id=model_name,
                response=response,
                messages=messages,
                stream=False,
                started_at=started_at,
                ended_at=now_iso(),
                wall_duration_seconds=_time.monotonic() - started_monotonic,
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
                wall_duration_seconds=_time.monotonic() - started_monotonic,
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

    return _ModelClient(name=model_name, chat=chat, stream=stream_chat, model_id=model_name, provider=provider)


def make_model_client(
    model_name: str,
    *,
    alias: str = "",
    request_timeout_seconds: float | None = None,
    raw_client: Any = None,
    provider: str | None = None,
    host: str | None = None,
) -> "ModelClient":
    """Shared ``ModelClient`` factory (telemetry + canonical-arg closure).

    Thin wrapper over ``tools.model_router._build_model_client`` imported
    lazily so the providers package stays import-cycle-free.
    """
    from tools.model_router import _build_model_client

    return _build_model_client(
        model_name,
        host=host,
        alias=alias,
        request_timeout_seconds=request_timeout_seconds,
        raw_client=raw_client,
        provider=provider or "",
    )
