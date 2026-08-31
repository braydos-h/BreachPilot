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
        return {
            "id": self.id,
            "name": self.display_name,
            "capabilities": self.capabilities.as_dict(),
            "configured": self.is_configured(self.provider_config(config)),
            "default_model": str(cfg.get("default_model", "")),
        }

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