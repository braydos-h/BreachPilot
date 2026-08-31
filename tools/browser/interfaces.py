"""BrowserBackend — the abstract seam a future engine must implement.

This is the ONLY interface the rest of BreachPilot will ever see for browser
control. A future Playwright/Selenium/CDP adapter implements this ABC in a
backend module; engine-specific types stay behind it exactly like
``tools/providers/base.py`` isolates Ollama/OpenAI translation behind the
provider adapters ("API-specific translation lives ENTIRELY inside the
adapter").

Contract:

- Nothing in this package launches a browser, opens a socket, or touches the
  filesystem. Implementations do — inside the future sandboxed browser worker
  (see ``docs/browser-agent-design.md`` §sandbox requirements).
- Methods return provider-neutral ``tools.browser.models`` types only. No
  Playwright/Selenium/CDP object may leak across this seam — adapters
  translate at the boundary (same rule as the provider seam: "No provider is
  required to emulate Ollama — Ollama is just one adapter").
- Every method MAY raise :class:`BrowserBackendError` subclasses; the base
  class provides no executable default — methods are ``abstractmethod`` so a
  backend must consciously implement (or reject) each operation.
- ``is_configured``/``health``/``availability`` are metadata-only and never
  launch anything, so the manager and API can probe the backend cheaply.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from tools.browser.models import (
    BrowserAction,
    BrowserArtifact,
    BrowserNetworkEvent,
    BrowserObservation,
    BrowserPageState,
    BrowserResult,
    BrowserSession,
    BrowserSessionId,
    BrowserStorageSnapshot,
)

__all__ = ["BrowserBackend"]


class BrowserBackend(ABC):
    """Abstract browser-engine backend (implemented in a LATER change).

    A backend owns its own engine lifecycle. It never touches the allowlist
    itself — the execution funnel that calls it is target-locked at the MCP
    layer (@require_allowlist) and sandboxed (see design doc §sandbox); the
    backend is the engine adapter, not the policy.
    """

    #: Stable backend id (matches ``browser.backend`` config).
    backend_id: str = ""
    display_name: str = ""
    #: ``browser.*`` capability names this backend can actually provide once
    #: configured (subset of ``tools.browser.capabilities``). Declared only —
    #: availability still requires ``browser.enabled`` + a configured backend.
    capabilities: tuple[str, ...] = ()

    # ── Metadata (never launches / never connects) ─────────────────────

    def is_configured(self, config: dict[str, Any] | None) -> bool:
        """Whether this backend has enough config (and runtime) to attempt a call.

        Default: False — no backend ships in this build, so availability is
        False until a real backend reports otherwise.
        """
        del config
        return False

    def health(self, config: dict[str, Any] | None) -> dict[str, Any]:
        """Doctor-shaped metadata check ({name, ok, detail}) — no side effects."""
        del config
        return {
            "name": f"browser_backend_{self.backend_id}",
            "ok": False,
            "detail": f"browser backend {self.backend_id!r} is declared but not implemented",
        }

    # ── Session lifecycle ──────────────────────────────────────────────

    @abstractmethod
    async def start_session(
        self,
        *,
        target: str,
        run_id: str = "",
        session_id: str = "",
        headless: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> BrowserSession:
        """Launch a backend session for the locked target and return its record."""

    @abstractmethod
    async def stop_session(self, session_id: str) -> BrowserResult:
        """Gracefully stop one session; resources must be released."""

    # ── Navigation / observation / interaction ─────────────────────────

    @abstractmethod
    async def navigate(self, session_id: str, url: str, *, timeout_seconds: float | None = None) -> BrowserResult:
        """Navigate the session (SPA- and redirect-aware)."""

    @abstractmethod
    async def observe(self, session_id: str, *, include_forms: bool = True, include_endpoints: bool = True) -> BrowserObservation:
        """Harvest a compact :class:`BrowserPageState` observation of the live page."""

    @abstractmethod
    async def execute_action(self, session_id: str, action: BrowserAction) -> BrowserResult:
        """Execute one typed :class:`BrowserAction` (JS, click, replay, ...)."""

    @abstractmethod
    async def capture_screenshot(self, session_id: str, *, artifact_path: str = "") -> BrowserArtifact:
        """Capture a full/viewport screenshot as a persisted artifact."""

    @abstractmethod
    async def get_network_events(self, session_id: str, *, limit: int = 100, after_id: str = "") -> list[BrowserNetworkEvent]:
        """Return captured network events (request/response records)."""

    @abstractmethod
    async def get_storage(self, session_id: str, *, origin: str = "") -> BrowserStorageSnapshot:
        """Harvest cookies + localStorage/sessionStorage for the current origin."""

    @abstractmethod
    async def get_page_state(self, session_id: str) -> BrowserPageState:
        """Return the current compact page state (URL/title/forms/endpoints)."""

    @abstractmethod
    async def close(self, session_id: str) -> BrowserResult:
        """Hard-close a session — terminal lifecycle transition."""