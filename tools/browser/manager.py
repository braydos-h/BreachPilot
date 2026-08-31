"""BrowserManager — the single ownership boundary for browser sessions.

The manager is the ONLY object in BreachPilot that will ever own browser
session lifecycle. In THIS change it is a pure metadata + validation seam:

it MAY
- validate lifecycle transitions (state machine in ``tools/browser/models.py``),
- allocate session ids,
- hold/serialize session metadata,
- track session ownership by run id,
- expose backend injection for tests and the future backend registry,

and it MUST NOT
- launch a browser, open sockets, visit URLs, execute JavaScript, submit
  forms, or mutate HTTP requests — every such capability delegates to the
  injected :class:`tools.browser.interfaces.BrowserBackend`, and with no
  backend injected every action fails closed with
  :class:`tools.browser.errors.BrowserBackendUnavailable`.

Fail-closed rule (sandbox discipline): "browser disabled" and "backend not
configured" produce a typed error, never a fallback that pretends a browser
exists. Nothing here can execute a browser action because the base backend
contract has no implementation in this build.
"""

from __future__ import annotations

from typing import Any

from tools.browser.errors import BrowserBackendUnavailable, BrowserSessionNotFound
from tools.browser.interfaces import BrowserBackend
from tools.browser.models import (
    BrowserAction,
    BrowserResult,
    BrowserSession,
    BrowserSessionId,
    BrowserSessionState,
    new_session_id,
    validate_session_transition,
)

__all__ = ["BrowserManager"]


class BrowserManager:
    """Session registry + lifecycle validator + backend injection seam."""

    def __init__(self, config: dict[str, Any] | None = None, *, backend: BrowserBackend | None = None) -> None:
        cfg = (config or {}).get("browser", {}) or {}
        self._cfg = dict(cfg)
        self._enabled = bool(cfg.get("enabled", False))
        self._backend_id = str(cfg.get("backend", "none") or "none")
        self._max_sessions = int(cfg.get("max_sessions", 2) or 0) or 2
        self._session_timeout_seconds = float(cfg.get("session_timeout_seconds", 300) or 300)
        self._backend = backend
        self._sessions: dict[BrowserSessionId, BrowserSession] = {}
        self._session_seq = 0

    # ── Availability / configuration (metadata only) ───────────────────

    @property
    def config(self) -> dict[str, Any]:
        """The effective browser config block (defaults coalesced)."""
        return dict(self._cfg)

    @property
    def backend_id(self) -> str:
        """Configured backend id; ``"none"`` until a real backend is configured."""
        return self._backend_id

    def available(self) -> bool:
        """Whether a configured backend is injected (never true for stock builds).

        ``BrowserManager(None)`` and any manager without an explicit
        ``backend=`` are unavailable — no launch, no error-free success.
        """
        return self._backend is not None and self._enabled

    def availability(self) -> dict[str, Any]:
        """Report block for API/system surfaces (secret-free, additive-safe)."""
        return {
            "enabled": self._enabled,
            "backend": self._backend_id,
            "available": self.available(),
            "max_sessions": self._max_sessions,
            "session_timeout_seconds": self._session_timeout_seconds,
        }

    # ── Session registry ───────────────────────────────────────────────

    def get_session(self, session_id: str) -> BrowserSession:
        session = self._sessions.get(session_id)
        if session is None:
            raise BrowserSessionNotFound(f"unknown browser session id: {session_id!r}")
        return session

    def sessions_metadata(self) -> list[dict[str, Any]]:
        """Serialized registry snapshot (deterministic per-session dicts)."""
        return [s.to_dict() for s in self._sessions.values()]

    def sessions_for_run(self, run_id: str) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self._sessions.values() if s.run_id == run_id]

    # ── Lifecycle (validation + backend delegation only) ───────────────

    def start_session(
        self,
        *,
        target_ip: str,
        run_id: str = "",
        original_target: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> BrowserSession:
        """Create a ``PENDING`` session record after availability validation.

        With the default configuration (no backend configured) this fails
        closed with :class:`BrowserBackendUnavailable` — the manager
        allocates nothing that could imply a working browser. Driving the
        actual backend start (PENDING -> STARTING -> READY) is the deferred
        async funnel's job, which composes these primitives with
        ``backend.start_session(...)``.
        """
        if not self._enabled:
            raise BrowserBackendUnavailable("browser subsystem is disabled (browser.enabled: false)")
        if not self.available():
            raise BrowserBackendUnavailable(f"browser backend {self._backend_id!r} is not available")
        if not target_ip:
            raise BrowserBackendUnavailable("browser session requires a locked target_ip")
        if (
            len([s for s in self._sessions.values() if s.state not in (BrowserSessionState.CLOSED, BrowserSessionState.FAILED)])
            >= self._max_sessions
        ):
            raise BrowserBackendUnavailable(
                f"browser session limit reached (browser.max_sessions={self._max_sessions})"
            )

        self._session_seq += 1
        session = BrowserSession(
            session_id=new_session_id(self._session_seq),
            state=BrowserSessionState.PENDING,
            run_id=run_id,
            target_ip=target_ip,
            original_target=original_target,
            backend_id=self._backend_id,
            metadata=dict(metadata or {}),
        )
        self._sessions[session.session_id] = session
        return session

    def transition(self, session_id: str, new_state: BrowserSessionState) -> BrowserSession:
        """Validate + apply one lifecycle transition on the session record."""
        session = self.get_session(session_id)
        validate_session_transition(session.state, new_state)
        session.state = new_state
        return session

    def mark_ready(self, session_id: str) -> BrowserSession:
        return self.transition(session_id, BrowserSessionState.READY)

    def mark_failed(self, session_id: str) -> BrowserSession:
        return self.transition(session_id, BrowserSessionState.FAILED)

    def stop_session(self, session_id: str) -> BrowserSession:
        """Transition a session to STOPPING (closed via :meth:`close_session`)."""
        session = self.get_session(session_id)
        if session.state in (BrowserSessionState.CLOSED, BrowserSessionState.FAILED):
            return session  # terminal states are idempotent
        return self.transition(session_id, BrowserSessionState.STOPPING)

    def close_session(self, session_id: str) -> BrowserSession:
        """Terminal close; delegating to the backend is the future path's job."""
        session = self.get_session(session_id)
        if session.state not in (BrowserSessionState.CLOSED, BrowserSessionState.FAILED):
            if session.state is not BrowserSessionState.STOPPING:
                self.transition(session_id, BrowserSessionState.STOPPING)
            self.transition(session_id, BrowserSessionState.CLOSED)
        return session

    def delegate_to_backend(self, session_id: str, method: str, action: BrowserAction | None = None) -> Any:
        """Future execution funnel: delegate an operation to the injected backend.

        In THIS build every path raises :class:`BrowserBackendUnavailable`
        (nothing is configured) — the manager structurally cannot execute a
        browser operation because no backend exists to receive it.
        """
        if not self.available():
            raise BrowserBackendUnavailable()
        self.get_session(session_id)
        del method, action  # consumed by the real delegation path (deferred)
        raise BrowserBackendUnavailable(
            f"backend {self._backend_id!r} is registered but browser execution is a deferred implementation"
        )