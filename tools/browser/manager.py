"""BrowserManager — the single ownership boundary for browser sessions.

The manager is the ONLY object in BreachPilot that will ever own browser
session lifecycle. It

it MAY
- validate lifecycle transitions (state machine in ``tools/browser/models.py``),
- allocate session ids,
- hold/serialize session metadata,
- track session ownership by run id,
- expose backend injection for tests and the future backend registry,
- drive the async execution funnel (``start_session_async`` / ``run_op`` /
  ``close_session_async``) composing transitions with backend calls,

and it MUST NOT
- launch a browser, open sockets, visit URLs, execute JavaScript, submit
  forms, or mutate HTTP requests itself — every such capability delegates to
  the injected :class:`tools.browser.interfaces.BrowserBackend`, and with no
  backend injected every action fails closed with
  :class:`tools.browser.errors.BrowserBackendUnavailable`.

Fail-closed rule (sandbox discipline): "browser disabled" and "backend not
configured" produce a typed error, never a fallback that pretends a browser
exists. The backend never touches the allowlist; the MCP layer calling this
funnel is target-locked and sandboxed.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from tools.browser.errors import (
    BrowserBackendUnavailable,
    BrowserScopeBlocked,
    BrowserSessionNotFound,
    BrowserTimeout,
    BrowserTransitionError,
)
from tools.browser.interfaces import BrowserBackend
from tools.browser.models import (
    BrowserAction,
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
        self._locks: dict[BrowserSessionId, asyncio.Lock] = {}
        self._last_active: dict[BrowserSessionId, float] = {}

    # ── Availability / configuration (metadata only) ───────────────────

    @property
    def config(self) -> dict[str, Any]:
        """The effective browser config block (defaults coalesced)."""
        return dict(self._cfg)

    @property
    def backend(self) -> BrowserBackend | None:
        """The injected backend (None until one is attached)."""
        return self._backend

    def attach_backend(self, backend: BrowserBackend | None) -> None:
        """(Re)attach the engine backend; sessions survive the swap."""
        self._backend = backend

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
            len(
                [
                    s
                    for s in self._sessions.values()
                    if s.state not in (BrowserSessionState.CLOSED, BrowserSessionState.FAILED)
                ]
            )
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
        """Deprecated sync shim — the async funnel is :meth:`run_op`.

        Kept (raising) so stale callers fail closed with a typed error instead
        of silently doing nothing. New code must ``await manager.run_op(...)``.
        """
        del session_id, method, action  # consumed by run_op (async)
        raise BrowserBackendUnavailable(
            "browser delegation is async-only in this build; await BrowserManager.run_op() instead"
        )

    # ── Ownership ──────────────────────────────────────────────────────

    def _check_owner(self, session: BrowserSession, run_id: str) -> None:
        """Deny cross-run session use (scope_blocked, never a silent share)."""
        if run_id and session.run_id and session.run_id != run_id:
            raise BrowserScopeBlocked(
                f"browser session {session.session_id!r} is owned by run {session.run_id!r}"
            )

    def _op_lock(self, session_id: str) -> asyncio.Lock:
        lock = self._locks.get(session_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[session_id] = lock
        return lock

    # ── Async execution funnel (manager transitions + backend calls) ────

    async def start_session_async(
        self,
        *,
        target_ip: str,
        run_id: str = "",
        original_target: str = "",
        metadata: dict[str, Any] | None = None,
        headless: bool = True,
    ) -> BrowserSession:
        """Allocate PENDING, drive STARTING→READY via the backend (fail closed)."""
        await self.reap_idle()
        session = self.start_session(
            target_ip=target_ip, run_id=run_id, original_target=original_target, metadata=metadata
        )
        session_id = session.session_id
        self.transition(session_id, BrowserSessionState.STARTING)
        if self._backend is None:
            self.mark_failed(session_id)
            raise BrowserBackendUnavailable(f"browser backend {self._backend_id!r} is not available")
        try:
            record = await asyncio.wait_for(
                self._backend.start_session(
                    target=target_ip, run_id=run_id, session_id=session_id, headless=headless,
                    metadata=metadata,
                ),
                timeout=self._session_timeout_seconds,
            )
        except (asyncio.TimeoutError, TimeoutError) as exc:
            self.mark_failed(session_id)
            raise BrowserTimeout(f"browser session start timed out after {self._session_timeout_seconds:g}s") from exc
        except BrowserBackendUnavailable:
            self.mark_failed(session_id)
            raise
        except Exception as exc:  # noqa: BLE001 — backend failure marks FAILED, never half-ready
            try:
                self.mark_failed(session_id)
            except Exception:  # noqa: BLE001 — transition bookkeeping is best-effort here
                pass
            raise
        session.backend_id = record.backend_id or session.backend_id
        session.started_at = record.started_at or session.started_at
        session.last_url = record.last_url
        session.metadata.update(dict(record.metadata or {}))
        self._last_active[session_id] = time.monotonic()
        return self.mark_ready(session_id)

    async def run_op(self, session_id: str, op: str, *, run_id: str = "", timeout_seconds: float | None = None, **kwargs: Any) -> Any:
        """Run one backend op under ownership/state guards; returns its result.

        ``op`` names a :class:`BrowserBackend` coroutine (``navigate``,
        ``observe``, ``execute_action``, ``capture_screenshot``,
        ``get_network_events``, ``get_storage``, ``get_page_state``).
        Transitions READY/SUSPENDED→ACTIVE→READY; a crashed backend marks the
        session FAILED. Timeouts keep the session usable (back to READY).
        """
        session = self.get_session(session_id)
        self._check_owner(session, run_id)
        if session.state not in (
            BrowserSessionState.READY,
            BrowserSessionState.ACTIVE,
            BrowserSessionState.SUSPENDED,
        ):
            raise BrowserTransitionError(
                f"browser session {session_id!r} is {session.state.value!r}; cannot run {op!r}"
            )
        if self._backend is None or not self._enabled:
            raise BrowserBackendUnavailable(f"browser backend {self._backend_id!r} is not available")
        fn = getattr(self._backend, op, None)
        if not callable(fn):
            raise BrowserBackendUnavailable(f"browser backend has no operation {op!r}")
        bound = timeout_seconds if timeout_seconds and timeout_seconds > 0 else self._session_timeout_seconds
        async with self._op_lock(session_id):
            resume_from_active = session.state is BrowserSessionState.ACTIVE
            if not resume_from_active:
                self.transition(session_id, BrowserSessionState.ACTIVE)
            try:
                result = await asyncio.wait_for(fn(session_id, **kwargs), timeout=bound)
            except (asyncio.TimeoutError, TimeoutError) as exc:
                self.transition(session_id, BrowserSessionState.READY)
                raise BrowserTimeout(f"browser {op} timed out after {bound:g}s") from exc
            except BrowserBackendError as exc:
                if exc.code == "transport_error":
                    try:
                        self.transition(session_id, BrowserSessionState.FAILED)
                    except BrowserTransitionError:
                        pass
                    self._last_active.pop(session_id, None)
                elif session.state is BrowserSessionState.ACTIVE:
                    self.transition(session_id, BrowserSessionState.READY)
                raise
            if session.state is BrowserSessionState.ACTIVE:
                self.transition(session_id, BrowserSessionState.READY)
            self._last_active[session_id] = time.monotonic()
            self._sync_last_url(session, result)
            return result

    def _sync_last_url(self, session: BrowserSession, result: Any) -> None:
        """Best-effort mirror of the live URL onto the metadata record."""
        try:
            from tools.browser.models import BrowserObservation, BrowserPageState, BrowserResult

            url = ""
            if isinstance(result, BrowserResult):
                url = str((result.metadata or {}).get("final_url", "") or "")
            elif isinstance(result, BrowserObservation):
                url = result.url
            elif isinstance(result, BrowserPageState):
                url = result.final_url or result.url
            if url:
                session.last_url = url
        except Exception:  # noqa: BLE001 — metadata sync never breaks the funnel
            pass

    async def close_session_async(self, session_id: str, *, run_id: str = "") -> BrowserSession:
        """Best-effort backend stop+close, then the metadata STOPPING→CLOSED."""
        session = self.get_session(session_id)
        self._check_owner(session, run_id)
        if session.state in (BrowserSessionState.CLOSED, BrowserSessionState.FAILED):
            return session
        crashed = False
        if self._backend is not None:
            try:
                await asyncio.wait_for(self._backend.stop_session(session_id), timeout=30.0)
            except Exception:  # noqa: BLE001 — close path degrades to hard close
                crashed = True
            try:
                await asyncio.wait_for(self._backend.close(session_id), timeout=30.0)
            except Exception:  # noqa: BLE001 — hard close never raises
                crashed = True
        if session.state is not BrowserSessionState.STOPPING:
            try:
                self.transition(session_id, BrowserSessionState.STOPPING)
            except BrowserTransitionError:
                pass
        self._last_active.pop(session_id, None)
        self._locks.pop(session_id, None)
        try:
            return self.transition(
                session_id, BrowserSessionState.FAILED if crashed else BrowserSessionState.CLOSED
            )
        except BrowserTransitionError:
            return session

    async def close_all_for_run(self, run_id: str) -> list[str]:
        """Deterministic cleanup: close every non-terminal session of one run."""
        closed: list[str] = []
        for session in list(self._sessions.values()):
            if session.run_id != run_id:
                continue
            if session.state in (BrowserSessionState.CLOSED, BrowserSessionState.FAILED):
                continue
            try:
                await self.close_session_async(session.session_id, run_id=run_id)
                closed.append(session.session_id)
            except Exception:  # noqa: BLE001 — one bad session never blocks the sweep
                continue
        return closed

    def idle_sessions(self, *, now: float | None = None) -> list[str]:
        """Session ids idle beyond ``session_timeout_seconds`` (non-terminal)."""
        moment = now if now is not None else time.monotonic()
        idle: list[str] = []
        for session_id, last in self._last_active.items():
            session = self._sessions.get(session_id)
            if session is None:
                continue
            if session.state in (BrowserSessionState.CLOSED, BrowserSessionState.FAILED, BrowserSessionState.PENDING):
                continue
            if moment - last > self._session_timeout_seconds:
                idle.append(session_id)
        return idle

    async def reap_idle(self) -> list[str]:
        """Close idle sessions (opportunistic; called on session start)."""
        reaped: list[str] = []
        for session_id in self.idle_sessions():
            try:
                await self.close_session_async(session_id)
                reaped.append(session_id)
            except Exception:  # noqa: BLE001 — reaping never breaks the funnel
                continue
        return reaped
