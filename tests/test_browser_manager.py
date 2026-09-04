"""BrowserManager lifecycle + fail-closed tests (architecture-only build).

The manager is the single ownership boundary for browser sessions. These tests
pin the fail-closed guarantee: with the stock configuration the manager can
never start a session, never delegate an operation, and every failure is a
typed error — never a silent fallback that pretends a browser exists.
"""

from __future__ import annotations

import asyncio

import pytest

from tools.browser import BrowserManager, BrowserSessionState
from tools.browser.errors import (
    BrowserBackendError,
    BrowserBackendUnavailable,
    BrowserSessionNotFound,
    BrowserTransitionError,
)
from tools.browser.interfaces import BrowserBackend
from tools.browser.models import BrowserAction

# Stock config = exactly what ships (architecture-only: no backend exists).
STOCK_CONFIG = {
    "browser": {
        "enabled": False,
        "backend": "none",
        "headless": True,
        "max_sessions": 2,
        "session_timeout_seconds": 300,
        "navigation_timeout_seconds": 30,
        "capture_screenshots": True,
        "capture_network": True,
        "capture_console": False,
        "persist_storage": False,
    }
}


def _stub_backend(backend_id: str = "stub") -> BrowserBackend:
    """A concrete-but-inert backend: implements the ABC, executes nothing."""
    from tools.browser.errors import BrowserBackendNotImplemented

    def _raising(fn_name):
        async def _fn(*args, **kwargs):
            raise BrowserBackendNotImplemented(fn_name, backend_id)

        return _fn

    namespace: dict = {"backend_id": backend_id}
    for name in (
        "start_session",
        "stop_session",
        "navigate",
        "observe",
        "execute_action",
        "capture_screenshot",
        "get_network_events",
        "get_storage",
        "get_page_state",
        "close",
    ):
        namespace[name] = staticmethod(_raising(name))
    return type("_StubBrowserBackend", (BrowserBackend,), namespace)()


# ── Fail-closed availability ──────────────────────────────────────────────


def test_default_config_reports_unavailable():
    for config in (None, {}, STOCK_CONFIG):
        manager = BrowserManager(config)
        assert manager.available() is False
        report = manager.availability()
        assert report == {
            "enabled": False,
            "backend": "none",
            "available": False,
            "max_sessions": 2,
            "session_timeout_seconds": 300,
        }


@pytest.mark.parametrize(
    "config",
    [
        {},  # no browser block at all behaves like the disabled default
        {"browser": {"enabled": False, "backend": "playwright"}},
        {"browser": {"enabled": True, "backend": "none"}},
        {"browser": {"enabled": True, "backend": "playwright"}},  # declared ≠ available
    ],
)
def test_start_session_fails_closed_without_backend(config):
    manager = BrowserManager(config)
    with pytest.raises(BrowserBackendUnavailable):
        manager.start_session(target_ip="10.0.0.50")


def test_start_session_requires_a_locked_target():
    manager = BrowserManager(
        {**STOCK_CONFIG, "browser": {**STOCK_CONFIG["browser"], "enabled": True}}, backend=_stub_backend()
    )
    with pytest.raises(BrowserBackendUnavailable):
        manager.start_session(target_ip="")


# ── Lifecycle validation ──────────────────────────────────────────────────


def test_session_lifecycle_with_stub_backend():
    manager = BrowserManager(
        {**STOCK_CONFIG, "browser": {**STOCK_CONFIG["browser"], "enabled": True}}, backend=_stub_backend()
    )
    assert manager.available() is True

    session = manager.start_session(target_ip="10.0.0.50", run_id="run-1")
    assert session.state is BrowserSessionState.PENDING
    assert session.target_ip == "10.0.0.50"
    assert session.run_id == "run-1"
    assert session.session_id.startswith("bs-0001-")

    # The manager only validates transitions; driving the backend start is the
    # deferred async funnel's job — the stub is never invoked here. The funnel
    # would compose PENDING -> STARTING -> READY; validation requires that path.
    starting = manager.transition(session.session_id, BrowserSessionState.STARTING)
    assert starting.state is BrowserSessionState.STARTING
    ready = manager.mark_ready(session.session_id)
    assert ready.state is BrowserSessionState.READY
    active = manager.transition(session.session_id, BrowserSessionState.ACTIVE)
    assert active.state is BrowserSessionState.ACTIVE

    closed = manager.close_session(session.session_id)
    assert closed.state is BrowserSessionState.CLOSED
    # Terminal close is idempotent.
    assert manager.close_session(session.session_id).state is BrowserSessionState.CLOSED

    assert [s["state"] for s in manager.sessions_metadata()] == ["closed"]
    assert manager.sessions_for_run("run-1") == manager.sessions_metadata()
    assert manager.sessions_for_run("other-run") == []


def test_unknown_session_raises_typed_error():
    manager = BrowserManager(STOCK_CONFIG)
    with pytest.raises(BrowserSessionNotFound):
        manager.get_session("bs-9999-doesnotexist")


def test_invalid_transition_is_rejected_and_recorded_not_applied():
    manager = BrowserManager(
        {**STOCK_CONFIG, "browser": {**STOCK_CONFIG["browser"], "enabled": True}}, backend=_stub_backend()
    )
    session = manager.start_session(target_ip="10.0.0.50")
    with pytest.raises(BrowserTransitionError):
        manager.mark_ready(session.session_id)  # PENDING must pass through STARTING
    assert manager.get_session(session.session_id).state is BrowserSessionState.PENDING


def test_max_sessions_cap_enforced():
    cfg = {**STOCK_CONFIG, "browser": {**STOCK_CONFIG["browser"], "enabled": True, "max_sessions": 1}}
    manager = BrowserManager(cfg, backend=_stub_backend())
    first = manager.start_session(target_ip="10.0.0.50")
    assert first.state is BrowserSessionState.PENDING
    with pytest.raises(BrowserBackendUnavailable):
        manager.start_session(target_ip="10.0.0.50")
    # Closing releases the slot.
    manager.close_session(first.session_id)
    assert manager.start_session(target_ip="10.0.0.50") is not None


# ── Delegation is async-only (the run_op funnel) ───────────────────────────


def test_delegate_to_backend_points_at_the_async_funnel():
    """The sync shim fails closed and directs callers to run_op()."""
    manager = BrowserManager(
        {**STOCK_CONFIG, "browser": {**STOCK_CONFIG["browser"], "enabled": True}}, backend=_stub_backend()
    )
    session = manager.start_session(target_ip="10.0.0.50")
    manager.transition(session.session_id, BrowserSessionState.STARTING)
    manager.mark_ready(session.session_id)
    with pytest.raises(BrowserBackendError, match="async-only"):
        manager.delegate_to_backend(
            session.session_id, "navigate", BrowserAction(action_id="a-1", session_id=session.session_id)
        )


def test_delegate_to_backend_without_session_or_availability():
    manager = BrowserManager(STOCK_CONFIG)
    with pytest.raises(BrowserBackendUnavailable):
        manager.delegate_to_backend("bs-9999-x", "navigate", None)


def test_stub_backend_never_executes():
    backend = _stub_backend()
    with pytest.raises(BrowserBackendError, match="deferred implementation"):
        asyncio.run(backend.navigate("s-1", "http://127.0.0.1/"))
    assert backend.is_configured({}) is False  # inert stub can never claim availability
