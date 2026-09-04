"""BrowserManager async funnel tests (working stub backend — no Chromium).

Pins the lifecycle boundary: PENDING→STARTING→READY via ``start_session_async``,
READY→ACTIVE→READY per op, crash→FAILED, timeout→READY, run ownership,
max-session enforcement, idle reaping, and deterministic per-run cleanup.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from tools.browser.errors import (
    BrowserBackendUnavailable,
    BrowserCrashed,
    BrowserScopeBlocked,
    BrowserTimeout,
    BrowserTransitionError,
)
from tools.browser.interfaces import BrowserBackend
from tools.browser.models import (
    BrowserObservation,
    BrowserObservationKind,
    BrowserPageState,
    BrowserResult,
    BrowserSession,
    BrowserSessionState,
    BrowserStorageSnapshot,
)

CONFIG = {
    "browser": {
        "enabled": True,
        "backend": "stub",
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


class WorkingBackend(BrowserBackend):
    """Minimal working backend: records calls, plays back canned models."""

    backend_id = "stub"
    display_name = "stub"
    capabilities: tuple[str, ...] = ("browser.navigate",)

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []
        self.fail_next: dict[str, Exception] = {}

    def is_configured(self, config: dict[str, Any] | None) -> bool:
        return True

    def _record(self, op: str, args: tuple, kwargs: dict) -> None:
        self.calls.append((op, args, kwargs))
        exc = self.fail_next.pop(op, None)
        if exc is not None:
            raise exc

    async def start_session(self, *, target, run_id="", session_id="", headless=True, metadata=None):
        self._record("start_session", (), {"target": target, "session_id": session_id})
        return BrowserSession(session_id=session_id or "bs-stub", state=BrowserSessionState.STARTING,
                              run_id=run_id, target_ip=target, backend_id=self.backend_id)

    async def stop_session(self, session_id):
        self._record("stop_session", (session_id,), {})
        return BrowserResult(success=True, session_id=session_id)

    async def navigate(self, session_id, url, *, timeout_seconds=None):
        self._record("navigate", (session_id, url), {"timeout_seconds": timeout_seconds})
        return BrowserResult(success=True, session_id=session_id,
                             metadata={"final_url": url, "status_code": 200})

    async def observe(self, session_id, *, include_forms=True, include_endpoints=True):
        self._record("observe", (session_id,), {})
        return BrowserObservation(observation_id="obs-1", session_id=session_id,
                                  kind=BrowserObservationKind.PAGE_STATE, url="http://10.0.0.50/",
                                  payload={"title": "t"})

    async def execute_action(self, session_id, action):
        self._record("execute_action", (session_id,), {})
        return BrowserResult(success=True, session_id=session_id)

    async def capture_screenshot(self, session_id, *, artifact_path=""):
        self._record("capture_screenshot", (session_id,), {})
        from tools.browser.models import BrowserArtifact

        return BrowserArtifact(artifact_id="ba-1", session_id=session_id, path=artifact_path or "s.png")

    async def get_network_events(self, session_id, *, limit=100, after_id=""):
        self._record("get_network_events", (session_id,), {})
        return []

    async def get_storage(self, session_id, *, origin=""):
        self._record("get_storage", (session_id,), {})
        return BrowserStorageSnapshot(origin=origin, session_id=session_id)

    async def get_page_state(self, session_id):
        self._record("get_page_state", (session_id,), {})
        return BrowserPageState(session_id=session_id, url="http://10.0.0.50/")

    async def close(self, session_id):
        self._record("close", (session_id,), {})
        return BrowserResult(success=True, session_id=session_id)


def _manager(**browser_overrides: Any):
    from tools.browser.manager import BrowserManager

    cfg = {"browser": {**CONFIG["browser"], **browser_overrides}}
    return BrowserManager(cfg, backend=WorkingBackend())


def test_start_async_drives_pending_to_ready():
    manager = _manager()
    session = asyncio.run(manager.start_session_async(target_ip="10.0.0.50", run_id="run-1"))
    assert session.state is BrowserSessionState.READY
    assert session.target_ip == "10.0.0.50"
    assert session.run_id == "run-1"
    assert session.backend_id == "stub"


def test_start_async_validates_before_allocating():
    manager = _manager()
    with pytest.raises(BrowserBackendUnavailable):
        asyncio.run(manager.start_session_async(target_ip=""))
    assert manager.sessions_metadata() == []


def test_start_async_marks_failed_when_backend_dies():
    manager = _manager()
    assert isinstance(manager.backend, WorkingBackend)
    manager.backend.fail_next["start_session"] = BrowserCrashed("boom")
    with pytest.raises(BrowserCrashed):
        asyncio.run(manager.start_session_async(target_ip="10.0.0.50"))
    metas = manager.sessions_metadata()
    assert len(metas) == 1
    assert metas[0]["state"] == "failed"


def test_run_op_guards_and_syncs_url():
    manager = _manager()
    session = asyncio.run(manager.start_session_async(target_ip="10.0.0.50", run_id="run-1"))
    result = asyncio.run(manager.run_op(session.session_id, "navigate", run_id="run-1", url="http://10.0.0.50/a"))
    assert result.success is True
    assert manager.get_session(session.session_id).state is BrowserSessionState.READY
    assert manager.get_session(session.session_id).last_url == "http://10.0.0.50/a"


def test_run_op_rejects_cross_run_use():
    manager = _manager()
    session = asyncio.run(manager.start_session_async(target_ip="10.0.0.50", run_id="run-1"))
    with pytest.raises(BrowserScopeBlocked):
        asyncio.run(manager.run_op(session.session_id, "navigate", run_id="run-2", url="http://10.0.0.50/"))


def test_run_op_rejects_bad_state_and_unknown_op():
    manager = _manager()
    pending = manager.start_session(target_ip="10.0.0.50")  # sync: stays PENDING
    with pytest.raises(BrowserTransitionError):
        asyncio.run(manager.run_op(pending.session_id, "navigate", url="http://10.0.0.50/"))
    session = asyncio.run(manager.start_session_async(target_ip="10.0.0.50"))
    with pytest.raises(BrowserBackendUnavailable):
        asyncio.run(manager.run_op(session.session_id, "teleport"))


def test_run_op_crash_marks_failed_but_timeout_keeps_ready():
    manager = _manager()
    crashed = asyncio.run(manager.start_session_async(target_ip="10.0.0.50"))
    assert isinstance(manager.backend, WorkingBackend)
    manager.backend.fail_next["navigate"] = BrowserCrashed("worker died")
    with pytest.raises(BrowserCrashed):
        asyncio.run(manager.run_op(crashed.session_id, "navigate", url="http://10.0.0.50/"))
    assert manager.get_session(crashed.session_id).state is BrowserSessionState.FAILED

    manager2 = _manager()
    timed = asyncio.run(manager2.start_session_async(target_ip="10.0.0.50"))
    assert isinstance(manager2.backend, WorkingBackend)
    manager2.backend.fail_next["navigate"] = TimeoutError("slow page")
    with pytest.raises(BrowserTimeout):
        asyncio.run(manager2.run_op(timed.session_id, "navigate", url="http://10.0.0.50/"))
    assert manager2.get_session(timed.session_id).state is BrowserSessionState.READY


def test_close_is_idempotent_and_deterministic_per_run():
    manager = _manager(max_sessions=5)
    keep = asyncio.run(manager.start_session_async(target_ip="10.0.0.50", run_id="run-keep"))
    first = asyncio.run(manager.start_session_async(target_ip="10.0.0.50", run_id="run-1"))
    second = asyncio.run(manager.start_session_async(target_ip="10.0.0.51", run_id="run-1"))
    closed = asyncio.run(manager.close_all_for_run("run-1"))
    assert sorted(closed) == sorted([first.session_id, second.session_id])
    assert manager.get_session(first.session_id).state is BrowserSessionState.CLOSED
    assert manager.get_session(keep.session_id).state is BrowserSessionState.READY
    # Idempotent: closing again returns the terminal record without backend calls.
    assert isinstance(manager.backend, WorkingBackend)
    calls_before = len(manager.backend.calls)
    asyncio.run(manager.close_session_async(first.session_id))
    assert len(manager.backend.calls) == calls_before


def test_max_sessions_enforced_on_async_start():
    manager = _manager(max_sessions=1)
    asyncio.run(manager.start_session_async(target_ip="10.0.0.50"))
    with pytest.raises(BrowserBackendUnavailable, match="session limit"):
        asyncio.run(manager.start_session_async(target_ip="10.0.0.51"))


def test_reap_idle_closes_stale_sessions():
    import time as _time

    manager = _manager(session_timeout_seconds=60)
    stale = asyncio.run(manager.start_session_async(target_ip="10.0.0.50"))
    fresh = asyncio.run(manager.start_session_async(target_ip="10.0.0.51"))
    manager._last_active[stale.session_id] = _time.monotonic() - 3600
    assert manager.idle_sessions() == [stale.session_id]
    reaped = asyncio.run(manager.reap_idle())
    assert reaped == [stale.session_id]
    assert manager.get_session(stale.session_id).state is BrowserSessionState.CLOSED
    assert manager.get_session(fresh.session_id).state is BrowserSessionState.READY
