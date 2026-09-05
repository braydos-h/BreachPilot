"""Browser shared-loop regression test (no Chromium).

Guards the host-mode fix in ``tools/mcp_tools/browser.py``: Playwright
connections bind to the loop that created them, so every browser coroutine
must hop onto ONE private loop. The previous ``asyncio.run(...)``-per-tool
pattern gave each call a fresh loop and every op after ``browser_start`` died
with ``'NoneType' object has no attribute 'send'``.
"""

from __future__ import annotations

import asyncio
from typing import Any

from tools.browser.interfaces import BrowserBackend
from tools.browser.manager import BrowserManager
from tools.browser.models import (
    BrowserPageState,
    BrowserResult,
    BrowserSession,
    BrowserSessionState,
)
from tools.mcp_tools.browser import _get_browser_loop, _run

CONFIG = {
    "browser": {
        "enabled": True,
        "backend": "stub",
        "max_sessions": 2,
        "session_timeout_seconds": 30,
    }
}


class LoopRecordingBackend(BrowserBackend):
    """Stub backend recording which event loop ran each call."""

    backend_id = "stub"
    display_name = "stub"

    def __init__(self) -> None:
        self.loops: dict[str, asyncio.AbstractEventLoop] = {}

    def _mark(self, op: str) -> None:
        self.loops[op] = asyncio.get_running_loop()

    async def start_session(self, *, target, run_id="", session_id="", headless=True, metadata=None):
        self._mark("start_session")
        return BrowserSession(
            session_id=session_id or "bs-stub",
            state=BrowserSessionState.STARTING,
            run_id=run_id,
            target_ip=target,
            backend_id=self.backend_id,
        )

    async def stop_session(self, session_id):
        self._mark("stop_session")
        return BrowserResult(success=True, session_id=session_id)

    async def navigate(self, session_id, url, *, timeout_seconds=None):
        self._mark("navigate")
        return BrowserResult(success=True, session_id=session_id, metadata={"final_url": url})

    async def observe(self, session_id, *, include_forms=True, include_endpoints=True):
        raise NotImplementedError

    async def execute_action(self, session_id, action):
        raise NotImplementedError

    async def capture_screenshot(self, session_id, *, artifact_path=""):
        raise NotImplementedError

    async def get_network_events(self, session_id, *, limit=100, after_id=""):
        raise NotImplementedError

    async def get_storage(self, session_id, *, origin=""):
        raise NotImplementedError

    async def get_page_state(self, session_id):
        self._mark("get_page_state")
        return BrowserPageState(session_id=session_id, url="http://127.0.0.1/")

    async def close(self, session_id):
        self._mark("close")
        return BrowserResult(success=True, session_id=session_id)


def test_sequential_ops_share_one_loop() -> None:
    """Two _run() hops (start, then op) must land on the same event loop."""
    backend = LoopRecordingBackend()
    manager = BrowserManager(CONFIG, backend=backend)
    session = _run(manager.start_session_async(target_ip="127.0.0.1", run_id="loop-test"))
    _run(manager.run_op(session.session_id, "get_page_state", run_id="loop-test"))
    assert backend.loops["start_session"] is backend.loops["get_page_state"]
    assert backend.loops["start_session"] is _get_browser_loop()


def test_loop_singleton_replaced_when_thread_dead(monkeypatch) -> None:
    """A dead loop thread must yield a fresh loop, never the orphaned one."""
    import tools.mcp_tools.browser as bmod

    first = _get_browser_loop()

    class _DeadThread:
        def is_alive(self) -> bool:
            return False

    monkeypatch.setattr(bmod, "_browser_thread", _DeadThread())
    second = _get_browser_loop()
    assert second is not first
    assert second is _get_browser_loop()


def test_run_returns_coroutine_result() -> None:
    async def _value() -> dict[str, Any]:
        return {"ok": True}

    assert _run(_value()) == {"ok": True}
