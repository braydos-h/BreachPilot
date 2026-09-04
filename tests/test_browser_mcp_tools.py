"""Browser MCP tool tests (fake launcher — no Chromium, no Docker).

Pins single-source registration (conditional on real availability), the
target-IP lock at the tool layer, the mutating-action gate, deferred
replay/submit, headed-sandbox refusal, and the strict no-host-fallback rule.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import tools.mcp_tools.browser as browser_mod
from tools.kernel.audit import make_audit_tool, make_require_allowlist

ALLOW_CONFIG = {
    "exploit": {"require_explicit_allowlist": True, "allowed_targets": ["10.0.0.50"]},
    "browser": {
        "enabled": True,
        "backend": "playwright",
        "headless": True,
        "max_sessions": 5,
        "session_timeout_seconds": 60,
        "navigation_timeout_seconds": 10,
        "capture_screenshots": True,
        "capture_network": True,
        "capture_console": False,
        "persist_storage": False,
        "allow_mutating_actions": False,
    },
}


class FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self):  # noqa: ANN001, ANN202 — mirrors the FastMCP decorator shape
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn

        return deco


class FakeCtx:
    def __init__(self, workspace: Path, config: dict[str, Any], *, sandbox: Any = None) -> None:
        self.workspace = workspace
        self.config = config
        # NOTE: no ``sandbox`` attribute unless passed — manager_from_ctx then
        # resolves None, exactly like a sandbox-disabled server.
        if sandbox is not None:
            self.sandbox = sandbox
        self.audit_tool = make_audit_tool(workspace)
        self.require_allowlist = make_require_allowlist(workspace, config)


class FakeLauncher:
    kind = "fake"

    def __init__(self) -> None:
        self.tokens: set[str] = set()

    async def launch(self, *, headless: bool = True, capture_console: bool = False) -> str:
        del headless, capture_console
        token = f"mcp-fake-{len(self.tokens)}"
        self.tokens.add(token)
        return token

    async def navigate(self, token: str, url: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        del token, timeout_ms, target_ip
        return {"url": url, "final_url": url, "status": 200, "redirect_chain": [url], "blocked_popups": 0}

    async def snapshot(self, token: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        del token, timeout_ms, target_ip
        return {
            "url": "http://10.0.0.50/",
            "title": "Target App",
            "text": "welcome to the target app console dashboard",
            "forms": [{"action": "/login", "method": "post", "inputs": [{"name": "user", "type": "text"}]}],
            "scripts": ["/static/app.js"],
            "head": "",
            "cookies": [{"name": "session", "value": "abc"}],
            "local_storage": {},
            "session_storage": {},
        }

    async def evaluate(self, token: str, expression: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        del token, timeout_ms, target_ip
        return {"ok": True, "value": f"eval:{expression[:50]}", "truncated": False}

    async def screenshot(
        self, token: str, *, full_page: bool = False, timeout_ms: int = 30000, target_ip: str = ""
    ) -> bytes:
        del token, full_page, timeout_ms, target_ip
        return b"\x89PNG\r\n\x1a\n" + b"\x00" * 16

    async def take_network(self, token: str, *, body_sample_max_bytes: int = 4096, target_ip: str = "") -> list[dict]:
        del token, body_sample_max_bytes, target_ip
        return []

    def drain_console(self, token: str) -> list[dict]:
        del token
        return []

    async def close(self, token: str) -> None:
        self.tokens.discard(token)


@pytest.fixture(autouse=True)
def _clean_browser_state():
    from tools.browser.capabilities import BACKEND_REGISTRY

    BACKEND_REGISTRY.pop("playwright", None)
    browser_mod._MANAGERS.clear()
    browser_mod._BACKENDS.clear()
    yield
    BACKEND_REGISTRY.pop("playwright", None)
    browser_mod._MANAGERS.clear()
    browser_mod._BACKENDS.clear()


def _register(config: dict[str, Any], workspace: Path, **ctx_kwargs: Any) -> tuple[FakeMCP, FakeCtx]:
    import copy

    mcp, ctx = FakeMCP(), FakeCtx(workspace, copy.deepcopy(config), **ctx_kwargs)
    browser_mod.register_browser_tools(mcp, ctx=ctx)
    return mcp, ctx


def test_no_registration_when_disabled(tmp_path):
    import copy

    config = copy.deepcopy(ALLOW_CONFIG)
    config["browser"]["enabled"] = False
    mcp, _ctx = _register(config, tmp_path)
    assert mcp.tools == {}


def test_no_registration_when_runtime_unavailable(tmp_path, monkeypatch):
    """SDK absent + sandbox disabled: declared but not runnable registers nothing."""
    from tools.browser import playwright_backend as _mod

    monkeypatch.setattr(_mod, "playwright_present", lambda: False)
    mcp, _ctx = _register(ALLOW_CONFIG, tmp_path)
    assert mcp.tools == {}


def test_registration_when_host_sdk_present(tmp_path, monkeypatch):
    from tools.browser import playwright_backend as _mod

    monkeypatch.setattr(_mod, "playwright_present", lambda: True)
    mcp, _ctx = _register(ALLOW_CONFIG, tmp_path)
    assert set(mcp.tools) == {
        "browser_start",
        "browser_navigate",
        "browser_observe",
        "browser_page_state",
        "browser_network_events",
        "browser_storage",
        "browser_screenshot",
        "browser_execute_js",
        "browser_discover_forms",
        "browser_discover_endpoints",
        "browser_close",
        "browser_replay",
        "browser_submit",
    }


def test_start_navigate_observe_close_flow(tmp_path, monkeypatch):
    import tools.browser.sandbox_launcher as _launcher_mod

    monkeypatch.setattr(_launcher_mod, "resolve_browser_launcher", lambda ctx, config: (FakeLauncher(), ""))
    from tools.browser import playwright_backend as _mod

    monkeypatch.setattr(_mod, "playwright_present", lambda: True)
    mcp, _ctx = _register(ALLOW_CONFIG, tmp_path)
    assert "browser_start" in mcp.tools

    started = mcp.tools["browser_start"]("10.0.0.50")
    assert started.startswith("SESSION_STARTED: ")
    session_id = started.split("SESSION_STARTED: ")[1].splitlines()[0].strip()

    navigated = mcp.tools["browser_navigate"]("10.0.0.50", session_id, "http://10.0.0.50/login")
    assert navigated.startswith("NAVIGATED: http://10.0.0.50/login")

    observed = mcp.tools["browser_observe"]("10.0.0.50", session_id)
    assert "Target App" in observed
    assert "FORMS: 1" in observed

    shot = mcp.tools["browser_screenshot"]("10.0.0.50", session_id)
    assert shot.startswith("SCREENSHOT: ")
    assert "SHA256: " in shot

    closed = mcp.tools["browser_close"]("10.0.0.50", session_id)
    assert closed == f"SESSION_CLOSED: {session_id}"


def test_target_lock_blocks_disallowed_target_and_url(tmp_path, monkeypatch):
    import tools.browser.sandbox_launcher as _launcher_mod

    monkeypatch.setattr(_launcher_mod, "resolve_browser_launcher", lambda ctx, config: (FakeLauncher(), ""))
    from tools.browser import playwright_backend as _mod

    monkeypatch.setattr(_mod, "playwright_present", lambda: True)
    mcp, _ctx = _register(ALLOW_CONFIG, tmp_path)

    denied = mcp.tools["browser_navigate"]("10.0.0.99", "bs-1", "http://10.0.0.99/")
    assert denied.startswith("BLOCKED:")

    started = mcp.tools["browser_start"]("10.0.0.50")
    session_id = started.split("SESSION_STARTED: ")[1].splitlines()[0].strip()
    oos = mcp.tools["browser_navigate"]("10.0.0.50", session_id, "http://evil.example.com/")
    assert oos.startswith("BLOCKED:")


def test_execute_js_gated_by_default(tmp_path, monkeypatch):
    import tools.browser.sandbox_launcher as _launcher_mod

    monkeypatch.setattr(_launcher_mod, "resolve_browser_launcher", lambda ctx, config: (FakeLauncher(), ""))
    from tools.browser import playwright_backend as _mod

    monkeypatch.setattr(_mod, "playwright_present", lambda: True)
    mcp, _ctx = _register(ALLOW_CONFIG, tmp_path)
    started = mcp.tools["browser_start"]("10.0.0.50")
    session_id = started.split("SESSION_STARTED: ")[1].splitlines()[0].strip()
    assert "allow_mutating_actions" in mcp.tools["browser_execute_js"]("10.0.0.50", session_id, "1+1")


def test_execute_js_allowed_with_opt_in(tmp_path, monkeypatch):
    import copy

    import tools.browser.sandbox_launcher as _launcher_mod

    monkeypatch.setattr(_launcher_mod, "resolve_browser_launcher", lambda ctx, config: (FakeLauncher(), ""))
    from tools.browser import playwright_backend as _mod

    monkeypatch.setattr(_mod, "playwright_present", lambda: True)
    config = copy.deepcopy(ALLOW_CONFIG)
    config["browser"]["allow_mutating_actions"] = True
    mcp, _ctx = _register(config, tmp_path)
    started = mcp.tools["browser_start"]("10.0.0.50")
    session_id = started.split("SESSION_STARTED: ")[1].splitlines()[0].strip()
    assert mcp.tools["browser_execute_js"]("10.0.0.50", session_id, "1+1").startswith("JS_RESULT: ")


def test_replay_and_submit_always_deferred(tmp_path, monkeypatch):
    from tools.browser import playwright_backend as _mod

    monkeypatch.setattr(_mod, "playwright_present", lambda: True)
    mcp, _ctx = _register(ALLOW_CONFIG, tmp_path)
    assert "deferred" in mcp.tools["browser_replay"]().lower()
    assert "deferred" in mcp.tools["browser_submit"]().lower()


def test_headed_refused_in_sandbox(tmp_path, monkeypatch):
    class SandboxFake(FakeLauncher):
        kind = "sandbox_worker"

    import tools.browser.sandbox_launcher as _launcher_mod

    monkeypatch.setattr(_launcher_mod, "resolve_browser_launcher", lambda ctx, config: (SandboxFake(), ""))
    from tools.browser import playwright_backend as _mod

    monkeypatch.setattr(_mod, "playwright_present", lambda: True)
    mcp, _ctx = _register(ALLOW_CONFIG, tmp_path)
    assert "headless" in mcp.tools["browser_start"]("10.0.0.50", headless=False).lower()


def test_strict_no_host_fallback_when_sandbox_unusable(tmp_path):
    """Sandbox enabled but no manager attached: SANDBOX_* block, never host Chromium."""
    import copy

    config = copy.deepcopy(ALLOW_CONFIG)
    config["sandbox"] = {"enabled": True}
    from tools.browser.capabilities import register_playwright_backend

    # Registration itself succeeds (a configured sandbox counts as runnable)...
    register_playwright_backend(config)
    mcp, _ctx = _register(config, tmp_path)
    assert "browser_start" in mcp.tools
    # ...but execution refuses the host fallback.
    result = mcp.tools["browser_start"]("10.0.0.50")
    assert "SANDBOX" in result
    assert "fallback" in result.lower()
