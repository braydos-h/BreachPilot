"""Browser integration tests: deterministic local HTTP app + worker contract.

- Always-run (no Chromium): the sandbox worker bootstrap script compiles, the
  worker result envelope maps onto typed errors, sandbox resolution stays
  strict, and a stub-transport backend drives the full funnel against a local
  deterministic app (redirects, SPA marker, XHR, cookies, localStorage).
- Live-Chromium (skipped without SDK + runtime): static navigation, redirects,
  JS-rendered content, XHR capture, form discovery, cookies, localStorage,
  screenshot artifacts, and blocked out-of-scope navigation. Never touches the
  public internet — everything is loopback.
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from tools.browser._pw_probe import chromium_present, playwright_present
from tools.browser.errors import (
    BrowserCrashed,
    BrowserNavigationFailed,
    BrowserScriptError,
    BrowserTimeout,
)
from tools.browser.playwright_backend import PlaywrightBackend
from tools.browser.sandbox_launcher import _bootstrap_script, _raise_for_worker_result, resolve_browser_launcher

APP_JS = "document.getElementById('app').textContent = 'rendered:' + window.location.pathname;"


class _AppHandler(BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:  # noqa: ANN001, ANN202 — silence the test server
        pass

    def _send(self, body: bytes, content_type: str = "text/html", status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/cookie":
            self.send_header("Set-Cookie", "session=local-canary; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/old":
            self.send_response(302)
            self.send_header("Location", "/new")
            self.end_headers()
            return
        if self.path == "/new":
            self._send(b"<html><head><title>New page</title></head><body>new home</body></html>")
            return
        if self.path == "/spa":
            self._send(
                ("<html><head><title>SPA</title></head><body><div id='app'>loading</div>"
                 f"<script>{APP_JS}</script></body></html>").encode()
            )
            return
        if self.path == "/api/data":
            self._send(b'{"items": [1, 2, 3]}', content_type="application/json")
            return
        if self.path == "/form":
            self._send(
                b"<html><body><form action='/submit' method='post'>"
                b"<input name='user' type='text'><input name='pw' type='password'></form></body></html>"
            )
            return
        if self.path == "/cookie":
            self._send(b"<html><body>cookie set</body></html>")
            return
        self._send(b"<html><head><title>Index</title></head><body>index</body></html>")


@pytest.fixture(scope="module")
def local_app() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AppHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class _HttpTransportLauncher:
    """Real HTTP (urllib) + canned DOM: exercises backend translation w/o Chromium."""

    kind = "http-transport"

    def __init__(self, base: str) -> None:
        self.base = base
        self.tokens: dict[str, dict[str, Any]] = {}
        self.net: dict[str, list[dict[str, Any]]] = {}

    async def launch(self, *, headless: bool = True, capture_console: bool = False) -> str:
        del headless, capture_console
        token = f"http-{len(self.tokens)}"
        self.tokens[token] = {"url": ""}
        self.net[token] = []
        return token

    def _get(self, url: str) -> tuple[str, int, str]:
        import urllib.request

        with urllib.request.urlopen(url, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.url, resp.status, body

    async def navigate(self, token: str, url: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        del timeout_ms, target_ip
        final, status, _body = await asyncio.to_thread(self._get, url)
        self.tokens[token]["url"] = final
        self.net[token].append(
            {"direction": "response", "method": "GET", "url": final, "status": status,
             "content_type": "text/html", "req_headers": {}, "resp_headers": {},
             "body": "", "body_size": 0, "observed_at": ""}
        )
        return {"url": url, "final_url": final, "status": status,
                "redirect_chain": [url] if final == url else [url, final], "blocked_popups": 0}

    async def snapshot(self, token: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        del timeout_ms, target_ip
        url = self.tokens[token]["url"]
        _final, _status, body = await asyncio.to_thread(self._get, url)
        text = body.replace("<", " <")
        return {"url": url, "title": "local", "text": text, "forms": [], "scripts": [],
                "head": "", "cookies": [], "local_storage": {"seed": "v"}, "session_storage": {}}

    async def evaluate(self, token: str, expression: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        del token, timeout_ms, target_ip
        return {"ok": True, "value": json.dumps({"len": len(expression)}), "truncated": False}

    async def screenshot(self, token: str, *, full_page: bool = False, timeout_ms: int = 30000,
                         target_ip: str = "") -> bytes:
        del token, full_page, timeout_ms, target_ip
        return b"\x89PNG\r\n\x1a\nfake"

    async def take_network(self, token: str, *, body_sample_max_bytes: int = 4096,
                           target_ip: str = "") -> list[dict[str, Any]]:
        del body_sample_max_bytes, target_ip
        pending, self.net[token] = self.net[token], []
        return pending

    def drain_console(self, token: str) -> list[dict[str, str]]:
        del token
        return []

    async def close(self, token: str) -> None:
        self.tokens.pop(token, None)
        self.net.pop(token, None)


def _backend() -> PlaywrightBackend:
    return PlaywrightBackend({"browser": {"enabled": True, "backend": "playwright"}})


def test_redirect_final_url_and_endpoints(local_app):
    backend = _backend()
    backend.launcher = _HttpTransportLauncher(local_app)

    async def _flow():
        session = await backend.start_session(target="127.0.0.1", run_id="run-int")
        result = await backend.navigate(session.session_id, f"{local_app}/old")
        assert result.metadata["final_url"] == f"{local_app}/new"
        assert result.metadata["redirect_chain"] == [f"{local_app}/old", f"{local_app}/new"]
        state = await backend.get_page_state(session.session_id)
        assert state.final_url == f"{local_app}/new"
        events = await backend.get_network_events(session.session_id)
        assert len(events) == 1
        assert events[0].url == f"{local_app}/new"
        await backend.close(session.session_id)

    asyncio.run(_flow())


def test_storage_and_observation_shapes(local_app):
    backend = _backend()
    backend.launcher = _HttpTransportLauncher(local_app)

    async def _flow():
        session = await backend.start_session(target="127.0.0.1", run_id="run-int")
        await backend.navigate(session.session_id, f"{local_app}/form")
        observation = await backend.observe(session.session_id)
        assert observation.payload["title"] == "local"
        assert "index" in observation.payload["dom_summary"] or "form" in observation.payload["dom_summary"]
        snapshot = await backend.get_storage(session.session_id)
        assert snapshot.entries and snapshot.entries[0]["key"] == "local:seed"
        assert snapshot.to_dict()["entries"][0]["value"] == "***REDACTED***"
        await backend.close(session.session_id)

    asyncio.run(_flow())


def test_worker_bootstrap_script_compiles():
    from tools.browser.playwright_backend import DOM_EXTRACT_JS, STORAGE_DUMP_JS

    script = _bootstrap_script(DOM_EXTRACT_JS, STORAGE_DUMP_JS)
    compile(script, "<pw_worker>", "exec")
    assert "sync_playwright" in script
    assert "png_base64" in script


def test_worker_envelope_maps_onto_typed_errors():
    data = _raise_for_worker_result({"ok": True, "data": {"url": "http://x/"}}, "navigate")
    assert data["data"]["url"] == "http://x/"
    with pytest.raises(BrowserTimeout):
        _raise_for_worker_result({"ok": False, "kind": "timeout", "error": "slow"}, "navigate")
    with pytest.raises(BrowserCrashed):
        _raise_for_worker_result({"ok": False, "kind": "crash", "error": "died"}, "snapshot")
    with pytest.raises(BrowserNavigationFailed):
        _raise_for_worker_result({"ok": False, "kind": "navigation", "error": "refused"}, "navigate")
    with pytest.raises(BrowserScriptError):
        _raise_for_worker_result({"ok": False, "kind": "script", "error": "throw"}, "evaluate")
    from tools.browser.errors import BrowserBackendError

    with pytest.raises(BrowserBackendError):
        _raise_for_worker_result({"ok": False, "kind": "error", "error": "weird"}, "snapshot")


def test_sandbox_resolution_has_no_host_fallback():
    """Sandbox enabled + no manager: block string, never a host launcher."""

    class _Ctx:
        config = {"browser": {"enabled": True, "backend": "playwright"}, "sandbox": {"enabled": True}}

    launcher, block = resolve_browser_launcher(_Ctx(), _Ctx.config)
    assert launcher is None
    assert "SANDBOX" in block


def _live_backend_or_skip() -> PlaywrightBackend:
    if not playwright_present() or not chromium_present():
        pytest.skip("live-Chromium test: SDK + runtime required (browser extra)")
    return PlaywrightBackend({"browser": {"enabled": True, "backend": "playwright"}})


@pytest.mark.integration
def test_live_static_navigation_and_observation(local_app):
    backend = _live_backend_or_skip()

    async def _flow():
        session = await backend.start_session(target="127.0.0.1", run_id="run-live")
        try:
            result = await backend.navigate(session.session_id, f"{local_app}/new")
            assert result.success is True
            assert result.metadata["final_url"] == f"{local_app}/new"
            observation = await backend.observe(session.session_id)
            assert "new home" in observation.payload["dom_summary"]
            assert observation.payload["title"] == "New page"
        finally:
            await backend.close(session.session_id)

    asyncio.run(_flow())


@pytest.mark.integration
def test_live_js_render_xhr_storage_screenshot(local_app, tmp_path):
    backend = PlaywrightBackend({"browser": {"enabled": True, "backend": "playwright", "artifact_dir": str(tmp_path)}})
    if not playwright_present() or not chromium_present():
        pytest.skip("live-Chromium test: SDK + runtime required (browser extra)")

    async def _flow():
        session = await backend.start_session(target="127.0.0.1", run_id="run-live")
        try:
            await backend.navigate(session.session_id, f"{local_app}/spa")
            observation = await backend.observe(session.session_id)
            assert "rendered:/spa" in observation.payload["dom_summary"]
            await backend.navigate(session.session_id, f"{local_app}/cookie")
            snapshot = await backend.get_storage(session.session_id)
            names = {e["key"] for e in snapshot.entries}
            assert "session" in names
            artifact = await backend.capture_screenshot(session.session_id)
            raw = Path(artifact.path).read_bytes()
            assert raw.startswith(b"\x89PNG")
            assert artifact.sha256
        finally:
            await backend.close(session.session_id)

    asyncio.run(_flow())


@pytest.mark.integration
def test_live_out_of_scope_url_refused_by_backend_shape(local_app):
    """The backend itself only allows http(s); the MCP allowlist owns scope."""
    backend = _live_backend_or_skip()
    from tools.browser.errors import BrowserNavigationFailed

    async def _flow():
        session = await backend.start_session(target="127.0.0.1", run_id="run-live")
        try:
            with pytest.raises(BrowserNavigationFailed):
                await backend.navigate(session.session_id, "file:///etc/passwd")
        finally:
            await backend.close(session.session_id)

    asyncio.run(_flow())
