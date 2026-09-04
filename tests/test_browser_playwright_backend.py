"""PlaywrightBackend unit tests (mocked launcher — no Chromium, no network).

The launcher seam lets every translation path run without the Playwright SDK:
``InProcessPlaywrightLauncher`` is never touched here, so this file is green
on stock installs. Real-Chromium coverage lives in
``tests/test_browser_integration.py`` (skipped without SDK + runtime).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from tools.browser.errors import (
    BrowserBackendUnavailable,
    BrowserCrashed,
    BrowserNavigationFailed,
    BrowserTimeout,
)
from tools.browser.models import (
    BrowserAction,
    BrowserActionKind,
    BrowserFailureClass,
    BrowserObservationKind,
    BrowserSessionState,
)
from tools.browser.playwright_backend import PlaywrightBackend

SECRET = "sk-CANARY-SESSION-TOKEN-abcdef123456"


class FakeLauncher:
    """Scriptable launcher: canned snapshot/network, injectable failures."""

    kind = "fake"

    def __init__(self) -> None:
        self.tokens: dict[str, dict[str, Any]] = {}
        self.closed: list[str] = []
        self.fail: dict[str, Exception] = {}
        self._network_armed = True

    async def launch(self, *, headless: bool = True, capture_console: bool = False) -> str:
        del headless, capture_console
        token = f"fake-{len(self.tokens)}"
        self.tokens[token] = {"url": ""}
        return token

    def _maybe_fail(self, op: str) -> None:
        exc = self.fail.get(op)
        if exc is not None:
            raise exc

    async def navigate(self, token: str, url: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        del timeout_ms, target_ip
        self._maybe_fail("navigate")
        final = url.replace("/old", "/new") if "/old" in url else url
        self.tokens[token]["url"] = final  # live pages report the post-redirect URL
        return {"url": url, "final_url": final, "status": 200, "redirect_chain": [url, final], "blocked_popups": 1}

    async def snapshot(self, token: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        del timeout_ms, target_ip
        self._maybe_fail("snapshot")
        url = self.tokens[token]["url"] or "http://10.0.0.50/"
        big_text = "lorem ipsum dolor sit amet " * 2000
        forms = [{"action": f"/f{i}", "method": "post", "inputs": [{"name": "u", "type": "text"}]} for i in range(60)]
        return {
            "url": url,
            "title": "Login — target app",
            "text": big_text,
            "forms": forms,
            "scripts": [f"https://cdn.example.com/app{i}.js" for i in range(120)],
            "head": '<html><head><meta name="generator" content="WordPress 6.4" /></head>',
            "cookies": [{"name": "session", "value": SECRET, "domain": "10.0.0.50"}],
            "local_storage": {"auth_token": SECRET, "theme": "dark"},
            "session_storage": {},
        }

    async def evaluate(self, token: str, expression: str, timeout_ms: int, *, target_ip: str = "") -> dict[str, Any]:
        del token, timeout_ms, target_ip
        self._maybe_fail("evaluate")
        rendered = json.dumps({"echo": expression, "token": SECRET})
        return {"ok": True, "value": rendered, "truncated": False}

    async def screenshot(
        self, token: str, *, full_page: bool = False, timeout_ms: int = 30000, target_ip: str = ""
    ) -> bytes:
        del token, full_page, timeout_ms, target_ip
        self._maybe_fail("screenshot")
        return b"\x89PNG\r\n\x1a\n" + b"\x00" * 64

    async def take_network(
        self, token: str, *, body_sample_max_bytes: int = 4096, target_ip: str = ""
    ) -> list[dict[str, Any]]:
        del token, body_sample_max_bytes, target_ip
        self._maybe_fail("take_network")
        if not self._network_armed:
            return []
        self._network_armed = False
        return [
            {
                "direction": "request",
                "method": "POST",
                "url": "http://10.0.0.50/api/login",
                "req_headers": {"Authorization": f"Bearer {SECRET}", "Content-Type": "application/json"},
                "resource_type": "xhr",
                "observed_at": "2026-01-01T00:00:00+00:00",
            },
            {
                "direction": "response",
                "method": "POST",
                "url": "http://10.0.0.50/api/login",
                "status": 200,
                "content_type": "application/json",
                "req_headers": {},
                "resp_headers": {"Set-Cookie": f"session={SECRET}; Path=/"},
                "body": json.dumps({"password": SECRET, "ok": True}),
                "body_size": 64,
                "timing_ms": 12.5,
                "observed_at": "2026-01-01T00:00:01+00:00",
            },
        ]

    def drain_console(self, token: str) -> list[dict[str, str]]:
        del token
        return []

    async def close(self, token: str) -> None:
        self.closed.append(token)
        self.tokens.pop(token, None)


def _backend(**overrides: Any) -> PlaywrightBackend:
    cfg = {"browser": {"enabled": True, "backend": "playwright", **overrides}}
    return PlaywrightBackend(cfg, launcher=FakeLauncher())


async def _started(backend: PlaywrightBackend, target: str = "10.0.0.50") -> str:
    session = await backend.start_session(target=target, run_id="run-1")
    assert session.state is BrowserSessionState.STARTING
    return session.session_id


def test_start_requires_a_locked_target():
    backend = _backend()
    with pytest.raises(BrowserBackendUnavailable):
        asyncio.run(backend.start_session(target=""))


def test_start_without_sdk_fails_closed(monkeypatch):
    from tools.browser import playwright_backend as _mod

    monkeypatch.setattr(_mod, "playwright_present", lambda: False)
    backend = PlaywrightBackend({"browser": {"enabled": True, "backend": "playwright"}})
    with pytest.raises(BrowserBackendUnavailable, match="[Bb]rowser"):
        asyncio.run(backend.start_session(target="10.0.0.50"))


def test_full_read_flow(tmp_path):
    backend = _backend(artifact_dir=str(tmp_path / "artifacts"))
    sid = asyncio.run(_started(backend))

    result = asyncio.run(backend.navigate(sid, "http://10.0.0.50/old"))
    assert result.success is True
    assert result.metadata["final_url"] == "http://10.0.0.50/new"
    assert result.metadata["redirect_chain"] == ["http://10.0.0.50/old", "http://10.0.0.50/new"]
    assert result.follow_ups and "browser_observe" in result.follow_ups

    observation = asyncio.run(backend.observe(sid))
    assert observation.kind is BrowserObservationKind.PAGE_STATE
    payload = observation.payload
    assert payload["title"] == "Login — target app"
    assert len(payload["forms"]) == 50  # bounded
    assert len(payload["scripts"]) == 100  # bounded
    assert len(payload["dom_summary"]) <= 8000 + 64
    assert "truncated" in payload["dom_summary"]
    assert "wordpress" in payload["indicators"]

    state = asyncio.run(backend.get_page_state(sid))
    assert state.final_url == "http://10.0.0.50/new"
    assert any(e["url"].endswith("/api/login") for e in state.endpoints)

    events = asyncio.run(backend.get_network_events(sid))
    assert len(events) == 2
    assert events[0].event_id < events[1].event_id  # stable, ordered ids
    req_red = events[0].to_redacted_dict()
    assert "CANARY-SESSION-TOKEN" not in json.dumps(req_red)
    assert req_red["request_headers"]["Content-Type"] == "application/json"  # non-secrets survive
    resp_red = events[1].to_redacted_dict()
    assert "CANARY-SESSION-TOKEN" not in json.dumps(resp_red)

    snapshot = asyncio.run(backend.get_storage(sid))
    assert len(snapshot.entries) == 3  # 1 cookie + 2 localStorage
    blob = json.dumps(snapshot.to_dict())
    assert "CANARY-SESSION-TOKEN" not in blob
    assert snapshot.to_dict(redact=False)["entries"][0]["value"] == SECRET  # explicit opt-in only

    artifact = asyncio.run(backend.capture_screenshot(sid, artifact_path=str(tmp_path / "shot.png")))
    raw = Path(str(tmp_path / "shot.png")).read_bytes()
    assert raw.startswith(b"\x89PNG")
    import hashlib as _hashlib

    assert artifact.sha256 == _hashlib.sha256(raw).hexdigest()
    assert artifact.evidence_type == "screenshot"
    assert artifact.content_type == "image/png"

    first = asyncio.run(backend.close(sid))
    assert first.success is True
    second = asyncio.run(backend.close(sid))  # idempotent
    assert second.success is True
    assert second.metadata.get("already_closed") is True


def test_no_playwright_types_leak():
    """No Playwright object may escape the backend boundary."""
    backend = _backend()

    async def _flow():
        sid = await _started(backend)
        results = [
            await backend.navigate(sid, "http://10.0.0.50/"),
            await backend.observe(sid),
            await backend.get_page_state(sid),
            await backend.get_storage(sid),
        ]
        results.extend(await backend.get_network_events(sid))
        action = BrowserAction(
            action_id="a-1", session_id=sid, kind=BrowserActionKind.EXECUTE_JS, parameters={"expression": "1+1"}
        )
        results.append(await backend.execute_action(sid, action))
        return results

    for model in asyncio.run(_flow()):
        assert "playwright" not in type(model).__module__
        model.to_dict()  # every output is JSON-serializable domain data
        json.dumps(model.to_dict(), default=str)


def test_timeout_translation():
    backend = _backend()
    assert isinstance(backend.launcher, FakeLauncher)
    backend.launcher.fail["navigate"] = TimeoutError("page load timed out after 30s")
    sid = asyncio.run(_started(backend))
    with pytest.raises(BrowserTimeout):
        asyncio.run(backend.navigate(sid, "http://10.0.0.50/"))


def test_crash_drops_the_engine_token():
    backend = _backend()
    sid = asyncio.run(_started(backend))
    token = backend._test_sessions[sid].token
    backend.launcher.fail["snapshot"] = Exception("Target has been closed")
    with pytest.raises(BrowserCrashed):
        asyncio.run(backend.observe(sid))
    assert token in backend.launcher.closed  # deterministic cleanup on crash


def test_invalid_url_scheme_is_rejected():
    backend = _backend()
    sid = asyncio.run(_started(backend))
    with pytest.raises(BrowserNavigationFailed):
        asyncio.run(backend.navigate(sid, "file:///etc/passwd"))


def test_js_expression_cap_and_preview_redaction():
    backend = _backend()
    sid = asyncio.run(_started(backend))
    big = BrowserAction(
        action_id="a-big", session_id=sid, kind=BrowserActionKind.EXECUTE_JS, parameters={"expression": "x" * 9000}
    )
    capped = asyncio.run(backend.execute_action(sid, big))
    assert capped.success is False
    assert capped.failure_class is BrowserFailureClass.SCRIPT_ERROR
    small = BrowserAction(
        action_id="a-ok",
        session_id=sid,
        kind=BrowserActionKind.EXECUTE_JS,
        parameters={"expression": "document.cookie"},
    )
    ok_result = asyncio.run(backend.execute_action(sid, small))
    assert ok_result.success is True
    assert "CANARY-SESSION-TOKEN" not in str(ok_result.metadata.get("return_preview", ""))


def test_replay_and_submit_are_deferred():
    backend = _backend()
    sid = asyncio.run(_started(backend))
    for kind in (BrowserActionKind.REPLAY_REQUEST, BrowserActionKind.SUBMIT_FORM):
        action = BrowserAction(action_id="a-def", session_id=sid, kind=kind)
        result = asyncio.run(backend.execute_action(sid, action))
        assert result.success is False
        assert result.failure_class is BrowserFailureClass.UNSUPPORTED_ACTION
        assert result.retryable is False


def test_network_pagination_bounds():
    backend = _backend()
    sid = asyncio.run(_started(backend))
    asyncio.run(backend.navigate(sid, "http://10.0.0.50/"))
    everything = asyncio.run(backend.get_network_events(sid, limit=10))
    assert len(everything) == 2
    first = asyncio.run(backend.get_network_events(sid, limit=1))
    assert len(first) == 1
    assert first[0].event_id == everything[-1].event_id  # most-recent window
    rest = asyncio.run(backend.get_network_events(sid, after_id=everything[0].event_id))
    assert [e.event_id for e in rest] == [everything[1].event_id]
    unknown = asyncio.run(backend.get_network_events(sid, after_id="evt-999999"))
    assert len(unknown) == 2  # unknown cursor degrades to full bounded history


def test_unknown_session_is_typed():
    from tools.browser.errors import BrowserSessionNotFound

    backend = _backend()
    with pytest.raises(BrowserSessionNotFound):
        asyncio.run(backend.navigate("bs-0000-deadbeefcafe", "http://10.0.0.50/"))


def test_health_and_config_gates(monkeypatch):
    from tools.browser import playwright_backend as _mod

    monkeypatch.setattr(_mod, "playwright_present", lambda: False)
    monkeypatch.setattr(_mod, "chromium_present", lambda **kwargs: False)
    backend = PlaywrightBackend({"browser": {"enabled": True, "backend": "playwright"}})
    assert backend.is_configured({"browser": {"enabled": True, "backend": "playwright"}}) is False
    health = backend.health({})
    assert health["ok"] is False
    assert health["name"] == "browser_backend_playwright"
    assert PlaywrightBackend({}).is_configured({"browser": {"backend": "other"}}) is False
