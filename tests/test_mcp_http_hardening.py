"""Tier 2 regression tests: HTTP transport hardening shared by both MCP servers.

``tools.mcp_shared.run_mcp_http_server`` centralizes three controls that
CLAUDE.md documents but were previously missing or only partially present:

1. ``assert_loopback_bind`` -- refuse a non-loopback bind unless BOTH the
   caller's ``allow_public_bind`` flag (the ``--allow-public-bind`` CLI arg)
   AND the ``MCP_ALLOW_PUBLIC_BIND`` env var are set (two-person rule).
2. ``_wrap_http_auth`` -- when ``MCP_HTTP_TOKEN`` is set, require an
   ``Authorization: Bearer <token>`` header on the streamable-http app;
   reject without/wrong token with 401. Constant-time compare.
3. ``run_mcp_http_server`` -- wires both servers through one path
   (``mcp.streamable_http_app()`` + ``uvicorn.run``) so the gate + auth
   live in one place.

These tests exercise the gate and the auth wrapper directly (no live
uvicorn bind), which is all that is needed on a box without the deps.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any

import pytest

from tools.mcp_shared import _wrap_http_auth, assert_loopback_bind


# ── assert_loopback_bind ───────────────────────────────────────────────────────


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_loopback_hosts_always_allowed(host: str, monkeypatch):
    monkeypatch.delenv("MCP_ALLOW_PUBLIC_BIND", raising=False)
    # Even with allow_public_bind=False, loopback is fine.
    assert_loopback_bind(host, allow_public_bind=False)  # must not raise


def test_public_bind_refused_without_override(monkeypatch):
    monkeypatch.delenv("MCP_ALLOW_PUBLIC_BIND", raising=False)
    with pytest.raises(ValueError, match="non-loopback"):
        assert_loopback_bind("0.0.0.0", allow_public_bind=False)


def test_public_bind_refused_with_only_flag(monkeypatch):
    """The CLI flag alone is not enough -- the env var must also be set."""
    monkeypatch.delenv("MCP_ALLOW_PUBLIC_BIND", raising=False)
    with pytest.raises(ValueError, match="non-loopback"):
        assert_loopback_bind("0.0.0.0", allow_public_bind=True)


def test_public_bind_refused_with_only_env(monkeypatch):
    """The env var alone is not enough -- the CLI flag must also be passed."""
    monkeypatch.setenv("MCP_ALLOW_PUBLIC_BIND", "1")
    with pytest.raises(ValueError, match="non-loopback"):
        assert_loopback_bind("0.0.0.0", allow_public_bind=False)


@pytest.mark.parametrize("val", ["1", "true", "yes", "on"])
def test_public_bind_allowed_with_both_flag_and_env(val: str, monkeypatch):
    monkeypatch.setenv("MCP_ALLOW_PUBLIC_BIND", val)
    assert_loopback_bind("0.0.0.0", allow_public_bind=True)  # must not raise


def test_public_bind_refused_when_env_falsy(monkeypatch):
    monkeypatch.setenv("MCP_ALLOW_PUBLIC_BIND", "0")
    with pytest.raises(ValueError, match="non-loopback"):
        assert_loopback_bind("0.0.0.0", allow_public_bind=True)


# ── _wrap_http_auth (ASGI middleware) ──────────────────────────────────────────


def _run_asgi(app, headers: list[tuple[bytes, bytes]], *, method: str = "GET", path: str = "/") -> tuple[int, bytes]:
    """Drive an ASGI app through a single HTTP request, return (status, body)."""
    scope: dict[str, Any] = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
    }
    sent: list[dict[str, Any]] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    status = 0
    body = b""
    for m in sent:
        if m.get("type") == "http.response.start":
            status = m.get("status", 0)
        elif m.get("type") == "http.response.body":
            body += m.get("body", b"")
    return status, body


def _dummy_app():
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"OK"})
    return app


def test_auth_wrapper_passes_with_correct_token():
    wrapped = _wrap_http_auth(_dummy_app(), "s3cret")
    status, body = _run_asgi(wrapped, [(b"authorization", b"Bearer s3cret")])
    assert status == 200
    assert body == b"OK"


def test_auth_wrapper_rejects_missing_token():
    wrapped = _wrap_http_auth(_dummy_app(), "s3cret")
    status, body = _run_asgi(wrapped, [])
    assert status == 401
    assert b"MCP_HTTP_TOKEN" in body


def test_auth_wrapper_rejects_wrong_token():
    wrapped = _wrap_http_auth(_dummy_app(), "s3cret")
    status, body = _run_asgi(wrapped, [(b"authorization", b"Bearer wrong")])
    assert status == 401
    assert b"MCP_HTTP_TOKEN" in body


def test_auth_wrapper_passes_non_http_scope():
    """Lifespan/other non-http scopes must pass through untouched."""
    wrapped = _wrap_http_auth(_dummy_app(), "s3cret")
    seen: list[str] = []

    async def passthrough_app(scope, receive, send):
        seen.append(scope.get("type", ""))

    wrapped2 = _wrap_http_auth(passthrough_app, "s3cret")

    async def run():
        scope = {"type": "lifespan"}
        await wrapped2(scope, _noop_receive, _noop_send)

    asyncio.run(run())
    assert seen == ["lifespan"]


async def _noop_receive():
    return {"type": "lifespan.startup"}


async def _noop_send(message):
    pass