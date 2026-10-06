"""Tests for the web-probe MCP tools (``tools/mcp_tools/modules/web.py``).

Covers the family hardening: port range (1-65535), CR/LF rejection on
``target_ip``/``endpoint``, concurrent fan-out cap (2-100), per-tool
timeout/deadline handling, socket cleanup (context-manager close),
IPv6/domain targets, and sprayed-password redaction. Worker network I/O is
mocked at the sandbox command boundary; ``time.sleep`` is stubbed so the
paced sweeps run instantly.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from tools.mcp_tools.modules.web import _SandboxSocket


def _make_server(
    tmp_path: Path,
    *,
    require_allowlist: bool = False,
    allowed_targets: list[str] | None = None,
):
    """Build an MCP server with the web-probe tools registered (allowlist off by default)."""
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        {
            "exploit": {
                "require_explicit_allowlist": require_allowlist,
                "allowed_targets": allowed_targets if allowed_targets is not None else ["10.0.0.50"],
            },
            "skills": {"enabled": False},
            "multi_model": {"enabled": False},
        },
    )


def _text(result: Any) -> str:
    """Extract text from an MCP CallToolResult (tuple or object form)."""
    content = result[0] if isinstance(result, (list, tuple)) else result
    if hasattr(content, "content"):
        content = content.content
    parts = []
    for c in content:
        t = getattr(c, "text", None)
        if t is None and isinstance(c, dict):
            t = c.get("text")
        if t is None:
            t = str(c)
        parts.append(t)
    return "".join(parts)


@pytest.fixture(autouse=True)
def _no_sleep():
    with patch("time.sleep", return_value=None):
        yield


def _conn(
    recv: bytes = b"HTTP/1.0 200 OK\r\n\r\nnothing interesting",
    *,
    observed: list[dict[str, Any]] | None = None,
):
    """Mock the worker command boundary; host socket APIs stay unused."""

    def fake_worker(_ctx, _argv, **kwargs):
        request = json.loads(kwargs["input_text"])
        assert request["host"]
        assert base64.b64decode(request["payload"])
        if observed is not None:
            observed.append(request)
        return "completed", 0, base64.b64encode(recv).decode("ascii"), 0.001

    return patch("tools.mcp_tools.modules.web.run_tool_argv_in_sandbox", side_effect=fake_worker)


def test_sandbox_socket_close_drops_request_and_response_buffers() -> None:
    sock = _SandboxSocket("example.com", 80, 1, ctx=SimpleNamespace(sandbox=object()), tool_name="test")
    sock.sent.extend(b"Authorization: Bearer secret\r\n")
    sock._received = b"private response"

    sock.close()

    assert sock.closed
    assert not sock.sent
    assert sock._received == b""


# ── port range ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ssti_probe_rejects_port_zero(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("ssti_probe", {"target_ip": "10.0.0.50", "port": 0}))
    assert text.startswith("BLOCKED:")
    assert "port" in text


@pytest.mark.asyncio
async def test_ssti_probe_rejects_port_above_max(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("ssti_probe", {"target_ip": "10.0.0.50", "port": 70000}))
    assert text.startswith("BLOCKED:")


@pytest.mark.asyncio
async def test_ssti_probe_rejects_non_numeric_port(tmp_path: Path):
    """A non-numeric port never reaches the tool body: the FastMCP/pydantic
    schema layer rejects it fail-closed first (ToolError, no socket opened)."""
    from mcp.server.fastmcp.exceptions import ToolError

    mcp = _make_server(tmp_path)
    with pytest.raises(ToolError):
        await mcp.call_tool("ssti_probe", {"target_ip": "10.0.0.50", "port": "abc"})


@pytest.mark.asyncio
async def test_graphql_rejects_port_out_of_range(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("graphql_introspect", {"target_ip": "10.0.0.50", "port": 65536}))
    assert text.startswith("BLOCKED:")


# ── CR/LF rejection ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_target_ip_crlf_rejected_without_worker_execution(tmp_path: Path):
    mcp = _make_server(tmp_path, allowed_targets=[])
    with patch("tools.mcp_tools.modules.web.run_tool_argv_in_sandbox") as mock_conn:
        text = _text(await mcp.call_tool("ssti_probe", {"target_ip": "10.0.0.50\r\n evil", "port": 80, "timeout": 5}))
    assert text.startswith("BLOCKED:")
    assert "CR/LF" in text
    mock_conn.assert_not_called()


@pytest.mark.asyncio
async def test_race_endpoint_crlf_rejected(tmp_path: Path):
    mcp = _make_server(tmp_path)
    with patch("tools.mcp_tools.modules.web.run_tool_argv_in_sandbox") as mock_conn:
        text = _text(
            await mcp.call_tool(
                "race_request",
                {"target_ip": "10.0.0.50", "port": 80, "endpoint": "/api/x\r\nInjected: 1"},
            )
        )
    assert text.startswith("BLOCKED:")
    mock_conn.assert_not_called()


@pytest.mark.asyncio
async def test_race_endpoint_must_be_absolute_path(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "race_request",
            {"target_ip": "10.0.0.50", "port": 80, "endpoint": "http://evil.example/"},
        )
    )
    assert text.startswith("BLOCKED:")


# ── concurrent cap ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_race_rejects_concurrent_below_min(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("race_request", {"target_ip": "10.0.0.50", "concurrent": 1}))
    assert text.startswith("BLOCKED:")


@pytest.mark.asyncio
async def test_race_rejects_concurrent_above_max(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("race_request", {"target_ip": "10.0.0.50", "concurrent": 200}))
    assert text.startswith("BLOCKED:")


@pytest.mark.asyncio
async def test_race_happy_path_small_fanout(tmp_path: Path):
    mcp = _make_server(tmp_path)
    with _conn(b"HTTP/1.0 200 OK\r\n\r\n{}"):
        text = _text(
            await mcp.call_tool(
                "race_request",
                {"target_ip": "10.0.0.50", "port": 80, "endpoint": "/api/redeem", "concurrent": 2},
            )
        )
    assert "RACE_REQUEST_RESULTS:" in text
    assert "Success: 2" in text


# ── IPv6 / domain targets + socket cleanup ────────────────────────────────────


@pytest.mark.asyncio
async def test_graphql_domain_target_and_sockets_closed(tmp_path: Path):
    mcp = _make_server(tmp_path, allowed_targets=["example.com"])
    body = b'HTTP/1.0 200 OK\r\n\r\n{"data":{"__schema":{"queryType":{"name":"Q"},"types":[{"name":"User"}]}}}'
    observed: list[dict[str, Any]] = []
    closed: list[bool] = []
    original_close = _SandboxSocket.close

    def record_close(sock: _SandboxSocket) -> None:
        closed.append(True)
        original_close(sock)

    with patch.object(_SandboxSocket, "close", record_close), _conn(body, observed=observed):
        text = _text(await mcp.call_tool("graphql_introspect", {"target_ip": "example.com", "port": 80, "timeout": 10}))
    assert "GRAPHQL_INTROSPECT_RESULTS: example.com:80" in text
    assert "Introspection ENABLED" in text
    assert observed, "expected a worker TCP exchange"
    assert closed, "every worker exchange must close"


@pytest.mark.asyncio
async def test_ssti_ipv6_target_bracketed_host_header(tmp_path: Path):
    mcp = _make_server(tmp_path, allowed_targets=["::1"])
    observed: list[dict[str, Any]] = []
    closed: list[bool] = []
    original_close = _SandboxSocket.close

    def record_close(sock: _SandboxSocket) -> None:
        closed.append(True)
        original_close(sock)

    with patch.object(_SandboxSocket, "close", record_close), _conn(b"HTTP/1.0 200 OK\r\n\r\n49", observed=observed):
        text = _text(await mcp.call_tool("ssti_probe", {"target_ip": "::1", "port": 80, "timeout": 10}))
    assert "SSTI_PROBE_RESULTS: ::1:80" in text
    assert observed
    assert b"Host: [::1]" in base64.b64decode(observed[0]["payload"])
    assert closed


@pytest.mark.asyncio
async def test_invalid_target_rejected(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("timing_oracle", {"target_ip": "not a target!!", "port": 80}))
    assert text.startswith("BLOCKED:")


def test_web_probe_without_worker_returns_sandbox_block(tmp_path: Path, monkeypatch):
    from tools.mcp_tools.modules.web import register_web_tools

    registered = {}

    class FakeMCP:
        def tool(self):
            return lambda fn: registered.setdefault(fn.__name__, fn)

    context = SimpleNamespace(
        workspace=tmp_path,
        config={"exploit": {"allowed_targets": ["example.com"]}},
        search=None,
        nvd=None,
        researcher=None,
        audit_tool=lambda fn: fn,
        require_allowlist=lambda *_args, **_kwargs: lambda fn: fn,
        sandbox=None,
    )
    register_web_tools(FakeMCP(), ctx=context)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("target traffic must never use the MCP host network")

    monkeypatch.setattr("socket.create_connection", forbidden)
    result = registered["graphql_introspect"]("example.com", port=80, timeout=5)
    assert "SANDBOX_UNAVAILABLE" in result
    assert "EXECUTED: nowhere" in result


# ── password redaction ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_password_spray_redacts_password(tmp_path: Path):
    mcp = _make_server(tmp_path)
    secret = "Sup3rS3cretPw-9z"
    with _conn(b"HTTP/1.0 401 Unauthorized\r\n\r\nno"):
        text = _text(
            await mcp.call_tool(
                "password_spray",
                {"target_ip": "10.0.0.50", "port": 80, "password": secret, "timeout": 60},
            )
        )
    assert "PASSWORD_SPRAY_RESULTS:" in text
    assert secret not in text, "sprayed password must never appear in display output"
    assert "[redacted]" in text


@pytest.mark.asyncio
async def test_password_spray_success_lists_user_not_password(tmp_path: Path):
    mcp = _make_server(tmp_path)
    secret = "An0therS3cret-42"
    with _conn(b'HTTP/1.0 200 OK\r\n\r\n{"token": "abc"}'):
        text = _text(
            await mcp.call_tool(
                "password_spray",
                {"target_ip": "10.0.0.50", "port": 80, "password": secret, "timeout": 120},
            )
        )
    assert "SUCCESS" in text
    assert secret not in text


# ── timeout / deadline ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_timing_oracle_reports_insufficient_samples_at_deadline(tmp_path: Path, monkeypatch):
    """With no remaining socket budget, sampling stops immediately."""
    import tools.mcp_tools.modules.web as web_mod

    mcp = _make_server(tmp_path)
    monkeypatch.setattr(web_mod, "_sock_budget", lambda _default, _deadline: 0.0)
    with _conn():
        text = _text(await mcp.call_tool("timing_oracle", {"target_ip": "10.0.0.50", "timeout": 60}))
    assert "TIMING_ORACLE_RESULTS:" in text
    assert "Insufficient samples." in text


@pytest.mark.asyncio
async def test_jwt_tamper_rejects_invalid_format(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("jwt_tamper", {"target_ip": "10.0.0.50", "jwt_token": "not-a-jwt"}))
    assert "Invalid JWT format" in text


@pytest.mark.asyncio
async def test_jwt_tamper_requires_target(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("jwt_tamper", {"target_ip": "", "jwt_token": "a.b.c"}))
    assert text.startswith("BLOCKED:")


@pytest.mark.asyncio
async def test_request_smuggling_baseline_envelope(tmp_path: Path):
    mcp = _make_server(tmp_path)
    closed: list[bool] = []
    original_close = _SandboxSocket.close

    def record_close(sock: _SandboxSocket) -> None:
        closed.append(True)
        original_close(sock)

    with patch.object(_SandboxSocket, "close", record_close), _conn(b"HTTP/1.0 200 OK\r\n\r\nbaseline"):
        text = _text(
            await mcp.call_tool("request_smuggling_probe", {"target_ip": "10.0.0.50", "port": 80, "timeout": 30})
        )
    assert "REQUEST_SMUGGLING_RESULTS: 10.0.0.50:80" in text
    assert "Baseline:" in text
    assert closed
