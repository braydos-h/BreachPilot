"""Recon safety regression tests: defensive-server scope gate, strict preflight,
and bounded DNS (no live Nmap/network/DNS -- everything mocked)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest


def _make_defensive_server(*, allow: list[str]):
    from mcp_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    return create_mcp_server(
        nvd=NVDClient(CVESearchSettings()),
        researcher=WebResearcher(WebResearcherSettings()),
        config={"research": {"allowed_assets": list(allow)}},
        allow=list(allow),
    )


def _text(result) -> str:
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


# ── Defensive run_limited_terminal scope gate ────────────────────────────────


@pytest.mark.asyncio
async def test_defensive_terminal_blocks_hostname_not_in_allowlist():
    """`nmap -sV evil.com` must be blocked: the old IPv4-only token regex saw
    no IP token and let the hostname straight through to nmap."""
    mcp = _make_defensive_server(allow=["10.0.0.5"])
    text = _text(await mcp.call_tool("run_limited_terminal", {"command": "nmap -sV evil.com"}))
    assert "not in scope" in text
    assert "evil.com" in text


@pytest.mark.asyncio
async def test_defensive_terminal_blocks_out_of_scope_ip():
    """The pre-existing IPv4 path keeps working."""
    mcp = _make_defensive_server(allow=["10.0.0.5"])
    text = _text(await mcp.call_tool("run_limited_terminal", {"command": "nmap -sV 10.0.0.99"}))
    assert "not in scope" in text


@pytest.mark.asyncio
async def test_defensive_terminal_allows_allowlisted_ip(monkeypatch):
    """An allowlisted IP passes the gate (nmap itself mocked -- no live scan)."""
    from typing import Any as _Any

    async def fake_nmap(args: list, timeout: int = 300) -> dict[str, _Any]:
        return {"ok": True, "stdout": "mocked", "stderr": "", "exit_code": 0, "duration_s": 0.0}

    monkeypatch.setattr("mcp_server._run_nmap", fake_nmap)
    mcp = _make_defensive_server(allow=["10.0.0.5"])
    text = _text(await mcp.call_tool("run_limited_terminal", {"command": "nmap -sV 10.0.0.5"}))
    assert "not in scope" not in text


@pytest.mark.asyncio
async def test_defensive_terminal_rejects_shell_metachars():
    """Chained commands are rejected outright (the tool's documented contract),
    even when the IP itself is allowlisted."""
    mcp = _make_defensive_server(allow=["10.0.0.5"])
    text = _text(await mcp.call_tool("run_limited_terminal", {"command": "nmap -sV 10.0.0.5; evil"}))
    assert "not allowed" in text


# ── preflight_command_check strict mode ─────────────────────────────────────


def test_preflight_default_allows_pipes_for_attack_mode():
    """Default stays permissive: attack-mode tools legitimately pipe/chain
    (their safety is the target-IP lock, not command-content inspection)."""
    from tools.validation_utils import preflight_command_check

    assert preflight_command_check("nmap -sV 10.0.0.5 | grep open")["valid"] is True
    assert preflight_command_check("nmap -sV 10.0.0.5")["valid"] is True


def test_preflight_strict_rejects_shell_metachars():
    """Opt-in strict mode (used by the defensive server) rejects chaining."""
    from tools.validation_utils import preflight_command_check

    for cmd in (
        "nmap -sV 10.0.0.5; curl evil",
        "nmap -sV 10.0.0.5 | grep open",
        "nmap -sV 10.0.0.5 && evil",
        "nmap -sV 10.0.0.5 `evil`",
        "nmap -sV 10.0.0.5 > /tmp/out",
    ):
        result = preflight_command_check(cmd, reject_shell_metachars=True)
        assert result["valid"] is False, cmd
        assert "not allowed" in (result["blocked_reason"] or "")
    ok = preflight_command_check("nmap -sV 10.0.0.5", reject_shell_metachars=True)
    assert ok["valid"] is True
    assert ok["blocked_reason"] is None


# ── Bounded DNS bruteforce ───────────────────────────────────────────────────


def _make_domain_server(tmp_path: Path):
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
                "require_explicit_allowlist": True,
                "allowed_targets": ["example.com"],
            },
            "skills": {"enabled": False},
            "multi_model": {"enabled": False},
        },
    )


@pytest.mark.asyncio
async def test_enumerate_subdomains_dns_timeout_bounded(tmp_path: Path, monkeypatch):
    """A hung resolver must not stall the bruteforce: 3 candidates x 5s bound
    on one pool wave (~5s), never 3 x 30s. No live DNS -- getaddrinfo hangs."""
    import socket as _socket

    def hanging_getaddrinfo(*args: Any, **kwargs: Any):
        time.sleep(30)
        raise _socket.gaierror("hung resolver")

    monkeypatch.setattr("tools.mcp_tools.domain._SUBDOMAIN_WORDLIST", ["zz1", "zz2", "zz3"])
    monkeypatch.setattr(_socket, "getaddrinfo", hanging_getaddrinfo)

    mcp = _make_domain_server(tmp_path)
    start = time.monotonic()
    text = _text(await mcp.call_tool("enumerate_subdomains", {"domain": "example.com", "sources": "dns_bruteforce"}))
    elapsed = time.monotonic() - start
    assert "SUBDOMAIN_RESULT:" in text
    assert "DISCOVERED: 0" in text
    assert elapsed < 20, f"DNS bruteforce must be bounded (took {elapsed:.1f}s)"
