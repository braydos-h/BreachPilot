"""Tests for the domain-attack MCP tools (Phase 4).

Covers ``resolve_domain``, ``enumerate_subdomains``, ``dns_recon``,
``vhost_enum``, and ``domain_whois`` -- the five new tools in
``tools/mcp_tools/domain.py``. All network calls are mocked.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


def _make_server(tmp_path: Path, *, require_allowlist: bool = False, allowed_targets: list[str] | None = None):
    """Build an MCP server with the domain tools registered (allowlist off for tests)."""
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
                "allowed_targets": allowed_targets or [],
            },
            "skills": {"enabled": False},
            "multi_model": {"enabled": False},
        },
    )


def _text(result) -> str:
    """Extract text from an MCP CallToolResult."""
    if hasattr(result, "content") and result.content:
        for item in result.content:
            if hasattr(item, "text"):
                return item.text
    return str(result)


# ── resolve_domain ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_resolve_domain_returns_a_aaaa(tmp_path: Path):
    mcp = _make_server(tmp_path)
    # Mock socket.getaddrinfo to return a fake A record.
    import socket as _sock
    fake_info = [(_sock.AF_INET, _sock.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    with patch("socket.getaddrinfo", return_value=fake_info):
        text = _text(await mcp.call_tool("resolve_domain", {"domain": "example.com"}))
    assert "DNS_RESULT:" in text
    assert "example.com" in text
    assert "93.184.216.34" in text


@pytest.mark.asyncio
async def test_resolve_domain_rejects_invalid(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("resolve_domain", {"domain": "not a domain"}))
    assert "ERROR" in text


@pytest.mark.asyncio
async def test_resolve_domain_rejects_empty(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("resolve_domain", {"domain": ""}))
    assert "ERROR" in text


# ── enumerate_subdomains ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enumerate_subdomains_crt_sh(tmp_path: Path, monkeypatch):
    mcp = _make_server(tmp_path)
    # Mock crt.sh to return two subdomains; mock DNS resolution for them.
    fake_crt_response = json.dumps([
        {"name_value": "www.example.com"},
        {"name_value": "api.example.com"},
    ]).encode()
    fake_urlresp = MagicMock()
    fake_urlresp.status = 200
    fake_urlresp.read.return_value = fake_crt_response
    fake_urlresp.headers = {}
    fake_urlresp.__enter__ = lambda self: self
    fake_urlresp.__exit__ = lambda self, *a: None
    fake_urlresp.status = 200

    import socket as _sock
    def fake_getaddrinfo(host, *a, **k):
        if host == "www.example.com":
            return [(_sock.AF_INET, _sock.SOCK_STREAM, 6, "", ("1.1.1.1", 0))]
        if host == "api.example.com":
            return [(_sock.AF_INET, _sock.SOCK_STREAM, 6, "", ("2.2.2.2", 0))]
        raise _sock.gaierror("no dns")

    # Patch the _stdlib_fetch used by domain.py to return our fake crt.sh response.
    with patch("tools.mcp_tools.domain._stdlib_fetch", return_value=(200, {}, json.dumps([
        {"name_value": "www.example.com"},
        {"name_value": "api.example.com"},
    ]))), \
         patch("tools.mcp_tools.domain.resolve_target_to_ip", side_effect=lambda h: {
             "www.example.com": "1.1.1.1",
             "api.example.com": "2.2.2.2",
         }.get(h)):
        text = _text(await mcp.call_tool("enumerate_subdomains", {
            "domain": "example.com",
            "sources": "crt_sh",
        }))
    assert "SUBDOMAIN_RESULT:" in text
    assert "www.example.com" in text
    assert "api.example.com" in text
    assert "AUTO_AUTHORIZED" in text


@pytest.mark.asyncio
async def test_enumerate_subdomains_rejects_invalid(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("enumerate_subdomains", {"domain": "no-tld"}))
    assert "ERROR" in text


# ── dns_recon ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dns_recon_falls_back_without_dnspython(tmp_path: Path):
    mcp = _make_server(tmp_path)
    # Mock socket.getaddrinfo for A records; ensure dnspython import fails.
    import socket as _sock
    fake_info = [(_sock.AF_INET, _sock.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    import builtins
    real_import = builtins.__import__
    def mock_import(name, *a, **k):
        if name == "dns.resolver" or name == "dns":
            raise ImportError("no dnspython")
        return real_import(name, *a, **k)
    with patch("socket.getaddrinfo", return_value=fake_info), \
         patch("builtins.__import__", side_effect=mock_import):
        text = _text(await mcp.call_tool("dns_recon", {"domain": "example.com"}))
    assert "DNS_RECON_RESULT:" in text
    assert "93.184.216.34" in text
    assert "AXFR_NOT_REQUESTED" in text or "AXFR_UNAVAILABLE" in text


@pytest.mark.asyncio
async def test_dns_recon_rejects_invalid(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("dns_recon", {"domain": ""}))
    assert "ERROR" in text


# ── vhost_enum ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vhost_enum_rejects_missing_domain(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("vhost_enum", {"target_ip": "10.0.0.5", "port": 80}))
    assert "ERROR" in text
    assert "domain" in text


@pytest.mark.asyncio
async def test_vhost_enum_finds_vhost(tmp_path: Path):
    mcp = _make_server(tmp_path)
    # Mock _stdlib_fetch: baseline returns body A, www returns body B (different length).
    def fake_fetch(url, *, timeout=15, headers=None, data=None):
        host = (headers or {}).get("Host", "")
        if "admin" in host:
            return 200, {}, "admin page content here"
        return 200, {}, "default page"
    with patch("tools.mcp_tools.domain._stdlib_fetch", side_effect=fake_fetch):
        text = _text(await mcp.call_tool("vhost_enum", {
            "target_ip": "10.0.0.5",
            "port": 80,
            "domain": "example.com",
        }))
    assert "VHOST_RESULT:" in text
    assert "admin.example.com" in text


# ── domain_whois ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_domain_whois_rejects_invalid(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("domain_whois", {"domain": "not a domain"}))
    assert "ERROR" in text


@pytest.mark.asyncio
async def test_domain_whois_returns_unavailable_when_no_lib(tmp_path: Path):
    mcp = _make_server(tmp_path)
    # Mock both python-whois and the whois binary as unavailable.
    import builtins
    real_import = builtins.__import__
    def mock_import(name, *a, **k):
        if name == "whois":
            raise ImportError("no python-whois")
        return real_import(name, *a, **k)
    with patch("builtins.__import__", side_effect=mock_import), \
         patch("shutil.which", return_value=None):
        text = _text(await mcp.call_tool("domain_whois", {"domain": "example.com"}))
    assert "WHOIS_RESULT:" in text
    assert "unavailable" in text.lower() or "not installed" in text.lower()


# ── domain briefing ──────────────────────────────────────────────────────────

def test_domain_briefing_for_domain():
    from tools.exploit_agent import build_domain_briefing
    briefing = build_domain_briefing("example.com", "93.184.216.34")
    assert "DOMAIN TARGET BRIEFING" in briefing
    assert "example.com" in briefing
    assert "93.184.216.34" in briefing
    assert "enumerate_subdomains" in briefing


def test_domain_briefing_empty_for_ip():
    from tools.exploit_agent import build_domain_briefing
    assert build_domain_briefing("10.0.0.5", None) == ""


def test_domain_briefing_empty_for_empty():
    from tools.exploit_agent import build_domain_briefing
    assert build_domain_briefing("", None) == ""


def test_domain_briefing_for_unresolved_domain():
    from tools.exploit_agent import build_domain_briefing
    briefing = build_domain_briefing("example.com", None)
    assert "DOMAIN TARGET BRIEFING" in briefing
    assert "unresolved" in briefing