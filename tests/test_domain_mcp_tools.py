"""Tests for the domain-attack MCP tools (Phase 4).

Covers ``resolve_domain``, ``enumerate_subdomains``, ``dns_recon``,
``vhost_enum``, and ``domain_whois`` -- the five new tools in
``tools/mcp_tools/domain.py``. All network calls are mocked.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# enumerate_subdomains internally calls add_discovered_target, which writes
# os.environ["EXPLOIT_DISCOVERED_TARGETS"] directly. monkeypatch does NOT
# restore direct os.environ[k]=v writes, so they leak for the whole pytest
# session and break later empty-allowlist tests. Snapshot+restore here.
@pytest.fixture(autouse=True)
def _restore_target_env():
    _snap = {k: os.environ.get(k) for k in
             ("EXPLOIT_TARGET", "EXPLOIT_TARGET_IP", "EXPLOIT_TARGET_DOMAIN", "EXPLOIT_DISCOVERED_TARGETS")}
    yield
    for _k, _v in _snap.items():
        if _v is None:
            os.environ.pop(_k, None)
        else:
            os.environ[_k] = _v


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


# ── Tier 1.1: allowlist gate uses the "domain" param, not "target_ip" ─────────
# Regression: @require_allowlist() defaulted target_param="target_ip", but
# resolve_domain / enumerate_subdomains / dns_recon / domain_whois all take
# ``domain`` as their first param. With require_explicit_allowlist=True (the
# config default), the decorator read "" and BLOCKED all 4 tools. These tests
# build the server with require_allowlist=True and assert the tools now pass
# the gate when the domain is in the allowlist (and BLOCK when it isn't).


@pytest.mark.asyncio
async def test_resolve_domain_passes_allowlist_when_domain_authorized(tmp_path: Path, monkeypatch):
    """resolve_domain must read the `domain` arg for the allowlist gate."""
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["example.com"])
    import socket as _sock
    fake_info = [(_sock.AF_INET, _sock.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    with patch("socket.getaddrinfo", return_value=fake_info):
        text = _text(await mcp.call_tool("resolve_domain", {"domain": "example.com"}))
    assert "DNS_RESULT:" in text, f"expected DNS_RESULT, got BLOCKED:\n{text}"
    assert "93.184.216.34" in text


@pytest.mark.asyncio
async def test_resolve_domain_blocks_when_domain_not_in_allowlist(tmp_path: Path, monkeypatch):
    """When the domain is NOT in the allowlist, the gate must BLOCK."""
    monkeypatch.delenv("EXPLOIT_TARGET", raising=False)
    monkeypatch.delenv("EXPLOIT_TARGET_DOMAIN", raising=False)
    monkeypatch.delenv("EXPLOIT_TARGET_IP", raising=False)
    monkeypatch.delenv("EXPLOIT_DISCOVERED_TARGETS", raising=False)
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["other.com"])
    text = _text(await mcp.call_tool("resolve_domain", {"domain": "example.com"}))
    assert "BLOCKED:" in text, f"expected BLOCKED for unauthorized domain, got:\n{text}"


@pytest.mark.asyncio
async def test_enumerate_subdomains_passes_allowlist_when_domain_authorized(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["example.com"])
    with patch("tools.mcp_tools.domain._stdlib_fetch", return_value=(200, {}, "[]")), \
         patch("tools.mcp_tools.domain.resolve_target_to_ip", return_value=None):
        text = _text(await mcp.call_tool("enumerate_subdomains", {
            "domain": "example.com",
            "sources": "crt_sh",
        }))
    assert "SUBDOMAIN_RESULT:" in text, f"expected SUBDOMAIN_RESULT, got BLOCKED:\n{text}"


@pytest.mark.asyncio
async def test_dns_recon_passes_allowlist_when_domain_authorized(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["example.com"])
    import socket as _sock
    fake_info = [(_sock.AF_INET, _sock.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    import builtins
    real_import = builtins.__import__
    def mock_import(name, *a, **k):
        if name.startswith("dns"):
            raise ImportError("no dnspython")
        return real_import(name, *a, **k)
    with patch("socket.getaddrinfo", return_value=fake_info), \
         patch("builtins.__import__", side_effect=mock_import):
        text = _text(await mcp.call_tool("dns_recon", {"domain": "example.com"}))
    assert "DNS_RECON_RESULT:" in text, f"expected DNS_RECON_RESULT, got BLOCKED:\n{text}"


@pytest.mark.asyncio
async def test_domain_whois_passes_allowlist_when_domain_authorized(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["example.com"])
    import builtins
    real_import = builtins.__import__
    def mock_import(name, *a, **k):
        if name == "whois":
            raise ImportError("no python-whois")
        return real_import(name, *a, **k)
    with patch("builtins.__import__", side_effect=mock_import), \
         patch("shutil.which", return_value=None):
        text = _text(await mcp.call_tool("domain_whois", {"domain": "example.com"}))
    # The tool runs (returns "unavailable") rather than BLOCKED — the gate passed.
    assert "WHOIS_RESULT:" in text, f"expected WHOIS_RESULT, got BLOCKED:\n{text}"
    assert "BLOCKED:" not in text


# ── Tier 2.1: takeover body-marker HTTP confirmation ──────────────────────


@pytest.mark.asyncio
async def test_takeover_confirmed_when_body_matches_marker(tmp_path: Path):
    """When the CNAME suffix matches AND the HTTP body contains the service
    marker, the status is upgraded from 'likely' to 'CONFIRMED'."""
    mcp = _make_server(tmp_path)
    # sub.example.com is unresolvable (no IP) but has a CNAME to herokuapp.com.
    # The HTTP probe of https://sub.example.com/ returns Heroku's "No such app".
    def fake_fetch(url, *, timeout=15, headers=None, data=None, max_bytes=4000):
        if "crt.sh" in url:
            return 200, {}, json.dumps([{"name_value": "sub.example.com"}])
        if url.startswith("https://sub.example.com") or url.startswith("http://sub.example.com"):
            return 404, {}, "herokucdn.com/error-pages/no-such-app.html"
        return 0, {}, ""
    # Mock CNAME resolution: dns.resolver.resolve(sub, "CNAME") returns a fake answer.
    class _FakeCname:
        def to_text(self):
            return "sub.example.herokuapp.com."
    class _FakeResolver:
        @staticmethod
        def resolve(name, rtype):
            if rtype == "CNAME" and "sub.example.com" in str(name):
                return [_FakeCname()]
            raise Exception("no answer")
    import sys
    dns_mod = type(sys)("dns")
    dns_mod.resolver = _FakeResolver
    with patch("tools.mcp_tools.domain._stdlib_fetch", side_effect=fake_fetch), \
         patch("tools.mcp_tools.domain.resolve_target_to_ip", return_value=None), \
         patch.dict("sys.modules", {"dns": dns_mod, "dns.resolver": _FakeResolver}):
        text = _text(await mcp.call_tool("enumerate_subdomains", {
            "domain": "example.com",
            "sources": "crt_sh",
        }))
    assert "TAKEOVER_CANDIDATES:" in text
    assert "CONFIRMED" in text, f"expected CONFIRMED takeover, got:\n{text}"
    assert "Heroku" in text


@pytest.mark.asyncio
async def test_takeover_likely_when_body_does_not_match(tmp_path: Path):
    """CNAME suffix matches but HTTP body doesn't contain the marker → 'likely'."""
    mcp = _make_server(tmp_path)
    def fake_fetch(url, *, timeout=15, headers=None, data=None, max_bytes=4000):
        if "crt.sh" in url:
            return 200, {}, json.dumps([{"name_value": "sub.example.com"}])
        # HTTP probe returns a generic page (no Heroku marker).
        return 200, {}, "<html>some other content</html>"
    class _FakeCname:
        def to_text(self):
            return "sub.example.herokuapp.com."
    class _FakeResolver:
        @staticmethod
        def resolve(name, rtype):
            if rtype == "CNAME":
                return [_FakeCname()]
            raise Exception("no answer")
    import sys
    dns_mod = type(sys)("dns")
    dns_mod.resolver = _FakeResolver
    with patch("tools.mcp_tools.domain._stdlib_fetch", side_effect=fake_fetch), \
         patch("tools.mcp_tools.domain.resolve_target_to_ip", return_value=None), \
         patch.dict("sys.modules", {"dns": dns_mod, "dns.resolver": _FakeResolver}):
        text = _text(await mcp.call_tool("enumerate_subdomains", {
            "domain": "example.com",
            "sources": "crt_sh",
        }))
    assert "likely dangling CNAME" in text, f"expected 'likely', got:\n{text}"
    assert "CONFIRMED" not in text


def test_takeover_fingerprints_has_25_plus_services():
    """The fingerprint table must cover ~25 services (Tier 2.1 expansion)."""
    from tools.mcp_tools.domain import _TAKEOVER_FINGERPRINTS
    assert len(_TAKEOVER_FINGERPRINTS) >= 25, (
        f"expected >=25 takeover fingerprints, got {len(_TAKEOVER_FINGERPRINTS)}"
    )
    # Each entry must have a suffix and body_markers.
    for svc, fp in _TAKEOVER_FINGERPRINTS.items():
        assert "suffix" in fp, f"{svc} missing suffix"
        assert "body_markers" in fp, f"{svc} missing body_markers"
        assert isinstance(fp["body_markers"], list) and fp["body_markers"], (
            f"{svc} body_markers must be a non-empty list"
        )
    # Spot-check a few of the new services.
    assert "Netlify" in _TAKEOVER_FINGERPRINTS
    assert "Vercel" in _TAKEOVER_FINGERPRINTS
    assert "Render" in _TAKEOVER_FINGERPRINTS
    assert "Cloudfront" in _TAKEOVER_FINGERPRINTS


# ── Tier 2.2: crt.sh large response (no truncation) ────────────────────────


@pytest.mark.asyncio
async def test_crt_sh_large_response_not_truncated(tmp_path: Path):
    """A crt.sh response >4000 chars must be fully parsed (5MB cap)."""
    mcp = _make_server(tmp_path)
    # Build a crt.sh JSON with many entries so it exceeds the old 4000-char cap.
    entries = [{"name_value": f"sub{i}.example.com"} for i in range(300)]
    big_json = json.dumps(entries)
    assert len(big_json) > 4000, "test data must exceed the old 4000-char cap"
    # Make the first 5 resolvable so they appear in the SUBDOMAINS section
    # (the rest are unresolvable and go to the takeover-investigate path,
    # but the key assertion is that the JSON was fully parsed, not truncated).
    resolvable = {f"sub{i}.example.com": f"10.0.0.{i}" for i in range(5)}
    with patch("tools.mcp_tools.domain._stdlib_fetch", return_value=(200, {}, big_json)), \
         patch("tools.mcp_tools.domain.resolve_target_to_ip", side_effect=lambda h: resolvable.get(h)):
        text = _text(await mcp.call_tool("enumerate_subdomains", {
            "domain": "example.com",
            "sources": "crt_sh",
        }))
    assert "SUBDOMAIN_RESULT:" in text
    # The first 5 (resolvable) must appear in the SUBDOMAINS section.
    assert "sub0.example.com" in text
    assert "sub4.example.com" in text
    # And the total count of resolvable subdomains must be 5 (not 0, which
    # would happen if the JSON was truncated and json.loads failed silently).
    assert "DISCOVERED: 5 resolvable subdomains" in text


# ── Tier 2.4: vhost content-hash comparison ──────────────────────────────


@pytest.mark.asyncio
async def test_vhost_content_hash_detects_same_length_different_content(tmp_path: Path):
    """A vhost returning the same length + status but different content must
    be detected via the SHA-256 hash (the old length-only check missed it)."""
    mcp = _make_server(tmp_path)
    # Baseline returns 100 chars of 'A'; admin returns 100 chars of 'B'.
    # Same length (100), same status (200) → length check misses it, hash catches it.
    def fake_fetch(url, *, timeout=15, headers=None, data=None, max_bytes=4000):
        host = (headers or {}).get("Host", "")
        if "admin" in host:
            return 200, {}, "B" * 100
        return 200, {}, "A" * 100
    with patch("tools.mcp_tools.domain._stdlib_fetch", side_effect=fake_fetch):
        text = _text(await mcp.call_tool("vhost_enum", {
            "target_ip": "10.0.0.5",
            "port": 80,
            "domain": "example.com",
        }))
    assert "VHOST_RESULT:" in text
    assert "admin.example.com" in text, f"admin vhost should be detected by hash:\n{text}"
    assert "hash=" in text


@pytest.mark.asyncio
async def test_vhost_https_shows_sni_note(tmp_path: Path):
    """HTTPS vhost_enum must emit the SNI-limitation note."""
    mcp = _make_server(tmp_path)
    with patch("tools.mcp_tools.domain._stdlib_fetch", return_value=(200, {}, "default")):
        text = _text(await mcp.call_tool("vhost_enum", {
            "target_ip": "10.0.0.5",
            "port": 443,
            "domain": "example.com",
        }))
    assert "VHOST_RESULT:" in text
    assert "SNI" in text, f"expected SNI limitation note, got:\n{text}"


# ── Tier 2.5: DNSSEC DS-record check ─────────────────────────────────────


@pytest.mark.asyncio
async def test_dns_recon_dnssec_uses_ds_record(tmp_path: Path):
    """DNSSEC status must come from a DS-record query, not the AD-flag heuristic."""
    mcp = _make_server(tmp_path)
    import socket as _sock
    fake_info = [(_sock.AF_INET, _sock.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    import builtins
    real_import = builtins.__import__
    def mock_import(name, *a, **k):
        if name.startswith("dns"):
            raise ImportError("no dnspython")
        return real_import(name, *a, **k)
    with patch("socket.getaddrinfo", return_value=fake_info), \
         patch("builtins.__import__", side_effect=mock_import):
        text = _text(await mcp.call_tool("dns_recon", {"domain": "example.com"}))
    assert "DNS_RECON_RESULT:" in text
    # Without dnspython, DNSSEC falls back to "unknown" (the socket path can't
    # query DS records). The key assertion: the old "enabled (AD flag set)"
    # string must NOT appear (that was the old heuristic's output).
    assert "AD flag" not in text, f"old AD-flag heuristic still present:\n{text}"


# ── Tier 3.2: domain_whois captures ALL name servers (not just the first) ──


@pytest.mark.asyncio
async def test_domain_whois_captures_all_nameservers(tmp_path: Path):
    """The binary-fallback parser must collect ALL name server: lines, not
    just the first (regression: the old `and not nameservers` guard stopped
    after the first NS)."""
    mcp = _make_server(tmp_path)
    # Mock python-whois as unavailable; mock the whois binary to return 3 NS lines.
    import builtins
    real_import = builtins.__import__
    def mock_import(name, *a, **k):
        if name == "whois":
            raise ImportError("no python-whois")
        return real_import(name, *a, **k)
    fake_whois_output = (
        "Registrar: Example Registrar, LLC\n"
        "Creation Date: 2020-01-01T00:00:00Z\n"
        "Registry Expiry Date: 2025-01-01T00:00:00Z\n"
        "Registrant Org: Example Inc\n"
        "Name Server: ns1.example.com\n"
        "Name Server: ns2.example.com\n"
        "Name Server: ns3.example.com\n"
    )
    with patch("builtins.__import__", side_effect=mock_import), \
         patch("shutil.which", return_value="/usr/bin/whois"), \
         patch("tools.mcp_tools.domain._run_with_pgrp_timeout",
               return_value=(0, fake_whois_output, "")):
        text = _text(await mcp.call_tool("domain_whois", {"domain": "example.com"}))
    assert "WHOIS_RESULT:" in text
    # All 3 nameservers must appear (the old guard captured only ns1).
    assert "ns1.example.com" in text
    assert "ns2.example.com" in text
    assert "ns3.example.com" in text


# ── Tier 3.4: ERROR: returns are audited as blocked ──────────────────────


def test_error_result_marker_is_blocked():
    """The _result_is_blocked helper must recognize ERROR: returns as blocked
    (Tier 3.4 added ERROR: to _BLOCKED_RESULT_MARKERS)."""
    from tools.mcp_shared import _result_is_blocked
    assert _result_is_blocked("ERROR: domain is required.") is True
    assert _result_is_blocked("ERROR: Invalid target (IP or domain).") is True
    assert _result_is_blocked("BLOCKED: target not in allowlist") is True
    # A successful result must NOT be flagged as blocked.
    assert _result_is_blocked("SUBDOMAIN_RESULT: completed\n...") is False
    assert _result_is_blocked("DNS_RESULT: completed") is False
