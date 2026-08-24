"""Phase 3 Round 2 — MCP registration + behavior of the 3 new recon tools.

Builds a real MCP server via ``create_mcp_server`` (mirroring
``test_mcp_tool_registration.py``) with ``require_explicit_allowlist: False``
so the allowlist decorator is a pass-through. No real network: OSINT and UDP
backends are monkeypatched.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _make_server(tmp_path: Path):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        {"exploit": {"require_explicit_allowlist": False}},
    )


def _to_text(result) -> str:
    """Coerce a FastMCP call_tool result (str / list[Content] / dict) to text."""
    if isinstance(result, str):
        return result
    if isinstance(result, list):
        parts = []
        for item in result:
            text = getattr(item, "text", None)
            if text is not None:
                parts.append(text)
            elif isinstance(item, dict):
                parts.append(json.dumps(item))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    if isinstance(result, dict):
        # FastMCP may return {"result": ...} or similar.
        for key in ("result", "text", "content"):
            if key in result:
                return _to_text(result[key])
        return json.dumps(result)
    return str(result)


@pytest.mark.asyncio
async def test_new_recon_tools_registered(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    names = {tool.name for tool in await mcp.list_tools()}
    assert "run_udp_recon" in names
    assert "run_osint_recon" in names
    assert "diff_recon_runs" in names


@pytest.mark.asyncio
async def test_diff_recon_runs_reports_added_port(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    old = {"target_ip": "10.0.0.50", "open_ports": [22, 80], "services": []}
    new = {"target_ip": "10.0.0.50", "open_ports": [22, 80, 443], "services": []}
    old_path = tmp_path / "old_recon.json"
    new_path = tmp_path / "new_recon.json"
    old_path.write_text(json.dumps(old), encoding="utf-8")
    new_path.write_text(json.dumps(new), encoding="utf-8")

    result = await mcp.call_tool(
        "diff_recon_runs", {"old_path": str(old_path), "new_path": str(new_path)}
    )
    text = _to_text(result)
    assert "RECON_DIFF" in text
    # 443 is the added port.
    assert "443" in text


@pytest.mark.asyncio
async def test_run_osint_recon_returns_summary(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    canned = {
        "target_ip": "10.0.0.50",
        "hostname": "host.example.com",
        "ipv6_addresses": ["2001:db8::1"],
        "reverse_dns": "host.example.com",
        "cert_transparency": {"domain": "host.example.com", "certs": [{}, {}], "count": 2},
        "shodan": {"enabled": False, "note": "no Shodan API key configured"},
    }
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("tools.recon_osint.run_osint", lambda ip, **k: canned)
        result = await mcp.call_tool("run_osint_recon", {"target_ip": "10.0.0.50"})
    text = _to_text(result)
    assert "OSINT" in text
    assert "2001:db8::1" in text
    assert "host.example.com" in text
    assert "2" in text  # cert transparency count
    assert "disabled" in text  # shodan disabled


@pytest.mark.asyncio
async def test_run_osint_recon_rejects_invalid_ip(tmp_path: Path):
    mcp = _make_server(tmp_path)
    # "not-an-ip" is neither a valid IPv4 nor a valid FQDN (no dot/TLD), so the
    # Phase 4 validate_target_or_ip gate rejects it. (A dotted string like
    # "not.an.ip.addr" IS a valid FQDN under the relaxed gate and would pass.)
    result = await mcp.call_tool("run_osint_recon", {"target_ip": "not-an-ip"})
    text = _to_text(result)
    assert "ERROR" in text
    assert "Invalid target (IP or domain)" in text


@pytest.mark.asyncio
async def test_run_udp_recon_returns_summary(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)

    async def fake_recon_udp(self, target, top_ports=100):
        from tools.recon_pipeline import HostReconResult, ServiceInfo

        return HostReconResult(
            target_ip=target,
            scan_tool="nmap-udp",
            udp_ports=[53, 161],
            services=[
                ServiceInfo(port=53, protocol="udp", service="domain"),
                ServiceInfo(port=161, protocol="udp", service="snmp"),
            ],
        )

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("tools.recon_pipeline.ReconPipeline.recon_udp", fake_recon_udp)
        result = await mcp.call_tool(
            "run_udp_recon", {"target_ip": "10.0.0.50", "top_ports": 100}
        )
    text = _to_text(result)
    assert "UDP_PORTS" in text
    assert "53" in text
    assert "161" in text
    assert "domain" in text
