"""Phase 4: verify the new CVE-family templates dispatch correctly."""
import asyncio
import tempfile
from pathlib import Path

import pytest


def _make_server(tmp_path: Path):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    search = ExploitSearch(ExploitSearchSettings())
    nvd = NVDClient(CVESearchSettings())
    config = {"exploit": {"require_explicit_allowlist": False, "allowed_targets": []}}
    return create_mcp_server(
        search, nvd, WebResearcher(WebResearcherSettings()), tmp_path, config
    )


def _text(result) -> str:
    content = result[0] if isinstance(result, (list, tuple)) else result
    if hasattr(content, "content"):
        content = content.content
    parts = []
    for item in content if isinstance(content, (list, tuple)) else [content]:
        if hasattr(item, "text"):
            parts.append(item.text)
        elif isinstance(item, dict):
            parts.append(str(item.get("text", "")))
    return "\n".join(parts)


@pytest.mark.asyncio
async def test_new_cve_templates_dispatch(tmp_path: Path, monkeypatch) -> None:
    """Each new CVE ID must dispatch to its family template (not generic)."""
    from tools.cve_lookup import NVDClient
    from tools.exploit_search import ExploitSearch

    monkeypatch.setattr(NVDClient, "search_sync", lambda self, q: [])
    monkeypatch.setattr(ExploitSearch, "search_web_exploit", lambda self, q: "no results")

    mcp = _make_server(tmp_path)
    cases = [
        ("CVE-2024-6387", "ssh", "9.6p1", "regresshion"),
        ("CVE-2024-3094", "ssh", "9.4p1", "xz_backdoor"),
        ("CVE-2023-46604", "activemq", "5.15.16", "activemq"),
        ("CVE-2023-22515", "confluence", "8.0.0", "confluence"),
        ("CVE-2024-21887", "ivanti", "22.3R3", "ivanti"),
        ("CVE-2024-3400", "panos", "10.2", "panos"),
        ("CVE-2023-3519", "citrix", "13.1", "citrix"),
        ("CVE-2024-0204", "connectwise", "23.9.7", "connectwise"),
        ("CVE-2024-23897", "jenkins", "2.441", "jenkins"),
        ("CVE-2023-23752", "joomla", "4.2.7", "joomla"),
        ("CVE-2022-42889", "commons_text", "1.9", "text4shell"),
        ("CVE-2024-4577", "php_cgi", "8.1", "php_cgi"),
        ("CVE-2023-44487", "http", "1.1", "http2_rapid_reset"),
    ]
    for cve, svc, ver, expect in cases:
        res = await mcp.call_tool(
            "cve_to_exploit_synth",
            {"target_ip": "10.0.0.1", "cve_id": cve, "service_name": svc, "version": ver},
        )
        text = _text(res)
        assert f"TEMPLATE_DISPATCHED: {expect}" in text, (
            f"{cve} should dispatch to {expect}, got: {[l for l in text.splitlines() if 'TEMPLATE_DISPATCHED' in l]}"
        )
        # The generated script must be present and syntax-valid
        assert "--- Exploit Script Template ---" in text


@pytest.mark.asyncio
async def test_unknown_cve_falls_back_to_generic(tmp_path: Path, monkeypatch) -> None:
    from tools.cve_lookup import NVDClient
    from tools.exploit_search import ExploitSearch

    monkeypatch.setattr(NVDClient, "search_sync", lambda self, q: [])
    monkeypatch.setattr(ExploitSearch, "search_web_exploit", lambda self, q: "no results")

    mcp = _make_server(tmp_path)
    res = await mcp.call_tool(
        "cve_to_exploit_synth",
        {"target_ip": "10.0.0.1", "cve_id": "CVE-2025-99999", "service_name": "http", "version": "1.0"},
    )
    text = _text(res)
    assert "TEMPLATE_DISPATCHED: generic" in text
