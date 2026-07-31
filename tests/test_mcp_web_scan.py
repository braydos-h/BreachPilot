"""Tests for the structured ``run_web_scan`` MCP tool (idea 7).

Covers: registration, the scanner allowlist, IPv4 validation, the target-IP
allowlist lock (via ``@require_allowlist``), shell-metachar ``options``
rejection, the happy path, and the not-installed friendly message.
"""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest


def _make_server(
    tmp_path: Path,
    *,
    require_allowlist: bool = True,
    allowed_targets: list[str] | None = None,
):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {
        "exploit": {
            "require_explicit_allowlist": require_allowlist,
            "allowed_targets": allowed_targets if allowed_targets is not None else ["10.0.0.50"],
        }
    }
    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        config,
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


def _patch_pgrp(monkeypatch, returncode=0, out="ok\n", err=""):
    """Patch ``_run_with_pgrp_timeout`` and return the captured-argv list."""
    import mcp_exploit_server as mes

    captured: list[Any] = []

    def _fake(args, timeout, stdout=None, stderr=None, cwd=None, env=None,
              input_text=None, **popen_kwargs):
        captured.append(list(args))
        return returncode, out, err

    monkeypatch.setattr(mes, "_run_with_pgrp_timeout", _fake)
    return captured


@pytest.mark.asyncio
async def test_run_web_scan_is_registered(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    names = {tool.name for tool in await mcp.list_tools()}
    assert "run_web_scan" in names


@pytest.mark.asyncio
async def test_run_web_scan_rejects_unsupported_scanner(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "run_web_scan", {"scanner": "nessus", "target_ip": "10.0.0.50"},
    ))
    assert text.startswith("BLOCKED:")
    assert "unsupported scanner" in text


@pytest.mark.asyncio
async def test_run_web_scan_rejects_invalid_target_ip(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "run_web_scan", {"scanner": "nikto", "target_ip": "not-an-ip"},
    ))
    assert text.startswith("BLOCKED:")
    assert "valid IPv4" in text


@pytest.mark.asyncio
async def test_run_web_scan_blocks_out_of_allowlist_target(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, allowed_targets=["10.0.0.50"])
    text = _text(await mcp.call_tool(
        "run_web_scan", {"scanner": "nikto", "target_ip": "10.0.0.99"},
    ))
    # @require_allowlist blocks before the function body runs.
    assert text.startswith("BLOCKED:")
    assert "10.0.0.99" in text


@pytest.mark.asyncio
async def test_run_web_scan_rejects_shell_metachar_options(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    text = _text(await mcp.call_tool(
        "run_web_scan",
        {"scanner": "nikto", "target_ip": "10.0.0.50", "options": "x; rm -rf /"},
    ))
    assert text.startswith("BLOCKED:")
    assert "metacharacters" in text


@pytest.mark.asyncio
async def test_run_web_scan_happy_path(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    captured = _patch_pgrp(monkeypatch, returncode=0, out="Server: nginx\n", err="")

    text = _text(await mcp.call_tool(
        "run_web_scan",
        {"scanner": "nikto", "target_ip": "10.0.0.50", "port": 8080},
    ))
    assert "WEB_SCAN_RESULT: completed" in text
    assert "SCANNER: nikto" in text
    assert "TARGET: 10.0.0.50:8080" in text
    # argv was a list (no shell) and targeted the allowlisted host.
    assert captured, "_run_with_pgrp_timeout was not invoked"
    assert captured[0][0] == "nikto"
    assert "10.0.0.50" in captured[0]
    assert "8080" in captured[0]


@pytest.mark.asyncio
async def test_run_web_scan_not_installed(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    text = _text(await mcp.call_tool(
        "run_web_scan", {"scanner": "nikto", "target_ip": "10.0.0.50"},
    ))
    assert text.startswith("SCANNER_NOT_INSTALLED:")


@pytest.mark.asyncio
async def test_run_web_scan_builds_url_scanner_argv(tmp_path: Path, monkeypatch) -> None:
    """nuclei/sqlmap/whatweb/wpscan take a URL, not -h; confirm the argv shape."""
    mcp = _make_server(tmp_path, require_allowlist=False)
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    captured = _patch_pgrp(monkeypatch)

    await mcp.call_tool(
        "run_web_scan",
        {"scanner": "nuclei", "target_ip": "10.0.0.50", "port": 80, "path": "/"},
    )
    assert captured[0][0] == "nuclei"
    assert "-u" in captured[0]
    assert "http://10.0.0.50:80/" in captured[0]