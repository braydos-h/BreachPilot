"""Tests for the engine MCP server (Feature A).

The engine server exposes advisory + history tools to foreign AI assistants.
v1 is read-only: skill search, skill body, NVD CVE lookup, run history.
No target touching, no terminal, no exploit surface.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.cve_lookup import CVESearchSettings, NVDClient


def _text(result: Any) -> str:
    if isinstance(result, tuple):
        result = result[0]
    if isinstance(result, list):
        blocks = result
    elif isinstance(result, dict):
        blocks = result.get("content", [])
    else:
        blocks = getattr(result, "content", None) or []
    out: list[str] = []
    for block in blocks:
        if isinstance(block, dict):
            out.append(str(block.get("text", "")))
        else:
            out.append(str(getattr(block, "text", "")))
    return "\n".join(out)


def _write_skill(root: Path, name: str, description: str, tags: list[str]) -> None:
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        f"description: {description}\n"
        "tags:\n"
        + "".join(f"- {tag}\n" for tag in tags)
        + "---\n"
        "# Skill\n\n## When to Use\nAuthorized testing only.\n\n## Workflow\nStay in scope.",
        encoding="utf-8",
    )


def _server(tmp_path: Path, skill_root: Path, *, nvd_enabled: bool = True, reports_dir: Path | None = None):
    from mcp_engine_server import create_mcp_server

    nvd = NVDClient(CVESearchSettings(enabled=nvd_enabled))
    return create_mcp_server(
        nvd=nvd,
        config={"skills": {"roots": [str(skill_root)]}},
        reports_dir=reports_dir or tmp_path / "reports",
        skill_roots=[skill_root],
    )


@pytest.mark.asyncio
async def test_engine_server_registers_five_advisory_tools(tmp_path: Path):
    skill_root = tmp_path / "skills"
    _write_skill(skill_root, "scanning-network-with-nmap-advanced", "Nmap recon", ["nmap", "recon"])
    mcp = _server(tmp_path, skill_root)

    names = {tool.name for tool in await mcp.list_tools()}
    assert {
        "search_skills", "get_skill", "cve_lookup", "list_runs", "get_run"
    } <= names
    # No offensive/terminal tools leak into the engine server.
    assert "run_exploit_terminal" not in names
    assert "run_msf_module" not in names


@pytest.mark.asyncio
async def test_search_skills_returns_lexical_matches(tmp_path: Path):
    skill_root = tmp_path / "skills"
    _write_skill(skill_root, "scanning-network-with-nmap-advanced", "Nmap recon methodology", ["nmap", "recon"])
    _write_skill(skill_root, "attacking-domains-end-to-end", "Domain attack flow", ["domain", "web"])
    mcp = _server(tmp_path, skill_root)

    raw = await mcp.call_tool("search_skills", {"query": "nmap", "limit": 5})
    data = json.loads(_text(raw))
    assert data["count"] >= 1
    names = [s["name"] for s in data["skills"]]
    assert "scanning-network-with-nmap-advanced" in names
    # The non-matching skill should not appear.
    assert "attacking-domains-end-to-end" not in names


@pytest.mark.asyncio
async def test_search_skills_limit_is_capped(tmp_path: Path):
    skill_root = tmp_path / "skills"
    for i in range(5):
        _write_skill(skill_root, f"skill-{i}", f"skill number {i}", ["test"])
    mcp = _server(tmp_path, skill_root)

    raw = await mcp.call_tool("search_skills", {"query": "skill", "limit": 3})
    data = json.loads(_text(raw))
    assert data["count"] == 3


@pytest.mark.asyncio
async def test_get_skill_returns_body_for_known_name(tmp_path: Path):
    skill_root = tmp_path / "skills"
    _write_skill(skill_root, "scanning-network-with-nmap-advanced", "Nmap recon", ["nmap"])
    mcp = _server(tmp_path, skill_root)

    raw = await mcp.call_tool("get_skill", {"name": "scanning-network-with-nmap-advanced"})
    data = json.loads(_text(raw))
    assert data["ok"] is True
    assert data["name"] == "scanning-network-with-nmap-advanced"
    assert "## When to Use" in data["body"]
    assert data["tags"] == ["nmap"]


@pytest.mark.asyncio
async def test_get_skill_returns_error_for_unknown_name(tmp_path: Path):
    skill_root = tmp_path / "skills"
    _write_skill(skill_root, "scanning-network-with-nmap-advanced", "Nmap recon", ["nmap"])
    mcp = _server(tmp_path, skill_root)

    raw = await mcp.call_tool("get_skill", {"name": "does-not-exist"})
    data = json.loads(_text(raw))
    assert data["ok"] is False
    assert "not found" in data["error"]


@pytest.mark.asyncio
async def test_cve_lookup_returns_formatted_string(tmp_path: Path):
    skill_root = tmp_path / "skills"
    _write_skill(skill_root, "skill-x", "x", ["x"])
    # NVDClient with enabled=False returns empty results without raising.
    mcp = _server(tmp_path, skill_root, nvd_enabled=False)

    raw = await mcp.call_tool("cve_lookup", {"query": "apache 2.4.49"})
    text = _text(raw)
    # format_cve_results on empty results still returns a deterministic string.
    assert isinstance(text, str)
    assert "apache 2.4.49" in text or "No CVE results" in text or text.strip() == ""


@pytest.mark.asyncio
async def test_list_runs_returns_empty_when_no_history(tmp_path: Path):
    skill_root = tmp_path / "skills"
    _write_skill(skill_root, "skill-x", "x", ["x"])
    reports = tmp_path / "reports"
    reports.mkdir()
    mcp = _server(tmp_path, skill_root, reports_dir=reports)

    raw = await mcp.call_tool("list_runs", {"limit": 10})
    data = json.loads(_text(raw))
    assert data["count"] == 0
    assert data["runs"] == []


@pytest.mark.asyncio
async def test_get_run_returns_error_for_unknown_id(tmp_path: Path):
    skill_root = tmp_path / "skills"
    _write_skill(skill_root, "skill-x", "x", ["x"])
    reports = tmp_path / "reports"
    reports.mkdir()
    mcp = _server(tmp_path, skill_root, reports_dir=reports)

    raw = await mcp.call_tool("get_run", {"run_id": "nonexistent"})
    data = json.loads(_text(raw))
    assert data["ok"] is False
    assert "not found" in data["error"]
