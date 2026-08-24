from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.cve_lookup import CVESearchSettings, NVDClient
from tools.exploit_search import ExploitSearch, ExploitSearchSettings
from tools.web_researcher import WebResearcher, WebResearcherSettings


def _text(result) -> str:
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


def _write_skill(root: Path, name: str, tags: list[str]) -> None:
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        "description: Runtime skill test.\n"
        "tags:\n" + "".join(f"- {tag}\n" for tag in tags) + "---\n"
        "# Skill\n\n## When to Use\nUse for authorized runtime guidance.\n\n## Workflow\nStay in scope.",
        encoding="utf-8",
    )


def _server(tmp_path: Path, skill_root: Path, *, allow_lookup: bool = True):
    from mcp_exploit_server import create_mcp_server

    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings(enabled=False)),
        NVDClient(CVESearchSettings(enabled=False)),
        WebResearcher(WebResearcherSettings(enabled=False)),
        tmp_path / "workspace",
        {
            "skills": {
                "enabled": True,
                "allow_model_lookup": allow_lookup,
                "roots": [str(skill_root)],
                "default_enabled": [],
                "max_chars_per_skill": 1200,
            }
        },
    )


@pytest.mark.asyncio
async def test_runtime_skill_mcp_tools_list_search_load_and_audit(tmp_path: Path):
    skill_root = tmp_path / "skills"
    _write_skill(skill_root, "scanning-network-with-nmap-advanced", ["nmap", "reconnaissance"])
    mcp = _server(tmp_path, skill_root)

    names = {tool.name for tool in await mcp.list_tools()}
    assert {"list_runtime_skills", "search_runtime_skills", "load_runtime_skill"} <= names

    listed = _text(await mcp.call_tool("list_runtime_skills", {}))
    searched = _text(await mcp.call_tool("search_runtime_skills", {"query": "nmap"}))
    loaded = _text(await mcp.call_tool("load_runtime_skill", {"name": "scanning-network-with-nmap-advanced"}))

    assert "scanning-network-with-nmap-advanced" in listed
    assert "scanning-network-with-nmap-advanced" in searched
    assert "RUNTIME_SKILL_LOAD: loaded" in loaded
    assert "SAFETY: Advisory only" in loaded

    audit_path = tmp_path / "workspace" / "exploit_audit.jsonl"
    audit = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert any(row.get("tool_name") == "load_runtime_skill" and row.get("status") == "completed" for row in audit)


@pytest.mark.asyncio
async def test_runtime_skill_mcp_tools_can_be_disabled(tmp_path: Path):
    skill_root = tmp_path / "skills"
    _write_skill(skill_root, "scanning-network-with-nmap-advanced", ["nmap"])
    mcp = _server(tmp_path, skill_root, allow_lookup=False)

    names = {tool.name for tool in await mcp.list_tools()}

    assert "load_runtime_skill" not in names


def _write_skill_with_bundle(root: Path, name: str) -> None:
    """Skill with references/*.md + NIST CSF / MITRE ATT&CK frontmatter."""
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        "description: Bundled skill.\n"
        "tags:\n- nmap\n"
        "nist_csf:\n- DE.AE\n- PR.AC\n"
        "mitre_attack:\n- T1046\n- T1595\n"
        "---\n# Skill\n\n## Workflow\nAuthorized use only.",
        encoding="utf-8",
    )
    refs = skill_dir / "references"
    refs.mkdir()
    (refs / "cve-2021-44228.md").write_text("# CVE-2021-44228\nSecret reference body never inlined.", encoding="utf-8")
    (refs / "notes.md").write_text("# Notes\nMore secret reference body.", encoding="utf-8")


@pytest.mark.asyncio
async def test_list_skill_references_returns_paths(tmp_path: Path):
    skill_root = tmp_path / "skills"
    _write_skill_with_bundle(skill_root, "bundled-skill")
    mcp = _server(tmp_path, skill_root)

    names = {tool.name for tool in await mcp.list_tools()}
    assert "list_skill_references" in names

    out = _text(await mcp.call_tool("list_skill_references", {"name": "bundled-skill"}))
    assert "RUNTIME_SKILL_REFERENCES: bundled-skill" in out
    assert "cve-2021-44228.md" in out
    assert "notes.md" in out
    assert "NIST CSF: DE.AE, PR.AC" in out
    assert "MITRE ATT&CK: T1046, T1595" in out
    # Paths only -- reference contents must NOT be inlined.
    assert "Secret reference body" not in out


@pytest.mark.asyncio
async def test_list_skill_references_unknown_skill(tmp_path: Path):
    skill_root = tmp_path / "skills"
    _write_skill(skill_root, "real-skill", ["nmap"])
    mcp = _server(tmp_path, skill_root)

    out = _text(await mcp.call_tool("list_skill_references", {"name": "no-such-skill"}))
    assert "not found" in out


@pytest.mark.asyncio
async def test_list_skill_references_disabled_by_config(tmp_path: Path):
    skill_root = tmp_path / "skills"
    _write_skill_with_bundle(skill_root, "bundled-skill")
    from mcp_exploit_server import create_mcp_server

    mcp = create_mcp_server(
        ExploitSearch(ExploitSearchSettings(enabled=False)),
        NVDClient(CVESearchSettings(enabled=False)),
        WebResearcher(WebResearcherSettings(enabled=False)),
        tmp_path / "workspace",
        {
            "skills": {
                "enabled": True,
                "allow_model_lookup": True,
                "roots": [str(skill_root)],
                "default_enabled": [],
                "allow_reference_listing": False,
            }
        },
    )
    out = _text(await mcp.call_tool("list_skill_references", {"name": "bundled-skill"}))
    assert "disabled" in out


@pytest.mark.asyncio
async def test_references_not_read_into_context(tmp_path: Path):
    """load_runtime_skill must never inline reference file contents (paths
    only, and only via the separate list_skill_references tool)."""
    skill_root = tmp_path / "skills"
    _write_skill_with_bundle(skill_root, "bundled-skill")
    mcp = _server(tmp_path, skill_root)

    loaded = _text(await mcp.call_tool("load_runtime_skill", {"name": "bundled-skill"}))
    assert "Secret reference body" not in loaded
    assert "More secret reference body" not in loaded


def test_skill_metadata_parses_references_and_frameworks(tmp_path: Path):
    """LoadedSkill.metadata carries references/nist_csf/mitre_attack (Tier 3.3)."""
    from tools.skill_registry import load_skill_registry

    skill_root = tmp_path / "skills"
    _write_skill_with_bundle(skill_root, "bundled-skill")
    reg = load_skill_registry([skill_root], base_dir=skill_root)
    skill = reg.get("bundled-skill")
    assert skill is not None
    ref_names = {p.name for p in skill.metadata.references}
    assert {"cve-2021-44228.md", "notes.md"} <= ref_names
    assert skill.metadata.nist_csf == ("DE.AE", "PR.AC")
    assert skill.metadata.mitre_attack == ("T1046", "T1595")


def test_render_skill_context_include_metadata_surfaces_frameworks(tmp_path: Path):
    from tools.skill_registry import load_skill_registry, render_skill_context

    skill_root = tmp_path / "skills"
    _write_skill_with_bundle(skill_root, "bundled-skill")
    reg = load_skill_registry([skill_root], base_dir=skill_root)
    skill = reg.get("bundled-skill")

    with_meta = render_skill_context([skill], include_metadata=True, max_total_chars=4000)
    without_meta = render_skill_context([skill], include_metadata=False, max_total_chars=4000)
    assert "NIST CSF: DE.AE, PR.AC" in with_meta
    assert "MITRE ATT&CK: T1046, T1595" in with_meta
    assert "References: cve-2021-44228.md" in with_meta
    assert "NIST CSF" not in without_meta
    # Both are still fenced as untrusted.
    assert "<untrusted_skill_guidance" in with_meta
    assert "</untrusted_skill_guidance>" in with_meta
