"""TODO 009: plugin without manifest/wrapper fails to load; audit row written."""

from __future__ import annotations

from pathlib import Path

from tools.plugins import (
    PluginManifest,
    PluginRegistry,
    validate_plugin_manifest,
    validate_plugin_mcp_wrappers,
)


def test_manifest_requires_provides_list(tmp_path):
    m = PluginManifest(name="x", capabilities=("mcp_tool",), target_touching=True)
    problems = validate_plugin_manifest(m, plugin_py_exists=True)
    assert any("provides_mcp_tools" in p for p in problems)


def test_undeclared_target_touching_refused():
    m = PluginManifest(name="x", capabilities=(), target_touching=True)
    problems = validate_plugin_manifest(m, plugin_py_exists=True)
    assert any("mcp_tool" in p for p in problems)


def test_wrapper_check_blocks_unwrapped_tool(tmp_path):
    bad = tmp_path / "plugin.py"
    bad.write_text(
        "def register_mcp_tools(mcp, ctx):\n    @mcp.tool()\n    def evil(target_ip: str):\n        return target_ip\n",
        encoding="utf-8",
    )
    offenders = validate_plugin_mcp_wrappers(bad)
    assert offenders, "undeclared target-touching tool must be blocked"


def test_wrapper_check_allows_wrapped_tool(tmp_path):
    good = tmp_path / "plugin.py"
    good.write_text(
        "def register_mcp_tools(mcp, ctx):\n"
        "    @mcp.tool()\n"
        "    @ctx.require_allowlist()\n"
        "    def ok_tool(target_ip: str):\n"
        "        return target_ip\n",
        encoding="utf-8",
    )
    assert validate_plugin_mcp_wrappers(good) == []


def test_example_plugin_manifest_declares_capabilities():
    import pathlib

    repo = pathlib.Path(__file__).resolve().parent.parent
    text = (repo / "plugins" / "example_recon_report" / "plugin.yaml").read_text(encoding="utf-8")
    assert "target_touching" in text
    assert "provides_mcp_tools" in text
    assert "plugin_info" in text


def test_audit_row_on_load():
    reg = PluginRegistry()
    m = PluginManifest(name="demo", capabilities=("mcp_tool",), provides_mcp_tools=("t",))
    reg.audit_plugin_event("load", m, "test")
    assert reg._plugin_audit and reg._plugin_audit[-1]["plugin"] == "demo"
    assert "chain" in reg._plugin_audit[-1]
