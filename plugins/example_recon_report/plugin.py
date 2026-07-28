"""Example NetAttackAi plugin: read-only recon-report attack module + plugin_info MCP tool.

This is a *reference* plugin. It demonstrates the full plugin contract:

* ``create_plugin()`` returns a :class:`Plugin` subclass whose ``manifest`` is
  loaded from the sibling ``plugin.yaml``.
* ``register(registry)`` contributes one attack module and one MCP tool factory.
* The MCP tool factory stacks ``@mcp.tool()`` then ``@ctx.require_allowlist()``
  exactly like ``tools/mcp_tools/recon.py`` so the target-IP allowlist lock and
  JSONL audit trail apply to the plugin tool.

SAFETY (lab build): plugins are trusted Python with full operator-box privileges.
The plugin manager does NOT sandbox code; it enforces opt-in (default disabled)
and documents the safety-decorator requirement. This plugin's only MCP tool is
read-only and target-locked via ``ctx.require_allowlist()``. It performs no log
clearing, timestomping, EDR defeat, DoS, or malware.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext
from tools.plugins import Plugin, PluginManifest, PluginRegistry

# Manifest lives next to this file: plugins/example_recon_report/plugin.yaml
_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"


class ExampleReportModule(AttackModule):
    """Read-only recon-report attack module (baseline, always selectable).

    A deliberately low-priority, side-effect-free module: it never executes a
    command against the target and never claims a shell or privilege level. It
    only summarizes that a recon report is available, target-locked to
    ``ctx.target_ip``.
    """

    name = "example_plugin_recon_report"
    description = "Example plugin: read-only recon summary (target-locked)."
    target_services: list[str] = []
    target_ports: list[int] = []
    required_cves: list[str] = []
    target_versions: dict[str, list[str]] = {}

    def applicability(self, ctx: ModuleContext) -> int:  # noqa: ARG002
        # Baseline score: always selectable, but the lowest priority so real
        # modules with service/port/CVE matches rank above it.
        return 10

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "info",
            "module": self.name,
            "target_ip": ctx.target_ip,
            "summary": "example plugin recon report",
            "note": "read-only",
        }


class ExampleReconReportPlugin(Plugin):
    """Plugin wrapper that registers the example module + plugin_info MCP tool."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        # Reuse the plugin manager's stdlib YAML subset parser so we don't add
        # a PyYAML dependency to the plugin itself.
        from tools.plugins import _parse_manifest_yaml  # type: ignore

        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        # 1. Attack module registration.
        registry.register_attack_module(ExampleReportModule)

        # 2. MCP tool factory. The factory MUST wrap each target-touching
        #    handler with ctx.require_allowlist() so the target-IP allowlist
        #    lock + audit trail apply. We stack @mcp.tool() then
        #    @ctx.require_allowlist() -- the same pattern as
        #    tools/mcp_tools/recon.py.
        def register_mcp_tools(mcp: Any, ctx: Any) -> None:
            require_allowlist = ctx.require_allowlist

            @mcp.tool()
            @require_allowlist()
            def plugin_info(target_ip: str) -> str:
                """Return static info about this plugin, target-locked to target_ip."""
                return f"PLUGIN_INFO: example_recon_report v0.1.0 target=<{target_ip}>"

        registry.register_mcp_tools(register_mcp_tools)


def create_plugin() -> Plugin:
    """Factory invoked by :class:`PluginManager` when loading this plugin."""
    return ExampleReconReportPlugin()