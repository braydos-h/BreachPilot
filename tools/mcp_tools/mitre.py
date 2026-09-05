"""MITRE ATT&CK Navigator export MCP tool registration.

Exposes ``export_attack_navigator`` as an ``@audit_tool``-gated MCP tool. The
tool is local-only (reads the operator's own audit trail, writes a JSON file);
no target touch, so ``@audit_tool`` (not ``@require_allowlist``) is the right
gate. See ``tools/mitre_export.py`` for the mapping logic.
"""

from __future__ import annotations

from typing import Any

from tools.mcp_tools.registry import ToolContext
from tools.mitre_export import export_attack_navigator as _export_attack_navigator


def register_mitre_tools(mcp: Any, *, ctx: ToolContext) -> None:
    config = ctx.config
    audit_tool = ctx.audit_tool

    @mcp.tool()
    @audit_tool
    def export_attack_navigator(target_ip: str, output_path: str = "") -> str:
        """Map this run's audit trail to MITRE ATT&CK techniques and write a
        Navigator layer JSON. Returns the layer path + technique summary.

        Reads exploit_workspace/exploit_audit.jsonl (filtered by target_ip),
        maps each tool_name to an ATT&CK technique ID, and writes a Navigator
        4.5 layer JSON the blue team opens in ATT&CK Navigator. Local-only: no
        target touch, no network. Optional output_path is coerced under
        mitre.navigator_output_dir (default reports/mitre/) to prevent path
        traversal. An empty audit trail returns techniques: [].
        """
        mitre_cfg = (config or {}).get("mitre", {}) or {}
        result = _export_attack_navigator(
            target_ip,
            output_path,
            technique_map_path=mitre_cfg.get("technique_map", "tools/mitre_technique_map.json"),
            navigator_output_dir=mitre_cfg.get("navigator_output_dir", "reports/mitre"),
            include_skills=bool(mitre_cfg.get("include_skill_tags", True)),
        )
        if "error" in result:
            return f"BLOCKED: {result['error']}"
        return (
            f"MITRE_NAVIGATOR_EXPORT:\n"
            f"layer_path: {result['layer_path']}\n"
            f"techniques: {result['techniques']}\n"
            f"technique_ids: {', '.join(result['technique_ids'])}\n"
            f"Open the layer JSON in ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/)."
        )
