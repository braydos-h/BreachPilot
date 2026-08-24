"""Replay simulator MCP tool registration (D2).

Registers ``replay_simulate`` -- a local-only ``@audit_tool`` (no target
touch) that dry-runs an attack plan against a saved ``ReconAssessment``
JSON for pre-commit critique. The LLM critiques its own plan; if the LLM
is unavailable, it degrades to rule-based scoring.

Opt-in: registered only when ``replay_simulator.enabled`` is true in config.
"""

from __future__ import annotations

from typing import Any

from tools.mcp_tools.registry import *
from tools.replay_simulator import (
    render_simulation_result,
    simulate,
)


def register_replay_simulator_tools(mcp: Any, *, ctx: ToolContext) -> None:
    config = ctx.config
    audit_tool = ctx.audit_tool
    enabled = bool((config or {}).get("replay_simulator", {}).get("enabled", False))

    if not enabled:
        return

    @mcp.tool()
    @audit_tool
    def replay_simulate(plan_json: str, recon_json: str) -> str:
        """Dry-run an attack plan against a saved ReconAssessment JSON for pre-commit critique. Both arguments are JSON strings. Returns confidence (0..1), critique text, and branch proposals. Zero target touch -- pure simulation. When the LLM is unavailable, degrades to rule-based scoring."""
        import json as _json

        if not plan_json or not plan_json.strip():
            return "BLOCKED: plan_json is required."
        if not recon_json or not recon_json.strip():
            return "BLOCKED: recon_json is required."
        try:
            plan = _json.loads(plan_json)
        except _json.JSONDecodeError as exc:
            return f"BLOCKED: plan_json is not valid JSON ({exc})."
        try:
            recon = _json.loads(recon_json)
        except _json.JSONDecodeError as exc:
            return f"BLOCKED: recon_json is not valid JSON ({exc})."
        if not isinstance(plan, dict) or not isinstance(recon, dict):
            return "BLOCKED: plan_json and recon_json must be JSON objects."

        # Try to use the configured model client; degrade to rules on failure.
        model_client = None
        model_alias = ""
        try:
            client, alias = _get_model_client(config)
            model_client = client
            model_alias = alias
        except Exception:
            model_client = None

        result = simulate(plan, recon, model_client=model_client, model_alias=model_alias)
        return render_simulation_result(result)


__all__ = ["register_replay_simulator_tools"]
