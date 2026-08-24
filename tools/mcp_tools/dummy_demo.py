"""Dummy demo — proves 1-file MCP tool add works.

This file is the PR demo for Phase 2 collapse. Adding this file is the ONLY edit
required to expose a new tool; ``mcp_exploit_server._discover_tool_registrars``
picks up ``register_dummy_demo_tools`` automatically, no edit to
``mcp_exploit_server.py`` or ``registry.py``.
"""
from __future__ import annotations

from typing import Any

from tools.mcp_tools.registry import ToolContext


def register_dummy_demo_tools(mcp: Any, *, ctx: ToolContext) -> None:
    audit_tool = ctx.audit_tool

    @mcp.tool()
    @audit_tool
    def dummy_demo_tool(echo: str) -> str:
        """Dummy demo tool — returns echo. Proves 1-file registration."""
        return f"DUMMY_DEMO_RESULT: {echo}"
