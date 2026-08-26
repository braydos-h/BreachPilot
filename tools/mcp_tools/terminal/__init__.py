"""Terminal MCP tool registration package."""

from __future__ import annotations

from typing import Any

from tools.mcp_tools.registry import ToolContext, _run_with_pgrp_timeout
from tools.mcp_tools.terminal.allowlist import _opsec_advisory_block, _target_lock_block
from tools.mcp_tools.terminal.execute import _register_execute_tools
from tools.mcp_tools.terminal.package import _register_package_tools
from tools.mcp_tools.terminal.privilege import (
    _check_env_default_tools,
    _find_windows_bash,
    _platform_system,
    _register_privilege_tools,
    _require_sudo_or_pivot,
)

__all__ = [
    "register_terminal_tools",
    "_target_lock_block",
    "_opsec_advisory_block",
    "_require_sudo_or_pivot",
    "_find_windows_bash",
    "_check_env_default_tools",
    "_platform_system",
    "_run_with_pgrp_timeout",
]


def register_terminal_tools(mcp: Any, *, ctx: ToolContext) -> None:
    """Aggregate terminal tool registrars (execute + privilege/env + package)."""
    _register_execute_tools(mcp, ctx=ctx)
    _register_privilege_tools(mcp, ctx=ctx)
    _register_package_tools(mcp, ctx=ctx)
