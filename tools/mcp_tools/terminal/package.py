"""Fail-closed compatibility tools for host package management.

Agent calls must not install packages or downloaded executables in the MCP
server process. Dependencies belong in the disposable sandbox image, which is
built and reviewed by the operator before an assessment.
"""

from __future__ import annotations

from typing import Any

from tools.mcp_tools.registry import ToolContext

__all__ = ["_register_package_tools"]

_BLOCKED = (
    "BLOCKED: package installation is disabled in the MCP host process. "
    "Add required tools and dependencies to the BreachPilot sandbox image, then rebuild it."
)


def _register_package_tools(mcp: Any, *, ctx: ToolContext) -> None:
    """Register legacy names as safe blocks for client compatibility.

    Keeping these schemas avoids turning older agents into unknown-tool retry
    loops. No argument is interpreted and no host command, download, or file
    write is performed.
    """
    audit_tool = ctx.audit_tool

    @mcp.tool()
    @audit_tool
    def apt_install(packages: str) -> str:
        """Legacy compatibility tool; host-side package installation is disabled."""
        return _BLOCKED

    @mcp.tool()
    @audit_tool
    def pip_install(packages: str) -> str:
        """Legacy compatibility tool; host-side package installation is disabled."""
        return _BLOCKED

    @mcp.tool()
    @audit_tool
    def install_package(manager: str, packages: str) -> str:
        """Legacy compatibility tool; host-side package installation is disabled."""
        return _BLOCKED

    @mcp.tool()
    @audit_tool
    def download_and_install(url: str, install_type: str = "auto", target_name: str = "") -> str:
        """Legacy compatibility tool; host-side downloads and installation are disabled."""
        return _BLOCKED

    @mcp.tool()
    @audit_tool
    def update_system(upgrade: bool = True) -> str:
        """Legacy compatibility tool; host package updates are disabled."""
        return _BLOCKED
