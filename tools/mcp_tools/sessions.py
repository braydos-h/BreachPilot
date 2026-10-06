"""Fail-closed session tool registration.

PersistentSessionManager launches and controls processes on the BreachPilot
host. These MCP tools remain registered for API compatibility, but they are
unavailable until a worker-backed persistent-session implementation exists.
Agent-controlled activity must not escape the disposable sandbox.
"""

from __future__ import annotations

from typing import Any

from tools.mcp_tools.registry import ToolContext
from tools.mcp_tools.sandbox_exec import sandbox_error_block
from tools.sandbox.exceptions import SandboxUnsupportedError


def register_session_tools(mcp: Any, *, ctx: ToolContext) -> None:
    """Register compatible session names that deny host-process operations."""

    def _blocked(tool_name: str) -> str:
        return sandbox_error_block(
            SandboxUnsupportedError(
                "persistent sessions are unavailable because this tool family has no sandbox-backed implementation"
            ),
            tool_name=tool_name,
        )

    @mcp.tool()
    @ctx.audit_tool
    def start_tmux_session(name: str, command: str) -> str:
        """Unavailable: persistent sessions are not yet backed by the sandbox worker."""
        return _blocked("start_tmux_session")

    @mcp.tool()
    @ctx.audit_tool
    def send_to_session(name: str, input_text: str) -> str:
        """Unavailable: host sessions cannot be controlled by agent-generated input."""
        return _blocked("send_to_session")

    @mcp.tool()
    @ctx.audit_tool
    def read_session_output(name: str, lines: int = 100) -> str:
        """Unavailable: session output is not exposed from host processes."""
        return _blocked("read_session_output")

    @mcp.tool()
    @ctx.audit_tool
    def kill_session(name: str) -> str:
        """Unavailable: session lifecycle operations are not host-backed."""
        return _blocked("kill_session")

    @mcp.tool()
    @ctx.audit_tool
    def start_background_job(name: str, command: str) -> str:
        """Unavailable: background jobs require a sandbox-backed implementation."""
        return _blocked("start_background_job")

    @mcp.tool()
    @ctx.audit_tool
    def read_job_output(name: str, lines: int = 100) -> str:
        """Unavailable: job output is not read from host processes."""
        return _blocked("read_job_output")

    @mcp.tool()
    @ctx.audit_tool
    def stop_background_job(name: str) -> str:
        """Unavailable: background jobs are not started on the host."""
        return _blocked("stop_background_job")

    @mcp.tool()
    @ctx.audit_tool
    def start_listener(
        name: str,
        port: int,
        listener_type: str = "netcat",
        protocol: str = "tcp",
        directory: str = "",
        upstream_host: str = "",
        upstream_port: int = 0,
    ) -> str:
        """Unavailable: listeners and pivot processes require sandbox support."""
        return _blocked("start_listener")

    @mcp.tool()
    @ctx.audit_tool
    def read_listener_output(name: str, lines: int = 100) -> str:
        """Unavailable: listener output is not read from host processes."""
        return _blocked("read_listener_output")

    @mcp.tool()
    @ctx.audit_tool
    def stop_listener(name: str) -> str:
        """Unavailable: listeners are not started on the host."""
        return _blocked("stop_listener")

    @mcp.tool()
    @ctx.audit_tool
    def list_sessions() -> str:
        """Unavailable: host process/session inventory is not exposed to agents."""
        return _blocked("list_sessions")

    @mcp.tool()
    @ctx.audit_tool
    def list_processes(pattern: str = "") -> str:
        """Unavailable: host process inventory is not exposed to agents."""
        return _blocked("list_processes")

    @mcp.tool()
    @ctx.audit_tool
    def kill_process(name_or_pid: str) -> str:
        """Unavailable: agent tools cannot signal host processes."""
        return _blocked("kill_process")
