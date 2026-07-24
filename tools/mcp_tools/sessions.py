"""Sessions MCP tool registration."""

from __future__ import annotations

from tools.mcp_tools.registry import *
from tools.mcp_tools.terminal import _target_lock_block


def register_session_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    _session_mgr: PersistentSessionManager | None = None
    mcp._session_mgr = None

    def _get_session_mgr() -> PersistentSessionManager:
        if mcp._session_mgr is None:
            mcp._session_mgr = get_session_manager(workspace)
        return mcp._session_mgr

    @mcp.tool()
    @audit_tool
    def start_tmux_session(name: str, command: str) -> str:
        """Start a named persistent tmux session for interactive commands. The session runs in the background and can be interacted with later via send_to_session and read_session_output. Use for: reverse shells, interactive msfconsole, long-running scans, ssh sessions, etc."""
        # Target-IP lock: the session command may connect to an off-allowlist host
        # (reverse shell callback, ssh, scanner). Gate it the same way as
        # run_exploit_terminal so free-text commands can't pivot past the target.
        _lock_reason = _target_lock_block(command, config)
        if _lock_reason:
            return f"BLOCKED: target-IP lock — {_lock_reason}"
        mgr = _get_session_mgr()
        result = mgr.start_tmux_session(name, command, cwd=workspace)
        if result["success"]:
            return (
                f"SESSION_STARTED: {name}\n"
                f"TYPE: tmux\n"
                f"COMMAND: {command}\n"
                f"PID: {result.get('pid')}\n"
                f"STATUS: running"
            )
        return f"SESSION_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def send_to_session(name: str, input_text: str) -> str:
        """Send text/keystrokes to a named tmux session. The text is sent followed by Enter. Use this to interact with running sessions: type commands in a shell, navigate msfconsole menus, respond to prompts, etc."""
        # Target-IP lock: keystrokes sent into a running session can issue a
        # command that pivots to an off-allowlist host. Gate the input text the
        # same way as a free-text terminal command (defense-in-depth).
        _lock_reason = _target_lock_block(input_text, config)
        if _lock_reason:
            return f"BLOCKED: target-IP lock — {_lock_reason}"
        mgr = _get_session_mgr()
        result = mgr.send_to_session(name, input_text)
        if result["success"]:
            return f"SENT_TO_SESSION: {name}\nINPUT: {input_text[:200]}"
        return f"SEND_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    def read_session_output(name: str, lines: int = 100) -> str:
        """Read the last N lines from a named tmux session. Use this to see the output after sending commands via send_to_session."""
        mgr = _get_session_mgr()
        result = mgr.read_session_output(name, lines=lines)
        if result["success"]:
            return (
                f"SESSION_OUTPUT: {name}\n"
                f"LINES: {lines}\n"
                f"OUTPUT:\n{result.get('output', '')}"
            )
        return f"READ_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    def kill_session(name: str) -> str:
        """Kill a named persistent session (tmux, background job, or listener)."""
        mgr = _get_session_mgr()
        result = mgr.kill_session(name)
        return (
            f"SESSION_KILLED: {name}\n"
            f"SUCCESS: {result['success']}\n"
            f"MESSAGE: {result.get('message', '')}"
        )

    @mcp.tool()
    @audit_tool
    def start_background_job(name: str, command: str) -> str:
        """Start a named background job using nohup. The job runs detached from the terminal and logs output to a file. Use for: long-running scans, listeners, file transfers, brute force attacks that take hours, etc."""
        # Target-IP lock: same gate as start_tmux_session / run_exploit_terminal.
        _lock_reason = _target_lock_block(command, config)
        if _lock_reason:
            return f"BLOCKED: target-IP lock — {_lock_reason}"
        mgr = _get_session_mgr()
        result = mgr.start_background_job(name, command, cwd=workspace)
        if result["success"]:
            return (
                f"JOB_STARTED: {name}\n"
                f"TYPE: background\n"
                f"COMMAND: {command}\n"
                f"PID: {result.get('pid')}\n"
                f"LOG: {result.get('log')}\n"
                f"STATUS: running"
            )
        return f"JOB_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    def read_job_output(name: str, lines: int = 100) -> str:
        """Read the last N lines from a background job's log file."""
        mgr = _get_session_mgr()
        result = mgr.read_job_output(name, lines=lines)
        return (
            f"JOB_OUTPUT: {name}\n"
            f"RUNNING: {result.get('running', False)}\n"
            f"LINES: {lines}\n"
            f"OUTPUT:\n{result.get('output', '')}"
        )

    @mcp.tool()
    def stop_background_job(name: str) -> str:
        """Stop a named background job."""
        mgr = _get_session_mgr()
        result = mgr.stop_background_job(name)
        return (
            f"JOB_STOPPED: {name}\n"
            f"SUCCESS: {result['success']}\n"
            f"MESSAGE: {result.get('message', '')}"
        )

    @mcp.tool()
    @audit_tool
    def start_listener(name: str, port: int, listener_type: str = "netcat", protocol: str = "tcp", directory: str = "") -> str:
        """Start a named network listener. Types: netcat (nc/ncat), socat, http (python http.server). Use for: catching reverse shells, serving payloads, port forwarding, etc."""
        mgr = _get_session_mgr()
        result = mgr.start_listener(name, port, listener_type, protocol, directory)
        if result["success"]:
            return (
                f"LISTENER_STARTED: {name}\n"
                f"TYPE: {listener_type}\n"
                f"PORT: {port}/{protocol}\n"
                f"PID: {result.get('pid')}\n"
                f"LOG: {result.get('log')}\n"
                f"STATUS: running"
            )
        return f"LISTENER_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    def read_listener_output(name: str, lines: int = 100) -> str:
        """Read the last N lines from a listener's log file."""
        mgr = _get_session_mgr()
        result = mgr.read_listener_output(name, lines=lines)
        return (
            f"LISTENER_OUTPUT: {name}\n"
            f"RUNNING: {result.get('running', False)}\n"
            f"LINES: {lines}\n"
            f"OUTPUT:\n{result.get('output', '')}"
        )

    @mcp.tool()
    def stop_listener(name: str) -> str:
        """Stop a named network listener."""
        mgr = _get_session_mgr()
        result = mgr.stop_listener(name)
        return (
            f"LISTENER_STOPPED: {name}\n"
            f"SUCCESS: {result['success']}\n"
            f"MESSAGE: {result.get('message', '')}"
        )

    @mcp.tool()
    def list_sessions() -> str:
        """List all persistent sessions (tmux, background jobs, listeners) with their status, PIDs, and types."""
        mgr = _get_session_mgr()
        sessions = mgr.list_all_sessions()
        if not sessions:
            return "SESSIONS: No active sessions."
        lines = [f"SESSIONS: {len(sessions)} active", ""]
        for s in sessions:
            status_icon = "Ã¢â€”Â" if s.get("running") else "Ã¢â€”â€¹"
            lines.append(
                f"  {status_icon} [{s['type']}] {s['name']} Ã¢â‚¬â€ {s.get('status', 'unknown')} "
                f"(pid={s.get('pid')}, cmd={s['command'][:60]})"
            )
            if s.get("log"):
                lines.append(f"      log: {s['log']}")
        return "\n".join(lines)

    @mcp.tool()
    def list_processes(pattern: str = "") -> str:
        """List system processes. Optionally filter by a pattern string. Use to find running tools, check if a listener is active, or locate a specific process."""
        mgr = _get_session_mgr()
        processes = mgr.list_processes(pattern)
        if not processes:
            return f"PROCESSES: No processes matching '{pattern}'."
        lines = [f"PROCESSES: {len(processes)} matching '{pattern}'", ""]
        for p in processes:
            if "error" in p:
                lines.append(f"  ERROR: {p['error']}")
            else:
                lines.append(
                    f"  PID {p['pid']} ({p['user']}) CPU:{p['cpu']}% MEM:{p['mem']}% Ã¢â‚¬â€ {p['command'][:80]}"
                )
        return "\n".join(lines)

    @mcp.tool()
    @audit_tool
    def kill_process(name_or_pid: str) -> str:
        """Kill a process by tracked name or raw PID. Use to stop runaway processes, kill old listeners, or clean up after exploitation."""
        mgr = _get_session_mgr()
        result = mgr.kill_process(name_or_pid)
        return (
            f"KILL_RESULT: {name_or_pid}\n"
            f"SUCCESS: {result['success']}\n"
            f"MESSAGE: {result.get('message', '')}"
        )



