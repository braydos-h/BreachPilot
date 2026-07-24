"""Metasploit MCP tool registration."""

from __future__ import annotations

import subprocess

from tools.mcp_tools.registry import *


def register_metasploit_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @require_allowlist()
    def run_msf_module(module: str, target_ip: str, options: str = "") -> str:
        """Run a Metasploit module against the target. Pass the module path (e.g. 'exploit/multi/http/log4shell_header_injection') and key=value options separated by spaces. The module runs in a visible terminal."""
        if not module or not module.strip():
            return "BLOCKED: module path is required."
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        # C1: validate module path -- only Metasploit module path chars
        # (letters, digits, _, ., /, -) and bounded length; reject anything
        # that could break out of the msfconsole `use` command.
        if not re.fullmatch(r"[A-Za-z0-9_./-]{1,120}", module):
            return "BLOCKED: module path must match [A-Za-z0-9_./-]{1,120}."
        if not validate_ipv4(target_ip):
            return "BLOCKED: target_ip must be a valid IPv4 address."

        attempt_dir, attempt_id = _attempt_dir(workspace)
        log_path = attempt_dir / "msf_output.log"

        # C1: parse opts with shlex and reject tokens without '=' or bearing
        # shell metacharacters. Rebuild the set commands from sanitized pairs so
        # a malicious ``options`` string cannot inject into the msfconsole
        # command stream (which previously was concatenated into a bash -c /
        # cmd /c ``msfconsole -x "..."`` string).
        opts = options.strip() if options else ""
        import shlex as _shlex
        set_lines: list[str] = []
        rejected_opts: list[str] = []
        if opts:
            try:
                tokens = _shlex.split(opts)
            except ValueError:
                return "BLOCKED: options string could not be parsed (unbalanced quotes)."
            for tok in tokens:
                if "=" not in tok:
                    rejected_opts.append(tok)
                    continue
                key, _, val = tok.partition("=")
                if not re.fullmatch(r"[A-Za-z0-9_]{1,60}", key):
                    return f"BLOCKED: invalid option key {key!r}."
                # Reject shell metacharacters in the value (defense-in-depth; the
                # value is written to a resource file and never reaches a shell,
                # but a value containing ;/`/$() could still confuse msfconsole).
                if re.search(r"[;|&$`()]|<|>|\\|\n", val):
                    return f"BLOCKED: option value for {key!r} contains forbidden characters."
                set_lines.append(f"set {key} {val}")
        if rejected_opts:
            return f"BLOCKED: options must be key=value pairs; rejected: {rejected_opts}."

        # Build a msfconsole resource file (one command per line) and invoke
        # msfconsole with an argv list (no shell). This replaces the previous
        # bash -c / cmd /c ``msfconsole -x "..."`` wrappers that were shell-
        # injectable via the module/opts/target_ip string.
        rc_path = attempt_dir / "msf_run.rc"
        rc_lines = [f"use {module}", f"set RHOSTS {target_ip}"]
        rc_lines.extend(set_lines)
        rc_lines.append("run")
        rc_lines.append("exit -y")
        rc_path.write_text("\n".join(rc_lines) + "\n", encoding="utf-8")

        # Linux/macOS: honor exploit.msfconsole_path from config when msfconsole
        # isn't on PATH under that name (default "msfconsole"). No effect on
        # Windows, which still uses the same argv via CREATE_NEW_CONSOLE.
        _msf_bin = str((config or {}).get("exploit", {}).get("msfconsole_path", "msfconsole")) or "msfconsole"
        msf_argv = [_msf_bin, "-q", "-r", str(rc_path)]
        start = time.monotonic()
        if _platform_system() == "Windows":
            proc = subprocess.Popen(
                msf_argv,
                cwd=str(attempt_dir),
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
            timeout = 600
            try:
                exit_code = proc.wait(timeout=timeout)
                status = "completed" if exit_code == 0 else "failed"
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                exit_code = None
                status = "timed_out"
        else:
            with open(str(log_path), "w") as fh:
                proc = subprocess.Popen(
                    msf_argv,
                    cwd=str(attempt_dir),
                    stdout=fh,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                timeout = 600
                try:
                    exit_code = proc.wait(timeout=timeout)
                    status = "completed" if exit_code == 0 else "failed"
                except subprocess.TimeoutExpired:
                    # M2: reap the whole process group on timeout.
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        try:
                            proc.kill()
                        except ProcessLookupError:
                            pass
                    exit_code = None
                    status = "timed_out"

        elapsed = time.monotonic() - start
        log_tail = ""
        if log_path.exists():
            text = log_path.read_text(encoding="utf-8", errors="replace")
            log_tail = text[-4000:]

        return (
            f"MSF_RESULT: {status} (exit_code={exit_code}, duration={elapsed:.1f}s)\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"MODULE: {module}\n"
            f"TARGET: {target_ip}\n"
            f"OPTIONS: {opts}\n"
            f"LOG_TAIL:\n{log_tail}"
        )

    _msf_bridge: MetasploitBridge | None = None
    mcp._msf_bridge = None

    def _get_msf_bridge() -> MetasploitBridge:
        if mcp._msf_bridge is None:
            mcp._msf_bridge = get_metasploit_bridge(workspace)
        return mcp._msf_bridge

    @mcp.tool()
    @audit_tool
    def msfconsole_start() -> str:
        """Start an interactive msfconsole session in a tmux session. This is a persistent session that stays running in the background. Use msfconsole_command to send commands to it."""
        bridge = _get_msf_bridge()
        result = bridge.start_console()
        if result.get("success"):
            return (
                f"MSFCONSOLE_STARTED\n"
                f"NAME: {result.get('name')}\n"
                f"MESSAGE: {result.get('message')}\n"
                f"INITIAL_OUTPUT:\n{result.get('initial_output', '')[:500]}"
            )
        return f"MSFCONSOLE_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msfconsole_stop() -> str:
        """Stop the interactive msfconsole session."""
        bridge = _get_msf_bridge()
        result = bridge.stop_console()
        return (
            f"MSFCONSOLE_STOPPED\n"
            f"SUCCESS: {result.get('success')}\n"
            f"MESSAGE: {result.get('message', '')}"
        )

    @mcp.tool()
    @audit_tool
    def msfconsole_command(command: str, wait_seconds: float = 2.0, read_lines: int = 100) -> str:
        """Execute a command in the interactive msfconsole session. Use for: loading modules, setting options, running exploits, checking sessions, etc. The command is sent to the persistent msfconsole and output is captured."""
        # Tool-layer scope gate: a direct MCP client can bypass the agent loop's
        # ExploitPolicy.approve_action, so extract RHOSTS/RHOST from the free-
        # text command and refuse any host not in exploit.allowed_targets.
        allowed, reason = check_targets_allowlist(_extract_msf_rhosts(command), config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msfconsole_command\nCOMMAND: {command[:200]}"
        bridge = _get_msf_bridge()
        result = bridge.console_command(command, wait_seconds, read_lines)
        if result.get("success"):
            return (
                f"MSFCONSOLE_COMMAND: {command}\n"
                f"WAIT: {wait_seconds}s\n"
                f"OUTPUT:\n{result.get('output', '')}"
            )
        return f"MSFCONSOLE_COMMAND_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @require_allowlist()
    def msf_run_exploit(module: str, target_ip: str, options: str = "", payload: str = "", wait_seconds: float = 30.0) -> str:
        """Run a Metasploit exploit module against a target using the persistent msfconsole. Provide module path (e.g., 'exploit/multi/http/log4shell_header_injection'), target IP, and optional key=value options separated by spaces. Returns the full exploit output including any session that was created."""
        if not validate_ipv4(target_ip):
            return "ERROR: Invalid IPv4 address."
        bridge = _get_msf_bridge()
        opts: dict[str, str] = {}
        if options.strip():
            for item in options.strip().split():
                if "=" in item:
                    k, v = item.split("=", 1)
                    opts[k] = v
        result = bridge.run_exploit(module, target_ip, opts, payload, wait_seconds)
        lines = [
            f"MSF_EXPLOIT_RESULT: {result.get('status', 'unknown')}",
            f"MODULE: {module}",
            f"TARGET: {target_ip}",
            f"DURATION: {result.get('duration_seconds', 0):.1f}s",
        ]
        if result.get("session_created"):
            sess = result["session_created"]
            lines.append(f"SESSION_OPENED: id={sess.get('session_id')} type={sess.get('session_type')} target={sess.get('target_ip')}")
        if result.get("error"):
            lines.append(f"ERROR: {result['error']}")
        lines.append(f"OUTPUT:\n{result.get('output', '')[:2000]}")
        return "\n".join(lines)

    @mcp.tool()
    @require_allowlist()
    def msf_run_auxiliary(module: str, target_ip: str, options: str = "", wait_seconds: float = 15.0) -> str:
        """Run a Metasploit auxiliary module (scanner, fuzzer, dos, etc.) against a target. Use for: port scanning, service enumeration, vulnerability checking."""
        if not validate_ipv4(target_ip):
            return "ERROR: Invalid IPv4 address."
        bridge = _get_msf_bridge()
        opts: dict[str, str] = {}
        if options.strip():
            for item in options.strip().split():
                if "=" in item:
                    k, v = item.split("=", 1)
                    opts[k] = v
        result = bridge.run_auxiliary(module, target_ip, opts, wait_seconds)
        if result.get("success"):
            return (
                f"MSF_AUXILIARY_RESULT: {module}\n"
                f"TARGET: {target_ip}\n"
                f"OUTPUT:\n{result.get('output', '')[:2000]}"
            )
        return f"MSF_AUXILIARY_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_list_sessions() -> str:
        """List all active Metasploit sessions (meterpreter, shell, cmd). Returns session IDs, types, target IPs, and platforms."""
        bridge = _get_msf_bridge()
        sessions = bridge.list_sessions()
        if not sessions:
            return "MSF_SESSIONS: No active Metasploit sessions."
        lines = [f"MSF_SESSIONS: {len(sessions)} active", ""]
        for s in sessions:
            lines.append(
                f"  [{s['session_id']}] {s['session_type']} {s['platform']} Ã¢â‚¬â€ "
                f"{s['target_ip']}:{s['target_port']} (via {s.get('via_exploit', 'unknown')})"
            )
            lines.append(f"      status: {s.get('status', 'unknown')}, info: {s.get('info', '')}")
        return "\n".join(lines)

    @mcp.tool()
    @audit_tool
    def msf_interact_session(session_id: int, command: str, wait_seconds: float = 3.0) -> str:
        """Send a command to a specific Metasploit session (meterpreter or shell). Use for: running post-exploitation commands, gathering system info, pivoting, etc. The session is backgrounded after the command completes."""
        # Tool-layer scope gate: the command can set RHOSTS for a route/portfwd
        # to a new host; refuse out-of-scope hosts even on an existing session.
        allowed, reason = check_targets_allowlist(_extract_msf_rhosts(command), config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_interact_session\nCOMMAND: {command[:200]}"
        bridge = _get_msf_bridge()
        result = bridge.interact_session(session_id, command, wait_seconds)
        if result.get("success"):
            return (
                f"MSF_SESSION_INTERACT: session {session_id}\n"
                f"COMMAND: {command}\n"
                f"OUTPUT:\n{result.get('output', '')[:2000]}"
            )
        return f"MSF_SESSION_INTERACT_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_run_post_module(module: str, session_id: int, options: str = "") -> str:
        """Run a post-exploitation module against a specific Metasploit session. Use for: privilege escalation, credential harvesting, persistence, keylogging, screenshot, etc."""
        bridge = _get_msf_bridge()
        opts: dict[str, str] = {}
        if options.strip():
            for item in options.strip().split():
                if "=" in item:
                    k, v = item.split("=", 1)
                    opts[k] = v
        result = bridge.run_post_module(module, session_id, opts)
        if result.get("success"):
            return (
                f"MSF_POST_RESULT: {module}\n"
                f"SESSION: {session_id}\n"
                f"OUTPUT:\n{result.get('output', '')[:2000]}"
            )
        return f"MSF_POST_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_kill_session(session_id: int) -> str:
        """Kill a specific Metasploit session."""
        bridge = _get_msf_bridge()
        result = bridge.kill_session(session_id)
        return (
            f"MSF_SESSION_KILLED: {session_id}\n"
            f"SUCCESS: {result.get('success', False)}\n"
            f"OUTPUT:\n{result.get('output', '')[:500]}"
        )

    @mcp.tool()
    @audit_tool
    def msf_generate_payload(payload_type: str, lhost: str, lport: int = 4444, fmt: str = "exe", platform: str = "windows", arch: str = "x64", options: str = "", encoder: str = "", iterations: int = 1) -> str:
        """Generate a payload using msfvenom through the Metasploit bridge. Supports encoders and bad character avoidance. Returns the path to the generated payload file."""
        # Tool-layer scope gate: lhost is the payload's callback host. A payload
        # that calls back to an out-of-scope host is an egress path the allowlist
        # must gate (mirrors the command-analyzer egress check on the agent path).
        allowed, reason = check_targets_allowlist([lhost], config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_generate_payload\nLHOST: {lhost}"
        bridge = _get_msf_bridge()
        result = bridge.generate_payload(payload_type, lhost, lport, fmt, platform, arch, options, encoder, iterations)
        if result.get("success"):
            return (
                f"MSF_PAYLOAD_GENERATED\n"
                f"TYPE: {payload_type}\n"
                f"FORMAT: {fmt}\n"
                f"PLATFORM: {platform}/{arch}\n"
                f"FILE: {result.get('file')}\n"
                f"SIZE: {result.get('file_size')} bytes\n"
                f"COMMAND: {result.get('command')}\n"
                f"OUTPUT:\n{result.get('output', '')[:1000]}"
            )
        return f"MSF_PAYLOAD_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_run_resource_script(script_content: str) -> str:
        """Create and run a Metasploit resource script in the persistent msfconsole. Resource scripts automate sequences of msfconsole commands. Use for: automated exploitation chains, mass scanning, post-exploitation workflows."""
        # Tool-layer scope gate: a resource script is free-text msfconsole
        # commands that can ``set RHOSTS <any host>; run``. Extract every
        # RHOSTS/RHOST value and refuse any host outside the allowlist.
        allowed, reason = check_targets_allowlist(_extract_msf_rhosts(script_content), config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_run_resource_script"
        bridge = _get_msf_bridge()
        result = bridge.run_resource_script(script_content)
        if result.get("success"):
            return (
                f"MSF_RESOURCE_SCRIPT_EXECUTED\n"
                f"OUTPUT:\n{result.get('output', '')[:2000]}"
            )
        return f"MSF_RESOURCE_FAILED: {result.get('error', 'unknown error')}"




