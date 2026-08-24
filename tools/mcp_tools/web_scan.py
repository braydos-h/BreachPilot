"""Web scanner MCP tool registration.

Structured first-class wrapper around the Kali web scanners the agent
otherwise shells out to via ``run_exploit_terminal`` (nikto/nuclei/sqlmap/
gobuster/feroxbuster/whatweb/wpscan/dirb/dirbuster). Gives parsed output,
consistent audit records, and the same target-IP allowlist lock the shell-out
path already has (``_extract_scanner_targets`` already recognizes these verbs).
"""

from __future__ import annotations

import shutil
import subprocess

from tools.mcp_tools.registry import *


def register_web_scan_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    _SCANNERS = {"nikto", "nuclei", "sqlmap", "gobuster", "feroxbuster",
                 "whatweb", "wpscan", "dirb", "dirbuster"}

    # Default wordlist for directory-content scanners (Kali standard location).
    _DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

    def _build_argv(scanner: str, target_ip: str, port: int, path: str) -> list[str]:
        url = f"http://{target_ip}:{port}{path}" if path else f"http://{target_ip}:{port}"
        if scanner == "nikto":
            return ["nikto", "-h", target_ip, "-p", str(port)]
        if scanner == "nuclei":
            return ["nuclei", "-u", url]
        if scanner == "sqlmap":
            return ["sqlmap", "-u", url, "--batch"]
        if scanner in {"gobuster", "feroxbuster", "dirb", "dirbuster"}:
            return [scanner, "dir", "-u", url, "-w", _DEFAULT_WORDLIST]
        if scanner == "whatweb":
            return ["whatweb", url]
        if scanner == "wpscan":
            return ["wpscan", "--url", url, "--enumerate", "u"]
        # Unreachable: caller gates on _SCANNERS, but keep a sane fallback.
        return [scanner, url]

    @mcp.tool()
    @require_allowlist()
    def run_web_scan(
        scanner: str,
        target_ip: str,
        port: int = 80,
        path: str = "",
        options: str = "",
        timeout: int = 300,
    ) -> str:
        """Run a web scanner (nikto/nuclei/sqlmap/gobuster/feroxbuster/whatweb/wpscan/dirb/dirbuster) against the target. Returns the scanner's parsed output. The target must be in the explicit allowlist. ``options`` are extra scanner flags (space-separated, no shell metacharacters)."""
        if not scanner or not scanner.strip():
            return "BLOCKED: scanner is required."
        sc = scanner.strip().lower()
        if sc not in _SCANNERS:
            return f"BLOCKED: unsupported scanner '{sc}'. Allowed: {', '.join(sorted(_SCANNERS))}."
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "BLOCKED: target_ip must be a valid IP address or domain."
        if not isinstance(port, int) or port < 1 or port > 65535:
            return "BLOCKED: port must be an integer between 1 and 65535."
        # Allowlist itself is enforced by @require_allowlist() on target_ip.

        # Sanitize extra options: shlex tokens, reject shell metacharacters
        # (mirrors generate_payload / run_msf_module so a malicious options
        # string can't inject into a shell -- though we never use a shell).
        extra_argv: list[str] = []
        opts = options.strip() if options else ""
        if opts:
            if re.search(r"[;|&$`()]|<|>|\n", opts):
                return "BLOCKED: options contains forbidden shell metacharacters."
            import shlex as _shlex
            try:
                extra_argv = _shlex.split(opts)
            except ValueError:
                return "BLOCKED: options string could not be parsed (unbalanced quotes)."

        if not shutil.which(sc):
            return (
                f"SCANNER_NOT_INSTALLED: {sc} is not on PATH. "
                f"Install it (e.g. apt install {sc}) on the operator box and retry."
            )

        argv = _build_argv(sc, target_ip, port, path.strip())
        argv.extend(extra_argv)
        cmd = " ".join(argv)  # reported for operator visibility

        attempt_dir, attempt_id = _attempt_dir(workspace)
        log_path = attempt_dir / f"{sc}.log"
        start = time.monotonic()
        try:
            returncode, out, err = _run_with_pgrp_timeout(
                argv,
                timeout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            output = (out + "\n" + err)[-4000:]
            status = "completed" if returncode == 0 else "failed"
        except subprocess.TimeoutExpired:
            status = "timed_out"
            output = f"{sc} timed out after {timeout}s"
            returncode = None
        except Exception as exc:
            status = "error"
            output = str(exc)
            returncode = None

        elapsed = time.monotonic() - start

        # Persist the raw scan log for the audit trail / later read_workspace_file.
        try:
            log_path.write_text(str(output), encoding="utf-8")
        except OSError:
            pass

        return (
            f"WEB_SCAN_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"SCANNER: {sc}\n"
            f"TARGET: {target_ip}:{port}\n"
            f"COMMAND: {cmd}\n"
            f"EXIT_CODE: {returncode}\n"
            f"DURATION: {elapsed:.1f}s\n"
            f"OUTPUT:\n{output}"
        )
