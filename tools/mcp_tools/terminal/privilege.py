"""Privilege helpers and environment probes for terminal tools."""

from __future__ import annotations

import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from tools.exceptions import _EXC_GROUP_CATCH, _log_nested_exceptions
from tools.mcp_tools.registry import ToolContext
from tools.mcp_tools.sandbox_exec import run_argv_in_sandbox, sandbox_error_block
from tools.mcp_tools.session_safety import host_execution_block
from tools.sandbox.exceptions import SandboxError

__all__ = [
    "_check_env_default_tools",
    "_find_windows_bash",
    "_platform_system",
    "_register_privilege_tools",
    "_require_sudo_or_pivot",
]


def _platform_system() -> str:
    if os.name == "nt":
        return "Windows"
    try:
        return platform.system()
    except Exception:  # ponytail: bare except intentional
        return "Linux"


def _require_sudo_or_pivot(tool_name: str, payload: str) -> str | None:
    """Return a ``BLOCKED:`` pivot message if passwordless sudo is unavailable,
    else None (caller proceeds to spawn the subprocess).

    Gap 3: ``apt_install`` / ``install_package`` (apt branch) / ``run_as_root``
    unconditionally prepend ``sudo`` via ``bash -c`` with no ``-n`` and no
    precheck, so on a sudo-less / password-required operator box the subprocess
    HANGS on an interactive password prompt. The env_probe prompt tells the
    LLM to pivot, but if the LLM ignores it the call still hangs. This helper
    short-circuits BEFORE the subprocess is spawned -- no hang, and the
    ``BLOCKED:`` prefix makes the LLM's existing BLOCKED-result detection
    (``exploit_agent/prompt.py`` RULES) treat it as a hard constraint.

    Never raises: an inability to determine sudo status falls through to the
    legacy spawn path (returns None). On Windows ``_can_passwordless_sudo``
    returns False, so Windows callers get the pivot message instead of a
    bogus ``sudo`` spawn.
    """
    try:
        from tools.env_probe import _can_passwordless_sudo

        if _can_passwordless_sudo():
            return None
    except _EXC_GROUP_CATCH:
        return None
    return (
        f"BLOCKED: {tool_name} requires passwordless sudo, which is unavailable "
        f"on this box. PIVOT: call preflight_env_check for a per-tool fallback "
        f"plan, then implement {payload!r} as a workspace Python script via "
        f"write_python_file + run_python_file. Do not retry "
        f"apt_install/install_package/run_as_root -- they will hang or fail opaquely."
    )


def _check_env_default_tools() -> list[str]:
    """Default tool list for ``check_environment`` (Gap 5).

    Derived from the single source of truth ``tools.env_probe.ENV_TOOLS`` plus an
    explicit extras set (secondary scanners / language runtimes / package
    managers worth surfacing that are not in the curated env_probe list), with
    dedup so the agent never sees two different "missing tools" answers from
    ``check_environment`` vs ``preflight_env_check``. ReconConfig's per-tool
    ``*_path`` fields are a separate concern (binary-path overrides) and are
    intentionally not unified here.
    """
    from tools.env_probe import ENV_TOOLS

    _CHECK_ENV_EXTRAS = [
        "masscan",
        "rustscan",
        "feroxbuster",
        "nuclei",
        "metasploit-framework",
        "ldapsearch",
        "aircrack-ng",
        "wireshark",
        "tcpdump",
        "wget",
        "ruby",
        "gem",
        "npm",
        "go",
        "cargo",
        "snap",
    ]
    seen: set[str] = set()
    out: list[str] = []
    for t in list(ENV_TOOLS) + _CHECK_ENV_EXTRAS:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _find_windows_bash(config: Any) -> str | None:
    """Locate a bash binary for ``run_exploit_terminal`` on Windows.

    Unix pipelines (``curl ... | head -100``) fail under cmd.exe because
    head/tail/grep don't exist there; Git Bash provides them. Resolution
    order: the configured ``exploit.shell`` on PATH, then common Git Bash
    install paths. Returns None when no bash is available (cmd.exe fallback).
    """
    _shell = str((config or {}).get("exploit", {}).get("shell", "bash")) or "bash"
    found = shutil.which(_shell)
    if found:
        return found
    if _shell in ("bash", "sh"):
        for _cand in (
            Path(r"C:\Program Files\Git\bin\bash.exe"),
            Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
            Path(r"C:\Program Files (x86)\Git\bin\bash.exe"),
        ):
            if _cand.exists():
                return str(_cand)
    return None


def _register_privilege_tools(mcp: Any, *, ctx: ToolContext) -> None:
    """Register environment-check tools (privilege-adjacent)."""

    audit_tool = ctx.audit_tool

    @mcp.tool()
    @audit_tool
    def check_environment(tools: str = "") -> str:
        """Check security tool availability in the sandbox worker or consented native environment.
        Provide executable basenames only (e.g., 'nmap metasploit-framework hydra gobuster'),
        or leave empty to check the default set. Path-shaped names are rejected.
        """
        default_tools = _check_env_default_tools()
        check_list = [t.strip() for t in tools.split() if t.strip()] if tools else default_tools
        invalid = [t for t in check_list if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}", t)]
        if invalid:
            return "BLOCKED: tool names must be executable basenames without path separators."

        sandbox_active = getattr(ctx, "sandbox", None) is not None
        if not sandbox_active:
            if block := host_execution_block(ctx, operation="host-side environment probes"):
                return block

        result_lines = ["ENVIRONMENT_CHECK:", ""]
        if sandbox_active:
            result_lines.append("EXECUTION_ENVIRONMENT: sandbox worker")
        else:
            result_lines.append(f"OS: {_platform_system()} {platform.release()} ({platform.machine()})")
            result_lines.append(f"Python: {sys.version.split()[0]}")
        result_lines.append("")

        installed: list[str] = []
        missing: list[str] = []
        if sandbox_active:
            probes = "; ".join(
                "if p=$(command -v "
                + shlex.quote(tool)
                + " 2>/dev/null); then v=$(\"$p\" --version 2>&1 | sed -n '1p'); "
                + 'if [ -z "$v" ]; then v=$("$p" -version 2>&1 | sed -n \'1p\'); fi; '
                + "printf 'AVAILABLE\\t%s\\t%s\\n' "
                + shlex.quote(tool)
                + " \"${v:-unknown}\"; else printf 'MISSING\\t%s\\t\\n' "
                + shlex.quote(tool)
                + "; fi"
                for tool in check_list
            )
            try:
                ran, proc = run_argv_in_sandbox(
                    ctx,
                    ["sh", "-c", probes],
                    timeout=60,
                    tool_name="check_environment",
                )
            except SandboxError as exc:
                return sandbox_error_block(exc, tool_name="check_environment")
            if not ran:
                return host_execution_block(ctx, operation="host-side environment probes") or (
                    "BLOCKED: SANDBOX_UNAVAILABLE — environment probes were not run."
                )
            records = {
                parts[1]: (parts[0] == "AVAILABLE", parts[2] if len(parts) > 2 else "unknown")
                for line in str(getattr(proc, "stdout", "")).splitlines()
                if len(parts := line.split("\t", 2)) >= 2 and parts[0] in {"AVAILABLE", "MISSING"}
            }
            for tool in check_list:
                available, version = records.get(tool, (False, ""))
                if available:
                    installed.append(tool)
                    result_lines.append(f"  [+] {tool}: sandbox PATH  ({version[:100] or 'unknown'})")
                else:
                    missing.append(tool)
                    result_lines.append(f"  [-] {tool}: NOT FOUND in sandbox")

        for tool in check_list:
            if sandbox_active:
                continue
            path = shutil.which(tool)
            if path:
                try:
                    resolved_path = Path(path).resolve()
                    workspace_path = ctx.workspace.resolve()
                except (OSError, RuntimeError):
                    return "BLOCKED: refusing to resolve an environment probe executable safely."
                try:
                    resolved_path.relative_to(workspace_path)
                except ValueError:
                    pass
                else:
                    return "BLOCKED: refusing to execute a workspace-local environment probe on the host."
            if path:
                installed.append(tool)
                version = "unknown"
                try:
                    proc = subprocess.run(
                        [tool, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if proc.returncode == 0 and proc.stdout:
                        version = proc.stdout.strip().split("\n")[0][:100]
                    else:
                        proc2 = subprocess.run(
                            [tool, "-version"],
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        if proc2.returncode == 0 and proc2.stdout:
                            version = proc2.stdout.strip().split("\n")[0][:100]
                except _EXC_GROUP_CATCH:
                    pass
                result_lines.append(f"  [+] {tool}: {path}  ({version})")
            else:
                missing.append(tool)
                result_lines.append(f"  [-] {tool}: NOT FOUND")

        result_lines.append("")
        result_lines.append(f"SUMMARY: {len(installed)}/{len(check_list)} tools available")
        if missing:
            result_lines.append(f"MISSING: {', '.join(missing)}")
            if sandbox_active:
                result_lines.append(
                    "HINT: Host package installation is unavailable while contained. "
                    "Use a derived sandbox image to add worker tools."
                )
            else:
                try:
                    from tools.env_probe import _can_passwordless_sudo

                    _has_sudo = _can_passwordless_sudo()
                except _EXC_GROUP_CATCH:
                    _has_sudo = True
                if _has_sudo:
                    result_lines.append(
                        "HINT: Use install_package or apt_install to install missing tools,"
                        " or call preflight_env_check for a per-tool fallback plan."
                    )
                else:
                    result_lines.append(
                        "HINT: sudo unavailable -- apt_install/install_package will fail. "
                        "Call preflight_env_check for a per-tool fallback plan, then pivot to "
                        "write_python_file Python implementations for missing tools."
                    )
        return "\n".join(result_lines)

    @mcp.tool()
    @audit_tool
    def preflight_env_check() -> str:
        """Probe installed pentest tools, sudo/pip installability, and the
        recommended fallback (install_via_apt / install_via_pip / write_python_fallback)
        for each MISSING tool. Call once at session start (the system prompt
        already carries the startup probe) or after installing a tool to
        re-probe. Native mode only; while contained, use check_environment for
        worker tools. Local-only; touches no target."""
        if getattr(ctx, "sandbox", None) is not None:
            return (
                "PREFLIGHT_ENV_CHECK: host installability is not relevant while contained. "
                "Use check_environment to inspect worker tools; package installation is "
                "unavailable until a derived sandbox image is built."
            )
        if block := host_execution_block(ctx, operation="host-side environment preflight"):
            return block
        try:
            from tools.env_probe import preflight_env_probe, render_env_context

            rendered = render_env_context(preflight_env_probe())
        except _EXC_GROUP_CATCH as exc:  # pragma: no cover - defensive
            _log_nested_exceptions(exc)
            return f"PREFLIGHT_ENV_CHECK_ERROR: {exc}"
        return rendered or "ENV_OK: all standard pentest tools present."
