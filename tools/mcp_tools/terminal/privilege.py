"""Privilege helpers and environment probes for terminal tools."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from tools.exceptions import _EXC_GROUP_CATCH, _log_nested_exceptions
from tools.mcp_tools.registry import ToolContext

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
        """Check which security testing tools are installed and available on the system.
        Provide a space-separated list of tool names (e.g., 'nmap metasploit-framework hydra gobuster'),
        or leave empty to check a default set of common pentesting tools.
        Returns version info and install status for each tool, plus OS details.
        """
        default_tools = _check_env_default_tools()
        check_list = [t.strip() for t in tools.split() if t.strip()] if tools else default_tools

        result_lines = ["ENVIRONMENT_CHECK:", ""]
        result_lines.append(f"OS: {_platform_system()} {platform.release()} ({platform.machine()})")
        result_lines.append(f"Python: {sys.version.split()[0]}")
        result_lines.append("")

        installed: list[str] = []
        missing: list[str] = []
        for tool in check_list:
            path = shutil.which(tool)
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
        re-probe. Local-only; touches no target."""
        try:
            from tools.env_probe import preflight_env_probe, render_env_context

            rendered = render_env_context(preflight_env_probe())
        except _EXC_GROUP_CATCH as exc:  # pragma: no cover - defensive
            _log_nested_exceptions(exc)
            return f"PREFLIGHT_ENV_CHECK_ERROR: {exc}"
        return rendered or "ENV_OK: all standard pentest tools present."
