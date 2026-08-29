"""Sandbox execution helpers for MCP tool families.

One funnel for "run this argv / this command inside the disposable worker
instead of on the host", with the shared destination extraction that both the
scope gate and the audit target come from. Fail-closed contract lives in
``tools/sandbox``: any ``SandboxError`` here becomes a ``SANDBOX_*`` result
block -- host execution is never an automatic fallback for attack commands.
"""

from __future__ import annotations

from typing import Any

from tools.command_analyzer import _endpoint_ips as _cmd_endpoint_ips
from tools.command_analyzer import _extract_destinations as _cmd_extract_destinations
from tools.sandbox.exceptions import SandboxError
from tools.sandbox.mcp_bridge import manager_from_ctx, sandbox_block
from tools.validation_utils import extract_ips_from_command

__all__ = [
    "collect_command_targets",
    "run_command_in_sandbox",
    "run_argv_in_sandbox",
    "sandbox_error_block",
]


def collect_command_targets(command: str) -> list[str]:
    """All host-shaped destinations a command plausibly touches.

    Same union of extractors the tool-layer target lock
    (``terminal.allowlist._target_lock_block``) uses, so the sandbox scope gate
    can never authorize what the string layer would deny (and vice versa).
    Endpoint tokens are expanded to concrete IPs where possible.
    """
    tokens: list[str] = []
    for tok in _cmd_extract_destinations(command):
        if tok and tok not in tokens:
            tokens.append(tok)
    for ip in extract_ips_from_command(command):
        if ip and ip not in tokens:
            tokens.append(ip)
    try:
        from tools.kernel.allowlist import _extract_scanner_targets

        for tok in _extract_scanner_targets(command):
            if tok and tok not in tokens:
                tokens.append(tok)
    except ImportError:  # defensive: extractor set must never break execution
        pass
    targets: list[str] = []
    for tok in tokens:
        decoded = _cmd_endpoint_ips(tok)
        for t in decoded if decoded else [tok]:
            if t and t not in targets:
                targets.append(t)
    return targets


def sandbox_error_block(exc: Exception, *, tool_name: str = "") -> str:
    """Canonical SANDBOX_* fail-closed block for any sandbox failure."""
    if isinstance(exc, SandboxError):
        return sandbox_block(exc, tool_name=tool_name)
    # Unexpected failure on the sandbox path: still fail closed.
    return sandbox_block(
        SandboxError(f"sandbox execution failed: {exc}"),
        tool_name=tool_name,
    )


def run_command_in_sandbox(
    ctx: Any,
    command: str,
    *,
    timeout: int,
    cwd_host: Any = None,
    tool_name: str = "",
    user: str = "",
) -> tuple[bool, Any]:
    """Execute one shell command inside the session sandbox.

    Returns ``(True, SandboxResult)`` on a contained execution (the sandbox
    itself is the boundary; exit codes are the agent's problem) and raises
    ``SandboxError`` on sandbox/policy/scope failure (caller renders the
    SANDBOX_* block). ``(False, None)`` means no sandbox manager is attached
    (sandbox disabled => documented legacy host-execution mode).

    ``cwd_host`` is a HOST path under the run workspace; it is mapped to its
    container path via the manager (paths outside the workspace fail closed).
    """
    manager = manager_from_ctx(ctx)
    if manager is None:
        return False, None
    targets = collect_command_targets(command)
    target_ip = targets[0] if targets else ""
    cwd = manager.container_path(cwd_host) if cwd_host is not None else None
    result = manager.execute(
        command,
        timeout=timeout,
        cwd=cwd,
        user=user,
        target_ip=target_ip,
        tool_name=tool_name or "run_exploit_terminal",
    )
    return True, result


def run_argv_in_sandbox(
    ctx: Any,
    argv: list[str],
    *,
    target_ip: str = "",
    command: str = "",
    timeout: int = 300,
    cwd_host: Any = None,
    tool_name: str = "",
) -> tuple[bool, Any]:
    """Argv-list variant for structured tools (web_scan, impacket, msfvenom...)."""
    manager = manager_from_ctx(ctx)
    if manager is None:
        return False, None
    targets = collect_command_targets(command) if command else []
    if target_ip and target_ip not in targets:
        targets.insert(0, target_ip)
    primary = targets[0] if targets else target_ip
    cwd = manager.container_path(cwd_host) if cwd_host is not None else None
    result = manager.execute_argv(
        argv,
        timeout=timeout,
        cwd=cwd,
        target_ip=primary,
        tool_name=tool_name,
    )
    return True, result
