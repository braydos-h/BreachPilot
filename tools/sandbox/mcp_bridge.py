"""MCP-facing helpers for the sandbox: error blocks + manager access.

The MCP tool layer must convert sandbox failures into structured ``SANDBOX_*``
result blocks (fail closed, visible to the LLM and the audit trail) instead of
tracebacks or silent host fallback. This module is the ONLY place that formats
those blocks so tests and docs reference one canonical text protocol.
"""

from __future__ import annotations

from typing import Any

from tools.sandbox.exceptions import (
    SANDBOX_POLICY_FAILED,
    SANDBOX_SCOPE_DENIED,
    SANDBOX_UNAVAILABLE,
    SANDBOX_UNSUPPORTED,
    SANDBOX_WORKSPACE_FAILED,
    SandboxError,
)

_REMEDIATION = {
    SANDBOX_UNAVAILABLE: (
        "Ensure Docker Desktop (Windows/macOS) or docker.io/docker-ce (Linux) is installed "
        "and running; build the sandbox image: docker build -t breachpilot-sandbox:latest docker/sandbox. "
        "To deliberately keep the legacy UNCONTAINED host-execution mode, set sandbox.enabled: false "
        "in config.yaml (explicit operator opt-out -- never automatic)."
    ),
    SANDBOX_POLICY_FAILED: (
        "The worker network firewall could not be installed (iptables-restore failed in the "
        "sidecar). The sandbox refuses to run contained. Check docker/sandbox image tooling "
        "and daemon logs; execution is blocked (fail-closed)."
    ),
    SANDBOX_SCOPE_DENIED: (
        "The target/allowlist policy denied this execution before any container work. "
        "Add the target to config.yaml exploit.allowed_targets (or via EXPLOIT_TARGET/"
        "EXPLOIT_DISCOVERED_TARGETS) to authorize it."
    ),
    SANDBOX_UNSUPPORTED: (
        "This operation has no sandbox-safe implementation; the project never auto-falls "
        "back to host execution for attack commands -- document the need and extend "
        "tools/sandbox/ (or run it through run_exploit_terminal)."
    ),
    SANDBOX_WORKSPACE_FAILED: (
        "The sandbox workspace bind failed validation (missing dir, symlink, or path outside "
        "the run workspace). Tools may only produce artifacts under the run's workspace."
    ),
}


def sandbox_block(exc: SandboxError, *, tool_name: str = "") -> str:
    """Canonical fail-closed result block for a sandbox failure."""
    code = getattr(exc, "code", None) or SANDBOX_UNAVAILABLE
    remediation = _REMEDIATION.get(code, "")
    lines = ["TERMINAL_RESULT: BLOCKED", code, str(exc)]
    if tool_name:
        lines.append(f"TOOL: {tool_name}")
    lines.append("EXECUTED: nowhere -- the command was not run on the host (fail closed)")
    if remediation:
        lines.append(f"REMEDIATION: {remediation}")
    return "\n".join(lines)


def manager_from_ctx(ctx: Any) -> Any | None:
    """Read the session SandboxManager from a tool context (None when disabled).

    Duck-typed: test FakeCtx objects without a ``sandbox`` attribute resolve to
    None (legacy host-execution mode), matching historical test expectations.
    """
    return getattr(ctx, "sandbox", None)


def is_sandbox_active(ctx: Any) -> bool:
    return manager_from_ctx(ctx) is not None
