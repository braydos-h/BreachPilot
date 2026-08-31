"""Sandbox exception hierarchy + the structured error codes MCP tools surface.

Every failure DURING an active sandbox session is FAIL CLOSED: the tool layer
catches ``SandboxError`` subclasses and converts them into ``SANDBOX_*`` result
blocks. Host execution is NEVER a per-command fallback -- a
sandbox/daemon/policy failure blocks the execution instead. The single
sanctioned fallback is the boot-time decision in
``tools/sandbox/manager.py::resolve_manager_with_fallback``: with
``sandbox.fallback_native`` true (default), a server whose Docker stack is
unusable degrades wholly to the documented legacy host-execution mode (with a
warning) BEFORE any tool exists, so no in-session command ever silently
switches between contained and native execution. See
``tools/sandbox/mcp_bridge.py::sandbox_block`` for the text protocol.
"""

from __future__ import annotations

__all__ = [
    "SandboxError",
    "SandboxUnavailableError",
    "SandboxPolicyError",
    "SandboxScopeError",
    "SandboxUnsupportedError",
    "SandboxWorkspaceError",
    "SANDBOX_UNAVAILABLE",
    "SANDBOX_POLICY_FAILED",
    "SANDBOX_SCOPE_DENIED",
    "SANDBOX_UNSUPPORTED",
    "SANDBOX_WORKSPACE_FAILED",
]

SANDBOX_UNAVAILABLE = "SANDBOX_UNAVAILABLE"
SANDBOX_POLICY_FAILED = "SANDBOX_POLICY_FAILED"
SANDBOX_SCOPE_DENIED = "SANDBOX_SCOPE_DENIED"
SANDBOX_UNSUPPORTED = "SANDBOX_UNSUPPORTED"
SANDBOX_WORKSPACE_FAILED = "SANDBOX_WORKSPACE_FAILED"


class SandboxError(Exception):
    """Base class for sandbox failures. Carries the structured error code."""

    code = SANDBOX_UNAVAILABLE

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class SandboxUnavailableError(SandboxError):
    """Sandbox could not be created/reached (Docker missing, daemon down, image absent)."""

    code = SANDBOX_UNAVAILABLE


class SandboxPolicyError(SandboxError):
    """Sandbox policy installation failed (firewall rules could not be established)."""

    code = SANDBOX_POLICY_FAILED


class SandboxScopeError(SandboxError):
    """An execution target/resource is outside the authorized set (scope denied)."""

    code = SANDBOX_SCOPE_DENIED


class SandboxUnsupportedError(SandboxError):
    """Operation has no sandbox-safe implementation (must not fall back to host)."""

    code = SANDBOX_UNSUPPORTED


class SandboxWorkspaceError(SandboxError):
    """Workspace mount/path validation failed."""

    code = SANDBOX_WORKSPACE_FAILED
