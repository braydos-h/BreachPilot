"""Sandbox exception hierarchy + the structured error codes MCP tools surface.

Every failure on the sandbox path is FAIL CLOSED: the tool layer catches
``SandboxError`` subclasses and converts them into ``SANDBOX_*`` result blocks.
Host execution is NEVER an automatic fallback for an attack command -- a
sandbox/daemon/policy failure blocks the execution instead. See
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