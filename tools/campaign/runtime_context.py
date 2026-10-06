"""Context-local policies for Flow A campaign construction."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any

SandboxReconProvider = Callable[[str], Awaitable[Any]]

_REQUIRED_SANDBOX_RECON: ContextVar[SandboxReconProvider | None] = ContextVar(
    "required_sandbox_recon_provider",
    default=None,
)


@contextmanager
def require_sandbox_recon(provider: SandboxReconProvider) -> Iterator[None]:
    """Require campaigns constructed in this Flow A context to use this provider.

    This carries Flow A execution policy across its frozen AgentLoop adapter
    without changing legacy code or making the library orchestrator globally
    dependent on MCP runtime objects.
    """
    token: Token[SandboxReconProvider | None] = _REQUIRED_SANDBOX_RECON.set(provider)
    try:
        yield
    finally:
        _REQUIRED_SANDBOX_RECON.reset(token)


def current_required_sandbox_recon() -> SandboxReconProvider | None:
    """Return the active Flow A sandbox recon provider, if one was installed."""
    return _REQUIRED_SANDBOX_RECON.get()
