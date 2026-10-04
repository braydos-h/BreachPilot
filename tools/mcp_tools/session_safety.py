"""Fail-closed policy for persistent host-side sessions and listeners."""

from __future__ import annotations

from typing import Any

from tools.sandbox.manager import native_execution_consent


def host_execution_block(ctx: Any, *, operation: str) -> str | None:
    """Return a denial unless an operation's host execution is authorized.

    Persistent tmux/nohup sessions and listeners do not have a contained
    implementation. They are available only after the server has selected an
    explicit native mode and the operator has supplied the documented
    acknowledgement token. A missing sandbox manager by itself never means
    native execution is allowed.
    """
    if getattr(ctx, "sandbox", None) is not None:
        return (
            f"BLOCKED: SANDBOX_UNSUPPORTED — {operation} has no sandbox-safe "
            "implementation. Use a contained tool or explicitly select native "
            "mode with operator consent."
        )

    config = getattr(ctx, "config", None)
    cfg = config if isinstance(config, dict) else {}
    sandbox = cfg.get("sandbox")
    sandbox_cfg = sandbox if isinstance(sandbox, dict) else {}
    native_requested = sandbox_cfg.get("enabled") is False or sandbox_cfg.get("fallback_native") is True
    if not native_requested:
        return (
            "BLOCKED: SANDBOX_UNAVAILABLE — no sandbox manager is attached and "
            "native session execution was not explicitly selected."
        )

    allowed, reason = native_execution_consent(cfg)
    if not allowed:
        return f"BLOCKED: NATIVE_EXECUTION_CONSENT — {reason}"
    return None
