"""Self-verification primitives for the NetAttackAi exploit engine.

Phase 1.3 of the self-verification core. This package provides proof-of-exec
(PoE) verification helpers that confirm a claimed compromise is real by
exercising the live tool executor against the target: a unique canary token is
written to the target filesystem, read back, and the identity probes
(``id`` / ``whoami`` / ``hostname``) are collected to classify privilege.

The verifier is intentionally executor-agnostic: it consumes the same
``tool_executor`` shape the swarm bridge and autonomous orchestrator already
use (a sync ``Callable[[str, dict[str, Any]], str]`` returning a textual
result that follows the ``BLOCKED:`` / ``TOOL_EXECUTION_ERROR:`` conventions).
"""

from __future__ import annotations

from .poe_verifier import (
    classify_privilege,
    extract_output,
    verify_compromise,
    verify_compromise_sync,
)

__all__ = [
    "verify_compromise",
    "verify_compromise_sync",
    "classify_privilege",
    "extract_output",
]
