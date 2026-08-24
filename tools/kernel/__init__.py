"""Shared kernel — pure functions used by both Flow A and Flow B.

Phase 2 extracts the allowlist / audit / workspace helpers that were
previously duplicated or centralized in ``tools.mcp_shared`` and
``tools.mcp_tools.registry`` so both flows import from one place.

``tools.mcp_shared`` and ``tools.mcp_tools.registry`` re-export these
symbols for backwards compat (tests and plugins import from there).

Ponytail: this package contains ONLY pure functions / small decorators.
No I/O beyond workspace-path checks, no global state except the
process-wide ``EXPLOIT_DISCOVERED_TARGETS`` env var (the target-IP lock).
"""
