"""PoC verification MCP tool registration (Killer Feature #3).

Registers ``verify_poc`` -- a local-only ``@audit_tool`` (no target touch)
that syntax-checks (``py_compile``) and optionally Docker-compile-tests a
synthesized PoC. The PoC is never executed; the Docker container is fully
isolated (``--network=none --read-only --memory=256m``).

If a future variant runs a PoC *against the live target*, it MUST switch to
``@require_allowlist()``.
"""

from __future__ import annotations

from typing import Any

from tools.mcp_tools.registry import ToolContext
from tools.poc_verifier import (
    poc_verification_config,
    render_verify_result,
)
from tools.poc_verifier import (
    verify_poc as _verify_poc_lib,
)


def register_poc_verifier_tools(mcp: Any, *, ctx: ToolContext) -> None:
    config = ctx.config
    audit_tool = ctx.audit_tool
    cfg = poc_verification_config(config)

    # If the feature is disabled in config, still register the tool -- the
    # agent can call it explicitly. The config flag controls whether
    # ``cve_to_exploit_synth`` auto-invokes it in its self-heal loop.
    @mcp.tool()
    @audit_tool
    def verify_poc(code: str, image: str = "") -> str:
        """Syntax-check (py_compile) and optionally Docker-compile-test a synthesized Python PoC. Returns {syntax_ok, docker_ok, stderr, code_sha256}. The PoC is NEVER executed -- this is a compile/import gate, not a sandbox guarantee. Docker container is isolated (--network=none --read-only --memory=256m). Use this to self-heal a PoC from cve_to_exploit_synth before declaring it ready."""
        if not code or not code.strip():
            return "BLOCKED: code is required."
        img = (image or "").strip() or cfg["docker_image"]
        result = _verify_poc_lib(
            code,
            image=img,
            timeout=cfg["compile_timeout_seconds"],
            network=cfg["docker_network"],
            read_only=cfg["docker_read_only"],
            memory=cfg["docker_memory"],
            use_docker=cfg["enabled"],
        )
        return render_verify_result(result)


__all__ = ["register_poc_verifier_tools"]
