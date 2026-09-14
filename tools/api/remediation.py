"""Stable remediation codes shared by backend and WebUI (#53).

Every user-facing failure maps to a code with a title, a fix, and a docs
pointer. The backend error envelope (``{error: {code, ...}}``) carries the
code; the WebUI renders ``REMEDIATION[code]`` from this same table so both
sides can never disagree. Codes are append-only: renaming a code breaks
clients — add a new one and alias the old.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "REMEDIATION_VERSION",
    "REMEDIATION_CODES",
    "remediation_for",
]

REMEDIATION_VERSION = 1


def _entry(title: str, fix: str, docs: str) -> dict[str, str]:
    return {"title": title, "fix": fix, "docs": docs}


REMEDIATION_CODES: dict[str, dict[str, str]] = {
    "sandbox_image_missing": _entry(
        "Sandbox worker image not built",
        "Run: docker build -t breachpilot-sandbox:latest docker/sandbox",
        "docs/sandbox.md",
    ),
    "sandbox_docker_down": _entry(
        "Docker daemon unreachable",
        "Start Docker Desktop / the docker daemon, or set sandbox.auto_manage_docker: true",
        "docs/sandbox.md",
    ),
    "sandbox_blocked_no_consent": _entry(
        "Native execution blocked: explicit consent required",
        "Keep containment (recommended), or export "
        "BREACHPILOT_ALLOW_NATIVE_EXECUTION=I_UNDERSTAND_THIS_RUNS_ON_THE_HOST",
        "docs/sandbox.md",
    ),
    "mcp_boot_timeout": _entry(
        "MCP server did not boot within 30s",
        "Run bp --doctor; check mcp_exploit_server.log tail (credentials redacted)",
        "docs/troubleshooting.md",
    ),
    "target_not_allowlisted": _entry(
        "Target outside the allowlist lock",
        "Add the target to exploit.allowed_targets (or pass --target so EXPLOIT_TARGET covers it)",
        "docs/safety-model.md",
    ),
    "scope_denied": _entry(
        "Mission scope gate denied this action",
        "Adjust mission.yaml allowed assets / forbidden_actions, or pick an in-scope goal",
        "docs/safety-model.md",
    ),
    "model_auth_failed": _entry(
        "Model provider authentication failed",
        "Set the provider key env (e.g. OLLAMA_API_KEY) or switch models.provider",
        "docs/providers.md",
    ),
    "browser_unavailable": _entry(
        "Browser worker unavailable",
        "Build the browser image (Dockerfile.browser) and set browser.enabled: true",
        "docs/browser-agent-design.md",
    ),
    "run_conflict": _entry(
        "Another run is already active",
        "Wait for or cancel the active run, or raise api.max_concurrent_runs",
        "docs/troubleshooting.md",
    ),
    "validation_error": _entry(
        "Request failed validation",
        "Re-read the field error in details; see docs/api.md for the contract",
        "docs/api.md",
    ),
    "not_found": _entry(
        "Resource not found",
        "Check the run/artifact id; lists are newest-first",
        "docs/api.md",
    ),
    "internal_error": _entry(
        "Unexpected internal error",
        "Retry once; if it persists, file an issue with the request_id",
        "docs/troubleshooting.md",
    ),
}


def remediation_for(code: str) -> dict[str, Any]:
    """Remediation entry for a code, or a generic fallback (never raises)."""
    entry = REMEDIATION_CODES.get(str(code or ""))
    if entry is None:
        entry = REMEDIATION_CODES["internal_error"]
        return {"code": "internal_error", **entry, "requested": str(code or "")}
    return {"code": str(code), **entry}
