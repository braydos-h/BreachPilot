"""Tool-family containment audit for the sandbox.

The contract (docs/sandbox.md, docs/benchmarks.md): agent-generated attack
execution always uses the sandbox; no configuration permits it to silently run
on the host.
This module is the explicit, reviewable registry of every tool family in
``tools/mcp_tools/`` that spawns processes, and its containment status:

- ``sandboxed``     — the family's target-touching commands funnel through
                      :mod:`tools.mcp_tools.sandbox_exec` into the worker.
- ``host_exception``— documented exception: the family executes on the host
                      with a stated reason (e.g. local-only utility, or
                      pending migration). Exceptions must be auditable and
                      intentional — this registry is enforced by test.

``audit_families()`` scans the package for modules that reference
``subprocess`` and asserts each is accounted for (sandboxed or registered
exception). The test suite fails when a new subprocess-using tool family
appears without a registry entry, so containment can never silently rot.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "FamilyStatus",
    "SANDBOXED_FAMILIES",
    "HOST_EXCEPTIONS",
    "PLANNED_FAMILIES",
    "audit_families",
    "describe_family_audit",
]

_MCP_TOOLS_DIR = Path(__file__).resolve().parent.parent / "mcp_tools"

_SANDBOX_SEAM_SYMBOLS = {
    "run_command_in_sandbox",
    "run_argv_in_sandbox",
    "run_tool_argv_in_sandbox",
    "manager_from_ctx",
    "sandbox_error_block",
}


@dataclass
class FamilyStatus:
    """Containment status of one tool family."""

    module: str
    status: str  # "sandboxed" | "host_exception" | "planned" (PLANNED_FAMILIES only)
    reason: str = ""
    target_touching: bool = True
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "status": self.status,
            "reason": self.reason,
            "target_touching": self.target_touching,
            "notes": list(self.notes),
        }


#: Families whose target-touching execution funnels through the sandbox.
_SANDBOX_FAMILY_NOTES: dict[str, list[str]] = {
    "metasploit": [
        "msfconsole_start spawns the long-lived console on the host (operator-driven; "
        "module EXECUTION funnels through run_argv_in_sandbox)"
    ],
    "workspace": [
        "start_background_job/list_processes manage host-side long-running jobs; "
        "run_python_file funnels through run_argv_in_sandbox"
    ],
    "browser": [
        "Playwright backend (tools/browser/playwright_backend.py) executes one Chromium op "
        "per docker exec inside the sandbox worker netns via SandboxPlaywrightLauncher "
        "(tools/browser/sandbox_launcher.py); strict fail-closed, never host fallback"
    ],
    "recon": [
        "check_os, quick_scan, run_full_recon, and get_service_fingerprint use fixed Nmap argv through "
        "run_argv_in_sandbox after DNS pinning. run_udp_recon is blocked because the worker intentionally "
        "drops NET_RAW. OSINT is bounded passive access to fixed public providers and does not connect to the target. "
        "This entry covers tools/mcp_tools/recon.py only; direct ReconPipeline callers in campaign and opt-in swarm "
        "paths remain host-side and are outside this module-level audit."
    ],
}
SANDBOXED_FAMILIES: dict[str, FamilyStatus] = {
    name: FamilyStatus(
        module=name,
        status="sandboxed",
        reason="commands run inside the sandbox worker",
        notes=_SANDBOX_FAMILY_NOTES.get(name, []),
    )
    for name in (
        "terminal/execute",  # run_exploit_terminal (sandboxed path)
        "web_scan",  # nikto/nuclei/sqlmap/... argv funnel
        "metasploit",  # msf module execution argv funnel
        "credentials",  # impacket lateral/credential tools use the shared argv funnel
        "ad",  # AD enumeration and execution tools use the shared argv funnel
        "payloads",  # msfvenom payload generation uses the shared argv funnel
        "workspace",  # run_python_file argv funnel (sandbox path)
        "browser",  # Playwright ops via SandboxPlaywrightLauncher (sandboxed path)
        "recon",  # target-active scanners via argv funnel; UDP scan is explicitly unsupported
    )
}

#: Documented host-execution exceptions for local/operator utilities and
#: passive recon. Agent-generated attack execution is never listed here.
HOST_EXCEPTIONS: dict[str, FamilyStatus] = {
    "terminal/package": FamilyStatus(
        module="terminal/package",
        status="host_exception",
        reason=(
            "apt/pip/git-clone install primitives execute on the operator host "
            "(pending sandbox migration; lab-only convenience tools, target-locked)"
        ),
        target_touching=False,
    ),
    "terminal/privilege": FamilyStatus(
        module="terminal/privilege",
        status="host_exception",
        reason=(
            "run_as_root and the Windows bash-locator execute on the operator host "
            "(pending sandbox migration; operator-box privilege helper)"
        ),
        target_touching=False,
    ),
    "cracking": FamilyStatus(
        module="cracking",
        status="host_exception",
        reason="hashcat/john run locally on hashes the operator supplies (no network, audit-only tool)",
        target_touching=False,
    ),
    "domain": FamilyStatus(
        module="domain",
        status="host_exception",
        reason=(
            "DNS tools execute dig/host/subfinder on the host (pending sandbox migration; "
            "reads are passive recon and the families are allowlist-locked at the MCP layer)"
        ),
        target_touching=True,
    ),
    "operator_connection": FamilyStatus(
        module="operator_connection",
        status="host_exception",
        reason="operator-directed connection lifecycle (RDP/VNC client launch) is an interactive operator tool, not agent offense",
        target_touching=False,
    ),
    "registry": FamilyStatus(
        module="registry",
        status="host_exception",
        reason="process-timeout helper wraps model-router work, not target execution",
        target_touching=False,
    ),
}


#: Future families whose tooling is PLANNED but not yet implemented. These
#: have no module file today (nothing to audit) and no active capability.
#: (The browser family graduated from here to SANDBOXED_FAMILIES when the
#: Playwright backend landed — see tools/browser/.)
#: Design: docs/browser-agent-design.md §sandbox requirements.
PLANNED_FAMILIES: dict[str, FamilyStatus] = {}


def _module_key(path: Path) -> str:
    """Module key relative to mcp_tools, without the .py suffix."""
    rel = path.relative_to(_MCP_TOOLS_DIR)
    return str(rel.with_suffix("")).replace("\\", "/")


def _uses_subprocess(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name == "subprocess" for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module == "subprocess":
                return True
    return False


def _uses_sandbox_seam(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return False
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
    return bool(names & _SANDBOX_SEAM_SYMBOLS)


def audit_families(mcp_tools_dir: Path | None = None) -> list[dict[str, Any]]:
    """Audit every subprocess-using module under ``tools/mcp_tools``.

    Returns a list of ``{module, status, reason, target_touching, problem}``
    rows. A row has ``problem`` set when the module spawns processes but has
    NO registry entry — the test suite treats that as a hard failure.
    """
    root = Path(mcp_tools_dir) if mcp_tools_dir else _MCP_TOOLS_DIR
    rows: list[dict[str, Any]] = []
    if not root.exists():
        return rows
    for path in sorted(root.rglob("*.py")):
        if path.name == "__init__.py" or "__pycache__" in path.parts:
            continue
        key = _module_key(path)
        # Structured process wrappers may delegate subprocess creation to the
        # sandbox funnel, so they do not import subprocess themselves. Keep
        # registered worker-process families visible in the audit summary.
        uses_worker_process = key in SANDBOXED_FAMILIES and _uses_sandbox_seam(path)
        if not (_uses_subprocess(path) or uses_worker_process):
            continue
        entry = SANDBOXED_FAMILIES.get(key) or HOST_EXCEPTIONS.get(key)
        if entry is not None:
            row = entry.to_dict()
            row["problem"] = ""
            # A module that spawns subprocesses AND imports the sandbox seam
            # but is registered as a host exception is a registry bug.
            if entry.status == "host_exception" and _uses_sandbox_seam(path):
                row["problem"] = "registered host_exception but module imports the sandbox seam"
        else:
            row = FamilyStatus(module=key, status="unregistered", reason="").to_dict()
            row["problem"] = "subprocess use without a containment registry entry"
        rows.append(row)
    return rows


def describe_family_audit() -> dict[str, Any]:
    """Machine-readable audit summary (used by docs + tests + status page)."""
    rows = audit_families()
    problems = [r for r in rows if r.get("problem")]
    # ``planned`` is additive metadata: planned families have no module file
    # yet, so they never appear as rows and never count as problems — the
    # pre-committed containment contract for the future browser family lives
    # in PLANNED_FAMILIES.
    return {
        "total": len(rows),
        "sandboxed": sum(1 for r in rows if r.get("status") == "sandboxed"),
        "host_exceptions": sum(1 for r in rows if r.get("status") == "host_exception"),
        "unregistered": sum(1 for r in rows if r.get("status") == "unregistered"),
        "problems": [r["module"] for r in problems],
        "rows": rows,
        "planned": [entry.to_dict() for entry in PLANNED_FAMILIES.values()],
    }
