"""Sandbox family-audit registration for the browser family (implemented).

Contract (docs/browser-agent-design.md §sandbox requirements): the browser
family is registered as ``sandboxed`` — Chromium executes one op per docker
exec inside the sandbox worker netns (``SandboxPlaywrightLauncher``), obeys
the effective target allowlist, and never falls back to host execution.
"""

from __future__ import annotations

import ast
from pathlib import Path

from tools.sandbox.family_audit import (
    HOST_EXCEPTIONS,
    PLANNED_FAMILIES,
    SANDBOXED_FAMILIES,
    describe_family_audit,
)


def test_browser_is_registered_as_sandboxed():
    assert "browser" in SANDBOXED_FAMILIES
    entry = SANDBOXED_FAMILIES["browser"]
    assert entry.status == "sandboxed"
    assert entry.target_touching is True
    assert any("sandbox" in note.lower() for note in entry.notes)
    assert any("fallback" in note.lower() for note in entry.notes)


def test_browser_graduated_from_planned():
    """The pre-committed contract is fulfilled — nothing stays planned."""
    assert "browser" not in PLANNED_FAMILIES


def test_browser_mcp_module_uses_the_sandbox_seam():
    """tools/mcp_tools/browser.py must funnel through the sandbox seam."""
    path = Path("tools/mcp_tools/browser.py")
    assert path.exists(), "browser MCP family module is missing"
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported.add(alias.asname or alias.name)
    seam_symbols = {"run_command_in_sandbox", "run_argv_in_sandbox", "manager_from_ctx", "sandbox_error_block"}
    assert imported & seam_symbols, "browser family is sandboxed but never imports the funnel"


def test_browser_never_imports_host_subprocess():
    """Contained execution goes through the manager — no direct host Popen."""
    path = Path("tools/mcp_tools/browser.py")
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name != "subprocess" for alias in node.names), "browser MCP must not use host subprocess"
        elif isinstance(node, ast.ImportFrom):
            assert node.module != "subprocess", "browser MCP must not use host subprocess"


def test_audit_summary_has_no_problems():
    summary = describe_family_audit()
    assert summary["unregistered"] == 0
    assert summary["problems"] == []


def test_registry_split_still_separates_real_statuses():
    """The real registries keep their exact guarantees after the move."""
    for entry in HOST_EXCEPTIONS.values():
        assert entry.status == "host_exception"
    for entry in SANDBOXED_FAMILIES.values():
        assert entry.status == "sandboxed"
    for entry in PLANNED_FAMILIES.values():
        assert entry.status == "planned"
