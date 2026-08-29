"""Sandbox containment audit for every MCP tool family.

Contract (docs/sandbox.md + docs/benchmarks.md §sandbox): when the sandbox is
enabled, no offensive/target-touching execution may silently run on the host.

This test enforces ``tools/sandbox/family_audit.py``: EVERY module under
``tools/mcp_tools/`` that spawns processes must be either

- registered as ``sandboxed`` (funnels through ``tools/mcp_tools/sandbox_exec``),
- or registered as a documented ``host_exception`` with a stated reason.

A new subprocess-using family without a registry entry FAILS this test —
containment coverage can never silently rot. The audit summary itself is
surfaced to the WebUI benchmark pages via the sandbox status.
"""

from __future__ import annotations

from tools.sandbox.family_audit import HOST_EXCEPTIONS, SANDBOXED_FAMILIES, audit_families, describe_family_audit


def test_every_subprocess_family_is_registered():
    """No module under tools/mcp_tools may use subprocess without a registry entry."""
    rows = audit_families()
    assert rows, "audit must find the subprocess-using families"
    unregistered = [r["module"] for r in rows if r.get("problem")]
    assert not unregistered, (
        "unregistered subprocess-using tool families: "
        f"{unregistered} — add a sandboxed or documented host_exception entry "
        "to tools/sandbox/family_audit.py"
    )


def test_registered_entries_reference_real_registry():
    """Rows returned by the audit must map to a real registry status."""
    rows = audit_families()
    for row in rows:
        assert row["status"] in {"sandboxed", "host_exception"}, row
        if row["status"] == "sandboxed":
            assert row["module"] in SANDBOXED_FAMILIES
        else:
            assert row["module"] in HOST_EXCEPTIONS
            assert row["reason"], "host exceptions must document a reason"


def test_sandboxed_families_use_the_sandbox_funnel():
    """Families registered as sandboxed must import the sandbox_exec seam."""
    import ast
    from pathlib import Path

    mcp_tools = Path("tools/mcp_tools")
    seam_symbols = {"run_command_in_sandbox", "run_argv_in_sandbox", "manager_from_ctx", "sandbox_error_block"}
    for name in SANDBOXED_FAMILIES:
        path = mcp_tools / f"{name}.py"
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported.add(alias.asname or alias.name)
        assert imported & seam_symbols, f"{name} is registered sandboxed but never imports the funnel"


def test_target_touching_exceptions_are_documented_gaps():
    """Target-touching host exceptions must say they are pending migration or
    the explicit sandbox-disabled opt-out — never silent host execution."""
    for name, entry in HOST_EXCEPTIONS.items():
        if entry.target_touching:
            ok = (
                "sandbox migration" in entry.reason
                or "pending" in entry.reason
                or "sandbox.enabled is false" in entry.reason
            )
            assert ok, (
                f"{name}: target-touching host exceptions must state the migration plan "
                "or the explicit opt-out condition"
            )


def test_audit_summary_shape():
    """The machine-readable summary stays consumable by the WebUI/status."""
    summary = describe_family_audit()
    assert set(summary) >= {"total", "sandboxed", "host_exceptions", "unregistered", "problems", "rows"}
    assert summary["unregistered"] == 0
    assert summary["problems"] == []
