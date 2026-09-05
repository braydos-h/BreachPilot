"""Gate test: every ``@mcp.tool`` in ``tools/mcp_tools/`` carries an audit gate.

Single-source registration (``collect_tools``) relies on the AST validator
``_validate_mcp_tool_decorators`` to fail CI when a tool lacks
``@audit_tool`` / ``@require_allowlist``. This pins that contract:
- the checked-in tree validates clean, and
- a tool WITHOUT the gate is flagged (negative case scans a probe file in
  ``tmp_path`` -- never the real package dir, so no stray file can break
  server boot or leak across tests).
"""

from __future__ import annotations

from pathlib import Path

from tools.mcp_tools.registry import _validate_mcp_tool_decorators

_PROBE_SRC = '''"""Probe file for the decorator-gate negative test."""


def register_probe_tools(mcp, ctx):
    @mcp.tool()
    def probe_tool_without_audit_gate(command: str) -> str:
        return command
'''


def test_all_mcp_tools_carry_audit_gate() -> None:
    assert _validate_mcp_tool_decorators() == []


def test_validator_flags_tool_without_audit_gate(tmp_path: Path) -> None:
    probe = tmp_path / "probe_family.py"
    probe.write_text(_PROBE_SRC, encoding="utf-8")
    errors = _validate_mcp_tool_decorators([probe])
    assert any("probe_tool_without_audit_gate" in e for e in errors), errors
