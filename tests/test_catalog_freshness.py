"""Generated MCP tool + skill catalogs must match live sources.

Same --check gate pattern as tests/test_source_map.py and
tests/test_generated_counts.py: the committed markdown drifts the moment a
tool/skill is added, renamed, re-gated, or re-documented. Regenerate with
the command the failure message prints.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _check(script: str) -> None:
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, f"scripts/{script}", "--check"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"{script} drift:\n{proc.stdout}\n{proc.stderr}"


def test_mcp_tool_catalog_fresh():
    assert (REPO / "docs" / "mcp" / "tool-catalog-generated.md").exists()
    _check("generate_mcp_tool_catalog.py")


def test_skill_catalog_fresh():
    assert (REPO / "docs" / "skills" / "catalog.md").exists()
    _check("generate_skill_catalog.py")
