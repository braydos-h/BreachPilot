"""TODO 010: generated capability counts must match live catalogs."""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_capability_counts_fresh():
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "scripts/generate_capability_counts.py", "--check"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"capability-counts drift:\n{proc.stdout}\n{proc.stderr}"


def test_no_hardcoded_stale_counts_in_readme():
    text = (REPO / "README.md").read_text(encoding="utf-8")
    assert "139 skills, 153 MCP tools" not in text
    assert "153 MCP" not in text
    assert "167 MCP" not in text
    # Generated file is authoritative.
    data = json.loads((REPO / "docs" / "generated" / "capability-counts.json").read_text(encoding="utf-8"))
    assert data["tools"] >= 100
    assert data["skills"] >= 100


def test_docs_reference_generated_counts():
    """Docs with counts must point at the generated file, not hand literals."""
    # reliability-metrics is allowed to echo numbers if it cites the generated source.
    rel = (REPO / "docs" / "reliability-metrics.md").read_text(encoding="utf-8")
    assert "capability-counts.json" in rel or "tool-catalog-generated" in rel
