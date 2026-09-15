"""TODO 019: evidence-first positioning, no count headlines."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_no_count_headline_above_fold():
    text = (REPO / "README.md").read_text(encoding="utf-8")
    first = "\n".join(text.splitlines()[:30])
    for banned in ("139 skills", "153 MCP", "167 tools", "most tools", "most agents"):
        assert banned not in first, f"count headline above fold: {banned}"
    assert "Auditable, evidence-driven" in text
    assert "docs/positioning.md" in text or "positioning" in text


def test_positioning_names_core_claims():
    text = (REPO / "docs" / "positioning.md").read_text(encoding="utf-8")
    for claim in ("verification", "containment", "provenance", "reproducibility"):
        assert claim.lower() in text.lower(), f"positioning must name {claim}"
    assert "full_access" in text or "throwaway" in text
