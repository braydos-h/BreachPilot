"""TODO 011: zero shims without a removal version; CI enforces expiry."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_all_deprecation_warnings_carry_removal_version():
    offenders: list[str] = []
    warn_re = re.compile(r"warnings\.warn\(.*DeprecationWarning", re.DOTALL)
    for py in list(REPO.glob("*.py")) + list((REPO / "tools").rglob("*.py")) + list((REPO / "legacy").rglob("*.py")):
        if ".venv" in str(py) or "__pycache__" in str(py):
            continue
        try:
            text = py.read_text(encoding="utf-8")
        except OSError:
            continue
        if not warn_re.search(text):
            continue
        # Every file that warns must name a removal version.
        if "remove in 0." not in text:
            offenders.append(str(py.relative_to(REPO)))
    assert not offenders, "shims without removal version:\n" + "\n".join(offenders)


def test_source_map_lists_shims():
    srcmap = REPO / "docs" / "source-map.md"
    assert srcmap.exists(), "docs/source-map.md must exist (TODO 020)"
    text = srcmap.read_text(encoding="utf-8")
    for shim in ("agent_loop", "legacy.agent_loop", "remove in 0.71"):
        assert shim in text
