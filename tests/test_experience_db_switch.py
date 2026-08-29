"""Phase 4 Round 2: experience-store DB switched to the shared default singleton.

Verifies:
  1. ``get_default_db`` is re-exported from tools.mcp_tools.registry.
  2. ``db.get_default_db`` returns the same singleton across calls.
  3. Structural guard: tools/mcp_tools/attack_modules.py no longer contains the
     per-workspace ``workspace / "experience.db"`` literal and does call
     ``get_default_db()``.
"""

from __future__ import annotations

from pathlib import Path

from db import DatabaseManager
from db import get_default_db as g2
from tools.mcp_tools.registry import get_default_db


def test_get_default_db_reexported_and_callable():
    """get_default_db is exported from tools.mcp_tools.registry and returns a
    DatabaseManager instance."""
    assert callable(get_default_db)
    db = get_default_db()
    assert isinstance(db, DatabaseManager)


def test_get_default_db_singleton_identity():
    """The db.get_default_db singleton returns the same instance on two calls."""
    a = g2()
    b = g2()
    assert a is b


def test_attack_modules_uses_default_db_no_workspace_literal():
    """Structural regression guard: the per-workspace experience.db literal is
    gone and get_default_db() is used instead.

    The ExperienceStore wiring moved from the ``attack_modules.py`` god file
    into ``tools/mcp_tools/modules/adaptive.py`` during the split, so the
    get_default_db() assertion follows the code there; the no-workspace-literal
    assertion still covers the old path too.
    """
    root = Path(__file__).resolve().parents[1]
    am_text = (root / "tools" / "mcp_tools" / "attack_modules.py").read_text(encoding="utf-8")
    adaptive_text = (root / "tools" / "mcp_tools" / "modules" / "adaptive.py").read_text(encoding="utf-8")
    for label, text in (("attack_modules.py", am_text), ("modules/adaptive.py", adaptive_text)):
        assert 'workspace / "experience.db"' not in text, (
            f"regression: per-workspace experience.db literal re-introduced in {label}"
        )
    assert "get_default_db()" in adaptive_text, "regression: get_default_db() call missing from modules/adaptive.py"
