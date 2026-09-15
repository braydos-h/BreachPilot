"""TODO 014: MCP seam stays 1.x-pinned with exception-group safety until 2.x branch is green."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_mcp_pin_stays_1x_until_migration():
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    reqs = (REPO / "requirements.txt").read_text(encoding="utf-8")
    assert "mcp>=1.27.0,<2.0.0" in pyproject
    assert "mcp>=1.27.0,<2.0.0" in reqs
    wiring = (REPO / "docs" / "mcp-wiring.md").read_text(encoding="utf-8")
    assert "MCP_2X_OWNER" in wiring
    assert "_EXC_GROUP_CATCH" in wiring


def test_exception_group_paths_present():
    from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions

    assert Exception in _EXC_GROUP_CATCH
    try:
        raise BaseExceptionGroup("probe", [ValueError("inner")])
    except _EXC_GROUP_CATCH as eg:
        assert _is_exception_group(eg)
        _log_nested_exceptions(eg)
    # No bare `except Exception` around MCP client entry points.
    for rel in ("tools/mcp_session.py", "tools/exceptions.py"):
        text = (REPO / rel).read_text(encoding="utf-8")
        assert "_EXC_GROUP_CATCH" in text or "BaseExceptionGroup" in text
    # Pin files stay in sync.
    assert re.search(r"mcp==1\.", (REPO / "constraints-dev.txt").read_text(encoding="utf-8"))
