from __future__ import annotations

import os
import uuid
from pathlib import Path

from mcp_exploit_server import _find_file, _resolve_workspace_file


def _workspace(name: str) -> Path:
    path = Path("test_workspace") / "unit" / f"{name}_{uuid.uuid4().hex}"
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def test_resolve_workspace_file_accepts_paths_returned_by_write_python_file() -> None:
    workspace = _workspace("mcp_paths")
    attempt_dir = workspace / "20260430_120000_000001"
    attempt_dir.mkdir()
    script = attempt_dir / "exploit.py"
    script.write_text("print('ok')", encoding="utf-8")

    assert _resolve_workspace_file(workspace, str(script), suffix=".py") == script.resolve()
    assert _resolve_workspace_file(workspace, "20260430_120000_000001/exploit.py", suffix=".py") == script.resolve()
    assert _find_file(workspace, "exploit.py") == script.resolve()


def test_resolve_workspace_file_uses_newest_basename_match() -> None:
    workspace = _workspace("mcp_newest")
    old_dir = workspace / "old"
    new_dir = workspace / "new"
    old_dir.mkdir()
    new_dir.mkdir()
    old_script = old_dir / "exploit.py"
    new_script = new_dir / "exploit.py"
    old_script.write_text("print('old')", encoding="utf-8")
    new_script.write_text("print('new')", encoding="utf-8")
    os.utime(old_script, (1, 1))
    os.utime(new_script, (2, 2))

    assert _resolve_workspace_file(workspace, "exploit.py", suffix=".py") == new_script.resolve()
