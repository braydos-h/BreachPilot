from __future__ import annotations

from pathlib import Path

import pytest

from tools.kernel.workspace_isolation import resolve_run_workspace


def test_relative_workspace_is_nested_under_the_run_reports(tmp_path: Path) -> None:
    reports = tmp_path / "reports" / "run-1"

    workspace = resolve_run_workspace("exploit_workspace", reports)

    assert workspace == (reports / "exploit_workspace").resolve()


def test_absolute_workspace_root_gets_distinct_stable_run_directories(tmp_path: Path) -> None:
    workspace_root = tmp_path / "shared-workspace-root"
    first_reports = tmp_path / "reports" / "run-1"
    second_reports = tmp_path / "reports" / "run-2"

    first = resolve_run_workspace(workspace_root, first_reports)
    second = resolve_run_workspace(workspace_root, second_reports)

    assert first.parent == workspace_root.resolve()
    assert second.parent == workspace_root.resolve()
    assert first != second
    assert first == resolve_run_workspace(workspace_root, first_reports)


@pytest.mark.parametrize("relative_workspace", ["../shared", "../../outside", "."])
def test_relative_workspace_cannot_escape_or_replace_run_reports(tmp_path: Path, relative_workspace: str) -> None:
    reports = tmp_path / "reports" / "run-1"

    with pytest.raises(ValueError):
        resolve_run_workspace(relative_workspace, reports)
