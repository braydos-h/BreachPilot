"""Regression coverage for GitHub Actions release-evidence metadata."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.validate_source_run import validate_source_run

_SHA = "a" * 40
_OTHER_SHA = "b" * 40


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/eval.yml",
        ".github/workflows/eval.yml@refs/heads/main",
    ],
)
def test_source_run_accepts_main_workflow_path_with_or_without_ref_suffix(path: str) -> None:
    validate_source_run(
        {
            "path": path,
            "head_branch": "main",
            "head_sha": _SHA,
            "event": "schedule",
            "status": "completed",
            "conclusion": "success",
        },
        ".github/workflows/eval.yml",
        _SHA,
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"path": ".github/workflows/eval.yml@refs/heads/feature"},
        {"head_branch": "feature"},
        {"event": "pull_request"},
        {"status": "in_progress"},
        {"conclusion": "failure"},
        {"head_sha": "short"},
        {"head_sha": _OTHER_SHA},
    ],
)
def test_source_run_rejects_untrusted_or_incomplete_metadata(overrides: dict[str, str]) -> None:
    run = {
        "path": ".github/workflows/eval.yml@refs/heads/main",
        "head_branch": "main",
        "head_sha": _SHA,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        **overrides,
    }

    with pytest.raises(ValueError, match="trusted main run"):
        validate_source_run(run, ".github/workflows/eval.yml", _SHA)


def test_source_run_rejects_malformed_release_sha() -> None:
    with pytest.raises(ValueError, match="trusted main run"):
        validate_source_run(
            {
                "path": ".github/workflows/eval.yml@refs/heads/main",
                "head_branch": "main",
                "head_sha": _SHA,
                "event": "schedule",
                "status": "completed",
                "conclusion": "success",
            },
            ".github/workflows/eval.yml",
            "short",
        )


def test_release_workflow_binds_source_run_to_release_sha() -> None:
    workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

    assert 'python scripts/validate_source_run.py "$metadata" "$workflow_path" "$GITHUB_SHA"' in workflow
