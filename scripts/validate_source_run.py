"""Validate GitHub Actions evidence-run metadata used by the release gate."""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_FULL_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")


def validate_source_run(run: Mapping[str, Any], expected_workflow: str, expected_sha: str) -> None:
    """Reject evidence unless it came from the release SHA's completed main run."""
    raw_path = str(run.get("path", "") or "")
    workflow_path, ref_marker, ref = raw_path.partition("@refs/")
    valid_ref = not ref_marker or ref == "heads/main"
    release_sha = str(expected_sha or "").lower()
    source_sha = str(run.get("head_sha", "") or "").lower()
    valid = (
        bool(_FULL_SHA.fullmatch(release_sha))
        and workflow_path == expected_workflow
        and valid_ref
        and run.get("head_branch") == "main"
        and run.get("event") in {"schedule", "workflow_dispatch"}
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and bool(_FULL_SHA.fullmatch(source_sha))
        and source_sha == release_sha
    )
    if not valid:
        raise ValueError("source run is not a successful trusted main run")


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: validate_source_run.py METADATA_JSON EXPECTED_WORKFLOW EXPECTED_SHA", file=sys.stderr)
        return 2
    try:
        payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("source run metadata must be a JSON object")
        validate_source_run(payload, sys.argv[2], sys.argv[3])
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"source run validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
