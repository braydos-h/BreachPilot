"""Fail when a workflow uses a mutable third-party GitHub Action ref."""

from __future__ import annotations

import re
from pathlib import Path

_USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def find_unpinned_actions(workflows_dir: Path) -> list[str]:
    """Return workflow locations whose external Action ref is not a full SHA."""
    offenders: list[str] = []
    workflow_paths = sorted([*workflows_dir.glob("*.yml"), *workflows_dir.glob("*.yaml")])
    for workflow in workflow_paths:
        for line_number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            match = _USES_RE.match(line)
            if match is None:
                continue
            action = match.group(1)
            if action.startswith("./"):
                continue
            name, separator, reference = action.rpartition("@")
            if not separator or not name or not _COMMIT_RE.fullmatch(reference):
                offenders.append(f"{workflow.name}:{line_number}:{line.strip()}")
    return offenders


def main() -> int:
    offenders = find_unpinned_actions(Path(".github/workflows"))
    if offenders:
        print("ERROR: mutable or unpinned GitHub Actions found; pin external Actions to full commit SHAs:")
        print("\n".join(offenders))
        return 1
    print("Action SHA-pin guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
