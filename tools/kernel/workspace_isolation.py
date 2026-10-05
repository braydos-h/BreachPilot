"""Per-run writable workspace resolution for sandboxed agent sessions."""

from __future__ import annotations

import hashlib
from pathlib import Path


def resolve_run_workspace(workspace_root: Path | str, reports_dir: Path | str) -> Path:
    """Resolve a worker workspace without sharing writable state across runs.

    Relative paths are anchored under the run's report directory. Absolute
    paths are treated as shared roots and receive a stable child keyed by the
    resolved report directory. This preserves reuse between recon and exploit
    phases of one run while separating concurrent runs using one configured
    absolute root.
    """
    try:
        configured = Path(workspace_root).expanduser()
        resolved_reports = Path(reports_dir).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("worker workspace or report directory cannot be resolved safely") from exc

    if configured.is_absolute():
        try:
            resolved_root = configured.resolve()
            run_key = hashlib.sha256(str(resolved_reports).encode("utf-8")).hexdigest()[:16]
            candidate = resolved_root / f"run-{run_key}"
            if candidate.is_symlink():
                raise ValueError("absolute worker workspace run directory must not be a symlink")
            workspace = candidate.resolve()
        except (OSError, RuntimeError) as exc:
            raise ValueError("absolute worker workspace cannot be resolved safely") from exc
        if workspace.parent != resolved_root:
            raise ValueError("absolute worker workspace run directory must remain under its configured root")
    else:
        try:
            workspace = (resolved_reports / configured).resolve()
        except (OSError, RuntimeError) as exc:
            raise ValueError("relative worker workspace cannot be resolved safely") from exc
        if resolved_reports not in workspace.parents:
            raise ValueError("relative worker workspace must remain inside the run report directory")

    if workspace == resolved_reports or workspace in resolved_reports.parents:
        raise ValueError("worker workspace must not contain the run report directory")
    return workspace
