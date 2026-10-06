"""Resolve host-owned audit paths outside the sandbox worker mount."""

from __future__ import annotations

from pathlib import Path

AUDIT_FILENAME = "exploit_audit.jsonl"


def validate_run_workspace(workspace: Path | str, reports_dir: Path | str) -> Path:
    """Resolve a worker workspace and keep it from containing run artifacts.

    A run's report directory holds operator-owned evidence and the frozen
    configuration used to start MCP. Binding that directory (or one of its
    ancestors) as the writable worker workspace would let generated commands
    alter reports and policy inputs. A nested workspace such as
    ``reports/<run_id>/exploit_workspace`` remains valid.
    """
    try:
        resolved_workspace = Path(workspace).expanduser().resolve()
        resolved_reports = Path(reports_dir).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("worker workspace or report directory cannot be resolved safely") from exc
    if resolved_workspace == resolved_reports or resolved_workspace in resolved_reports.parents:
        raise ValueError("worker workspace must not contain the run report directory")
    return resolved_workspace


def validate_external_audit_path(workspace: Path | str, audit_path: Path | str) -> Path:
    """Resolve ``audit_path`` and reject any path inside the worker workspace.

    The worker receives the workspace itself as a writable ``/workspace`` bind.
    Checking resolved paths also rejects symlink aliases that point back into
    that bind.
    """
    resolved_workspace = Path(workspace).expanduser().resolve()
    try:
        candidate = Path(audit_path).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        resolved_audit = candidate.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("audit path cannot be resolved safely") from exc
    if resolved_audit == resolved_workspace or resolved_workspace in resolved_audit.parents:
        raise ValueError("audit path must resolve outside the writable worker workspace")
    return resolved_audit


def external_audit_path(workspace: Path | str, preferred_path: Path | str | None = None) -> Path:
    """Choose a per-workspace audit file that is outside the worker mount.

    A preferred report path is used when it is outside the workspace. When a
    benchmark or direct caller uses the same directory for reports and worker
    files, a uniquely named sibling preserves that caller's isolation.
    """
    resolved_workspace = Path(workspace).expanduser().resolve()
    if preferred_path is not None:
        try:
            return validate_external_audit_path(resolved_workspace, preferred_path)
        except ValueError:
            # Some supported callers use one directory for both reports and
            # worker files. Keep the audit protected by placing it beside that
            # directory instead of silently putting it back in the bind.
            pass
    name = resolved_workspace.name or resolved_workspace.parent.name or "workspace"
    fallback = resolved_workspace.parent / f"{name}-{AUDIT_FILENAME}"
    return validate_external_audit_path(resolved_workspace, fallback)


def prepare_external_audit_path(workspace: Path | str, preferred_path: Path | str | None = None) -> Path:
    """Create the host-owned audit file before the sandbox worker starts."""
    audit_path = external_audit_path(workspace, preferred_path)
    try:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.touch(exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"cannot prepare protected exploit audit path: {audit_path}") from exc
    return audit_path
