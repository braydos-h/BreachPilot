"""Canonical filesystem paths shared by benchmark entry points."""

from __future__ import annotations

from pathlib import Path

DEFAULT_BASELINE_PATH = "reports/benchmarks/baseline.json"

__all__ = ["DEFAULT_BASELINE_PATH", "resolve_baseline_path"]


def resolve_baseline_path(configured_path: Path | str | None, storage_root: Path | str) -> Path:
    """Resolve a configured baseline path using the benchmark storage root.

    The historical default value names the baseline relative to the default
    output directory. Treating it as a generic relative path would duplicate
    that directory when a custom output root is used, so the default maps to
    ``<storage_root>/baseline.json``. Other relative paths are rooted under
    ``storage_root``; absolute paths are preserved.
    """
    root = Path(storage_root).absolute()
    configured = str(configured_path or "")
    if not configured or Path(configured) == Path(DEFAULT_BASELINE_PATH):
        return root / "baseline.json"

    path = Path(configured)
    return path if path.is_absolute() else (root / path).absolute()
