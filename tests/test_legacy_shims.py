"""p2-05: legacy shim warnings + canonical namespace + import-lint guard.

Canonical decision (recorded in legacy/README.md): the Flow B namespace is
``legacy.*``. The ``breachpilot.legacy.*`` package rename is explicitly
dropped as unnecessary churn (no ``breachpilot`` package exists; installs
expose top-level ``legacy``). Root ``*.py`` Flow B files are thin
``DeprecationWarning`` re-exports, removal in 0.71.

This file enforces the decision three ways:

1. Every root shim warns on import and points at its canonical target.
2. Canonical ``legacy.*`` imports work warning-free.
3. Import-lint: Flow A code must not import ``legacy`` (except the three
   frozen-surface bridge adapters, allowlisted below), and NOBODY outside
   the shims may import Flow B through a root-shim deep path
   (``from observer import ...``); the canonical path is ``legacy.*``.
   Shared-kernel roots (``db``, ``scope_gate``, ``outcome_judge``,
   ``target_graph``, ``summarizer``) are real files, not shims, and stay
   importable at root.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

SHIM_MARKER = "Legacy shim --"

# Flow B bridge adapters: the ONLY Flow A files allowed to import legacy.*.
# They are the frozen-surface consumers (defects C4/C5/C6, the interactive
# mission menu, and the run-service swarm bridge) reaching Flow B through
# the canonical namespace; each may import exactly its documented
# counterpart. Anything else importing legacy.* fails the guard below.
LEGACY_IMPORT_ALLOWLIST: dict[str, set[str]] = {
    "tools/intelligence/adapters/observer_adapter.py": {"legacy.observer"},
    "tools/intelligence/adapters/memory_adapter.py": {"legacy.memory"},
    "tools/intelligence/adapters/finding_adapter.py": {"legacy.finding_verifier"},
    "tools/interactive_menu.py": {"legacy.mission"},
    "tools/run_service/tasks.py": {"legacy.agent_loop"},
}

# Representative shims exercised via subprocess (full list checked statically).
SUBPROCESS_SHIMS = ("cli", "agent_loop", "mission")

_SKIP_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    "webui",
    "oauth",
    # Generated / runtime state, never linted sources.
    "build",
    "dist",
    "breachpilot.egg-info",
    "reports",
    "research_workspace",
    "exploit_workspace",
    "swarm_workspace",
}


def _root_shims() -> dict[str, Path]:
    """Root *.py files that are thin legacy re-exports (marker-detected)."""
    shims: dict[str, Path] = {}
    for path in REPO.glob("*.py"):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if SHIM_MARKER in text.splitlines()[0] if text else False:
            shims[path.stem] = path
    return shims


def _iter_repo_py() -> list[Path]:
    out: list[Path] = []
    for path in REPO.rglob("*.py"):
        parts = set(path.relative_to(REPO).parts[:-1])
        if parts & _SKIP_DIRS:
            continue
        out.append(path)
    return out


def _import_names(line: str) -> list[str]:
    """Top-level imported module roots from an import statement line."""
    line = line.split("#", 1)[0].strip()
    names: list[str] = []
    m = re.match(r"import\s+(.+)", line)
    if m:
        for chunk in m.group(1).split(","):
            names.append(chunk.strip().split(" ")[0].split(".")[0])
        return names
    m = re.match(r"from\s+([a-zA-Z0-9_.]+)\s+import\s+", line)
    if m:
        names.append(m.group(1))
        return names
    return names


def test_all_shims_carry_marker_and_canonical_target():
    shims = _root_shims()
    assert shims, "no root legacy shims detected"
    for name, path in sorted(shims.items()):
        text = path.read_text(encoding="utf-8")
        assert "DeprecationWarning" in text, f"{path} must warn"
        assert "remove in 0.71" in text, f"{path} must state removal version"
        assert f"legacy.{name}" in text, f"{path} must point at canonical legacy.{name}"


def test_shims_warn_with_canonical_target():
    for shim in SUBPROCESS_SHIMS:
        proc = subprocess.run(
            [sys.executable, "-W", "always", "-c", f"import {shim}"],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert proc.returncode == 0, f"import {shim} failed: {proc.stderr}"
        assert "legacy" in proc.stderr.lower() or "deprecat" in proc.stderr.lower(), (
            f"import {shim} must emit a DeprecationWarning naming legacy: {proc.stderr!r}"
        )


def test_canonical_namespace_imports_warning_free():
    proc = subprocess.run(
        [sys.executable, "-W", "error::DeprecationWarning", "-c", "import legacy.agent_loop, legacy.cli"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, f"canonical legacy.* import must be warning-free: {proc.stderr}"


def test_no_banned_legacy_imports():
    """Flow A must not depend on Flow B (except allowlisted bridges)."""
    shims = _root_shims()
    violations: list[str] = []
    for path in _iter_repo_py():
        rel = path.relative_to(REPO).as_posix()
        parts = path.relative_to(REPO).parts
        if parts[0] in ("legacy", "tests"):
            continue
        if len(parts) == 1 and parts[0] in {f"{s}.py" for s in shims}:
            continue  # the shims themselves
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, 1):
            for name in _import_names(line):
                if name == "legacy" or name.startswith("legacy."):
                    allowed = LEGACY_IMPORT_ALLOWLIST.get(rel, set())
                    if name not in allowed and "legacy" not in allowed:
                        violations.append(f"{rel}:{lineno}: {line.strip()}")
    assert not violations, "banned `import legacy` outside shims/allowlist:\n" + "\n".join(violations)


def test_no_root_shim_deep_imports():
    """Nobody imports Flow B through a root-shim path; use legacy.*."""
    shims = _root_shims()
    violations: list[str] = []
    for path in _iter_repo_py():
        rel = path.relative_to(REPO).as_posix()
        parts = path.relative_to(REPO).parts
        if parts[0] in ("legacy", "tests"):
            continue
        if len(parts) == 1 and parts[0] in {f"{s}.py" for s in shims}:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, 1):
            for name in _import_names(line):
                root = name.split(".")[0]
                if root in shims:
                    violations.append(f"{rel}:{lineno}: {line.strip()} (use legacy.{root})")
    assert not violations, "root-shim deep imports (use canonical legacy.*):\n" + "\n".join(violations)
