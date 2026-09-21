#!/usr/bin/env python3
"""Single-command release version bump (p1-05-release-truth).

Moves the advertised version everywhere at once, then verifies with the
docs-truth ``versions`` check:

- ``pyproject.toml`` (``[project] version``)
- ``tools/cli_args.py`` (``__version__``, re-exported by ``main.py``)
- ``webui/package.json`` (``version``)
- installer pins (``releases/download/vX.Y.Z`` / ``install-vX.Y.Z``) in
  ``README.md``, ``docs/deployment.md``, ``install.sh`` and
  ``scripts/verify-installer.sh``

Usage (from repo root)::

    python scripts/bump-version.py X.Y.Z   # bump everything, then verify
    python scripts/bump-version.py --check # verify only (CI gate; exit 1 on drift)

Versioned asset names (``install-<tag>.sh``, frozen per tag by the release
workflow) cannot be addressed by a ``latest`` redirect, so the quick-start
pins the exact version and this script keeps every pin exact. Stdlib only.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
INSTALLER_PIN_RE = re.compile(r"(?:releases/download/v|install-v)(\d+\.\d+\.\d+)")

PYPROJECT_RE = re.compile(r'(?m)^version\s*=\s*"[^"]*"')
MAIN_RE = re.compile(r'__version__\s*=\s*"[^"]*"')
PACKAGE_JSON_RE = re.compile(r'"version"\s*:\s*"[^"]*"')
# p2-03 split: the __version__ literal lives in tools/cli_args.py; main.py
# only re-exports it. Bumps target the canonical home.
VERSION_LITERAL_FILE = REPO / "tools" / "cli_args.py"

PIN_FILES = [
    REPO / "README.md",
    REPO / "docs" / "deployment.md",
    REPO / "install.sh",
    REPO / "scripts" / "verify-installer.sh",
]


def current_version() -> str:
    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"]).strip()


def _load_truth_audit():
    path = REPO / "scripts" / "docs_truth_audit.py"
    spec = importlib.util.spec_from_file_location("docs_truth_audit", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _replace(path: Path, pattern: re.Pattern[str], new: str, desc: str) -> bool:
    text = path.read_text(encoding="utf-8")
    updated, count = pattern.subn(new, text)
    if count == 0:
        print(f"  ! {path.relative_to(REPO)}: no {desc} found")
        return False
    path.write_text(updated, encoding="utf-8")
    print(f"  * {path.relative_to(REPO)}: {desc} x{count}")
    return True


def bump(new: str) -> int:
    if not SEMVER_RE.match(new):
        print(f"ERROR: version must be X.Y.Z (got {new!r})", file=sys.stderr)
        return 2
    old = current_version()
    print(f"bump {old} -> {new}")
    _replace(REPO / "pyproject.toml", PYPROJECT_RE, f'version = "{new}"', "pyproject version")
    _replace(
        VERSION_LITERAL_FILE, MAIN_RE, f'__version__ = "{new}"', "tools/cli_args __version__ (re-exported by main)"
    )
    _replace(REPO / "webui" / "package.json", PACKAGE_JSON_RE, f'"version": "{new}"', "package.json version")
    for path in PIN_FILES:
        text = path.read_text(encoding="utf-8")
        updated, count = INSTALLER_PIN_RE.subn(lambda m: m.group(0)[: -len(m.group(1))] + new, text)
        if count:
            path.write_text(updated, encoding="utf-8")
            print(f"  * {path.relative_to(REPO)}: installer pin x{count}")
    return verify()


def verify() -> int:
    """Verify-only mode (and post-bump gate): exit 0 when green, 1 on drift."""
    problems: list[str] = []
    expected = current_version()
    try:
        cli_text = VERSION_LITERAL_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        problems.append(f"cannot read tools/cli_args.py: {exc}")
        cli_text = ""
    match = re.search(r'__version__\s*=\s*"([^"]+)"', cli_text)
    if not match:
        problems.append("tools/cli_args.py has no __version__")
    elif match.group(1).strip() != expected:
        problems.append(f"version mismatch: tools/cli_args.py __version__={match.group(1)!r} != pyproject {expected!r}")
    mod = _load_truth_audit()
    problems.extend(mod.check_versions())
    for path in PIN_FILES:
        if path.suffix != ".sh":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            problems.append(f"cannot read {path.relative_to(REPO)}: {exc}")
            continue
        for pin in INSTALLER_PIN_RE.finditer(text):
            if pin.group(1) != expected:
                line = text.count("\n", 0, pin.start()) + 1
                problems.append(f"{path}:{line}: stale installer pin v{pin.group(1)} (current is {expected})")
    if problems:
        print("bump-version --check FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"bump-version --check passed: all sources + installer pins at {expected}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bump the release version everywhere at once.")
    parser.add_argument("version", nargs="?", help="new version X.Y.Z (omit with --check)")
    parser.add_argument("--check", action="store_true", help="verify only; exit 1 on drift")
    args = parser.parse_args(argv)
    if args.check:
        return verify()
    if not args.version:
        parser.error("need a version X.Y.Z (or --check)")
    return bump(args.version)


if __name__ == "__main__":
    raise SystemExit(main())
