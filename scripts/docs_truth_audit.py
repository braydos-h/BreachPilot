#!/usr/bin/env python3
"""Mechanical docs-truth guard (packet 07: Make documentation mechanically truthful).

Two checks, stdlib only:

``links`` — every internal Markdown link/anchor across the product docs must
resolve. Scans ``README.md``, ``CLAUDE.md``, ``AGENTS.md``,
``CONTRIBUTING.md``, ``SECURITY.md`` plus ``docs/**/*.md`` (fenced code
blocks and inline code spans are ignored so examples never count as links).
``todo/`` (backlog working docs), ``reports/`` (dated snapshots), ``webui/``
(own tsc/vitest), ``oauth/`` (vendored) and runtime workspace dirs are out
of scope. Fails on: missing target file, or an ``#anchor`` with no matching
GitHub-slug heading (duplicate headings get ``-1``/``-2`` suffixes, explicit
``<a name/id>`` anchors count).

``versions`` — the advertised package version must be single-sourced truth:
``pyproject.toml`` == ``main.py::__version__`` == ``webui/package.json``,
and the scanned docs must contain no stale installer pins (``releases/download/vX.Y.Z``
or ``install-vX.Y.Z`` where ``X.Y.Z`` != the current ``pyproject.toml`` version)
or old branding (``netcheck``, any case). Installer pins live in fenced code
blocks, so this check scans raw text (unlike ``links``). Use
``scripts/bump-version.py`` to move every pin at once.

Exit 0 with a summary when green, 1 listing every offender otherwise. Wired
into the CI ``lint`` job so docs truth is part of the aggregate signal.
"""

from __future__ import annotations

import argparse
import json
import re
import tomllib
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

SCAN_TOP = ["README.md", "CLAUDE.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md"]
SCAN_DIR = REPO / "docs"

EXTERNAL_RE = re.compile(r"^(?:https?://|mailto:|ftp://|data:|tel:)", re.IGNORECASE)
INLINE_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+(?:\s+\"[^\"]*\")?)\)")
REF_LINK_RE = re.compile(r"!?\[[^\]]+\]\[([^\]]*)\]")
REF_DEF_RE = re.compile(r"^\s{0,3}\[([^\]]+)\]:\s*(\S+)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
HTML_ANCHOR_RE = re.compile(r'<a\s+[^>]*(?:name|id)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
HEADING_ID_RE = re.compile(r'<h[1-6][^>]*\sid\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")
CODE_SPAN_RE = re.compile(r"`[^`]*`")

# Installer pins are versioned asset names (release.yml freezes
# ``install-<tag>.sh`` per tag), so a ``latest`` redirect cannot address them:
# the README/deployment quick-start pins the exact version instead, and
# scripts/bump-version.py moves every pin on release. Any installer-context
# pin that disagrees with the current pyproject.toml version is stale.
INSTALLER_PIN_RE = re.compile(r"(?:releases/download/v|install-v)(\d+\.\d+\.\d+)")


def scan_files() -> list[Path]:
    files = [REPO / name for name in SCAN_TOP if (REPO / name).is_file()]
    if SCAN_DIR.is_dir():
        files.extend(sorted(SCAN_DIR.rglob("*.md")))
    return files


def github_slug(text: str) -> str:
    # GitHub heading slugs: keep the rendered text of code spans/links (a
    # heading that IS a code span like "### `GET /health`" slugs to
    # "get-health"), drop formatting/HTML, lowercase, keep alnum/space/-/_,
    # spaces become hyphens. Underscores are preserved (diagnostic headings
    # like "MCP_HTTP_TOKEN mismatch" slug with underscores intact).
    text = CODE_SPAN_RE.sub(lambda match: match.group(0).strip("`"), text)
    text = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("**", "").replace("__", "")
    text = text.strip().strip("#").strip()
    slug = text.lower()
    slug = re.sub(r"[^a-z0-9 _-]", "", slug)
    return slug.replace(" ", "-")


def file_anchors(path: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return set()
    in_fence = False
    counts: dict[str, int] = {}
    anchors: set[str] = set()
    for line in text.splitlines():
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for found in HTML_ANCHOR_RE.findall(line):
            anchors.add(found)
            anchors.add(found.lower())
        for found in HEADING_ID_RE.findall(line):
            anchors.add(found)
            anchors.add(found.lower())
        match = HEADING_RE.match(line)
        if not match:
            continue
        slug = github_slug(match.group(2))
        if not slug:
            continue
        seen = counts.get(slug, 0)
        anchors.add(slug if seen == 0 else f"{slug}-{seen}")
        counts[slug] = seen + 1
    return anchors


def iter_links(path: Path) -> list[tuple[int, str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    ref_defs: dict[str, str] = {}
    for line in lines:
        def_match = REF_DEF_RE.match(line)
        if def_match:
            ref_defs[def_match.group(1).strip().lower()] = def_match.group(2).strip().strip("<>")
    out: list[tuple[int, str]] = []
    in_fence = False
    for lineno, line in enumerate(lines, start=1):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        clean = CODE_SPAN_RE.sub("", line)
        for match in INLINE_LINK_RE.finditer(clean):
            target = match.group(1).strip().split()[0].strip("<>")
            out.append((lineno, target))
        for match in REF_LINK_RE.finditer(clean):
            key = (match.group(1) or "").strip().lower()
            if key in ref_defs:
                out.append((lineno, ref_defs[key]))
    return out


def check_links() -> list[str]:
    problems: list[str] = []
    anchor_cache: dict[Path, set[str]] = {}
    repo_root = REPO.resolve()
    for path in scan_files():
        try:
            path.resolve().relative_to(repo_root)
            constrain_to_repo = True
        except ValueError:
            constrain_to_repo = False  # tmp fixtures in tests; production scans are in-repo
        for lineno, target in iter_links(path):
            if EXTERNAL_RE.match(target):
                continue
            decoded = urllib.parse.unquote(target)
            if "#" in decoded:
                file_part, anchor = decoded.split("#", 1)
            else:
                file_part, anchor = decoded, ""
            if not file_part:
                resolved: Path | None = path
            elif file_part.startswith("/"):
                resolved = (REPO / file_part.lstrip("/")).resolve()
            else:
                resolved = (path.parent / file_part).resolve()
                if constrain_to_repo:
                    try:
                        resolved.relative_to(repo_root)
                    except ValueError:
                        problems.append(f"{path}:{lineno}: escapes repo: {target}")
                        continue
            if resolved is None or not resolved.exists():
                problems.append(f"{path}:{lineno}: missing file: {target}")
                continue
            if anchor:
                if resolved.is_dir():
                    problems.append(f"{path}:{lineno}: anchor on directory: {target}")
                    continue
                if resolved not in anchor_cache:
                    anchor_cache[resolved] = file_anchors(resolved)
                want = anchor.strip().lower()
                if want not in anchor_cache[resolved]:
                    problems.append(f"{path}:{lineno}: missing anchor #{anchor} in {target}")
    return problems


def read_version(path: Path) -> str:
    if path.name == "pyproject.toml":
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return str(data["project"]["version"]).strip()
    if path.name == "main.py":
        text = path.read_text(encoding="utf-8")
        match = re.search(r"__version__\s*=\s*[\"']([^\"']+)[\"']", text)
        if match:
            return match.group(1).strip()
        # p2-03 split: the literal lives in tools/cli_args.py and main.py
        # re-exports it (`from tools.cli_args import __version__`). Follow
        # the indirection instead of failing on the shim.
        if re.search(r"from tools\.cli_args import[^\n]*__version__", text):
            cli_args = REPO / "tools" / "cli_args.py"
            cmatch = re.search(
                r"__version__\s*=\s*[\"']([^\"']+)[\"']",
                cli_args.read_text(encoding="utf-8"),
            )
            if cmatch:
                return cmatch.group(1).strip()
        raise ValueError("main.py has no __version__ (and no tools.cli_args re-export)")
    data = json.loads(path.read_text(encoding="utf-8"))
    return str(data["version"]).strip()


def check_versions() -> list[str]:
    problems: list[str] = []
    sources = {
        "pyproject.toml": REPO / "pyproject.toml",
        "main.py::__version__": REPO / "main.py",
        "webui/package.json": REPO / "webui" / "package.json",
    }
    values: dict[str, str] = {}
    for label, path in sources.items():
        try:
            values[label] = read_version(path)
        except (OSError, ValueError, KeyError) as exc:
            problems.append(f"cannot read version from {label}: {exc}")
    if len(set(values.values())) > 1:
        problems.append("version mismatch: " + ", ".join(f"{label}={value!r}" for label, value in values.items()))
    current = values.get("pyproject.toml")
    for path in scan_files():
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if current is not None:
            for match in INSTALLER_PIN_RE.finditer(text):
                if match.group(1) != current:
                    line = text.count("\n", 0, match.start()) + 1
                    problems.append(f"{path}:{line}: stale installer pin v{match.group(1)} (current is {current})")
        for match in re.finditer(r"netcheck", text, re.IGNORECASE):
            line = text.count("\n", 0, match.start()) + 1
            problems.append(f"{path}:{line}: stale branding {match.group(0)!r}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mechanical docs-truth guard (links + versions).")
    parser.add_argument("--check", choices=("links", "versions", "all"), default="all")
    args = parser.parse_args(argv)
    problems: list[str] = []
    if args.check in ("links", "all"):
        problems.extend(check_links())
    if args.check in ("versions", "all"):
        problems.extend(check_versions())
    if problems:
        print("docs-truth audit FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    files = len(scan_files())
    print(f"docs-truth audit passed ({args.check}): {files} files checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
