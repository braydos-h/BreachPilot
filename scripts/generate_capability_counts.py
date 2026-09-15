"""Generate docs/generated/capability-counts.json from live catalogs.

Counts are derived, never hand-maintained (TODO 010):
- tools / families from docs/mcp/tool-catalog-generated.md header
  (fallback: AST parse of tools/mcp_tools)
- skills from skills/**/SKILL.md
- modules from tools.attack_modules.registry.list_modules()

Usage:
    python scripts/generate_capability_counts.py [--check]
--check exits nonzero when the committed JSON drifts from live code.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "generated" / "capability-counts.json"


def _git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=str(REPO), text=True).strip()
    except Exception:
        return "unknown"


def _tool_counts() -> tuple[int, int]:
    catalog = REPO / "docs" / "mcp" / "tool-catalog-generated.md"
    try:
        text = catalog.read_text(encoding="utf-8")
        m = re.search(r"(\d+)\s+tools\s+across\s+(\d+)\s+families", text)
        if m:
            return int(m.group(1)), int(m.group(2))
    except OSError:
        pass
    # Fallback: AST count of @mcp.tool defs.
    import ast

    total = 0
    families = 0
    for base in (REPO / "tools" / "mcp_tools", REPO / "tools" / "mcp_tools" / "modules"):
        if not base.is_dir():
            continue
        for py in sorted(base.glob("*.py")):
            if py.name == "__init__.py":
                continue
            try:
                tree = ast.parse(py.read_text(encoding="utf-8"))
            except (OSError, SyntaxError):
                continue
            tools = [
                n
                for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and any("mcp.tool" in (ast.unparse(d) if hasattr(ast, "unparse") else "") for d in n.decorator_list)
            ]
            if tools:
                families += 1
                total += len(tools)
    return total, families


def _skill_counts() -> tuple[int, int, int]:
    files = sorted((REPO / "skills").glob("**/SKILL.md"))
    total = len(files)
    maybe = sum(1 for p in files if "maybe" in p.relative_to(REPO / "skills").parts)
    return total, total - maybe, maybe


def _module_counts() -> tuple[int, int]:
    sys.path.insert(0, str(REPO))
    try:
        from tools.attack_modules.registry import list_modules

        modules = list_modules()
        n_modules = len(modules)
    except Exception:
        n_modules = 0
    finally:
        try:
            sys.path.remove(str(REPO))
        except ValueError:
            pass
    # Module families = source files under tools/attack_modules/modules/
    # (docs/attack-modules.md: 15 families). Count top-level .py files +
    # subpackage dirs with modules (e.g. modules/ics/, modules/web/).
    mod_dir = REPO / "tools" / "attack_modules" / "modules"
    families = 0
    if mod_dir.is_dir():
        families = len([p for p in mod_dir.glob("*.py") if p.name != "__init__.py"])
        for sub in mod_dir.iterdir():
            if sub.is_dir() and not sub.name.startswith("__") and list(sub.glob("*.py")):
                # Count subpackage as one family group beyond its files?
                # Keep simple: each top-level file is a family; subdirs already
                # covered by their parent concept in docs (15 families).
                pass
    return n_modules, families


def collect() -> dict:
    tools, families = _tool_counts()
    skills_total, skills_top, skills_maybe = _skill_counts()
    modules, module_families = _module_counts()
    return {
        "generated": datetime.date.today().isoformat(),
        "git_sha": _git_sha(),
        "tools": tools,
        "tool_families": families,
        "skills": skills_total,
        "skills_top_level": skills_top,
        "skills_maybe": skills_maybe,
        "modules": modules,
        "module_families": module_families,
        "sources": {
            "tools": "docs/mcp/tool-catalog-generated.md",
            "skills": "skills/**/SKILL.md",
            "modules": "tools.attack_modules.registry.list_modules()",
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail when committed JSON drifts")
    args = ap.parse_args(argv)
    live = collect()
    if args.check:
        try:
            committed = json.loads(OUT.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"capability-counts missing/unreadable: {exc}", file=sys.stderr)
            return 1
        drift = [k for k in ("tools", "tool_families", "skills", "modules") if committed.get(k) != live.get(k)]
        if drift:
            print(f"capability counts drift in {drift}: committed={committed} live={live}", file=sys.stderr)
            return 1
        print(f"capability counts fresh: {live}")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(live, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}: {live}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
