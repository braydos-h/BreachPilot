"""Regenerate docs/reference/cli-generated.md from tools/cli_args.py:parse_args.

Stdlib only. Parses tools/cli_args.py with ast (never imports it) so flag facts —
flag, aliases, type/choices, default, help — always match the source.
Hand-curated columns (conflicts, runtime path, examples, config keys, exit)
are preserved per flag from the existing doc; new flags get rows from
NEW_ROWS below plus their live add_argument line number.

p2-03 split: parse_args moved verbatim from main.py to tools/cli_args.py;
main.py only re-exports it. The canonical scan target is tools/cli_args.py
(main.py has zero add_argument calls); a main.py fallback remains so --check
keeps working on pre-split checkouts.

Usage (from repo root):
    python scripts/generate_cli_reference.py [--check]
"""

from __future__ import annotations

import ast
import datetime
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# Canonical home of parse_args (p2-03 split moved it verbatim out of main.py).
CLI_ARGS = REPO / "tools" / "cli_args.py"
MAIN = REPO / "main.py"
SRC_LABEL = "tools/cli_args.py"
DOC = REPO / "docs" / "reference" / "cli-generated.md"

DAEMON_CONFLICT_NOTE = "daemon/web"


class Flag:
    def __init__(self, node: ast.Call):
        self.lineno = node.lineno
        opts = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        self.options: list[str] = [o for o in opts if o.startswith("-")]
        self.kw: dict[str, ast.expr] = {k.arg: k.value for k in node.keywords if k.arg}
        self.help = self._str("help")
        self.action = self._str("action")
        self.dest = self._str("dest")
        self.nargs = self._const("nargs")
        self.metavar = self._str("metavar")
        self.choices = self._str_list("choices")
        self.type_name = self._type_name()
        self.default = self._default()

    def _str(self, name: str) -> str | None:
        node = self.kw.get(name)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _const(self, name: str):
        node = self.kw.get(name)
        if isinstance(node, ast.Constant):
            return node.value
        return None

    def _str_list(self, name: str) -> list[str]:
        node = self.kw.get(name)
        if isinstance(node, (ast.Tuple, ast.List)):
            return [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        return []

    def _type_name(self) -> str | None:
        node = self.kw.get("type")
        if isinstance(node, ast.Name):
            return node.id
        return None

    def _default(self) -> str:
        node = self.kw.get("default")
        if node is None:
            return "n/a"
        try:
            return repr(ast.literal_eval(node))
        except Exception:
            pass
        try:
            return ast.unparse(node).strip()
        except Exception:
            return "?"

    @property
    def primary(self) -> str:
        longs = [o for o in self.options if o.startswith("--")]
        return longs[0] if longs else (self.options[0] if self.options else "?")

    def type_cell(self) -> str:
        if self.action == "version":
            return "`store version`"
        if self.action in ("store_true", "store_false"):
            base = f"`{self.action}`"
            if self.action == "store_false" and self.dest:
                return base + " (same dest)"
            if self.dest:
                note = f" (`dest {self.dest}`"
                if self.default == "None":
                    note += ", `default None`"
                return base + note + ")"
            return base
        if self.action == "append":
            meta = f" (`metavar {self.metavar}`" if self.metavar else " ("
            return f"`append`{meta}, `default None`)"
        parts = []
        if self.nargs == "*":
            meta = f" (`metavar {self.metavar}`)" if self.metavar else ""
            parts.append(f'`nargs="*"`{meta}')
        if self.choices:
            parts.append("`choices: " + " \\| ".join(self.choices) + "`")
        elif self.type_name:
            parts.append(f"`{self.type_name}`")
        elif not parts:
            parts.append("`str`")
        cell = " ".join(parts)
        if self.default == "None" and "`None`" not in cell:
            cell += " \\| `None`"
        if self.dest and self.action != "store_false":
            cell += f" (`dest {self.dest}`)"
        return cell

    def default_cell(self) -> str:
        if self.primary == "--api-key-file":
            return '`Path("secr.json")` (`DEFAULT_API_KEY_FILE`)'
        d = self.default
        if d in ("n/a", "?"):
            return d
        # Match doc style: double quotes for "" and Path("...").
        if d == "''":
            return '`""`'
        if d.startswith("Path('") and d.endswith("')"):
            d = 'Path("' + d[len("Path('") : -len("')")] + '")'
        return f"`{d}`"


def _scan_source() -> tuple[Path, str]:
    """Return (path, label) of the file defining parse_args (canonical first)."""
    for path, label in ((CLI_ARGS, SRC_LABEL), (MAIN, "main.py")):
        if not path.is_file():
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        if any(isinstance(n, ast.FunctionDef) and n.name == "parse_args" for n in ast.walk(tree)):
            return path, label
    raise SystemExit("no parse_args found in tools/cli_args.py or main.py — refusing to generate")


def collect_flags() -> tuple[list[Flag], int, int]:
    src, _ = _scan_source()
    tree = ast.parse(src.read_text(encoding="utf-8"))
    func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "parse_args")
    flags: list[Flag] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument":
            f = Flag(node)
            if f.options:
                flags.append(f)
    flags.sort(key=lambda f: f.lineno)
    return flags, func.lineno, func.end_lineno or func.lineno


def split_row(line: str) -> list[str]:
    # The doc escapes in-cell pipes as `\|` — split on unescaped pipes only.
    return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]


def esc(text: str) -> str:
    return text.replace("|", "\\|")


def parse_existing_rows(text: str) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.startswith("| `--"):
            continue
        cells = split_row(line)
        if len(cells) < 9:
            continue
        m = re.search(r"`(--[a-z0-9-]+)`", cells[0])
        if m:
            rows[m.group(1)] = cells
    return rows


def refresh_lineno(cell: str, lineno: int) -> str:
    # Pre-split rows cite `main.py:NNN`; rewrite any scan-source prefix to the
    # canonical label so every runtime path points at the file that defines it.
    return re.sub(r"^`?(?:main\.py|tools/cli_args\.py):\d+`?", f"`{SRC_LABEL}:{lineno}`", cell, count=1)


# Hand-curated columns for flags added since the last doc refresh
# (verified against main(): daemon guard, dispatch, exits).
NEW_ROWS: dict[str, dict[str, str]] = {
    "--eval-list": {
        "aliases": "—",
        "conflicts": DAEMON_CONFLICT_NOTE,
        "examples": "`python main.py --eval-list`",
        "config": "`eval_targets/*.oracle.json`",
        "exit": "0 + stdout",
    },
    "--save-baseline": {
        "aliases": "—",
        "conflicts": "requires `--eval`/`--benchmark` → 2",
        "examples": "`python main.py --eval --save-baseline`",
        "config": "`eval.baseline_path`",
        "exit": "0 + writes baseline",
    },
    "--check-regression": {
        "aliases": "—",
        "conflicts": "requires `--eval`/`--benchmark` → 2",
        "examples": "`python main.py --eval --check-regression`",
        "config": "`eval.baseline_path`, `eval.regression_tolerance`",
        "exit": "1 on hard regression",
    },
    "--benchmark": {
        "aliases": "—",
        "conflicts": DAEMON_CONFLICT_NOTE,
        "examples": "`python main.py --benchmark xben`",
        "config": "`benchmark.*`",
        "exit": "via `run_benchmark_cli`",
    },
    "--benchmark-list": {
        "aliases": "—",
        "conflicts": DAEMON_CONFLICT_NOTE,
        "examples": "`python main.py --benchmark-list`",
        "config": "`benchmark.*` suites",
        "exit": "0 + stdout",
    },
    "--scenario": {
        "aliases": "—",
        "conflicts": "— (read only on `--benchmark` path)",
        "examples": "`python main.py --benchmark xben --scenario S1 --scenario S2`",
        "config": "—",
        "exit": "—",
    },
    "--tag": {
        "aliases": "—",
        "conflicts": "— (read only on `--benchmark` path)",
        "examples": "`python main.py --benchmark xben --tag web`",
        "config": "—",
        "exit": "—",
    },
    "--trials": {
        "aliases": "—",
        "conflicts": "— (read only on `--benchmark` path)",
        "examples": "`python main.py --benchmark xben --trials 3`",
        "config": "`benchmark.trials` (1-20)",
        "exit": "—",
    },
}

# Full-row rewrites for flags whose preserved cells went stale.
EVAL_ROW = {
    "aliases": "—",
    "type": '`nargs="*"` (`metavar TARGET`)',
    "default": "`None` (bare `--eval` = `[]` → all graded targets)",
    "conflicts": DAEMON_CONFLICT_NOTE,
    "runtime": "eval group → `run_graded_eval` (no `--target`) or legacy `run_eval` (with `--target`)",
    "examples": "`python main.py --eval`<br>`python main.py --eval dvwa juice_shop`<br>`python main.py --eval --target 10.0.0.50` (legacy single-target)",
    "config": "`eval.*` (output_dir, max_rounds, baseline_path)",
    "exit": "graded 0 (1 on `--check-regression` fail); legacy writes `reports/eval/<run_id>/`",
}

DEFAULT_OVERRIDES = {
    # async_main defaults an empty --mode to recon, not attack.
    "--mode": '`""` → `recon` in `RunRequest`',
}


def build_row(f: Flag, old: list[str] | None) -> str:
    name = f"`{f.primary}`"
    if f.primary == "--eval":
        r = EVAL_ROW
        runtime = f"`{SRC_LABEL}:{f.lineno}` " + r["runtime"]
        return (
            f"| {name} | {r['aliases']} | {r['type']} | {r['default']} | {r['conflicts']} "
            f"| {runtime} | {r['examples']} | {r['config']} | {r['exit']} |"
        )
    type_cell = f.type_cell()
    default_cell = DEFAULT_OVERRIDES.get(f.primary, f.default_cell())
    if old is not None:
        flag_cell, aliases, old_type, old_default, conflicts, runtime, examples, config, ex = old[0:9]
        # Preserve the exact flag/alias cells (e.g. combined `--demon`/`--daemon`).
        name = flag_cell
        aliases = aliases
        # Keep hand-curated annotations (e.g. `None` → `models.default_alias`,
        # repeatable `append`, `dest` notes); AST refreshes only if the old
        # cell no longer contains the AST-extracted bare value.
        bare_type = esc(re.sub(r"\s*\(.*\)$", "", type_cell).strip("`").replace("\\|", "|"))
        if bare_type and bare_type not in old_type.replace("\\|", "|"):
            old_type = type_cell

        def norm(s: str) -> str:
            return s.strip().strip("`").replace('"', "").replace("'", "").strip()

        bare_default = default_cell.strip("`")
        if bare_default not in ("n/a", "?") and norm(bare_default) not in norm(old_default):
            if re.fullmatch(r"`[^`]+`", old_default.strip()):
                old_default = default_cell  # stale bare literal — AST wins
            else:
                old_default = default_cell + (f" ({old_default})" if old_default != "—" else "")
        runtime = refresh_lineno(runtime, f.lineno)
        # Stale prose in preserved cells corrected against current source.
        if f.primary == "--ctf-root-shell":
            runtime = runtime.replace("`default True`", "`default False`")
        if f.primary == "--mode":
            old_default = DEFAULT_OVERRIDES["--mode"]
        return (
            f"| {name} | {aliases} | {old_type} | {old_default} | {conflicts} "
            f"| {runtime} | {examples} | {config} | {ex} |"
        )
    n = NEW_ROWS.get(f.primary, {})
    aliases = n.get("aliases", "—")
    if len(f.options) > 1:
        aliases = esc(", ".join(f"`{o}`" for o in f.options if o != f.primary))
    return (
        f"| {name} | {aliases} | {type_cell} | {default_cell} | {n.get('conflicts', '—')} "
        f"| `{SRC_LABEL}:{f.lineno}` | {n.get('examples', '—')} | {n.get('config', '—')} "
        f"| {n.get('exit', '—')} |"
    )


HEADER = """\
---
title: CLI Reference (Generated)
description: Complete matrix for every python main.py flag — flag, aliases, type, default, conflicts, runtime path, examples, config keys, exit behavior. Verified against tools/cli_args.py:parse_args (re-exported by main).
source: [tools/cli_args.py]
generated_from: tools/cli_args.py:parse_args
verify: every flag exists in tools/cli_args.py:parse_args at time of generation ({today})
---

# CLI Reference (Generated)

> Verified against `tools/cli_args.py:parse_args` (`tools/cli_args.py:{start}-{end}`, re-exported by `main`). No invented flags. Run `python main.py --help` to cross-check. Dispatch order is in `main()`.

- **Default no-args** → **WebUI daemon** (`--web`: build `webui/dist/` if needed, serve `http://127.0.0.1:8765/`, open a browser) via `main._run_daemon`. `--menu` forces the legacy interactive terminal menu instead.
- **API-key bootstrap** → `tools/config_cli.bootstrap_startup_api_keys` with `prompt = --menu` only.
- **Daemon guard** — `--demon/--daemon/--web` refuse `target/mode/goal/custom_goal/menu/doctor/demo/self_test/eval/benchmark/skills_list/list_plugins/setup_api_keys` → exit 2.
- **Dispatch** — `setup_api_keys` solo exit → daemon/web → `--doctor` → `--self-test` → `--eval-list` → `--save-baseline/--check-regression` gate → `--benchmark` → `--eval` (graded without `--target`, legacy with `--target`) → `--ctf` → `--demo` → `--skills-list` → `--list-plugins` → `--menu` → no-args web → `async_main`.

Exit codes: `0` success/clean abort, `1` run/config/auth failure (or `--check-regression` fail), `2` flag conflict / non-loopback bind / `--save-baseline/--check-regression` without `--eval/--benchmark`, `130` `KeyboardInterrupt`.

## Flag matrix

| Flag | Aliases | Type | Default | Conflicts | Runtime path | Examples | Config keys | Exit |
|------|---------|------|---------|-----------|--------------|----------|-------------|------|
"""


def _normalized(text: str) -> str:
    """Date-stamps are metadata: normalize them so --check tracks content drift."""
    return re.sub(r"\d{4}-\d{2}-\d{2}", "DATE", text)


def render() -> tuple[str, list[Flag], int, int, dict[str, list[str]]]:
    """Build the regenerated file text without writing (shared by write + --check)."""
    flags, start, end = collect_flags()
    old_text = DOC.read_text(encoding="utf-8")
    old_rows = parse_existing_rows(old_text)
    today = datetime.date.today().isoformat()

    out = [HEADER.format(today=today, start=start, end=end)]
    for f in flags:
        out.append(build_row(f, old_rows.get(f.primary)))
    out.append("")

    # Preserve everything from the legacy Flow B section onward, with the
    # stale epilog line reference refreshed.
    tail_idx = old_text.find("### Flow B legacy")
    if tail_idx == -1:
        raise SystemExit("existing doc missing '### Flow B legacy' section — refusing to overwrite")
    tail = old_text[tail_idx:].rstrip() + "\n"
    tail = tail.replace("from `main.py:342` epilog", f"from `{SRC_LABEL}:{start + 8}` epilog")
    out.append(tail)
    return "\n".join(out), flags, start, end, old_rows


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Regenerate docs/reference/cli-generated.md from parse_args.")
    parser.add_argument("--check", action="store_true", help="fail (exit 1) when the doc drifts; do not write")
    args = parser.parse_args(argv)
    new_text, flags, start, end, old_rows = render()
    if args.check:
        if _normalized(DOC.read_text(encoding="utf-8")) != _normalized(new_text):
            print("cli-reference drift: run python scripts/generate_cli_reference.py", file=sys.stderr)
            return 1
        print(f"cli-reference fresh: flags={len(flags)} parse_args {start}-{end}")
        return 0
    DOC.write_text(new_text, encoding="utf-8")

    missing = [p for p in old_rows if p not in {f.primary for f in flags}]
    print(
        f"flags: {len(flags)}, preserved rows: {len(old_rows) - len(missing)}, new rows: "
        f"{len([f for f in flags if f.primary not in old_rows])}"
    )
    if missing:
        print(f"WARNING: doc flags gone from parse_args (kept out): {missing}")
    print(f"wrote {DOC} (parse_args {start}-{end})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
