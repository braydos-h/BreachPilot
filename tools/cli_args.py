"""CLI argument parsing for the BreachPilot entry point.

Moved verbatim out of ``main.py`` (p2-03 split) — no flag behavior change.
``main.parse_args`` is this same function object (re-exported), so existing
tests, ``tools/interactive_menu.py``, and ``--help`` output keep working.
``__version__`` is canonical here and re-exported by ``main`` for the lazy
``from main import __version__`` consumers (benchmark envinfo, eval harness,
attack UI banner).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.api_key_store import DEFAULT_API_KEY_FILE

__version__ = "0.68.4"

__all__ = ["__version__", "parse_args"]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "BreachPilot — autonomous penetration testing AI. Run with no arguments "
            "to start the WebUI daemon (http://127.0.0.1:8765); use --menu for the "
            "legacy interactive terminal menu."
        ),
        epilog=(
            "examples:\n"
            "  python main.py                                          WebUI daemon + browser (default)\n"
            "  python main.py --menu                                   legacy interactive terminal menu\n"
            "  python main.py --target 10.0.0.50 --mode attack --goal backdoor\n"
            "  python main.py --target 10.0.0.50 --mode recon --goal initial_access\n"
            "  python main.py --target 10.0.0.50 --ctf --ctf-flag-path /root/flag.txt\n"
            "  python main.py --doctor                                  environment self-check\n"
            "  python main.py --self-test                                safe localhost smoke test\n"
            "  python main.py --web                                     WebUI + API daemon\n"
            "  python main.py --rebuild                                 force-rebuild webui/dist/ and exit\n"
            "  python main.py --resume <run_id>                          resume a prior run\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"BreachPilot {__version__}")

    core = parser.add_argument_group("targeting")
    core.add_argument("--target", default="", help="Target IP address or domain to attack or recon")
    core.add_argument(
        "--mode",
        choices=("recon", "attack", "fast"),
        default="",
        help="recon = gather intel, attack = full exploitation, fast = parallel recon preset then attack",
    )
    core.add_argument(
        "--goal", default="", help="Preset goal name (e.g. backdoor, initial_access, privilege_escalation)"
    )
    core.add_argument("--custom-goal", default="", help="Custom goal description")
    core.add_argument("--config", type=Path, default=Path("config.yaml"), help="Config file (default: config.yaml)")
    core.add_argument(
        "--model", default=None, help="Override default model alias (glm/kimi/deepseek/deepseek_flash/minimax)"
    )
    core.add_argument(
        "--model-strategy",
        choices=("default", "round-robin", "random", "specific"),
        default="default",
        help="How to pick model across targets",
    )
    core.add_argument(
        "--mcp-transport",
        choices=("stdio", "http"),
        default=None,
        help="MCP transport (ignored on the run path: always forced to http so the target-IP lock reaches the server)",
    )
    core.add_argument("--http-port", type=int, default=None, help="MCP HTTP port")
    core.add_argument(
        "--reports-dir", type=Path, default=Path("reports"), help="Where run artifacts are written (default: reports/)"
    )

    keys = parser.add_argument_group("api keys")
    keys.add_argument(
        "--setup-api-keys", action="store_true", help="Prompt for provider API keys and save them to secr.json"
    )
    keys.add_argument(
        "--api-key-file", type=Path, default=DEFAULT_API_KEY_FILE, help="Local JSON file for saved provider API keys"
    )
    keys.add_argument("--no-api-key-prompt", action="store_true", help="Skip the interactive startup API-key prompt")

    out = parser.add_argument_group("output")
    out.add_argument("--plain", action="store_true", help="Disable color output")
    out.add_argument("--menu", action="store_true", help="Force interactive menu mode even with other args")
    out.add_argument("--json", action="store_true", help="Emit machine-readable JSON to stdout where supported")
    out.add_argument("--quiet", action="store_true", help="Reduce output to warnings/errors only")
    out.add_argument("--debug", action="store_true", help="Enable verbose debug output")

    swarm = parser.add_argument_group("swarm & reasoning")
    swarm.add_argument(
        "--swarm",
        action="store_true",
        help="Enable multi-agent swarm mode: six specialists decompose a single target "
        "(parallel recon + vuln research, critic pre-check, reflection). Without it, "
        "attack mode runs the persistent autonomous campaign queue (resume + checkpoints). "
        "Combine both on high-value targets. See docs/swarm.md.",
    )
    swarm.add_argument(
        "--parallel-swarm",
        action="store_true",
        help="Enable parallel sub-agents (route_parallel + spawn_subagent MCP tool). "
        "Off by default; flips swarm.parallel_enabled to true. Recon-first: "
        "recon + vuln-research parallelize; exploit/post_exploit stay sequential "
        "unless swarm.exploit_parallel is also true.",
    )
    swarm.add_argument("--critic", action="store_true", help="Enable critic agent pre-approval (requires --swarm)")
    swarm.add_argument("--reflection", action="store_true", help="Enable reflection agent (requires --swarm)")
    swarm.add_argument(
        "--adaptive-exploits", action="store_true", help="Enable adaptive exploit generation with mutation"
    )
    swarm.add_argument(
        "--long-session",
        dest="long_session",
        action="store_true",
        help="Raise context window (num_ctx), LLM call timeout, round/command/duration budgets, "
        "and the swarm cap for a multi-hour attack run; checkpoints compacted messages for crash-safe resume",
    )
    swarm.add_argument(
        "--multi-model-consult",
        dest="multi_model_consult",
        action="store_true",
        default=None,
        help="Allow the agent to ask configured peer models for advisory help",
    )
    swarm.add_argument(
        "--no-multi-model-consult",
        dest="multi_model_consult",
        action="store_false",
        help="Disable peer-model consultation for this run",
    )
    swarm.add_argument(
        "--observer-mode",
        choices=("heuristic", "llm", "hybrid"),
        default="hybrid",
        help="Observer mode for fact extraction",
    )
    swarm.add_argument(
        "--recon-first",
        action="store_true",
        default=None,
        help="Force recon-first mode: scan target, suggest rated goals, then ask for goal selection",
    )
    swarm.add_argument(
        "--no-recon-first",
        action="store_false",
        dest="recon_first",
        help="Skip recon-first mode; go directly to goal selection",
    )
    swarm.add_argument(
        "--ultrathink",
        action="store_true",
        help="Enable deep reasoning mode: verbose chain-of-thought and frequent reflection",
    )

    ops = parser.add_argument_group("operational")
    ops.add_argument("--doctor", action="store_true", help="Run a self-check (Python, nmap, Ollama, config) and exit")
    ops.add_argument("--demo", action="store_true", help="Run against a local sandbox target (DVWA-style)")
    ops.add_argument("--resume", type=str, default="", help="Resume a prior run by run_id or session_id")
    ops.add_argument(
        "--export-run",
        type=str,
        default="",
        metavar="RUN_ID",
        help="Export reports/<RUN_ID>/ + run_manifest.json into a portable zip bundle and exit",
    )
    ops.add_argument("--yes", action="store_true", help="Skip the ready-to-begin confirmation gate (use with caution)")
    ops.add_argument(
        "--self-test", action="store_true", help="Run a safe localhost smoke test against 127.0.0.1 and exit"
    )
    evalgrp = parser.add_argument_group("eval & regression")
    evalgrp.add_argument(
        "--eval",
        nargs="*",
        default=None,
        metavar="TARGET",
        help="Run the graded eval suite (oracle v2) against eval_targets/ — no target ids = all "
        "targets, or pass specific ids (e.g. --eval dvwa juice_shop). With --target <ip>, runs the "
        "legacy single-target benchmark instead and writes reports/eval/<run_id>/",
    )
    evalgrp.add_argument(
        "--eval-list",
        dest="eval_list",
        action="store_true",
        help="List graded-eval oracle targets (id + flag count) and exit",
    )
    evalgrp.add_argument(
        "--save-baseline",
        dest="save_baseline",
        action="store_true",
        help="With --eval: persist the graded report as the regression baseline (eval.baseline_path)",
    )
    evalgrp.add_argument(
        "--check-regression",
        dest="check_regression",
        action="store_true",
        help="With --eval/--benchmark: exit 1 on hard regressions vs the saved baseline",
    )
    benchgrp = parser.add_argument_group("benchmark suite")
    benchgrp.add_argument(
        "--benchmark",
        nargs="*",
        default=None,
        metavar="SUITE",
        help="Run a benchmark suite (e.g. --benchmark xben). With --trials N runs repeated trials; "
        "filters via --scenario/--tag. Use --save-baseline/--check-regression for baseline workflows.",
    )
    benchgrp.add_argument(
        "--benchmark-list",
        dest="benchmark_list",
        action="store_true",
        help="List registered benchmark suites (id, scenario count, tags) and exit",
    )
    benchgrp.add_argument(
        "--scenario",
        action="append",
        default=None,
        metavar="ID",
        help="With --benchmark: restrict to specific scenario ids (repeatable)",
    )
    benchgrp.add_argument(
        "--tag",
        action="append",
        default=None,
        metavar="TAG",
        help="With --benchmark: restrict to scenarios carrying a tag (repeatable)",
    )
    benchgrp.add_argument(
        "--trials",
        type=int,
        default=None,
        metavar="N",
        help="With --benchmark: repeated trials per scenario (default benchmark.trials, 1-20)",
    )

    ctf = parser.add_argument_group("ctf autopilot")
    ctf.add_argument(
        "--ctf",
        action="store_true",
        help="CTF autopilot: run against --target and stop when the goal is heuristically met "
        "(flag marker / uid=0 / port-marker). Target-locked via the normal allowlist.",
    )
    ctf.add_argument(
        "--ctf-flag-path",
        dest="ctf_flag_path",
        default="",
        help="CTF goal: flag file path on the target (e.g. /root/flag.txt)",
    )
    ctf.add_argument(
        "--ctf-root-shell",
        dest="ctf_root_shell",
        action="store_true",
        default=False,
        help="CTF goal: treat uid=0 in any output as goal-met (default False)",
    )
    ctf.add_argument(
        "--ctf-port", dest="ctf_port", type=int, default=0, help="CTF goal: port to probe for the known-string marker"
    )
    ctf.add_argument(
        "--ctf-marker", dest="ctf_marker", default="", help="CTF goal: known-string marker expected from --ctf-port"
    )

    skills = parser.add_argument_group("runtime skills")
    skills.add_argument(
        "--skills",
        choices=("on", "off", "hints", "lookup"),
        default=None,
        help="Override runtime-skills behavior for this run: on=startup context injected, "
        "hints=hints only (default), lookup=MCP tools only, off=skills disabled",
    )
    skills.add_argument(
        "--skills-list", action="store_true", help="Print the runtime-skill catalog and exit (read-only)"
    )
    skills.add_argument(
        "--skills-include",
        action="append",
        default=None,
        metavar="NAME",
        help="Force-include a skill by name for this run (sticky across re-selection). Repeatable.",
    )
    skills.add_argument(
        "--skills-exclude",
        action="append",
        default=None,
        metavar="NAME",
        help="Exclude a skill by name for this run. Repeatable.",
    )
    skills.add_argument(
        "--no-skills-reselect", action="store_true", help="Disable mid-run skill re-selection for this run"
    )

    plugins = parser.add_argument_group("plugins")
    plugins.add_argument(
        "--list-plugins",
        dest="list_plugins",
        action="store_true",
        help="Print discovered plugins (name/version/capabilities/loaded) and exit",
    )

    webui = parser.add_argument_group("webui")
    webui.add_argument(
        "--demon",
        "--daemon",
        dest="daemon",
        action="store_true",
        help="Start the local WebUI API server instead of the terminal menu",
    )
    webui.add_argument(
        "--web",
        dest="web",
        action="store_true",
        help="Build the WebUI if needed, serve it from the daemon at /, and open a browser",
    )
    webui.add_argument(
        "--rebuild",
        "-rebuild",
        dest="rebuild",
        action="store_true",
        help="Force a clean rebuild of the WebUI (npm install + npm run build) for updates; "
        "with --web/--daemon rebuilds before serving, otherwise rebuilds and exits",
    )
    webui.add_argument("--api-host", default=None, help="API daemon bind host (loopback only; default 127.0.0.1)")
    webui.add_argument("--api-port", type=int, default=None, help="API daemon port (default 8765)")
    parsed = parser.parse_args(argv)
    return parsed
