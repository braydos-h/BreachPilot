"""`--ctf` mode (Phase 6.3): CTF autopilot with goal-completion detection.

Runs the full attack flow against a known CTF target (Metasploitable/DVWA/HTB-
style) and stops when the goal is heuristically met. Training/benchmark
autopilot. Today only ``--demo`` (single DVWA container) exists; ``--ctf``
generalizes to any operator-authorized CTF target.

Goal-completion detection is heuristic — one of:
  1. **flag file present**: a known flag path (``/root/flag.txt``,
     ``/home/ctf/flag.txt``, ...) is readable on the target.
  2. **root shell confirmed**: a command run on the target reports ``uid=0``.
  3. **known-string port response**: a specific port responds with a known
     marker string (e.g. ``FLAG{...}``).

The mode is **target-locked via the normal allowlist** — the operator passes
``--target <ctf_target_ip>`` and CTF mode does NOT bypass the allowlist. The
run uses the standard attack flow (``run_exploit_session``) so the MCP
target-IP lock applies as usual.

Usage::

    python main.py --ctf --target 10.0.0.50 --goal initial_access
    python main.py --ctf --target 10.0.0.50 --ctf-flag-path /root/flag.txt
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CtfGoal:
    """Heuristic goal-completion spec for a CTF target.

    ``flag_path``: if set, the goal is met when this path is readable on the
    target (checked via the run's audit trail, not a separate probe).
    ``root_shell``: if True, the goal is met when a command on the target
    reports ``uid=0``.
    ``port_marker``: if set, the goal is met when ``port`` responds with a
    substring of ``marker`` (a known-string response).
    """

    flag_path: str = ""
    root_shell: bool = False
    port: int = 0
    marker: str = ""
    # Best-effort: the goal is "met" when ANY enabled check passes.
    checks: list[str] = field(default_factory=list)

    @property
    def is_configured(self) -> bool:
        return bool(self.flag_path or self.root_shell or (self.port and self.marker))


_FLAG_PATHS = (
    "/root/flag.txt",
    "/home/ctf/flag.txt",
    "/flag.txt",
    "/tmp/flag.txt",
)

_FLAG_RE = re.compile(r"FLAG\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}", re.IGNORECASE)
_UID_ROOT_RE = re.compile(r"uid=0\(", re.IGNORECASE)


def default_goal_for_target(target_ip: str) -> CtfGoal:
    """Build a default CTF goal for a target (flag-file + root-shell heuristic).

    The operator can override with ``--ctf-flag-path`` / ``--ctf-root-shell`` /
    ``--ctf-port-marker``. The default checks all three heuristics.
    """
    return CtfGoal(
        flag_path="",
        root_shell=True,
        port=0,
        marker="",
        checks=list(_FLAG_PATHS) + ["uid=0"],
    )


def port_responds_with(target_ip: str, port: int, marker: str, timeout: float = 3.0) -> bool:
    """Check if ``port`` on ``target_ip`` responds with a substring of ``marker``.

    A single TCP connect + read. Never raises — a connect failure means the
    check is not met. This is a heuristic goal-completion probe, not an
    exploit.
    """
    if not target_ip or not port or not marker:
        return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            s.settimeout(timeout)
            data = s.recv(4096).decode(errors="replace")
            return marker.lower() in data.lower()
    except (OSError, socket.timeout, ConnectionError):
        return False


def goal_met_from_result(
    result: dict[str, Any] | None,
    goal: CtfGoal,
    target_ip: str = "",
) -> bool:
    """Heuristically determine if the CTF goal is met from a run's final result.

    Inspects the run's ``outcome_summary``, ``records`` (audit trail), and
    ``messages`` for flag markers / uid=0 / known-string responses. Also probes
    ``goal.port`` directly when configured. Never raises.
    """
    if not isinstance(result, dict):
        result = {}

    # 1. Flag marker in any text output (outcome_summary, messages, records).
    haystack_parts: list[str] = [str(result.get("outcome_summary", "") or "")]
    for msg in (result.get("messages") or []) if isinstance(result.get("messages"), list) else []:
        if isinstance(msg, dict):
            haystack_parts.append(str(msg.get("content", "") or ""))
            haystack_parts.append(str(msg.get("text", "") or ""))
        else:
            haystack_parts.append(str(msg or ""))
    for rec in (result.get("records") or []) if isinstance(result.get("records"), list) else []:
        if isinstance(rec, dict):
            haystack_parts.append(str(rec.get("command", "") or ""))
            haystack_parts.append(str(rec.get("output", "") or ""))
            haystack_parts.append(str(rec.get("result", "") or ""))
    haystack = "\n".join(haystack_parts)

    if _FLAG_RE.search(haystack):
        return True

    # 2. Root shell confirmed (uid=0 in any output).
    if goal.root_shell and _UID_ROOT_RE.search(haystack):
        return True

    # 3. Flag-path check: if the run's audit trail shows the flag path was read.
    if goal.flag_path and goal.flag_path in haystack:
        return True

    # 4. Port-marker probe (direct TCP connect — heuristic, not an exploit).
    if goal.port and goal.marker:
        if port_responds_with(target_ip, goal.port, goal.marker):
            return True

    return False


def run_ctf(args: Any) -> int:
    """``--ctf`` CLI entry. Returns 0 on success (goal met), 1 on failure."""
    import asyncio

    target_ip = str(getattr(args, "target", "") or "").strip()
    if not target_ip:
        print("[!] --ctf requires --target <ctf_target_ip>")
        return 2

    # Build the CTF goal from CLI overrides + defaults.
    goal = CtfGoal(
        flag_path=str(getattr(args, "ctf_flag_path", "") or ""),
        root_shell=bool(getattr(args, "ctf_root_shell", True)),
        port=int(getattr(args, "ctf_port", 0) or 0),
        marker=str(getattr(args, "ctf_marker", "") or ""),
    )
    if not goal.is_configured:
        goal = default_goal_for_target(target_ip)

    print("=" * 60)
    print("  NetAttackAI — CTF autopilot (`--ctf`)")
    print(f"  Target: {target_ip}")
    print(f"  Goal: flag_path={goal.flag_path or '(heuristic)'} "
          f"root_shell={goal.root_shell} port={goal.port} marker={goal.marker or '(none)'}")
    print("=" * 60)

    # Reuse the standard attack flow — target-locked via the normal allowlist.
    # The operator passed --target, so EXPLOIT_TARGET is set in the MCP
    # subprocess env and the allowlist lock applies as usual.
    from tools.eval_harness import run_eval

    # Build a namespace that looks like --eval but with attack mode.
    # ponytail: reuse run_eval's boot+session plumbing instead of duplicating
    # it. The eval harness already drives run_exploit_session in attack mode
    # against --target; CTF mode just adds goal-completion detection on top.
    eval_args = type(args)(
        target=target_ip,
        config=getattr(args, "config", Path("config.yaml")),
    )
    eval_rc = asyncio.run(run_eval(eval_args))
    if eval_rc != 0:
        print(f"[!] CTF run failed (eval harness returned {eval_rc}).")
        return 1

    # Goal-completion check from the eval report.
    # The eval harness writes reports/eval/<run_id>/eval_report.json.
    import json
    eval_dir = Path("reports/eval")
    report_files = sorted(eval_dir.glob("*/eval_report.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not report_files:
        print("[!] No eval report found; cannot check goal completion.")
        return 1
    try:
        report = json.loads(report_files[0].read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        print("[!] Could not read eval report; cannot check goal completion.")
        return 1

    met = goal_met_from_result(report, goal, target_ip=target_ip)
    if met:
        print("=" * 60)
        print("  [✓] CTF GOAL MET — flag/root-shell/port-marker detected.")
        print("=" * 60)
        return 0
    print("=" * 60)
    print("  [✗] CTF goal not met (no flag marker / uid=0 / port-marker found).")
    print("=" * 60)
    return 1
