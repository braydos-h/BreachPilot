"""CLI for the Authorized Bug Bounty Research Agent.

Commands:
  init-mission     Create a new mission from a YAML config
  add-scope        Add an allow or deny scope rule
  list-scope       Show all scope rules for the active mission
  next-task        Show the next pending task
  list-tasks       List all open tasks
  run-task         Execute a specific task (by ID or next pending)
  summarize-target Show target memory summary
  list-findings    List all findings
  validate-finding Run validation on a finding
  generate-report  Generate a markdown report for a finding
  status           Show agent loop status

Usage:
  python cli.py init-mission --config mission.yaml
  python cli.py add-scope --allow "*.example.com"
  python cli.py add-scope --deny "payments.example.com"
  python cli.py next-task
  python cli.py run-task T-00001
  python cli.py summarize-target
  python cli.py list-findings
  python cli.py validate-finding F-00001
  python cli.py generate-report F-00001
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

WS_ENV = "RESEARCH_WORKSPACE"


def _workspace_root() -> Path:
    return Path(os.environ.get(WS_ENV, "research_workspace"))


def _load_db():
    from db import DatabaseManager
    return DatabaseManager(_workspace_root() / "research.db")


def _load_mission(db: Any, mission_id: str | None = None) -> dict[str, Any] | None:
    """Load a mission row from the DB.

    If ``mission_id`` is given, load THAT mission by id regardless of status —
    this is the resume path (Tier 1.3): a reattached campaign may be ``active``
    or ``paused``, and the operator named it explicitly, so status filtering
    would be wrong. Without an id, fall back to the latest ``active`` mission
    (the historical behavior every other command relied on).
    """
    with db.connection() as conn:
        if mission_id:
            cur = conn.execute("SELECT * FROM missions WHERE id=?", (mission_id,))
        else:
            cur = conn.execute(
                "SELECT * FROM missions WHERE status='active' "
                "ORDER BY created_at DESC LIMIT 1"
            )
        row = cur.fetchone()
        if not row:
            return None
        return dict(row)


def _require_mission(args: argparse.Namespace) -> tuple[Any, dict[str, Any] | None]:
    """Load the DB + mission (by ``--mission-id`` if given, else latest active).

    Prints a context-accurate error and returns ``(db, None)`` when no mission
    resolves, so callers can ``db, mission = _require_mission(args); if not
    mission: return 1``. Centralizes the 10 identical load-and-check blocks.
    """
    db = _load_db()
    mid = getattr(args, "mission_id", None)
    mission = _load_mission(db, mid)
    if not mission:
        if mid:
            print(f"ERROR: No mission with id {mid!r} in {_workspace_root() / 'research.db'}.")
        else:
            print("ERROR: No active mission found. Run `init-mission` first.")
    return db, mission


def _get_mission_ctrl(db: Any) -> Any:
    from mission import MissionController
    return MissionController(db, _workspace_root())


# ── Commands ────────────────────────────────────────────────────────────────


def cmd_init_mission(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"ERROR: Config file not found: {config_path}")
        return 1

    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    ws = _workspace_root()
    ws.mkdir(parents=True, exist_ok=True)

    db = _load_db()
    ctrl = _get_mission_ctrl(db)

    try:
        mission = ctrl.create_from_config(config)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 1

    print(f"\n{'='*60}")
    print(f"  MISSION CREATED")
    print(f"{'='*60}")
    print(f"  ID:              {mission.mission_id}")
    print(f"  Program:         {mission.program_name}")
    print(f"  Risk Profile:    {mission.risk_profile}")
    print(f"  Scope (allow):   {len(mission.allowed_assets)} rules")
    print(f"  Scope (deny):    {len(mission.disallowed_assets)} rules")
    print(f"  Forbidden:       {len(mission.forbidden_actions)} actions")
    print(f"  Testing Modes:   {', '.join(mission.testing_modes)}")
    print(f"  Workspace:       {ws}")
    print(f"{'='*60}\n")

    print(f"Mission stored. Database at: {ws / 'research.db'}")
    return 0


def cmd_add_scope(args: argparse.Namespace) -> int:
    if not args.allow and not args.deny:
        print("ERROR: Must specify --allow or --deny")
        return 1

    db, mission = _require_mission(args)
    if not mission:
        return 1

    mid = mission["id"]

    if args.allow:
        pattern = args.allow
        rule_type = "allow"
    else:
        pattern = args.deny
        rule_type = "deny"

    from mission import _classify_asset
    target_type = _classify_asset(pattern)

    with db.connection(write=True) as conn:
        sid = db.add_scope_rule(conn, mid, rule_type, target_type, pattern, notes=args.notes or "")

    print(f"Scope rule added: [{rule_type}] {pattern} ({target_type}) → ID: {sid}")
    return 0


def cmd_list_scope(args: argparse.Namespace) -> int:
    db, mission = _require_mission(args)
    if not mission:
        return 1

    mid = mission["id"]
    from scope_gate import ScopeGate
    from mission import Mission
    m = Mission.from_dict(mission)
    gate = ScopeGate(
        db, mid,
        allowed_assets=m.allowed_assets,
        disallowed_assets=m.disallowed_assets,
        forbidden_actions=m.forbidden_actions,
        risk_profile=m.risk_profile,
    )
    gate.load_from_db()

    scope = gate.list_scope()
    print(f"\n=== Scope for: {mission.get('program_name', mid)} ===")

    print("\n[ALLOW]:")
    for a in scope["allow"]:
        print(f"  + {a}")
    if not scope["allow"]:
        print("  (none)")

    print("\n[DENY]:")
    for d in scope["deny"]:
        print(f"  - {d}")
    if not scope["deny"]:
        print("  (none)")

    print("\n[FORBIDDEN ACTIONS]:")
    for f in scope["forbidden_actions"]:
        print(f"  X {f}")

    return 0


def cmd_next_task(args: argparse.Namespace) -> int:
    db, mission = _require_mission(args)
    if not mission:
        return 1

    mid = mission["id"]
    from task_queue import TaskQueue
    queue = TaskQueue(db, mid)
    task = queue.get_next_task()

    if not task:
        print("No pending tasks. Planning needed.")
        return 0

    print(f"\n=== NEXT TASK ===")
    print(f"  ID:        {task['task_id']}")
    print(f"  Phase:     {task['phase']}")
    print(f"  Target:    {task['target']}")
    print(f"  Objective: {task['objective']}")
    print(f"  Hypothesis:{task['hypothesis']}")
    print(f"  Tools:     {', '.join(task['allowed_tools'])}")
    print(f"  Risk:      {task['risk_level']}")
    print(f"  Priority:  {task['priority']}")
    return 0


def cmd_list_tasks(args: argparse.Namespace) -> int:
    db, mission = _require_mission(args)
    if not mission:
        return 1

    mid = mission["id"]
    from task_queue import TaskQueue
    queue = TaskQueue(db, mid)

    open_tasks = queue.list_open_tasks()
    blocked_tasks = queue.list_blocked_tasks()
    counts = queue.count_by_status()

    print(f"\n=== TASKS for Mission: {mid} ===")
    print(f"  Counts: {counts}")
    print()

    if open_tasks:
        print("--- Pending / Running ---")
        for t in open_tasks[:10]:
            print(f"  [{t['priority']:3}] {t['task_id']} [{t['phase']}] {t['objective'][:80]}")
        if len(open_tasks) > 10:
            print(f"  ... and {len(open_tasks) - 10} more")
    else:
        print("  No open tasks.")

    if blocked_tasks:
        print("\n--- Blocked ---")
        for t in blocked_tasks[:5]:
            print(f"  {t['task_id']}: {t.get('block_reason','?')[:100]}")
    return 0


def cmd_run_task(args: argparse.Namespace) -> int:
    db, mission_data = _require_mission(args)
    if not mission_data:
        return 1

    mid = mission_data["id"]
    from mission import Mission
    mission = Mission.from_dict(mission_data)

    from task_queue import TaskQueue
    queue = TaskQueue(db, mid)

    task_id = args.task_id
    if task_id:
        task = queue.get_task(task_id)
        if not task:
            print(f"ERROR: Task {task_id} not found.")
            return 1
    else:
        task = queue.get_next_task()
        if not task:
            print("No pending tasks. Cannot run.")
            return 1

    print(f"\n=== RUNNING TASK: {task['task_id']} ===")
    print(f"  Objective: {task['objective']}")
    print(f"  Target:    {task['target']}")

    # Scope check via ScopeGate
    from scope_gate import ScopeGate
    gate = ScopeGate(
        db, mid,
        allowed_assets=mission.allowed_assets,
        disallowed_assets=mission.disallowed_assets,
        forbidden_actions=mission.forbidden_actions,
        risk_profile=mission.risk_profile,
    )
    gate.load_from_db()

    scope = gate.check_scope(task["target"], task["phase"],
                              task["allowed_tools"][0] if task["allowed_tools"] else "",
                              task["risk_level"])
    if not scope.allowed:
        print(f"\n  BLOCKED: {scope.reason}")
        queue.block_task(task["task_id"], scope.reason)
        return 1

    print(f"  Scope:    PASSED ({scope.matched_scope_rule})")

    from risk_controller import RiskController
    risk_ctrl = RiskController(
        risk_profile=mission.risk_profile,
        max_commands=mission.max_commands_per_session,
        max_tasks=mission.max_tasks_active,
        allow_exploitation=mission.allows_exploitation,
        allow_pivoting=mission.allows_pivoting,
    )
    risk = risk_ctrl.assess_action(task["phase"],
                                    task["allowed_tools"][0] if task["allowed_tools"] else "unknown",
                                    json.dumps(task)[:300],
                                    task["target"],
                                    task["risk_level"])
    if not risk.allowed:
        print(f"\n  BLOCKED: {risk.reason}")
        queue.block_task(task["task_id"], risk.reason)
        return 1
    print(f"  Risk:     PASSED")

    # H16: honor requires_human_approval from either the scope check or the
    # risk assessment. ``ScopeCheckResult`` may return allowed=True with
    # requires_human_approval=True (high-risk actions under a non-
    # high_authorized_testing profile) and ``RiskAssessment`` carries the same
    # flag -- both are *not* green lights to execute. Mirror agent_loop.py:544-552:
    # mark the task needs_approval and bail before constructing the executor.
    if getattr(scope, "requires_human_approval", False) or getattr(risk, "requires_human_approval", False):
        queue.update_task_status(task["task_id"], "needs_approval")
        print(f"\n  [NEEDS APPROVAL] Task {task['task_id']} requires human confirmation.")
        return 1

    from evidence import EvidenceStore
    evidence = EvidenceStore(db, mid, _workspace_root())

    from tool_router import ToolRouter
    tool_router = ToolRouter(
        scope_gate=gate,
        risk_controller=risk_ctrl,
        evidence_store=evidence,
        tool_executor=lambda name, args: f"[tool] {name} called with {json.dumps(args, default=str)[:200]}",
        db=db,
        mission_id=mid,
    )

    from executor import ExecutorAgent
    executor = ExecutorAgent(tool_router)
    result = executor.execute(task)

    if result.success:
        queue.complete_task(task["task_id"], result.output_summary, result.evidence_refs)
        print(f"\n  ✓ Task completed successfully.")
        print(f"  Summary: {result.output_summary[:300]}")
        print(f"  Evidence: {result.evidence_refs}")
    else:
        queue.update_task_status(task["task_id"], "failed", result.error)
        print(f"\n  ✗ Task failed: {result.error}")

    from observer import ObserverAgent
    obs = ObserverAgent()
    observation = obs.observe(task, result.output_summary, result.tool_name, evidence_refs=result.evidence_refs)
    from summarizer import summarize_observation
    print(f"\n  Observation: {summarize_observation(observation.to_dict())}")

    return 0


def cmd_summarize_target(args: argparse.Namespace) -> int:
    db, mission = _require_mission(args)
    if not mission:
        return 1

    mid = mission["id"]

    from memory import MemoryManager
    mem = MemoryManager(db, mid)

    name = args.target or mission.get("program_name", "")
    summary = mem.summarize_target(name)
    print(summary)

    from target_graph import TargetGraph
    graph = TargetGraph(db, mid)
    print()
    print(graph.summarize_graph())

    return 0


def cmd_list_findings(args: argparse.Namespace) -> int:
    db, mission = _require_mission(args)
    if not mission:
        return 1

    mid = mission["id"]
    from finding_verifier import FindingVerifier
    verifier = FindingVerifier(db, mid)

    all_findings = verifier.list_all()

    if not all_findings:
        print("No findings created yet.")
        return 0

    print(f"\n=== FINDINGS ({len(all_findings)} total) ===\n")
    for f in all_findings:
        status_icon = {"candidate": "○", "needs_validation": "?", "validated": "✓",
                        "report_ready": "★", "rejected": "✗", "duplicate_suspected": "≃"}.get(f["status"], "?")
        print(f"  {status_icon} [{f['finding_id']}] [{f['status']}] {f['title'][:80]}")

    return 0


def cmd_validate_finding(args: argparse.Namespace) -> int:
    db, mission = _require_mission(args)
    if not mission:
        return 1

    mid = mission["id"]

    from finding_verifier import FindingVerifier
    from scope_gate import ScopeGate
    from evidence import EvidenceStore
    from mission import Mission

    verifier = FindingVerifier(db, mid)
    m = Mission.from_dict(mission)
    gate = ScopeGate(db, mid, allowed_assets=m.allowed_assets,
                      disallowed_assets=m.disallowed_assets,
                      risk_profile=m.risk_profile)
    gate.load_from_db()
    ev = EvidenceStore(db, mid, _workspace_root())

    result = verifier.validate_finding(args.finding_id, scope_gate=gate, evidence_store=ev)
    print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_generate_report(args: argparse.Namespace) -> int:
    db, mission = _require_mission(args)
    if not mission:
        return 1

    mid = mission["id"]
    from report_generator import ReportGenerator

    reporter = ReportGenerator(db, mid, _workspace_root())

    try:
        report = reporter.generate_report(args.finding_id)
        print(report)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 1

    return 0


def cmd_status(args: argparse.Namespace) -> int:
    db, mission = _require_mission(args)
    if not mission:
        # _require_mission already printed the error; status is a no-op here.
        return 0

    mid = mission["id"]

    from task_queue import TaskQueue
    from finding_verifier import FindingVerifier

    queue = TaskQueue(db, mid)
    verifier = FindingVerifier(db, mid)
    counts = queue.count_by_status()
    findings = verifier.list_all()

    print(f"\n=== Agent Status ===")
    print(f"  Mission:    {mission.get('program_name','')} ({mid})")
    print(f"  Risk:       {mission.get('risk_profile','')}")
    print(f"  Status:     {mission.get('status','')}")
    print(f"  Created:    {mission.get('created_at','')}")
    print()
    print(f"  Tasks:")
    for st, cnt in sorted(counts.items()):
        print(f"    {st:12}: {cnt}")
    print(f"\n  Findings:   {len(findings)} total")
    ready = [f for f in findings if f["status"] == "report_ready"]
    print(f"  Report-Ready: {len(ready)}")

    return 0


# ── Argument parser ────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # Common --mission-id flag shared by every command that operates on an
    # existing mission (Tier 1.3 resume). init-mission mints a NEW mission so
    # it deliberately does NOT get this flag. Using parents= lets the operator
    # place --mission-id AFTER the subcommand (e.g. `next-task --mission-id
    # M-001`), which is the natural reading order.
    mid_parser = argparse.ArgumentParser(add_help=False)
    mid_parser.add_argument(
        "--mission-id", default=None,
        help="Operate on this specific mission id (resume/reattach) instead of "
             "the latest active one. The mission may be 'active' or 'paused'.",
    )

    # init-mission
    p_init = sub.add_parser("init-mission", help="Create a new mission")
    p_init.add_argument("--config", required=True, help="Path to mission YAML config")
    p_init.set_defaults(func=cmd_init_mission)

    # add-scope
    p_scope = sub.add_parser("add-scope", help="Add scope rule", parents=[mid_parser])
    p_scope.add_argument("--allow", help="Add an allowed asset (domain, IP, CIDR, *.wildcard)")
    p_scope.add_argument("--deny", help="Add an excluded asset")
    p_scope.add_argument("--notes", default="", help="Notes for this rule")
    p_scope.set_defaults(func=cmd_add_scope)

    # list-scope
    p_ls = sub.add_parser("list-scope", help="Show scope rules", parents=[mid_parser])
    p_ls.set_defaults(func=cmd_list_scope)

    # next-task
    p_next = sub.add_parser("next-task", help="Show next pending task", parents=[mid_parser])
    p_next.set_defaults(func=cmd_next_task)

    # list-tasks
    p_lt = sub.add_parser("list-tasks", help="List tasks", parents=[mid_parser])
    p_lt.set_defaults(func=cmd_list_tasks)

    # run-task
    p_run = sub.add_parser("run-task", help="Execute a task", parents=[mid_parser])
    p_run.add_argument("task_id", nargs="?", default="", help="Task ID or empty for next pending")
    p_run.set_defaults(func=cmd_run_task)

    # summarize-target
    p_sum = sub.add_parser("summarize-target", help="Show target memory + graph", parents=[mid_parser])
    p_sum.add_argument("--target", default="", help="Target to summarize")
    p_sum.set_defaults(func=cmd_summarize_target)

    # list-findings
    p_lf = sub.add_parser("list-findings", help="List all findings", parents=[mid_parser])
    p_lf.set_defaults(func=cmd_list_findings)

    # validate-finding
    p_vf = sub.add_parser("validate-finding", help="Run validation on a finding", parents=[mid_parser])
    p_vf.add_argument("finding_id", help="Finding ID (e.g., F-00001)")
    p_vf.set_defaults(func=cmd_validate_finding)

    # generate-report
    p_gr = sub.add_parser("generate-report", help="Generate a report for a finding", parents=[mid_parser])
    p_gr.add_argument("finding_id", help="Finding ID")
    p_gr.set_defaults(func=cmd_generate_report)

    # status
    p_st = sub.add_parser("status", help="Show agent status summary", parents=[mid_parser])
    p_st.set_defaults(func=cmd_status)

    return parser


# ── Main ───────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv or sys.argv[1:])

    if not hasattr(args, "func") or not args.func:
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nAborted.")
        return 130
    except Exception as exc:
        import traceback
        print(f"\nUNEXPECTED ERROR: {exc}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
