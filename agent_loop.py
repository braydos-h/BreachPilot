"""Main Agent Loop — orchestrates the full research workflow.

Flow:
    User mission → MissionController → ScopeGate
    → Planner → TaskQueue → Executor → Observer
    → Memory + TargetGraph + EvidenceStore
    → FindingVerifier → ReportGenerator

The loop is interruptible, auditable, and scope-enforced at every step.

Enhanced with:
    - Autonomous attack orchestration
    - Deep reconnaissance pipeline
    - Automatic attack chaining
    - Adaptive aggression levels
    - Retry with modified parameters
    - Attack timeline recording
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from db import DatabaseManager
from evidence import EvidenceStore
from executor import ExecutionResult, ExecutorAgent
from finding_verifier import FindingVerifier
from memory import MemoryManager
from mission import Mission, MissionController
from observer import ObserverAgent
from outcome_judge import (
    ClosedHypothesisError,
    DuplicateInvestigationError,
    HypothesisRepository,
    HypothesisStatus,
    OutcomeAssessment,
    OutcomeJudge,
)
from planner import _SERVICE_ATTACK_MAP, PlannerAgent
from report_generator import ReportGenerator
from risk_controller import RiskController
from scope_gate import ScopeGate
from target_graph import TargetGraph
from task_queue import TaskQueue
from tool_router import ToolRouter
from tools.autonomous_orchestrator import AutonomousOrchestrator
from tools.enhanced_reporting import EnhancedReportGenerator
from tools.experience_store import ExperienceStore
from tools.recon_pipeline import ReconConfig, ReconPipeline
from tools.semantic_memory import SemanticMemoryManager
from tools.swarm import SwarmOrchestrator
from tools.swarm.base import AgentStatus
from tools.validation_utils import parse_service_banners

# ── Agent state ────────────────────────────────────────────────────────────


class AgentLoop:
    """Orchestrates the complete authorized research workflow.

    Usage::

        loop = AgentLoop(mission_config, workspace_root, tool_executor_fn)
        loop.run(max_cycles=10)
    """

    def __init__(
        self,
        mission_config: dict[str, Any],
        workspace_root: Path,
        tool_executor: Callable[[str, dict[str, Any]], str],
        *,
        human_approval_fn: Callable[[str, dict[str, Any]], bool] | None = None,
        console_ui: Any | None = None,
        state_dir: Path | None = None,
        mission_id: str | None = None,
    ) -> None:
        self._workspace_root = workspace_root
        self._workspace_root.mkdir(parents=True, exist_ok=True)
        self._console_ui = console_ui

        # ── DB ──
        db_path = workspace_root / "research.db"
        self._db = DatabaseManager(db_path)

        # ── Mission ──
        # Tier 1.3: when ``mission_id`` is passed, RESUME an existing mission
        # instead of creating a new row. The DB already holds the entire
        # resumable state (mission row, scope_rules, tasks w/ status,
        # observations, findings, evidence, graph, memory, audit) -- so resume
        # is "load the mission row by id and re-point every manager at it",
        # not "re-parse config". mission_config is still required for the
        # non-mission-row settings (memory, swarm, models, ollama host) but its
        # mission fields (allowed_assets etc.) are IGNORED on resume -- the
        # saved DB row is the source of truth, so a resumed campaign continues
        # exactly the scope it was started with.
        self._mission_ctrl = MissionController(self._db, workspace_root)
        self._resumed = mission_id is not None
        if self._resumed:
            # Ensure the schema exists before reading (a fresh/empty DB, or one
            # whose migrations haven't run, would otherwise make load_mission's
            # SELECT raise 'no such table'). create_from_config ensures it on the
            # fresh path; the resume path must too.
            with self._db.connection(write=True) as conn:
                self._db.ensure_schema(conn)
            self._mission = self._mission_ctrl.load_mission(mission_id)
            if self._mission is None:
                raise ValueError(
                    f"Cannot resume: no mission with id {mission_id!r} in "
                    f"{db_path}."
                )
            self._mission_id = self._mission.mission_id
        else:
            self._mission = self._mission_ctrl.create_from_config(mission_config)
            self._mission_id = self._mission.mission_id

        # ── Scope ──
        self._scope_gate = ScopeGate(
            self._db,
            self._mission_id,
            allowed_assets=self._mission.allowed_assets,
            disallowed_assets=self._mission.disallowed_assets,
            forbidden_actions=self._mission.forbidden_actions,
            rate_limits=self._mission.rate_limits,
            risk_profile=self._mission.risk_profile,
        )
        self._scope_gate.load_from_db()

        # ── Risk ──
        self._risk_ctrl = RiskController(
            risk_profile=self._mission.risk_profile,
            max_commands=self._mission.max_commands_per_session,
            max_tasks=self._mission.max_tasks_active,
            allow_exploitation=self._mission.allows_exploitation,
            allow_pivoting=self._mission.allows_pivoting,
        )

        # ── Evidence ──
        self._evidence = EvidenceStore(
            self._db, self._mission_id, workspace_root
        )

        # ── Tool Router ──
        self._tool_router = ToolRouter(
            scope_gate=self._scope_gate,
            risk_controller=self._risk_ctrl,
            evidence_store=self._evidence,
            tool_executor=tool_executor,
            db=self._db,
            mission_id=self._mission_id,
            human_approval_fn=human_approval_fn,
        )

        # Store for AutonomousOrchestrator (used in run_autonomous_campaign)
        self._tool_executor = tool_executor

        # ── Memory ──
        semantic_cfg = mission_config.get("memory", {})
        self._semantic_memory: SemanticMemoryManager | None = None
        if semantic_cfg.get("semantic_enabled", False):
            self._semantic_memory = SemanticMemoryManager(
                db=self._db,
                ollama_host=mission_config.get("ollama", {}).get("host", "http://localhost:11434"),
                embedding_model=semantic_cfg.get("embedding_model", "nomic-embed-text"),
            )
        self._memory = MemoryManager(self._db, self._mission_id, semantic_memory=self._semantic_memory)

        # ── Experience Store ──
        # Tier 1.1: gate Beta confidence on min-samples + time decay so thin or
        # stale data doesn't masquerade as a confident ratio. Defaults (3 / 90d)
        # match Flow A; overridable via memory.experience_min_samples /
        # memory.experience_time_decay_days (added in T5).
        self._experience = ExperienceStore(
            self._db,
            min_samples=int(semantic_cfg.get("experience_min_samples", 3)),
            time_decay_days=float(semantic_cfg.get("experience_time_decay_days", 90.0)),
        )

        # ── Graph ──
        self._graph = TargetGraph(self._db, self._mission_id)

        # ── Queue ──
        self._queue = TaskQueue(self._db, self._mission_id)
        self._hypotheses = HypothesisRepository(self._db, self._mission_id)
        judgment_cfg = mission_config.get("outcome_judgment", {})
        if judgment_cfg is None:
            judgment_cfg = {}
        if not isinstance(judgment_cfg, dict):
            raise ValueError("outcome_judgment must be a mapping")
        self._outcome_judge = OutcomeJudge(
            max_inconclusive_attempts=judgment_cfg.get(
                "max_inconclusive_attempts", 3
            ),
            confirmation_threshold=judgment_cfg.get(
                "confirmation_threshold", 0.75
            ),
            refutation_threshold=judgment_cfg.get("refutation_threshold", 0.75),
            min_evidence_references=judgment_cfg.get(
                "min_evidence_references", 1
            ),
        )
        # Tier 1.3: on resume, re-queue any tasks left 'running' by a crashed
        # prior run back to 'pending' so they're re-attempted (not silently
        # dropped, and not left as in-flight where get_next_task would never
        # pick them up). This is the safety-critical resume step.
        if self._resumed:
            reset = self._queue.reset_stale_running()
            if reset and self._console_ui is not None:
                try:
                    self._console_ui.info(
                        f"[RESUME] Re-queued {reset} stale 'running' task(s)."
                    )
                except Exception:
                    pass

        # ── Components ──
        self._planner = PlannerAgent(risk_profile=self._mission.risk_profile)
        self._executor = ExecutorAgent(self._tool_router)
        self._observer = ObserverAgent(semantic_memory=self._semantic_memory)
        self._verifier = FindingVerifier(self._db, self._mission_id)
        self._reporter = ReportGenerator(self._db, self._mission_id, workspace_root)

        # ── Swarm (always built; drives execution when enabled) ──
        self._use_swarm = mission_config.get("use_swarm", True)
        swarm_context = {
            "mission": self._mission.to_dict(),
            "memory": self._memory,
            "graph": self._graph,
            "scope_gate": self._scope_gate,
            "risk_controller": self._risk_ctrl,
            "db": self._db,
            "mission_id": self._mission_id,
            "tool_router": self._tool_router,
            "config": mission_config,
            "model_client": None,  # populated by caller via set_model_client()
            "model_alias": mission_config.get("models", {}).get("default_alias", "glm"),
            # Tier 1.1: cross-mission learning handles surfaced to swarm agents.
            # reflection_agent persists its strategy shift as a lesson + outcome
            # via these. Both may be None (semantic memory off); agents guard on
            # that so a down Ollama degrades to a no-op, never raises.
            "semantic_memory": self._semantic_memory,
            "experience": self._experience,
        }
        self._state_dir = state_dir or (self._workspace_root / "state")
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._swarm_state_path = self._state_dir / "swarm_state.json"
        self._swarm_events_path = self._state_dir / "swarm_events.jsonl"
        self._swarm = SwarmOrchestrator(
            swarm_context,
            # Tier 1.8: read the config.yaml key (swarm.max_parallel_agents).
            # Pre-1.8 this read a non-existent top-level ``swarm_max_parallel``
            # key, so the configured value was NEVER honored (always fell back
            # to 3). Keep the legacy top-level key as a back-compat fallback.
            max_parallel=mission_config.get("swarm", {}).get(
                "max_parallel_agents", mission_config.get("swarm_max_parallel", 3)
            ),
            critic_enabled=mission_config.get("critic_enabled", True),
            reflection_enabled=mission_config.get("reflection_enabled", True),
            event_callback=self._emit_event,
            state_path=self._swarm_state_path,
        )

        # Tier 1.3: on resume, restore the swarm's shared blackboard from the
        # prior run's swarm_state.json so the specialist agents (and the
        # blackboard-aware CriticAgent) see previously-discovered services /
        # vulnerability hypotheses / credentials / failed modules — instead of
        # starting from an empty blackboard and repeating already-tried work.
        # Best-effort: a missing/corrupt file is a no-op (fresh blackboard).
        if self._resumed:
            try:
                loaded_bb = self._swarm.load_state(self._swarm_state_path)
                if loaded_bb:
                    self._emit_event("resume", {
                        "component": "swarm_blackboard",
                        "state_path": str(self._swarm_state_path),
                    })
            except Exception:
                # Never let a bad state file wedge the resumed loop.
                pass

        self._cycles: int = 0
        # Default cap on autonomous-campaign cycles. Callers can pass
        # `max_cycles` to `run()` or `run_autonomous_campaign()` to override.
        self._max_cycles: int = int(mission_config.get("attack_max_rounds") or 200)
        self._running: bool = True
        self._battle_log: list[dict[str, Any]] = []
        self._reflection_interval: int = mission_config.get("reflection_every_n_actions", 10)
        # Tier 1.1: stashed by set_model_client() for _distill_episode_summary().
        self._model_client: Any = None
        self._model_name: str = ""

        # Phase 0.1: ensure all the new flags are first-class attributes so
        # downstream code (and the --swarm/--critic/--reflection wiring in
        # main.py) can introspect them on the loop instance.
        self.use_swarm: bool = bool(mission_config.get("use_swarm", self._use_swarm))
        self.critic_enabled: bool = bool(mission_config.get("critic_enabled", True))
        self.reflection_enabled: bool = bool(mission_config.get("reflection_enabled", True))
        self.adaptive_exploits_enabled: bool = bool(
            mission_config.get("adaptive_exploits_enabled", False)
        )

        # ── Web dashboard event callback ──
        self._event_callback: Callable[[str, dict[str, Any]], None] | None = None

        # Phase tracking for minimum enforcement
        self._phase_counts: dict[str, int] = {
            "recon": 0,
            "service_enumeration": 0,
            "vulnerability_research": 0,
            "validation": 0,
            "reporting": 0,
        }
        self._services_detected: int = 0
        self._versions_identified: int = 0

    # ── Properties ─────────────────────────────────────────────────────

    @property
    def mission(self) -> Mission:
        return self._mission

    @property
    def mission_id(self) -> str:
        return self._mission_id

    @property
    def cycles(self) -> int:
        return self._cycles

    def set_model_client(self, client: Any, alias: str = "glm") -> None:
        """Inject an LLM model client for swarm agents that need reasoning.

        Tier 1.1: also stashed on ``self`` so ``_distill_episode_summary`` can ask
        the model to condense the campaign's episodic memories into a semantic
        lesson without re-reading the swarm context.
        """
        self._swarm._context["model_client"] = client
        self._swarm._context["model_alias"] = alias
        self._model_client = client
        self._model_name = alias

    def _emit_event(self, event_type: str, data: dict[str, Any] | None = None) -> None:
        """Emit an event to the web dashboard callback if configured."""
        payload = data or {}
        if self._event_callback:
            try:
                self._event_callback(event_type, payload)
            except Exception:
                pass
        self._console_event_handler(event_type, payload)
        self._persist_event(event_type, payload)

    def _console_event_handler(self, event_type: str, data: dict[str, Any]) -> None:
        """Render swarm events through the console UI."""
        if self._console_ui is None:
            return
        ui = self._console_ui
        try:
            if event_type == "agent_started":
                ui.status(
                    f"Swarm {data.get('agent_type', 'agent')} started "
                    f"({data.get('agent_id', '')}) on {data.get('task_id', '')}"
                )
            elif event_type in ("agent_complete", "agent_failed", "agent_blocked"):
                status = event_type.replace("agent_", "")
                if status == "complete":
                    ui.ok(
                        f"Swarm {data.get('agent_type', 'agent')} {status} "
                        f"({data.get('execution_time', 0):.1f}s) on {data.get('task_id', '')}"
                    )
                elif status == "failed":
                    ui.error(
                        f"Swarm {data.get('agent_type', 'agent')} {status} on {data.get('task_id', '')}: "
                        f"{data.get('summary', '')[:120]}"
                    )
                else:
                    ui.blocked(
                        f"Swarm {data.get('agent_type', 'agent')} {status} on {data.get('task_id', '')}: "
                        f"{data.get('reason', '')[:120]}"
                    )
            elif event_type == "critic_decision":
                decision = data.get("decision", "approve")
                if decision == "deny":
                    ui.blocked(
                        f"Critic DENIED {data.get('task_id', '')}: {data.get('reasoning', '')[:120]}"
                    )
                elif decision == "modify":
                    ui.info(
                        f"Critic modified {data.get('task_id', '')}: {data.get('reasoning', '')[:120]}"
                    )
                else:
                    ui.info(f"Critic approved {data.get('task_id', '')}")
            elif event_type == "reflection_output":
                shift = data.get("recommended_strategy_shift", "")
                if shift:
                    ui.thinking(f"Reflection: {shift}")
            elif event_type == "blackboard_updated":
                key = data.get("key", "")
                if key == "access_achieved":
                    ui.success("Swarm blackboard: access achieved")
                elif key in ("credentials_found", "loot"):
                    ui.info(f"Swarm blackboard update: {key}")
            elif event_type == "outcome_judgment":
                status = data.get("hypothesis_status", "inconclusive")
                message = (
                    f"Hypothesis {status.upper()} "
                    f"({float(data.get('confidence', 0.0)):.2f}): "
                    f"{data.get('reasoning', '')[:160]}"
                )
                if status == HypothesisStatus.CONFIRMED.value:
                    ui.ok(message)
                elif status in {
                    HypothesisStatus.REFUTED.value,
                    HypothesisStatus.EXHAUSTED.value,
                }:
                    ui.blocked(message)
                else:
                    ui.info(message)
        except Exception:
            pass

    def _persist_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Append swarm events to a JSONL trail for TUI replay."""
        try:
            record = {"ts": time.time(), "event_type": event_type, "data": data}
            with self._swarm_events_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, default=str) + "\n")
        except Exception:
            pass

    # ── Main loop ──────────────────────────────────────────────────────

    def run(self, max_cycles: int = 50) -> dict[str, Any]:
        """Run the research loop for up to max_cycles iterations.

        Returns a summary dict with counts and results.
        """
        stats = {
            "tasks_created": 0,
            "tasks_completed": 0,
            "tasks_blocked": 0,
            "tasks_failed": 0,
            "observations": 0,
            "findings_created": 0,
            "findings_validated": 0,
            "findings_rejected": 0,
            "findings_report_ready": 0,
            "evidence_saved": 0,
            "cycles": 0,
        }

        print(f"\n{'='*60}")
        print("  RESEARCH AGENT LOOP STARTING")
        print(f"  Mission: {self._mission.program_name}")
        print(f"  Risk Profile: {self._mission.risk_profile}")
        print(f"  Scope: {len(self._mission.allowed_assets)} allow, {len(self._mission.disallowed_assets)} deny rules")
        print(f"  Workspace: {self._workspace_root}")
        print(f"{'='*60}\n")

        while self._running and self._cycles < max_cycles:
            self._cycles += 1
            self._emit_event("cycle_start", {"cycle": self._cycles})

            # Budget check
            if not self._risk_ctrl.can_proceed():
                print(f"\n[Budget exhausted at cycle {self._cycles}]")
                self._emit_event("ai_thinking", {"agent": "RiskController", "text": "Budget exhausted."})
                break

            # ── 1. Get next task or plan new ones ──
            task = self._queue.get_next_task()

            if task is None:
                print(f"\n[Cycle {self._cycles}] No pending tasks. Planning new ones...")

                target_summary = self._memory.summarize_target(
                    self._mission.program_name or ""
                )
                graph_summary = self._graph.summarize_graph()
                hypothesis_states = self._hypotheses.list_all()
                hypotheses = [
                    state.to_dict()
                    for state in hypothesis_states
                    if not state.is_terminal
                ]

                # Tier 1.1: cross-mission recall — append lessons + prior-mission
                # memory relevant to the current planning context so the planner
                # leans on past engagements. No-op (empty string) when semantic
                # memory is off or Ollama is down; never raises.
                hyp_text = " ".join(
                    (
                        h.get("statement", h.get("hypothesis", ""))
                        if isinstance(h, dict)
                        else str(h)
                    )
                    for h in (hypotheses or [])
                )
                recall_ctx = " ".join(
                    s for s in (target_summary, graph_summary, hyp_text) if s
                )
                recall = self._cross_mission_recall(recall_ctx)
                if recall:
                    target_summary = f"{target_summary}\n{recall}"

                self._emit_event("ai_thinking", {
                    "agent": "Planner",
                    "text": f"Planning new tasks. Target summary: {target_summary[:200]}",
                })

                plan_tasks = self._planner.plan(
                    mission=self._mission.to_dict(),
                    target_summary=target_summary,
                    graph_summary=graph_summary,
                    open_hypotheses=hypotheses,
                    hypothesis_states=[state.to_dict() for state in hypothesis_states],
                    existing_task_count=self._queue.count_total(),
                )

                created_this_plan = 0
                for pt in plan_tasks:
                    try:
                        tid = self._queue.create_task(pt)
                    except (DuplicateInvestigationError, ClosedHypothesisError) as exc:
                        self._emit_event(
                            "task_rejected",
                            {
                                "hypothesis": pt.get("hypothesis", ""),
                                "objective": pt.get("objective", ""),
                                "reason": str(exc),
                            },
                        )
                        continue
                    stats["tasks_created"] += 1
                    created_this_plan += 1
                    self._emit_event("task_created", {
                        "task_id": tid,
                        "phase": pt.get("phase", "recon"),
                        "target": pt.get("target", ""),
                        "objective": pt.get("objective", ""),
                        "risk_level": pt.get("risk_level", "low"),
                        "priority": pt.get("priority", 0),
                    })

                # Dedup
                removed = self._queue.deduplicate()
                if removed:
                    print(f"  Deduplicated {removed} duplicate task(s).")

                if created_this_plan == 0:
                    met, reason = self._phase_minima_met()
                    if met:
                        print("  No new tasks to create. Research phase complete.")
                        self._emit_event("ai_thinking", {"agent": "Planner", "text": "Research phase complete."})
                        break
                    print(
                        f"  No materially different task is justified; "
                        f"phase minima remain unmet: {reason}."
                    )
                    self._emit_event(
                        "ai_thinking",
                        {
                            "agent": "Planner",
                            "text": (
                                "Stopped planning because every proposed check "
                                f"was duplicate or terminal. {reason}"
                            ),
                        },
                    )
                    break

                # Tasks were created — loop back to pick one up
                continue

            # ── 2. Scope check the task ──
            if task is None:
                continue

            scope_result = self._scope_gate.check_scope(
                asset=task.get("target", ""),
                action_type=task.get("phase", "recon"),
                tool_name=task.get("allowed_tools", [""])[0] if task.get("allowed_tools") else "",
                risk_level=task.get("risk_level", "low"),
                enforce_rate_limit=True,
            )

            self._emit_event("scope_check", {
                "task_id": task.get("task_id", ""),
                "target": task.get("target", ""),
                "allowed": scope_result.allowed,
                "reason": scope_result.reason,
                "matched_rule": scope_result.matched_scope_rule,
            })

            if not scope_result.allowed:
                self._queue.block_task(task["task_id"], scope_result.reason)
                stats["tasks_blocked"] += 1
                print(f"  [BLOCKED] Task {task['task_id']}: {scope_result.reason}")
                self._emit_event("task_blocked", {
                    "task_id": task["task_id"],
                    "reason": scope_result.reason,
                    "target": task.get("target", ""),
                })
                continue

            if scope_result.requires_human_approval:
                self._queue.update_task_status(task["task_id"], "needs_approval")
                print(f"  [NEEDS APPROVAL] Task {task['task_id']} requires human confirmation.")
                self._emit_event("human_approval_needed", {
                    "task_id": task["task_id"],
                    "target": task.get("target", ""),
                    "objective": task.get("objective", ""),
                })
                continue

            # ── 3. Execute (swarm-driven by default) ──
            print(f"\n[Cycle {self._cycles}] Executing: {task.get('objective', task['task_id'])[:100]}")
            self._emit_event("task_started", {
                "task_id": task.get("task_id", ""),
                "target": task.get("target", ""),
                "objective": task.get("objective", ""),
            })

            if self._use_swarm:
                swarm_result = self._swarm.route(task)
                exec_result = ExecutionResult(
                    task_id=task.get("task_id", ""),
                    success=(swarm_result.status.value in ("complete",)),
                    output_summary=json.dumps(swarm_result.output) if swarm_result.output else swarm_result.error,
                    evidence_refs=swarm_result.evidence_refs,
                    tool_name=swarm_result.agent_type,
                    target=task.get("target", ""),
                    scope_gate_passed=(swarm_result.status != AgentStatus.BLOCKED),
                    risk_gate_passed=(swarm_result.status != AgentStatus.BLOCKED),
                    raw_output=(
                        json.dumps(swarm_result.output)
                        if swarm_result.output
                        else swarm_result.error
                    ),
                )
                # Emit swarm agent thinking
                if swarm_result.output:
                    self._emit_event("ai_thinking", {
                        "agent": swarm_result.agent_type or "SwarmAgent",
                        "text": json.dumps(swarm_result.output)[:500],
                    })
                # Merge swarm-derived new tasks into queue
                for nt in swarm_result.new_tasks:
                    try:
                        tid = self._queue.create_task(nt)
                    except (DuplicateInvestigationError, ClosedHypothesisError) as exc:
                        self._emit_event(
                            "task_rejected",
                            {
                                "hypothesis": nt.get("hypothesis", ""),
                                "objective": nt.get("objective", ""),
                                "reason": str(exc),
                            },
                        )
                        continue
                    stats["tasks_created"] += 1
                    self._emit_event("task_created", {
                        "task_id": tid,
                        "phase": nt.get("phase", "recon"),
                        "target": nt.get("target", ""),
                        "objective": nt.get("objective", ""),
                    })
                # Merge swarm memory updates
                for mu in swarm_result.memory_updates:
                    self._memory.remember(
                        mu.get("target", ""),
                        mu.get("content", ""),
                        mu.get("memory_type", "working"),
                        tags=mu.get("tags", []),
                    )
                    self._emit_event("memory_update", {
                        "target": mu.get("target", ""),
                        "content": mu.get("content", "")[:200],
                    })
                # Merge swarm graph updates
                for gu in swarm_result.graph_updates:
                    node_type = gu.get("node_type", "asset")
                    value = gu.get("value", "")
                    if value:
                        self._graph.add_node(node_type, value)
                    for edge in gu.get("edges", []):
                        self._graph.add_edge(value, edge.get("to", ""), edge.get("relation", "related"))
                    self._emit_event("graph_update", gu)
                # Merge swarm findings
                for f in swarm_result.findings:
                    fid = self._verifier.create_candidate(
                        title=f.get("title", ""),
                        affected_asset=f.get("affected_asset", ""),
                        summary=f.get("summary", ""),
                        vuln_class=f.get("vuln_class", ""),
                        confidence=f.get("confidence", 0.5),
                    )
                    stats["findings_created"] += 1
                    self._emit_event("finding_created", {
                        "finding_id": fid,
                        "title": f.get("title", ""),
                        "affected_asset": f.get("affected_asset", ""),
                        "vuln_class": f.get("vuln_class", ""),
                        "confidence": f.get("confidence", 0.5),
                    })
            else:
                exec_result = self._executor.execute(task)

            if not exec_result.scope_gate_passed:
                self._queue.block_task(task["task_id"], exec_result.error)
                stats["tasks_blocked"] += 1
                self._emit_event("task_blocked", {
                    "task_id": task["task_id"],
                    "reason": exec_result.error,
                })
                continue

            # ── 4. Observe ──
            observation = self._observer.observe(
                task=task,
                raw_output=(
                    exec_result.raw_output
                    or exec_result.output_summary
                    or exec_result.error
                ),
                tool_name=exec_result.tool_name,
                evidence_refs=exec_result.evidence_refs,
            )
            stats["observations"] += 1

            # Emit observation data
            self._emit_event("observation", {
                "task_id": task.get("task_id", ""),
                "target": observation.target,
                "tool": observation.tool_name,
                "facts": observation.facts[:10],
                "technologies": observation.new_technologies[:10],
                "endpoints": observation.new_endpoints[:10],
                "signals": observation.interesting_signals[:5],
                "confidence": observation.confidence,
                "usefulness": observation.usefulness,
            })

            # Emit service detection events
            for tech in observation.new_technologies[:10]:
                if tech and not tech.startswith("OS:"):
                    self._emit_event("service_detected", {
                        "service": tech,
                        "target": observation.target,
                    })

            # Emit possible attacks based on detected services
            for tech in observation.new_technologies[:10]:
                service_name = tech.split()[0].lower().rstrip(":") if tech else ""
                attacks = _SERVICE_ATTACK_MAP.get(service_name, [])
                for atk in attacks[:3]:
                    self._emit_event("possible_attack", {
                        "service": service_name,
                        "module": atk.get("module", ""),
                        "risk": atk.get("risk", ""),
                        "priority": atk.get("priority", 0),
                        "tools": atk.get("tools", []),
                    })

            self._save_observation(observation)
            self._update_memory_from_observation(observation)
            self._update_graph_from_observation(observation)

            # ── 5. Judge evidence and persist hypothesis state ──
            prior_hypothesis = self._hypotheses.get_for_task(task)
            assessment = self._outcome_judge.judge(
                task,
                exec_result,
                observation,
                exec_result.evidence_refs,
                prior_hypothesis=prior_hypothesis,
            )
            assessment, hypothesis_state = self._hypotheses.persist_assessment(
                task, assessment
            )
            self._emit_event(
                "outcome_judgment",
                {
                    **assessment.to_dict(),
                    "hypothesis": task.get("hypothesis", ""),
                    "target": task.get("target", ""),
                },
            )
            self._record_outcome_and_lesson(task, assessment)

            # Task status remains an operational execution status. It does not
            # inherit confirmed/refuted/inconclusive/exhausted from the judge.
            result_summary = exec_result.output_summary or exec_result.error
            if exec_result.success:
                self._queue.complete_task(
                    task["task_id"],
                    result_summary=result_summary,
                    evidence_refs=exec_result.evidence_refs,
                )
                stats["tasks_completed"] += 1
                self._risk_ctrl.record_task_complete()
                self._record_task_phase(task, result_summary)
                self._emit_event(
                    "task_complete",
                    {
                        "task_id": task["task_id"],
                        "summary": result_summary[:300],
                        "evidence_refs": exec_result.evidence_refs,
                        "hypothesis_status": assessment.hypothesis_status.value,
                    },
                )
            else:
                self._queue.update_task_status(
                    task["task_id"],
                    "failed",
                    result_summary,
                    exec_result.evidence_refs,
                )
                stats["tasks_failed"] += 1
                self._memory.mark_dead_end(
                    task.get("target", ""),
                    f"Task {task['task_id']} failed: {result_summary}",
                    metadata={
                        "hypothesis_status": assessment.hypothesis_status.value,
                        "evidence_refs": assessment.evidence_refs,
                    },
                )
                self._emit_event(
                    "task_failed",
                    {
                        "task_id": task["task_id"],
                        "error": result_summary,
                        "target": task.get("target", ""),
                        "hypothesis_status": assessment.hypothesis_status.value,
                    },
                )

                # A failed command may justify another check, but only if the
                # judge kept the hypothesis unresolved and the planner can
                # construct a materially different method.
                if assessment.another_investigation_justified:
                    retry_task = self._planner.plan_retry_with_modifications(
                        failed_task=task,
                        error=result_summary,
                        attempt=assessment.attempt_count,
                        hypothesis_state=(
                            hypothesis_state.to_dict() if hypothesis_state else None
                        ),
                    )
                    if retry_task:
                        try:
                            retry_tid = self._queue.create_task(retry_task)
                        except (
                            DuplicateInvestigationError,
                            ClosedHypothesisError,
                        ) as exc:
                            self._emit_event(
                                "task_rejected",
                                {
                                    "hypothesis": retry_task.get("hypothesis", ""),
                                    "objective": retry_task.get("objective", ""),
                                    "reason": str(exc),
                                },
                            )
                        else:
                            stats["tasks_created"] += 1
                            self._emit_event(
                                "task_created",
                                {
                                    "task_id": retry_tid,
                                    "phase": retry_task.get("phase", "recon"),
                                    "target": retry_task.get("target", ""),
                                    "objective": retry_task.get("objective", ""),
                                    "retry_of": task["task_id"],
                                },
                            )
            stats["evidence_saved"] += len(exec_result.evidence_refs)

            # Append to battle log for reflection
            self._battle_log.append({
                "task_id": task.get("task_id", ""),
                "tool": exec_result.tool_name,
                "target": task.get("target", ""),
                "success": exec_result.success,
                "partial_success": exec_result.success and len(exec_result.output_summary) < 50,
                "summary": exec_result.output_summary[:200],
                "error": exec_result.error,
                "hypothesis_status": assessment.hypothesis_status.value,
                "evidential_outcome": assessment.evidential_outcome,
                "evidence_refs": assessment.evidence_refs,
            })

            # Trigger reflection every N actions when swarm is enabled
            if (
                exec_result.success
                and self._use_swarm
                and stats["tasks_completed"] % self._reflection_interval == 0
            ):
                print(f"\n[Cycle {self._cycles}] Running reflection...")
                self._emit_event("ai_thinking", {"agent": "Reflection", "text": "Running reflection..."})
                reflection_result = self._swarm.reflect(
                    battle_log=self._battle_log[-self._reflection_interval:],
                    session_state={"target_ip": task.get("target", "")},
                )
                if reflection_result.output:
                    print(f"  Reflection: {reflection_result.output.get('recommended_strategy_shift', '')}")
                    self._emit_event("ai_reflection", {
                        "recommended_strategy_shift": reflection_result.output.get("recommended_strategy_shift", ""),
                        "output": json.dumps(reflection_result.output)[:500],
                    })
                    # Store reflection in memory (episodic — memories table)
                    self._memory.remember(
                        task.get("target", ""),
                        reflection_result.output.get("recommended_strategy_shift", ""),
                        "semantic",
                        tags=["reflection", "strategy"],
                    )
                    # Tier 1.1: the cross-mission *lesson* (lessons table) is
                    # persisted by reflection_agent.run() itself, which owns the
                    # reflection and is reached via both Flow B (swarm.reflect)
                    # and Flow A (autonomous_orchestrator) — so we don't double-write here.

            # ── 6. Create finding candidates ──
            for pf in observation.possible_findings:
                fid = self._verifier.create_candidate(
                    title=pf.get("title", f"Potential {pf.get('type', 'finding')} on {pf.get('target', '')}"),
                    affected_asset=pf.get("target", task.get("target", "")),
                    summary=json.dumps(pf) if isinstance(pf, dict) else str(pf),
                    vuln_class=pf.get("type", ""),
                    confidence=pf.get("confidence", observation.confidence),
                    evidence_refs=exec_result.evidence_refs,
                )
                stats["findings_created"] += 1
                self._emit_event("finding_created", {
                    "finding_id": fid,
                    "title": pf.get("title", ""),
                    "affected_asset": pf.get("target", task.get("target", "")),
                    "vuln_class": pf.get("type", ""),
                    "confidence": pf.get("confidence", observation.confidence),
                })

            # ── 7. Check open candidates for auto-validation ──
            candidates = self._verifier.list_needs_validation()
            if not candidates:
                candidates = self._verifier.list_candidates()

            for cand in candidates[:3]:
                val_result = self._verifier.validate_finding(
                    cand["finding_id"],
                    scope_gate=self._scope_gate,
                    evidence_store=self._evidence,
                )
                if val_result.get("valid"):
                    self._verifier.mark_report_ready(cand["finding_id"])
                    stats["findings_report_ready"] += 1
                    self._emit_event("finding_validated", {
                        "finding_id": cand["finding_id"],
                        "title": cand.get("title", ""),
                    })
                elif val_result.get("missing"):
                    self._verifier.mark_needs_validation(
                        cand["finding_id"], val_result["missing"]
                    )

            # ── 8. Reprioritize queue ──
            self._queue.reprioritize()

            # Stats summary every 5 cycles
            if self._cycles % 5 == 0:
                print(f"\n--- Progress at cycle {self._cycles} ---")
                print(f"  Tasks: {stats['tasks_completed']} done, {stats['tasks_blocked']} blocked, {stats['tasks_failed']} failed")
                print(f"  Findings: {stats['findings_created']} created, {stats['findings_report_ready']} report-ready")
                print(f"  Budgets: {self._risk_ctrl.budgets()}")
                self._emit_event("stats_update", {
                    "cycles": self._cycles,
                    "tasks_completed": stats["tasks_completed"],
                    "tasks_blocked": stats["tasks_blocked"],
                    "tasks_failed": stats["tasks_failed"],
                    "findings_created": stats["findings_created"],
                    "findings_report_ready": stats["findings_report_ready"],
                    "budgets": self._risk_ctrl.budgets(),
                })

        stats["cycles"] = self._cycles

        # ── Final: generate summary report ──
        try:
            self._reporter.generate_summary_report()
            print("\n[Summary report generated]")
        except Exception as exc:
            print(f"[Summary report error]: {exc}")

        # ── Report-ready findings → generate reports ──
        for finding in self._verifier.list_report_ready():
            try:
                self._reporter.generate_report(finding["finding_id"])
            except Exception as exc:
                print(f"[Report error for {finding['finding_id']}]: {exc}")

        # Tier 1.1: distill this campaign's episodic memories into a semantic
        # lesson so the next mission starts with what this one learned. No-op
        # when semantic memory is off or Ollama is down; never raises.
        self._distill_episode_summary()

        # Final audit
        with self._db.connection(write=True) as conn:
            self._db.log_audit(
                conn,
                self._mission_id,
                "loop_complete",
                f"Agent loop finished after {self._cycles} cycles.",
                metadata=stats,
            )

        self._mission_ctrl.update_status(self._mission_id, "completed")

        print(f"\n{'='*60}")
        print("  RESEARCH LOOP COMPLETE")
        print(f"  Cycles: {self._cycles}")
        print(f"  Tasks: {stats['tasks_completed']} complete, {stats['tasks_blocked']} blocked, {stats['tasks_failed']} failed")
        print(f"  Findings: {stats['findings_created']} created, {stats['findings_report_ready']} report-ready, {stats['findings_rejected']} rejected")
        print(f"  Evidence: {stats['evidence_saved']} items")
        print(f"{'='*60}")

        return stats

    def stop(self) -> None:
        self._running = False

    def _phase_minima_met(self) -> tuple[bool, str]:
        """Check whether required minimum actions per phase have been completed."""
        if self._phase_counts["recon"] < 2:
            return False, f"Need >=2 recon actions (have {self._phase_counts['recon']})"
        min_svc = max(1, self._services_detected)
        if self._phase_counts["service_enumeration"] < min_svc:
            return False, f"Need >={min_svc} service enumeration actions (have {self._phase_counts['service_enumeration']})"
        min_vuln = max(1, self._versions_identified)
        if self._phase_counts["vulnerability_research"] < min_vuln:
            return False, f"Need >={min_vuln} vulnerability research actions (have {self._phase_counts['vulnerability_research']})"
        if self._phase_counts["reporting"] < 1:
            return False, "Need >=1 reporting action"
        return True, "Phase minima satisfied."

    def _record_task_phase(self, task: dict[str, Any], result_text: str = "") -> None:
        """Update phase counters based on task metadata and output."""
        phase = task.get("phase", "recon")
        if phase in self._phase_counts:
            self._phase_counts[phase] += 1

        # Parse banners from recon results to drive phase requirements
        if phase in ("recon", "analysis") and result_text:
            banners = parse_service_banners(result_text)
            if banners:
                self._services_detected = max(self._services_detected, len(banners))
                versions = sum(1 for b in banners if b.get("version"))
                self._versions_identified = max(self._versions_identified, versions)

    # ── Autonomous Attack Orchestration ──────────────────────────────────

    async def run_autonomous_campaign(self, targets: list[str]) -> dict[str, Any]:
        """Run a full autonomous attack campaign with deep reconnaissance.

        This is the aggressive autonomous mode that:
        1. Runs deep reconnaissance on all targets
        2. Automatically chains findings into attack paths
        3. Retries failed exploits with modified parameters
        4. Escalates aggression if initial attempts fail
        5. Never stops after a single successful action
        6. Records full attack timeline
        """
        print(f"\n{'='*60}")
        print("  AUTONOMOUS ATTACK CAMPAIGN STARTING")
        print(f"  Targets: {targets}")
        print(f"  Risk Profile: {self._mission.risk_profile}")
        print(f"  Max Cycles: {self._max_cycles}")
        print(f"{'='*60}\n")

        # Initialize autonomous orchestrator
        recon_config = ReconConfig(
            aggression_level="aggressive" if self._mission.allows_exploitation else "normal",
            fallback_enabled=True,
            parallel_secondary=True,
            max_concurrent_secondary=3,
        )

        # Tier 0 item 0.6b: wire the swarm's critic/reflection/blackboard into
        # the autonomous orchestrator so the most aggressive path no longer
        # bypasses multi-layer reasoning. We pass the swarm's LIVE blackboard
        # (not get_blackboard()'s snapshot) so module failures/patterns recorded
        # by AttackModuleExecutor accumulate across both paths -- the swarm's
        # CriticAgent then sees autonomous-path failures too. The autonomous
        # campaign and the swarm route() loop are alternative execution paths
        # within a run (never concurrent), so a shared mutable reference is safe.
        from tools.swarm.agents.critic_agent import CriticAgent
        from tools.swarm.agents.reflection_agent import ReflectionAgent

        orchestrator = AutonomousOrchestrator(
            mission_config=self._mission.to_dict(),
            workspace_root=self._workspace_root / "autonomous",
            tool_executor=self._tool_executor,
            recon_config=recon_config,
            scope_gate=self._scope_gate,
            risk_controller=self._risk_ctrl,
            evidence_store=self._evidence,
            blackboard=self._swarm.share_blackboard(),
            model_client=self._swarm.model_client,
            critic_agent=CriticAgent() if self.critic_enabled else None,
            reflection_agent=ReflectionAgent() if self.reflection_enabled else None,
        )

        # Run the campaign. Tier 1.3: when this AgentLoop was itself resumed
        # (constructed with mission_id pointing at an existing mission), pass
        # resume=True so the orchestrator reloads its attack_states.json and
        # continues the prior campaign (skip done recon, don't re-fire
        # succeeded/failed modules) instead of starting over from scratch.
        campaign_result = await orchestrator.run_autonomous_campaign(
            targets, resume=self._resumed
        )

        # Save states
        orchestrator.save_state()

        # Update our stats
        stats = {
            "targets": targets,
            "duration": campaign_result.get("duration", 0),
            "total_tasks": campaign_result.get("total_tasks", 0),
            "successful_exploits": campaign_result.get("successful_exploits", 0),
            "states": campaign_result.get("states", {}),
        }

        # Create findings from successful exploits
        for target, state_dict in campaign_result.get("states", {}).items():
            for exploit in state_dict.get("successful_exploits", []):
                self._verifier.create_candidate(
                    title=f"Successful exploitation: {exploit} on {target}",
                    affected_asset=target,
                    summary=json.dumps({"exploit": exploit, "state": state_dict}),
                    vuln_class="Known CVE" if "CVE" in exploit else "Other",
                    confidence=0.9,
                )

        # Generate enhanced red-team report
        try:
            enhanced_reporter = EnhancedReportGenerator(
                db=self._db,
                mission_id=self._mission_id,
                workspace=self._workspace_root,
            )
            report_paths = enhanced_reporter.generate_full_report(campaign_result, output_format="both")
            stats["report_paths"] = {k: str(v) for k, v in report_paths.items()}
            print("\n[Enhanced reports generated]")
            for fmt, path in report_paths.items():
                print(f"  {fmt}: {path}")
        except Exception as exc:
            print(f"[Enhanced report error]: {exc}")

        print(f"\n{'='*60}")
        print("  AUTONOMOUS CAMPAIGN COMPLETE")
        print(f"  Duration: {stats['duration']:.1f}s")
        print(f"  Tasks: {stats['total_tasks']}")
        print(f"  Successful Exploits: {stats['successful_exploits']}")
        print(f"{'='*60}")

        return stats

    async def run_deep_recon(self, targets: list[str]) -> dict[str, Any]:
        """Run deep reconnaissance and automatically create follow-up tasks."""
        print(f"\n[DEEP RECON] Starting reconnaissance on {len(targets)} targets")

        recon_config = ReconConfig(
            aggression_level="normal",
            fallback_enabled=True,
            parallel_secondary=True,
        )
        pipeline = ReconPipeline(recon_config)

        results = await pipeline.recon_hosts(targets)

        # Process results and create attack tasks
        for result in results:
            if isinstance(result, Exception):
                print(f"[RECON ERROR] {result}")
                continue

            print(f"[RECON] {result.target_ip}: {len(result.open_ports)} ports, {len(result.services)} services")

            # Save recon result to memory
            self._memory.remember(
                result.target_ip,
                f"Recon complete: {len(result.open_ports)} ports, OS={result.os_family}",
                "target",
                tags=["recon"],
                metadata=result.to_dict(),
            )

            # Create follow-up tasks based on findings
            attack_surface = pipeline.get_attack_surface_summary(result)

            # Create tasks for high-value targets
            for target_info in attack_surface.get("high_value_targets", []):
                task = self._planner._create_task(
                    phase="test",
                    target=result.target_ip,
                    asset_type="host",
                    objective=f"Attack {target_info['service']} on port {target_info['port']}",
                    hypothesis=f"{target_info['service']} {target_info['version']} may be exploitable",
                    allowed_tools=["attack_module", "exploit_agent"],
                    risk_level="medium",
                    priority=75,
                )
                try:
                    self._queue.create_task(task)
                except (DuplicateInvestigationError, ClosedHypothesisError):
                    pass

            # Create tasks for web targets
            for web_target in attack_surface.get("web_targets", []):
                task = self._planner._create_task(
                    phase="test",
                    target=result.target_ip,
                    asset_type="web_app",
                    objective=f"Test web application on port {web_target['port']}",
                    hypothesis="Web application may have injection or authentication vulnerabilities",
                    allowed_tools=["web_vuln_scan", "sqlmap", "dir_enum"],
                    risk_level="medium",
                    priority=70,
                )
                try:
                    self._queue.create_task(task)
                except (DuplicateInvestigationError, ClosedHypothesisError):
                    pass

            # Create tasks for credential targets
            for cred_target in attack_surface.get("credential_targets", []):
                task = self._planner._create_task(
                    phase="test",
                    target=result.target_ip,
                    asset_type="host",
                    objective=f"Test credentials on {cred_target['service']}:{cred_target['port']}",
                    hypothesis="Default or weak credentials may be in use",
                    allowed_tools=["hydra", "medusa", "brute_force"],
                    risk_level="medium",
                    priority=65,
                )
                try:
                    self._queue.create_task(task)
                except (DuplicateInvestigationError, ClosedHypothesisError):
                    pass

        return {"targets": targets, "results": [r.to_dict() if hasattr(r, 'to_dict') else str(r) for r in results]}

    # ── Internal helpers ───────────────────────────────────────────────

    def _save_observation(self, obs) -> None:
        with self._db.connection(write=True) as conn:
            from db import _new_id, _now_iso
            obs_id = _new_id("OBS")
            conn.execute(
                """INSERT INTO observations(
                    id, task_id, target, tool_name, input_summary, output_summary,
                    facts_json, new_assets_json, new_endpoints_json, new_parameters_json,
                    new_technologies_json, new_identities_json, new_objects_json,
                    interesting_signals_json, possible_findings_json, dead_ends_json,
                    recommended_followup_tasks_json, memory_updates_json, graph_updates_json,
                    evidence_refs_json, hypothesis_evidence_json,
                    confidence, usefulness, created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    obs_id,
                    obs.task_id,
                    obs.target,
                    obs.tool_name,
                    obs.input_summary,
                    obs.output_summary,
                    json.dumps(obs.facts),
                    json.dumps(obs.new_assets),
                    json.dumps(obs.new_endpoints),
                    json.dumps(obs.new_parameters),
                    json.dumps(obs.new_technologies),
                    json.dumps(obs.new_identities),
                    json.dumps(obs.new_objects),
                    json.dumps(obs.interesting_signals),
                    json.dumps(obs.possible_findings),
                    json.dumps(obs.dead_ends),
                    json.dumps(obs.recommended_followup_tasks),
                    json.dumps(obs.memory_updates),
                    json.dumps(obs.graph_updates),
                    json.dumps(obs.evidence_refs),
                    json.dumps(obs.hypothesis_evidence),
                    obs.confidence,
                    obs.usefulness,
                    _now_iso(),
                ),
            )

    # ── Tier 1.1: cross-mission learning helpers ───────────────────────────
    # Every helper is a no-op (never raises) when semantic memory is off or
    # Ollama is unreachable: a down embedder costs only the next campaign's
    # recall, never the current run.

    def _cross_mission_recall(self, context_text: str, top_k: int = 3) -> str:
        """Recall cross-mission lessons + prior-mission memory for a context.

        Returns a human-readable block (empty when semantic memory is off, the
        context is blank, or Ollama is down) suitable for appending to the
        planner's ``target_summary``. Every failure path is swallowed.
        """
        if self._semantic_memory is None or not context_text.strip():
            return ""
        bits: list[str] = []
        try:
            lessons = self._semantic_memory.find_similar_lessons(
                text=context_text, outcome="success", top_k=top_k,
            )
            if lessons:
                joined = "; ".join(
                    f"{lesson.get('action_type', '?')} on {lesson.get('target_signature', '?')} "
                    f"-> {lesson.get('outcome', '?')} "
                    f"(sim {float(lesson.get('similarity', 0.0)):.2f})"
                    for lesson in lessons
                )
                bits.append(f"CROSS-MISSION LESSONS: {joined}")
        except Exception as exc:
            print(f"[Cross-mission] find_similar_lessons failed: {exc}")
        try:
            mems = self._memory.retrieve_relevant(
                target=self._mission.program_name or "",
                context=context_text,
                limit=top_k,
            )
            if mems:
                joined = "; ".join(
                    (m.get("fact") or "")[:120] for m in mems if m.get("fact")
                )
                if joined:
                    bits.append(f"PRIOR MISSION MEMORY: {joined}")
        except Exception as exc:
            print(f"[Cross-mission] retrieve_relevant failed: {exc}")
        return "\n".join(bits)

    def _record_outcome_and_lesson(
        self,
        task: dict[str, Any],
        assessment: OutcomeAssessment,
    ) -> None:
        """Persist only evidence-supported judgments as cross-mission learning.

        The Bayesian write (``record_outcome``) feeds ``get_confidence`` for
        action selection; the semantic write (``store_lesson``) feeds
        ``find_similar_lessons`` for cross-mission recall. Both are independently
        guarded: a missing store, a down Ollama, or any exception never raises —
        the worst case is one fewer lesson in the next campaign.
        """
        outcome = assessment.evidential_outcome
        if outcome is None or not assessment.evidence_refs:
            return
        target = task.get("target", "") or self._mission.program_name or "unknown"
        phase = task.get("phase", "recon")
        objective = (task.get("objective") or "")[:60]
        action = f"{phase}:{objective}" if objective else phase
        # 1. Bayesian outcome (writes a '[]'-embedding row that find_similar_lessons
        #    filters out of recall; used only for confidence scoring).
        try:
            self._experience.record_evidential_outcome(
                target,
                action,
                assessment.hypothesis_status.value,
                confidence=assessment.confidence,
                evidence_refs=assessment.evidence_refs,
                metadata={
                    "assessment_id": assessment.assessment_id,
                    "task_id": assessment.task_id,
                    "reasoning": assessment.reasoning,
                },
            )
        except Exception as exc:
            print(f"[Cross-mission] record_outcome failed: {exc}")
        # 2. Real-embedding semantic lesson (the recall path). No-op when semantic
        #    memory is off; store_lesson skips + logs when Ollama is down.
        if self._semantic_memory is None:
            return
        text = f"{target} {action} -> {outcome}"
        if assessment.reasoning:
            text += f" | {assessment.reasoning[:300]}"
        try:
            self._semantic_memory.store_lesson(
                target_signature=target,
                action_type=action,
                outcome=outcome,
                text=text,
                confidence=assessment.confidence,
                metadata={
                    "task_id": task.get("task_id", ""),
                    "phase": phase,
                    "objective": task.get("objective", ""),
                    "target": target,
                    "assessment_id": assessment.assessment_id,
                    "hypothesis_status": assessment.hypothesis_status.value,
                    "evidence_refs": assessment.evidence_refs,
                },
            )
        except Exception as exc:  # pragma: no cover - never break the loop
            print(f"[Cross-mission] store_lesson failed: {exc}")

    def _distill_episode_summary(self) -> None:
        """Condense this campaign's episodic memories into one semantic lesson.

        Asks the model (when wired) to distill recent episodes via
        ``summarize_episodes``; if no model is wired or there are no episodic
        memories, falls back to a factual roll-up of the battle log. No-op when
        semantic memory is off; never raises.
        """
        if self._semantic_memory is None:
            return
        try:
            summary = ""
            if self._model_client is not None:
                summary = self._semantic_memory.summarize_episodes(
                    "episodic", self._mission_id,
                    client=self._model_client, model=self._model_name,
                )
                # summarize_episodes returns a fallback message when there are
                # no episodic memories (or the client vanished mid-call) — treat
                # those as "no summary" so the factual fallback can take over.
                if summary.startswith("No memories") or "no LLM client" in summary:
                    summary = ""
            if not summary and self._battle_log:
                wins = sum(1 for b in self._battle_log if b.get("success"))
                summary = (
                    f"Campaign over {self._cycles} cycles: "
                    f"{wins}/{len(self._battle_log)} tasks succeeded."
                )
            if not summary:
                return
            target = self._mission.program_name or self._mission_id
            self._semantic_memory.store_lesson(
                target_signature=target,
                action_type="campaign:episode_summary",
                outcome="unknown",
                text=summary[:1000],
                confidence=0.6,
                metadata={
                    "mission_id": self._mission_id,
                    "cycles": self._cycles,
                    "model": self._model_name,
                },
            )
        except Exception as exc:  # pragma: no cover
            print(f"[Cross-mission] distill_episode_summary failed: {exc}")

    def _update_memory_from_observation(self, obs) -> None:
        for fact in obs.facts[:5]:
            self._memory.remember(obs.target, fact, "target")
        for tech in obs.new_technologies[:3]:
            self._memory.remember(obs.target, f"Technology: {tech}", "target")
        for signal in obs.interesting_signals[:3]:
            self._memory.remember(obs.target, signal, "target", tags=["signal"])
        for dead in obs.dead_ends[:3]:
            self._memory.mark_dead_end(obs.target, dead)

    def _update_graph_from_observation(self, obs) -> None:
        for asset in obs.new_assets[:5]:
            self._graph.add_node("asset", asset)
        for ep in obs.new_endpoints[:5]:
            self._graph.add_node("endpoint", ep)
        for tech in obs.new_technologies[:3]:
            self._graph.add_node("technology", tech)
