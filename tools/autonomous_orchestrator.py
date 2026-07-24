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

from __future__ import annotations

import asyncio
import inspect
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from tools.logging_setup import get_logger
from tools.recon_pipeline import ReconPipeline, ReconConfig, HostReconResult
from tools.attack_modules import (
    AttackModule,
    ModuleContext,
    find_modules,
    get_module,
    list_modules,
)

logger = get_logger()

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
        if result.get("privilege_level"):
            self.privilege_level = result["privilege_level"]
        if result.get("credentials"):
            self.credentials_found.extend(result["credentials"])
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
    ) -> None:
        self._scope_gate = scope_gate
        self._risk_controller = risk_controller
        self._evidence_store = evidence_store
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

    async def execute(
        self,
        task: AttackTask,
        state: AttackState,
    ) -> dict[str, Any]:
        """Execute an attack module with full lifecycle management."""
        task.status = TaskStatus.RUNNING
        task.started_at = time.monotonic()

        logger.info(f"Executing {task.module_name} against {task.target} (attempt {task.retry_count + 1})")
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
        critic_decision = self._run_critic(task)
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

        # Build context
        ctx = ModuleContext(
            target_ip=task.target,
            target_os=state.recon_result.os_family if state.recon_result else None,
            services=[
                {"service": s.service, "port": f"{s.port}/{s.protocol}"}
                for s in (state.recon_result.services if state.recon_result else [])
            ],
        )

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

            # Process result
            task.result = result
            # A module that ran but did not achieve exploitation is NOT a success:
            # the retry/mutation loop (_execute_task_batch), lateral recursion
            # (_attack_target), and reflection (_run_reflection) all key off
            # result["success"] / task.status, so a ran-but-failed module must
            # report success=False and TaskStatus.FAILED -- otherwise failed
            # modules are counted as completed and never retried.
            _succeeded = result.get("status") in ("success", "exploited", "script_generated", "info")
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
            self._run_reflection(task, state, {"success": _succeeded, "result": result})

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
        """
        bb = self._blackboard
        if not bb:
            return
        failed = bb.setdefault("failed_modules", [])
        if module_name not in failed:
            failed.append(module_name)

    def _record_success_on_blackboard(self, module_name: str) -> None:
        """Record a module success on the shared blackboard.

        Clears the module from the repeat-failure list (so the critic stops
        flagging it) and notes it as successful. No-op when no blackboard wired.
        """
        bb = self._blackboard
        if not bb:
            return
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


# ---------------------------------------------------------------------------
# Autonomous orchestrator
# ---------------------------------------------------------------------------

class AutonomousOrchestrator:
    """Main autonomous attack orchestrator.

    Usage::
        orchestrator = AutonomousOrchestrator(mission_config, workspace, tool_executor)
        results = await orchestrator.run_autonomous_campaign(targets=["10.0.0.50"])
    """

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
    ) -> None:
        self._workspace = workspace_root
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._mission = mission_config
        self._tool_executor = tool_executor
        self._recon_config = recon_config or ReconConfig()
        self._recon = ReconPipeline(self._recon_config)
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
        )

        self._states: dict[str, AttackState] = {}
        self._tasks: dict[str, AttackTask] = {}
        self._task_counter = 0
        self._running = True
        self._max_cycles = mission_config.get("max_cycles", 100)
        self._max_aggression = AggressionLevel(mission_config.get("max_aggression", "maximum"))
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

    def _new_task_id(self) -> str:
        self._task_counter += 1
        return f"ATK-{self._task_counter:05d}"

    def get_state(self, target: str) -> AttackState:
        if target not in self._states:
            self._states[target] = AttackState(target=target)
        return self._states[target]

    # ── Main campaign runner ─────────────────────────────────────────────

    async def run_autonomous_campaign(
        self,
        targets: list[str],
        *,
        resume: bool = False,
    ) -> dict[str, Any]:
        """Run a full autonomous attack campaign against multiple targets.

        Tier 1.3: when ``resume`` is True, load previously-saved attack state
        from ``attack_states.json`` in the workspace BEFORE attacking. The
        recovered per-target ``AttackState`` (recon_result, successful_exploits,
        failed_attempts, current_phase, credentials, access) means each target
        skips recon it already finished and doesn't re-fire modules that
        already succeeded/failed. A missing/empty state file degrades
        gracefully to a fresh start (see ``load_state``).
        """
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

        for target in targets:
            if not self._running:
                break
            result = await self._attack_target(target)
            results[target] = result

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

        # Phase 1: Deep reconnaissance
        await self._phase_reconnaissance(state)
        if not state.recon_result or not state.recon_result.open_ports:
            logger.warning(f"No open ports on {target}, ending campaign")
            state.add_timeline_event("no_attack_surface", "No open ports found")
            return {"status": "no_attack_surface", "state": state.to_dict()}

        # Phase 2: Service enumeration (already done in recon pipeline)
        state.current_phase = AttackPhase.ENUMERATION

        # Phase 3: Exploitation - automatically select and run attack modules
        await self._phase_exploitation(state)

        # Phase 4: Privilege escalation
        if state.access_achieved and state.privilege_level not in ("system", "root", "admin"):
            await self._phase_privilege_escalation(state)

        # Phase 5: Lateral movement
        if state.pivot_targets:
            await self._phase_lateral_movement(state, _depth)

        # Phase 6: Validation
        await self._phase_validation(state)

        state.add_timeline_event("campaign_end", f"Attack campaign completed for {target}")
        return {"status": "complete", "state": state.to_dict()}

    # ── Phase handlers ───────────────────────────────────────────────────

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
        state.current_phase = AttackPhase.RECONNAISSANCE
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

    async def _phase_exploitation(self, state: AttackState) -> None:
        """Automatically select and execute attack modules based on recon."""
        logger.info(f"[EXPLOIT] Starting exploitation against {state.target}")
        state.current_phase = AttackPhase.EXPLOITATION
        state.add_timeline_event("phase_start", "Exploitation phase started")

        if not state.recon_result:
            logger.warning("No recon result available for exploitation")
            return

        # Get applicable modules sorted by score
        ctx = ModuleContext(
            target_ip=state.target,
            target_os=state.recon_result.os_family,
            services=[
                {"service": s.service, "port": f"{s.port}/{s.protocol}"}
                for s in state.recon_result.services
            ],
            cves=[
                cve for s in state.recon_result.services
                for cve in s.scripts.get("openssh_cves", [])
            ],
        )

        scored_modules = find_modules(ctx)
        logger.info(f"[EXPLOIT] {len(scored_modules)} applicable modules found")

        # Create attack tasks for top modules
        tasks: list[AttackTask] = []
        for score, module in scored_modules[:15]:  # Top 15 modules
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

        # Also add service-specific tasks
        service_tasks = self._create_service_specific_tasks(state)
        tasks.extend(service_tasks)

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
        state.current_phase = AttackPhase.PRIVILEGE_ESCALATION
        state.add_timeline_event("phase_start", "Privilege escalation phase started")

        privesc_modules = []
        if state.recon_result and "linux" in state.recon_result.os_family.lower():
            privesc_modules = ["LinuxPrivescCheck", "SUIDEnumeration", "KernelExploitCheck"]
        elif state.recon_result and "windows" in state.recon_result.os_family.lower():
            privesc_modules = ["WindowsPrivescCheck", "TokenImpersonation", "ServiceMisconfiguration"]
        else:
            privesc_modules = ["LinuxPrivescCheck", "WindowsPrivescCheck", "ContainerBreakout"]

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

    async def _phase_lateral_movement(self, state: AttackState, _depth: int = 0) -> None:
        """Attempt lateral movement to discovered pivot targets.

        ``_depth`` is the pivot-hop count of the calling target; further recursion
        is capped at ``self._max_pivot_depth`` (Tier 0 item 0.6a) and any pivot we
        have already attacked is skipped (visited guard) so a rediscovered host
        can't loop the campaign.
        """
        logger.info(f"[LATERAL] Starting lateral movement from {state.target} (pivot depth {_depth})")
        state.current_phase = AttackPhase.LATERAL_MOVEMENT
        state.add_timeline_event("phase_start", "Lateral movement phase started")

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
        state.current_phase = AttackPhase.VALIDATION
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

    # ── Task execution ───────────────────────────────────────────────────

    async def _execute_task_batch(self, tasks: list[AttackTask], state: AttackState) -> None:
        """Execute a batch of tasks with concurrency control."""
        semaphore = asyncio.Semaphore(3)  # Max 3 concurrent attacks

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

    async def _retry_failed_modules(self, state: AttackState) -> None:
        """Retry failed modules with escalated aggression."""
        failed_modules = set(state.failed_attempts.keys()) - set(state.successful_exploits)

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
