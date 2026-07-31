"""Swarm Orchestrator — routes tasks to specialist agents and merges results.

V2: Shared blackboard for inter-agent state, parallel dispatch with semaphore,
critic pre-check with blackboard awareness, and reflection-driven strategy adaptation.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from tools.swarm.base import Agent, AgentResult, AgentStatus
from tools.swarm.blackboard import Blackboard
from tools.swarm.agents.recon_agent import ReconAgent
from tools.swarm.agents.vuln_agent import VulnAgent
from tools.swarm.agents.exploit_agent import ExploitAgent
from tools.swarm.agents.post_exploit_agent import PostExploitAgent
from tools.swarm.agents.critic_agent import CriticAgent
from tools.swarm.agents.reflection_agent import ReflectionAgent


# Mapping from task phase/type to default agent class
_DEFAULT_AGENT_MAP: dict[str, type[Agent]] = {
    "recon": ReconAgent,
    "analysis": VulnAgent,
    "test": VulnAgent,
    "validate": ExploitAgent,
    "exploit": ExploitAgent,
    "post_exploit": PostExploitAgent,
    "report": ReflectionAgent,
}


class SwarmOrchestrator:
    """Routes tasks to registered agents and aggregates their results.

    V2 improvements:
    - Shared blackboard for inter-agent state communication
    - Critic pre-check with blackboard awareness (repeat failure detection)
    - Parallel dispatch with semaphore-based concurrency
    - Reflection-driven strategy adaptation
    - Battle log accumulation for reflection agent
    """

    def __init__(
        self,
        context: dict[str, Any],
        *,
        agent_registry: dict[str, type[Agent]] | None = None,
        max_parallel: int = 3,
        critic_enabled: bool = True,
        reflection_enabled: bool = True,
        event_callback: Callable[[str, dict[str, Any]], None] | None = None,
        state_path: Path | str | None = None,
    ) -> None:
        self._context = context
        self._agent_registry = agent_registry or dict(_DEFAULT_AGENT_MAP)
        self._max_parallel = max_parallel
        self._critic_enabled = critic_enabled
        self._reflection_enabled = reflection_enabled
        self._event_callback = event_callback
        self._state_path: Path | None = Path(state_path) if state_path else None
        self._agents: dict[str, Agent] = {}
        self._results: list[AgentResult] = []
        self._battle_log: list[dict[str, Any]] = []
        self._lock = threading.RLock()

        # In-memory growth caps. ``_results`` and ``_battle_log`` are only read
        # for their length and a recent tail (see _persist_state's
        # ``battle_log[-20:]`` and _distill_episode_summary's win-count roll-up),
        # so bounding them reclaims the memory a long multi-cycle campaign would
        # otherwise leak without losing any consumed data. The full per-task
        # outcome is already persisted to swarm_state.json on every event.
        self._max_results = 500
        self._max_battle_log = 500

        # ── Shared blackboard for inter-agent state ──
        # ``Blackboard`` (tools/swarm/blackboard.py) is a dict subclass with
        # atomic append_to/extend_list and per-target namespacing. Subclassing
        # dict means every existing ``bb["k"]`` / ``bb.get("k")`` read site in
        # the 6 agents keeps working unchanged (reads hit the __global__
        # bucket, the legacy flat-dict view); only write sites are migrated to
        # the atomic methods so parallel dispatch in route_parallel no longer
        # races on the get-then-set list appends the old plain dict allowed.
        self._blackboard: Blackboard = Blackboard({
            "recon_complete": False,
            "vuln_research_complete": False,
            "access_achieved": False,
            "discovered_services": [],
            "vulnerability_hypotheses": [],
            "compromised_hosts": [],
            "credentials_found": [],
            "pivot_targets": [],
            "loot": [],
            "failed_modules": [],
            "attack_surface_score": 0,
            "strategy_shift": "",
        })

        # Inject blackboard into context so all agents can access it. Agents
        # read it as a dict (bb["k"] / bb.get) and write via the atomic API
        # (bb.set_scalar / bb.append_to / bb.extend_list).
        self._context["blackboard"] = self._blackboard

        # ── Runtime skill selection for advisory phase hints ──
        # Build one mission-level SkillSelection and stash it on the shared
        # context so each specialist agent can derive phase-relevant hints.
        # Advisory only; never grants execution authority. Best-effort: a
        # missing/empty config or disabled skills yields an empty selection
        # and agents no-op.
        try:
            from tools.skill_pipeline import build_skill_selection_for_swarm

            self._context.setdefault("skill_selection", build_skill_selection_for_swarm(self._context))
        except Exception:
            self._context.setdefault("skill_selection", None)

    # ── Public API ──────────────────────────────────────────────────────

    def route(self, task: dict[str, Any]) -> AgentResult:
        """Route a single task to the appropriate agent (sequential).

        Includes critic pre-check with blackboard awareness.
        """
        with self._lock:
            phase = task.get("phase", "recon")
            agent_cls = self._agent_registry.get(phase)
            if agent_cls is None:
                return AgentResult(
                    agent_type="unknown",
                    status=AgentStatus.FAILED,
                    task_id=task.get("task_id", task.get("id", "")),
                    error=f"No agent registered for phase '{phase}'.",
                )

            task_id = task.get("task_id", task.get("id", ""))
            target = task.get("target", "")
            agent = self._spawn(agent_cls, task_id=task_id)

            # ── Critic pre-check (with blackboard awareness) ──
            if self._critic_enabled and phase not in ("recon", "report"):
                critic_cls = self._agent_registry.get("critic", CriticAgent)
                critic = critic_cls()
                critic_task = {
                    "task_id": f"critic-{task_id}",
                    "proposed_action": task,
                }
                critic_result = critic.run(critic_task, self._context)
                decision = critic_result.output.get("decision", "approve") if critic_result.output else "approve"
                reasoning = critic_result.output.get("reasoning", "") if critic_result.output else ""

                self._emit(
                    "critic_decision",
                    {
                        "task_id": task_id,
                        "target": target,
                        "decision": decision,
                        "reasoning": reasoning,
                    },
                )

                if decision == "deny":
                    blocked_result = AgentResult(
                        agent_type=agent.agent_type,
                        status=AgentStatus.BLOCKED,
                        task_id=task_id,
                        error=f"Critic blocked: {reasoning}",
                    )
                    agent._set_status(AgentStatus.BLOCKED)
                    self._results.append(blocked_result)
                    self._battle_log.append({
                        "task_id": task_id,
                        "tool": task.get("tool", task.get("phase", "")),
                        "target": target,
                        "success": False,
                        "error": f"Critic blocked: {reasoning}",
                    })
                    self._trim_history()
                    self._emit(
                        "agent_blocked",
                        {
                            "agent_id": agent.agent_id,
                            "agent_type": agent.agent_type,
                            "task_id": task_id,
                            "reason": f"Critic blocked: {reasoning}",
                        },
                    )
                    self._persist_state()
                    return blocked_result

                if decision == "modify":
                    modifications = critic_result.output.get("modifications", {})
                    task.update(modifications)

            # ── Execute agent ──
            result = agent.run(task, self._context)
            agent._set_status(result.status)
            self._results.append(result)

            self._emit(
                f"agent_{result.status.value}",
                {
                    "agent_id": agent.agent_id,
                    "agent_type": agent.agent_type,
                    "task_id": task_id,
                    "status": result.status.value,
                    "execution_time": result.execution_time,
                    "summary": str(result.output)[:200] if result.output else result.error,
                    "findings_count": len(result.findings),
                    "new_tasks_count": len(result.new_tasks),
                },
            )

            # ── Update battle log with richer context ──
            self._battle_log.append({
                "task_id": task_id,
                "tool": task.get("tool", task.get("phase", "")),
                "target": target,
                "success": result.status == AgentStatus.COMPLETE,
                "summary": str(result.output)[:500],
                "error": result.error,
                "findings": result.findings,
                "new_tasks": result.new_tasks,
            })
            self._trim_history()

            # ── Blackboard milestone events ──
            if result.output:
                for key in ("access_achieved", "compromised_hosts", "credentials_found", "loot"):
                    value = result.output.get(key) if isinstance(result.output, dict) else None
                    if value:
                        # Bug #18 (preserved): the old ``setdefault(key, value)``
                        # on a list value was a no-op once the key existed — the
                        # first task's list stuck and every later task's list was
                        # silently dropped. We now merge list values
                        # (order-preserving dedupe) and keep first-write
                        # semantics for scalars. The Blackboard API makes this
                        # atomic (lock-protected get-then-set) so the same merge
                        # is safe under route_parallel's unlocked agent.run.
                        if isinstance(value, list):
                            self._blackboard.extend_list(key, value)
                        else:
                            # First-write-wins for scalars: only set if absent.
                            if key not in self._blackboard:
                                self._blackboard.set_scalar(key, value)
                        if key == "access_achieved" and value:
                            self._blackboard.set_scalar("access_achieved", True)
                        self._emit(
                            "blackboard_updated",
                            {"key": key, "value": value, "task_id": task_id, "agent_type": agent.agent_type},
                        )

            self._persist_state()

            # ── Auto-reflect after exploitation phases ──
            if self._reflection_enabled and phase in ("exploit", "post_exploit"):
                self.reflect(self._battle_log, {"target_ip": target})

            return result

    async def route_parallel(self, tasks: list[dict[str, Any]]) -> list[AgentResult]:
        """Route multiple tasks in parallel with a concurrency limit.

        .. warning::

            **Not wired into production and not safe to enable as-is.** This method
            is retained as Tier 1.9 groundwork. It is *not* called from ``agent_loop``
            (production dispatch is sequential: ``route()`` one task per cycle). Do
            not wire it into the default dispatch until the following land in the
            Tier 1.9 typed/per-target blackboard refactor -- each is a concrete
            correctness hazard verified against the current code:

            1. **The ``route()`` RLock serializes this method to one task at a time.**
               ``route()`` holds ``self._lock`` across ``agent.run()``
               (orchestrator.py:97-216), so even with the semaphore below, real
               concurrency is 1. Shrinking that lock is the easy part -- but doing
               it alone is a footgun, because:
            2. **The shared blackboard is single + un-namespaced.** Same-phase tasks
               *overwrite* phase keys (``recon`` sets ``discovered_services`` at
               ``recon_agent.py:255``; ``vuln`` sets ``vulnerability_hypotheses`` at
               ``vuln_agent.py:251``). Parallelizing multiple recon targets loses all
               but the last writer's services. Needs per-target namespacing.
            3. **Four list read-modify-writes race** once ``agent.run()`` is unlocked:
               ``exploit_agent.py:233`` (``compromised_hosts``),
               ``post_exploit_agent.py:149`` (``credentials_found``) / ``:151``
               (``loot``), ``reflection_agent.py:223-226`` (``failed_modules``) --
               each does ``bb["k"] = bb.get("k", []) + [...]`` (get-then-set, not
               atomic). Needs a thread-safe ``Blackboard`` with atomic
               ``append_to``/``extend_list``.
            4. **No precondition gating.** The queue (``task_queue.py:113-123``)
               sorts by priority, not phase; agents silently fall back to ``[]`` when
               a dependency's blackboard key is absent (``vuln_agent.py:114``,
               ``exploit_agent.py:113-116``). Cross-phase parallelism silently breaks
               the recon→vuln→exploit chain.
            5. **Shared-filesystem writes race**: post_exploit appends to one
               ``workspace/loot/credentials.jsonl``/``loot.jsonl``
               (``post_exploit_agent.py:104,108``) and exploit writes under one
               ``reports_dir``/``workspace_root`` (``exploit_agent.py:156-166``).
               Needs per-task workspace subpaths.

            Until 1.9 lands all five, keep production on sequential ``route()``.
        """
        semaphore = asyncio.Semaphore(self._max_parallel)

        async def _run_one(task: dict[str, Any]) -> AgentResult:
            async with semaphore:
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(None, self.route, task)

        results = await asyncio.gather(*[_run_one(t) for t in tasks])
        return list(results)

    def reflect(self, battle_log: list[dict[str, Any]], session_state: dict[str, Any]) -> AgentResult:
        """Run the reflection agent on the current phase results.

        The reflection agent analyzes the battle log, identifies patterns,
        and recommends strategy shifts. Results are stored on the blackboard.
        """
        with self._lock:
            if not self._reflection_enabled:
                return AgentResult(
                    agent_type="reflection",
                    status=AgentStatus.IDLE,
                    task_id="reflection-skip",
                    output={},
                )
            agent = ReflectionAgent()
            task = {
                "task_id": f"reflect-{int(time.time())}",
                "battle_log": battle_log,
                "session_state": session_state,
            }
            result = agent.run(task, self._context)
            self._results.append(result)
            self._trim_history()
            if result.output:
                self._blackboard.set_scalar("last_reflection", result.output)
                self._blackboard.set_scalar("strategy_shift", result.output.get("recommended_strategy_shift", ""))
                self._emit(
                    "reflection_output",
                    {
                        "task_id": task["task_id"],
                        "recommended_strategy_shift": self._blackboard["strategy_shift"],
                        "output_summary": str(result.output)[:500],
                    },
                )
                self._persist_state()

            return result

    def get_blackboard(self) -> dict[str, Any]:
        """Return a snapshot of the global (legacy flat-dict) blackboard state.

        Read-only consumers (diagnostics, the resume JSON's
        ``last_reflection``/``strategy_shift`` echoes) get the flat view they
        always had. Per-target namespaced state is NOT included here — use
        ``self._blackboard.snapshot()`` for the full namespaced picture, or
        ``self._blackboard.get_target(ip)`` for one host.
        """
        return self._blackboard.flat()

    def share_blackboard(self) -> "Blackboard":
        """Return the LIVE shared blackboard (not a copy).

        Used by the autonomous orchestrator (Tier 0 item 0.6b) so the autonomous
        attack path and the swarm ``route()`` loop share one source of truth --
        ``AttackModuleExecutor`` records module failures / reflection output
        into this Blackboard and the swarm's ``CriticAgent`` reads them back.
        The autonomous campaign and the swarm ``route()`` loop are alternative
        execution paths within a run (never concurrent), so a shared mutable
        reference is safe here; callers must use the atomic ``set_scalar`` /
        ``append_to`` / ``extend_list`` methods (not bare ``bb[k] = v``) so the
        internal lock protects writes. ``get_blackboard()`` remains the snapshot
        API for read-only persistence and diagnostics consumers.
        """
        return self._blackboard

    @property
    def model_client(self) -> Any:
        """The LLM client shared with swarm agents (None until set_model_client)."""
        return self._context.get("model_client")

    # ── Event emission + state persistence ───────────────────────────────

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        """Emit an event to the registered callback, swallowing errors."""
        if self._event_callback is None:
            return
        try:
            self._event_callback(event_type, data)
        except Exception:
            pass

    def _trim_history(self) -> None:
        """Bound ``_results`` and ``_battle_log`` in memory.

        Both lists are read only for their length and a recent tail
        (``_persist_state`` snapshots ``battle_log[-20:]``;
        ``_distill_episode_summary`` rolls up win-counts over the log). The
        full per-task outcome is persisted to ``swarm_state.json`` on every
        event, so dropping old in-memory entries reclaims the memory a long
        multi-cycle campaign would otherwise leak without losing any data a
        consumer actually reads.
        """
        if len(self._results) > self._max_results:
            del self._results[: len(self._results) - self._max_results]
        if len(self._battle_log) > self._max_battle_log:
            del self._battle_log[: len(self._battle_log) - self._max_battle_log]

    def _persist_state(self) -> None:
        """Persist a snapshot of swarm state for resume and live CLI progress."""
        if self._state_path is None:
            return
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            snapshot = {
                "agents": [
                    {
                        "agent_id": agent.agent_id,
                        "agent_type": agent.agent_type,
                        "status": agent.status.value,
                        "task_id": getattr(agent, "_task_id", ""),
                    }
                    for agent in self._agents.values()
                ],
                # Persist the FULL namespaced snapshot (global + per-target
                # buckets) so a resumed run restores per-host findings too,
                # not just the legacy flat global view. ``Blackboard.snapshot``
                # returns ``{__global__: {...}, "<target>": {...}, ...}``.
                "blackboard": self._blackboard.snapshot(),
                "blackboard_schema": "namespaced",
                "battle_log_tail": self._battle_log[-20:],
                "results_count": len(self._results),
                "last_reflection": self._blackboard.get("last_reflection", {}),
                "strategy_shift": self._blackboard.get("strategy_shift", ""),
                "updated_at": time.time(),
            }
            # Atomic write so progress and resume readers never see a partial file.
            # ``os.replace`` atomically overwrites an existing target on both
            # Windows and POSIX (``Path.rename`` raises ``FileExistsError`` on
            # Windows when the target exists — the second+ persist would throw,
            # be swallowed by the bare ``except``, and leave the stale first-
            # write file on disk; that's why ``access_achieved`` never showed
            # ``True`` on Windows even after the milestone block set it).
            tmp = self._state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
            os.replace(tmp, self._state_path)
        except Exception:
            pass

    def load_state(self, path: Path | str | None = None) -> bool:
        """Restore the shared blackboard from a persisted swarm_state.json.

        Tier 1.3: ``_persist_state`` already writes the blackboard snapshot on
        every event, but nothing originally read it back — so a
        resumed swarm started with a fresh blackboard, losing every discovered
        service / vulnerability hypothesis / credential / failed-module the
        prior run had accumulated. This restores those keys so the resumed
        swarm's agents (and critic, which is blackboard-aware) see the prior
        run's findings and don't repeat already-tried-and-failed work.

        Only the blackboard is restored (the agent list and battle-log tail are
        per-run execution state, not resumable intelligence). Unknown/extra
        keys in the file are ignored; missing keys keep their defaults. A
        missing/corrupt file returns False (fresh start), never raises — so a
        bad state file can't wedge the swarm.

        Handles two on-disk shapes:

        * **Namespaced** (current, ``blackboard_schema == "namespaced"`` or
          detected by presence of a ``__global__`` key): the value is
          ``{__global__: {...}, "<target>": {...}, ...}`` and is passed to
          ``Blackboard.merge_snapshot`` which restores both the global bucket
          and per-target buckets.
        * **Flat** (legacy, pre-parallel-swarm): the value is a plain
          ``{k: v}`` dict (the old ``dict(self._blackboard)`` global view).
          Merged key-by-key into the global bucket to preserve the original
          resume semantics — list values extended (order-preserving dedup),
          scalars replaced.
        """
        state_path = Path(path) if path is not None else self._state_path
        if state_path is None or not state_path.exists():
            return False
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        if not isinstance(data, dict):
            return False
        bb = data.get("blackboard")
        if not isinstance(bb, dict):
            return False

        # Namespaced shape (current): delegate to Blackboard.merge_snapshot.
        if data.get("blackboard_schema") == "namespaced" or "__global__" in bb:
            self._blackboard.merge_snapshot(bb)
            return True

        # Legacy flat shape: merge key-by-key into the global bucket. Keeps
        # the original resume semantics (list extend w/ dedup, scalar replace)
        # so a pre-parallel-swarm state file still resumes cleanly.
        for key, value in bb.items():
            current = self._blackboard.get(key)
            if isinstance(current, list) and isinstance(value, list):
                # Preserve ordering + dedup so resumed findings don't double up.
                self._blackboard.extend_list(key, value)
            else:
                self._blackboard.set_scalar(key, value)
        return True

    # ── Internal ────────────────────────────────────────────────────────

    def _spawn(self, agent_cls: type[Agent], task_id: str = "") -> Agent:
        """Instantiate a fresh agent instance."""
        agent = agent_cls()
        agent._task_id = task_id  # type: ignore[attr-defined]
        self._agents[agent.agent_id] = agent
        agent._set_status(AgentStatus.RUNNING)
        self._emit(
            "agent_started",
            {
                "agent_id": agent.agent_id,
                "agent_type": agent.agent_type,
                "task_id": task_id,
            },
        )
        self._persist_state()
        return agent
