"""Swarm Orchestrator — routes tasks to specialist agents and merges results.

V2: Shared blackboard for inter-agent state, parallel dispatch with semaphore,
critic pre-check with blackboard awareness, and reflection-driven strategy adaptation.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from tools.swarm.agents.critic_agent import CriticAgent
from tools.swarm.agents.exploit_agent import ExploitAgent
from tools.swarm.agents.post_exploit_agent import PostExploitAgent
from tools.swarm.agents.recon_agent import ReconAgent
from tools.swarm.agents.reflection_agent import ReflectionAgent
from tools.swarm.agents.vuln_agent import VulnAgent
from tools.swarm.base import Agent, AgentResult, AgentStatus
from tools.swarm.blackboard import Blackboard

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
        # Phase 3: ``exploit_parallel`` controls whether exploit/post_exploit
        # tasks parallelize in ``route_parallel``. False (default) = recon-
        # first policy (only recon + analysis parallelize). True = exploits
        # also run in parallel (higher IDS/crash risk; opt in via
        # ``swarm.exploit_parallel: true`` in config.yaml).
        exploit_parallel: bool = False,
        # Bounded critic↔exploit negotiation rounds. 0 = legacy one-shot
        # behavior (critic's ``modify`` is applied once, then the task runs).
        # N>0 = after applying a ``modify``, the modified task is re-reviewed
        # by the critic up to N times until it returns ``approve``/``deny``,
        # a scope-expanding modification is proposed (rejected + logged), or
        # the same modification repeats twice in a row (deadlock break). The
        # negotiation is about *how* to execute a planned action (risk level,
        # tool swap, mutation flag, rate limiting), never *what* target/scope
        # to hit — the allowlist lock is untouched. See ``_negotiate``.
        negotiation_rounds: int = 0,
    ) -> None:
        self._context = context
        self._agent_registry = agent_registry or dict(_DEFAULT_AGENT_MAP)
        self._max_parallel = max_parallel
        self._critic_enabled = critic_enabled
        self._reflection_enabled = reflection_enabled
        self._event_callback = event_callback
        self._exploit_parallel = exploit_parallel
        self._negotiation_rounds = max(0, int(negotiation_rounds))
        self._state_path: Path | None = Path(state_path) if state_path else None
        self._agents: dict[str, Agent] = {}
        self._results: list[AgentResult] = []
        self._battle_log: list[dict[str, Any]] = []
        self._lock = threading.RLock()
        # §13: models.roles resolution runs lazily on first critic dispatch
        # (the router build is lazy + cached, so deferring keeps construction
        # cheap and avoids import weight on paths that never dispatch a critic).
        self._role_clients_resolved = False

        # Phase 3: per-(target, phase) milestone events. A dependent task
        # (e.g. a vuln task waiting on recon for the same target) awaits the
        # event before its agent runs, so cross-phase parallelism can't start
        # the recon→vuln→exploit chain out of order. Same-phase, different-
        # target tasks don't wait on each other (parallel recon on N hosts is
        # the win). ``threading.Event`` (not asyncio.Event) because agents run
        # in run_in_executor worker threads under route_parallel; the
        # await_milestone helper hops to the main loop to wait.
        self._milestone_events: dict[tuple[str, str], threading.Event] = {}

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
        self._blackboard: Blackboard = Blackboard(
            {
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
            }
        )

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

        Phase 3: the ``self._lock`` (an ``RLock``) now guards ONLY the
        orchestrator's own mutable state (``_agents``, ``_results``,
        ``_battle_log``, ``_milestone_events``) — NOT ``agent.run()`` /
        ``critic.run()``. Those run outside the lock so ``route_parallel`` can
        dispatch multiple agents concurrently (the lock is reentrant for the
        ``_spawn`` / ``_results.append`` / ``_battle_log.append`` /
        ``_mark_milestone`` calls that happen before/after the unlocked
        ``agent.run``). This is hazard #1 from the route_parallel warning,
        fixed. Hazards #2-#5 are fixed by Phase 1 (Blackboard), Phase 2
        (per-attempt workspaces), and the milestone gating below.
        """
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
        with self._lock:
            agent = self._spawn(agent_cls, task_id=task_id)

        # ── Critic pre-check (with blackboard awareness) ──
        # Runs UNLOCKED — critic.run() reads the blackboard (atomic via
        # Blackboard.get) and may call an LLM; holding the orchestrator lock
        # across that would serialize all parallel agents.
        if self._critic_enabled and phase not in ("recon", "report"):
            self._ensure_role_clients()
            critic_cls = self._agent_registry.get("critic", CriticAgent)
            critic = critic_cls()
            outcome = self._negotiate(critic, task, task_id, target, agent)
            if outcome is not None:
                # ``deny`` short-circuits the route — the blocked result is
                # already recorded and persisted by ``_negotiate``.
                return outcome

        # ── Execute agent ──
        # Runs UNLOCKED so parallel agents (route_parallel) actually run
        # concurrently. All blackboard writes inside agent.run go through the
        # atomic Blackboard API (Phase 1); per-attempt workspaces (Phase 2)
        # isolate filesystem writes. The orchestrator's own state
        # (_results, _battle_log, _agents) is touched only in the locked
        # blocks below.
        result = agent.run(task, self._context)
        agent._set_status(result.status)

        with self._lock:
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
        with self._lock:
            self._battle_log.append(
                {
                    "task_id": task_id,
                    "tool": task.get("tool", task.get("phase", "")),
                    "target": target,
                    "success": result.status == AgentStatus.COMPLETE,
                    "summary": str(result.output)[:500],
                    "error": result.error,
                    "findings": result.findings,
                    "new_tasks": result.new_tasks,
                }
            )
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

        # ── Phase milestone ──
        # Mark this (target, phase) complete so any dependent task waiting in
        # route_parallel can proceed. ``recon``→``analysis``/``exploit`` chain
        # depends on this; ``post_exploit`` depends on ``exploit``. Done in a
        # finally-style block so a failed agent still unblocks dependents (a
        # failed recon shouldn't wedge the whole campaign forever).
        self._mark_milestone(target, phase)

        self._persist_state()

        # ── Auto-reflect after exploitation phases ──
        if self._reflection_enabled and phase in ("exploit", "post_exploit"):
            self.reflect(self._battle_log, {"target_ip": target})

        return result

    async def route_parallel(self, tasks: list[dict[str, Any]]) -> list[AgentResult]:
        """Route multiple tasks in parallel with a concurrency limit.

        Phase 3: re-enabled. The 5 hazards from the old warning are fixed:

        1. **``route()`` RLock no longer serializes agent.run** — the lock now
           guards only ``_spawn``/``_results.append``/``_battle_log.append``/
           ``_mark_milestone`` (short, metadata-only critical sections);
           ``agent.run()`` and ``critic.run()`` run unlocked.
        2. **Blackboard is thread-safe + per-target namespaced** (Phase 1) —
           same-phase tasks on different targets write to isolated buckets;
           atomic ``extend_list``/``append_to`` make list merges race-free.
        3. **List read-modify-writes are atomic** (Phase 1) — all 4 named
           races (compromised_hosts, credentials_found, loot, failed_modules)
           go through ``Blackboard.append_to``/``extend_list``.
        4. **Precondition gating** (Phase 3) — a task with ``depends_on`` set
           to ``(target, phase)`` awaits the milestone event before running,
           so a vuln task won't start until its target's recon is done. Same-
           phase, different-target tasks run concurrently (parallel recon on
           N hosts is the win).
        5. **Per-attempt UUID workspaces** (Phase 2) — parallel exploit/post-
           exploit agents get isolated ``<ip>/<attempt_uuid>/`` dirs so they
           don't collide on exploit_script.py / loot.jsonl.

        Recon-first policy: by default only ``recon`` and ``analysis`` phases
        parallelize here. ``exploit``/``post_exploit`` stay sequential (run
        via the plain ``route()`` path) unless the caller passes them through
        here explicitly (e.g. a future ``swarm.exploit_parallel: true`` config
        flips the policy). This matches the operator's recon-first rollout
        choice — parallel recon (multi-host scan) + vuln research (multi-
        service CVE lookup) first; parallel exploits (higher IDS/crash risk)
        stay sequential until explicitly opted in.
        """
        # Recon-first filter: only parallelize the safe read-only phases here
        # by default. ``self._exploit_parallel`` (from config.yaml
        # ``swarm.exploit_parallel``) flips the policy so exploit/post_exploit
        # also parallelize. A task can also opt in individually via
        # ``force_parallel`` (used by the Phase 4 spawn_subagent tool when the
        # main AI explicitly delegates a parallel exploit batch).
        if self._exploit_parallel:
            _parallel_phases = ("recon", "analysis", "exploit", "post_exploit")
        else:
            _parallel_phases = ("recon", "analysis")
        parallel_tasks: list[dict[str, Any]] = []
        sequential_tasks: list[dict[str, Any]] = []
        for t in tasks:
            phase = t.get("phase", "recon")
            if phase in _parallel_phases or t.get("force_parallel"):
                parallel_tasks.append(t)
            else:
                sequential_tasks.append(t)

        semaphore = asyncio.Semaphore(self._max_parallel)

        async def _run_one(task: dict[str, Any]) -> AgentResult:
            # Precondition gating: wait for the dependency milestone before
            # starting the agent. ``depends_on`` is a (target, phase) tuple
            # serialized as a 2-list (JSON-friendly). Same-target deps block;
            # different-target same-phase tasks don't wait on each other (so
            # parallel recon on N hosts runs concurrently).
            depends_on = task.get("depends_on")
            if depends_on and isinstance(depends_on, (list, tuple)) and len(depends_on) == 2:
                dep_target, dep_phase = depends_on
                # Block in this worker thread (only this task waits, not the
                # whole loop). 10-min ceiling so a stuck dependency can't
                # wedge the campaign forever.
                self._await_milestone(dep_target, dep_phase, timeout=600.0)
            async with semaphore:
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(None, self.route, task)

        parallel_results: list[AgentResult] = []
        if parallel_tasks:
            parallel_results = list(await asyncio.gather(*[_run_one(t) for t in parallel_tasks]))

        # Sequential tasks (exploit/post_exploit in recon-first mode) run
        # via route() one at a time, after the parallel batch finishes, so a
        # vuln result feeds the next exploit cycle cleanly.
        sequential_results: list[AgentResult] = []
        for t in sequential_tasks:
            sequential_results.append(self.route(t))

        # Preserve input order: return results in the same order as ``tasks``.
        # gather preserves order for parallel_tasks; the sequential loop
        # preserves order for sequential_tasks; we interleave by matching
        # task_id back to the original input position.
        result_by_task_id: dict[str, AgentResult] = {}
        for r in parallel_results + sequential_results:
            result_by_task_id[r.task_id] = r
        ordered: list[AgentResult] = []
        for t in tasks:
            tid = t.get("task_id", t.get("id", ""))
            r = result_by_task_id.get(tid)
            if r is not None:
                ordered.append(r)
        # Any task that didn't produce a result (shouldn't happen) falls back
        # to a failed placeholder so the caller gets exactly len(tasks) items.
        while len(ordered) < len(tasks):
            ordered.append(
                AgentResult(
                    agent_type="unknown",
                    status=AgentStatus.FAILED,
                    task_id="",
                    error="route_parallel: no result produced for task",
                )
            )
        return ordered

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

    def _mark_milestone(self, target: str, phase: str) -> None:
        """Mark ``(target, phase)`` complete so dependent tasks can proceed.

        Idempotent: creating the event and setting it are both no-ops if
        already done. Called after every ``agent.run`` (even on failure) so a
        failed recon doesn't wedge a waiting vuln task forever — the vuln
        task will see an empty ``discovered_services`` and no-op, which is the
        correct degraded behavior, rather than hanging the campaign.
        """
        key = (target, phase)
        with self._lock:
            event = self._milestone_events.get(key)
            if event is None:
                event = threading.Event()
                self._milestone_events[key] = event
        event.set()

    def is_milestone_set(self, target: str, phase: str) -> bool:
        """Check whether ``(target, phase)`` has completed (non-blocking).

        Useful for a caller deciding whether to skip a redundant task, or for
        the agent loop to avoid re-dispatching a phase that already ran.
        """
        with self._lock:
            event = self._milestone_events.get((target, phase))
        return event is not None and event.is_set()

    def _await_milestone(self, target: str, phase: str, timeout: float | None = None) -> bool:
        """Block until ``(target, phase)`` is marked complete. Returns True if
        the event was set within timeout, False on timeout. Called from a
        worker thread (route_parallel runs agents via run_in_executor); safe
        to block here because only THIS task is waiting, not the whole loop.
        """
        with self._lock:
            event = self._milestone_events.get((target, phase))
            if event is None:
                event = threading.Event()
                self._milestone_events[(target, phase)] = event
        return event.wait(timeout=timeout)

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

    # ── Critic negotiation ─────────────────────────────────────────────

    # Keys the critic is allowed to modify during a negotiation. A ``modify``
    # proposing a change to any key NOT in this set is treated as a scope
    # expansion attempt and rejected (the modification is dropped, the
    # negotiation stops, and the original task runs). The negotiation is about
    # *how* to execute a planned action — never *what* target/scope to hit.
    # ``target``/``phase``/``scope``/``allowed_tools``/``asset_type`` define
    # WHAT the action touches, so they are off the table. The allowlist lock is
    # untouched by this allowlist: it is enforced separately at the MCP tool
    # layer regardless of what the critic proposes.
    _NEGOTIABLE_KEYS: frozenset[str] = frozenset(
        {
            "risk_level",
            "require_mutation",
            "alternative_tool",
            "rate_limit_seconds",
            "delay_seconds",
            "timeout_seconds",
            "max_retries",
            "mutation_strategy",
        }
    )

    def _negotiate(
        self,
        critic: Agent,
        task: dict[str, Any],
        task_id: str,
        target: str,
        agent: Agent,
    ) -> AgentResult | None:
        """Run the bounded critic↔exploit negotiation and return a blocked
        result on ``deny``, or ``None`` to let the route proceed.

        Behavior by ``self._negotiation_rounds``:

        - ``0`` (default, legacy one-shot): critic reviews once. ``deny``
          blocks; ``modify`` is applied once and the task runs (no re-review).
          Byte-for-byte the pre-negotiation behavior.
        - ``N>0``: critic reviews; on ``modify`` the modifications are applied
          and the critic re-reviews the modified task, up to ``N`` rounds. The
          loop stops early on: ``approve`` (task runs), ``deny`` (blocked), a
          scope-expanding modification (rejected + logged, original task runs),
          or a repeated modification (deadlock — original task runs).

        The negotiation never changes the target/scope: any modification
        touching a key outside ``_NEGOTIABLE_KEYS`` is dropped and the loop
        terminates with the pre-modification task. The allowlist lock is not
        consulted here (it lives at the MCP tool layer); this guard only
        prevents the critic from expanding WHAT the action touches.

        Runs UNLOCKED — ``critic.run`` may call an LLM. All orchestrator state
        mutations (``_results``/``_battle_log``) on the deny path happen under
        ``self._lock``.
        """
        critic_task = {
            "task_id": f"critic-{task_id}",
            "proposed_action": task,
        }
        critic_result = critic.run(critic_task, self._context)
        decision = critic_result.output.get("decision", "approve") if critic_result.output else "approve"
        reasoning = critic_result.output.get("reasoning", "") if critic_result.output else ""

        self._emit(
            "critic_decision",
            {"task_id": task_id, "target": target, "decision": decision, "reasoning": reasoning, "round": 0},
        )

        if decision == "deny":
            return self._record_block(critic, task, task_id, target, agent, reasoning)

        if decision == "modify":
            modifications = critic_result.output.get("modifications", {}) or {}
            # Legacy one-shot path: apply once, no re-review.
            if self._negotiation_rounds <= 0:
                safe = self._filter_modifications(modifications, task_id, target, round_idx=0)
                task.update(safe)
                return None
            # Bounded loop: re-review the modified task up to N rounds.
            return self._negotiation_loop(critic, task, task_id, target, agent, modifications)

        return None

    def _negotiation_loop(
        self,
        critic: Agent,
        task: dict[str, Any],
        task_id: str,
        target: str,
        agent: Agent,
        first_modifications: dict[str, Any],
    ) -> AgentResult | None:
        """Bounded re-review loop. ``first_modifications`` is the round-0
        ``modify`` output already extracted by ``_negotiate``."""
        # Track a hash of each round's proposed modifications so a repeated
        # proposal (same bytes twice in a row) breaks the loop as a deadlock.
        # ponytail: SHA256 of the JSON-sorted modifications dict — O(1) per
        # round, detects the exact-repeat case. A smarter detector would diff
        # semantic content; upgrade if a critic oscillates between two
        # different but equivalent modifications.
        last_hash = self._modifications_hash(first_modifications)
        # Apply the round-0 modifications (filtered for scope safety).
        safe = self._filter_modifications(first_modifications, task_id, target, round_idx=0)
        task.update(safe)

        for round_idx in range(1, self._negotiation_rounds + 1):
            critic_task = {"task_id": f"critic-{task_id}", "proposed_action": task}
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
                    "round": round_idx,
                },
            )

            if decision == "deny":
                return self._record_block(critic, task, task_id, target, agent, reasoning)
            if decision == "approve":
                return None
            # decision == "modify": check for scope expansion + deadlock.
            modifications = critic_result.output.get("modifications", {}) or {}
            cur_hash = self._modifications_hash(modifications)
            # If every proposed key is out-of-scope, the critic tried to expand
            # scope — reject, stop negotiating, run the pre-modification task.
            if not self._filter_modifications(modifications, task_id, target, round_idx=round_idx):
                self._emit(
                    "negotiation_scope_rejected",
                    {"task_id": task_id, "target": target, "round": round_idx, "modifications": modifications},
                )
                return None
            # Deadlock: same modification repeated twice in a row.
            if cur_hash == last_hash:
                self._emit(
                    "negotiation_deadlock",
                    {"task_id": task_id, "target": target, "round": round_idx},
                )
                return None
            last_hash = cur_hash
            safe = self._filter_modifications(modifications, task_id, target, round_idx=round_idx)
            task.update(safe)

        # Rounds exhausted without consensus: fall back to the current task
        # state (the last accepted modifications) + log. The task runs with
        # whatever modifications were applied in the final accepted round.
        self._emit(
            "negotiation_exhausted",
            {"task_id": task_id, "target": target, "rounds": self._negotiation_rounds},
        )
        return None

    def _filter_modifications(
        self,
        modifications: dict[str, Any],
        task_id: str,
        target: str,
        *,
        round_idx: int,
    ) -> dict[str, Any]:
        """Return only the keys in ``_NEGOTIABLE_KEYS``. Out-of-scope keys are
        dropped silently (the caller emits a ``negotiation_scope_rejected``
        event when the WHOLE modification is empty after filtering)."""
        if not isinstance(modifications, dict):
            return {}
        safe: dict[str, Any] = {}
        rejected: list[str] = []
        for key, value in modifications.items():
            if key in self._NEGOTIABLE_KEYS:
                safe[key] = value
            else:
                rejected.append(key)
        if rejected:
            self._emit(
                "negotiation_keys_rejected",
                {"task_id": task_id, "target": target, "round": round_idx, "keys": rejected},
            )
        return safe

    @staticmethod
    def _modifications_hash(modifications: dict[str, Any]) -> str:
        """Stable hash of a modifications dict for deadlock detection."""
        try:
            return hashlib.sha256(json.dumps(modifications, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        except (TypeError, ValueError):
            return ""

    def _record_block(
        self,
        critic: Agent,
        task: dict[str, Any],
        task_id: str,
        target: str,
        agent: Agent,
        reasoning: str,
    ) -> AgentResult:
        """Record a critic ``deny`` as a blocked result + battle-log entry."""
        with self._lock:
            blocked_result = AgentResult(
                agent_type=agent.agent_type,
                status=AgentStatus.BLOCKED,
                task_id=task_id,
                error=f"Critic blocked: {reasoning}",
            )
            agent._set_status(AgentStatus.BLOCKED)
            self._results.append(blocked_result)
            self._battle_log.append(
                {
                    "task_id": task_id,
                    "tool": task.get("tool", task.get("phase", "")),
                    "target": target,
                    "success": False,
                    "error": f"Critic blocked: {reasoning}",
                }
            )
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
