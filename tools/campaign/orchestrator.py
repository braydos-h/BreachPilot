"""Campaign orchestrator — AutonomousOrchestrator core.

Canonical source for AutonomousOrchestrator.
Moved from tools.autonomous_orchestrator to break the god file.
Phase handlers live in tools.campaign.phases and are bound after class definition
to preserve ``self._phase_*`` call sites.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from tools.attack_ui import get_ui
from tools.logging_setup import get_logger
from tools.recon_pipeline import ReconConfig, ReconPipeline
from tools.validation_utils import is_local_target

from tools.campaign.executor import AttackModuleExecutor
from tools.campaign.state import (
    AggressionLevel,
    AttackPhase,
    AttackState,
    AttackTask,
    RetryEngine,
    TaskStatus,
    _report_autonomous_progress,
)

logger = get_logger()
ui = get_ui()

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

                _ollama_cfg = mission_config.get("ollama", {}) or {}
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
            scope_gate,
            risk_controller,
            evidence_store,
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
        self._hard_target_max_rounds = max(0, int(mission_config.get("hard_target_max_rounds", 0) or 0))

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
            logger.info(f"[PREFLIGHT] {len(targets)} target(s) -> {len(kept)} after preflight")
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
                state.add_timeline_event("target_crash", f"Target {target} aborted: {exc}", {"error": str(exc)})
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
            state.add_timeline_event("campaign_end", "Local-takeover campaign completed for local target")
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
            if not state.access_achieved and self._hard_target_max_rounds and state.aggression >= self._max_aggression:
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
                    if task.created_from != "recovery:prerequisite" and task.task_id not in prereq_scheduled:
                        prereq_task = self._maybe_schedule_prereq(
                            task,
                            state,
                            result.get("error", ""),
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
                        task.parameters.update(RetryEngine.get_retry_parameters(task.module_name, task.retry_count))
                        task.status = TaskStatus.RETRYING
                        logger.info(
                            f"Retrying {task.module_name} with modified parameters (attempt {task.retry_count})"
                        )
                        await asyncio.sleep(2**task.retry_count)  # Exponential backoff
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
        self,
        task: AttackTask,
        state: AttackState,
        error: str,
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
            # shim-aware find_producers
            try:
                import tools.autonomous_orchestrator as _ao_shim3  # type: ignore[import]

                _find_producers = getattr(_ao_shim3, "find_producers", None)
            except Exception:
                _find_producers = None
            if _find_producers is None:
                from tools.attack_modules import find_producers as _find_producers  # type: ignore[import]
            for mod in _find_producers(kind):
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
        failed_modules = {m for m in all_failed if len(state.failed_attempts.get(m, [])) < self._max_module_failures}
        dropped = all_failed - failed_modules
        if dropped:
            logger.info(
                f"Not retrying {len(dropped)} module(s) at failure cap ({self._max_module_failures}): {sorted(dropped)}"
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
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="SSHBruteForce",
                        target=state.target,
                        parameters={"port": port, "version": svc.version},
                        priority=75,
                    )
                )
                if "CVE-2024-6387" in str(svc.scripts.get("openssh_cves", "")):
                    tasks.append(
                        AttackTask(
                            task_id=self._new_task_id(),
                            phase=AttackPhase.EXPLOITATION,
                            module_name="RegreSSHion",
                            target=state.target,
                            parameters={"port": port},
                            priority=95,
                        )
                    )

            # SMB tasks
            elif service in ("microsoft-ds", "smb", "netbios-ssn"):
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="SMBRelay",
                        target=state.target,
                        parameters={"port": port},
                        priority=70,
                    )
                )
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="SMBNullSession",
                        target=state.target,
                        parameters={"port": port},
                        priority=65,
                    )
                )

            # HTTP/HTTPS tasks
            elif service in ("http", "https", "http-proxy"):
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="WebShellUpload",
                        target=state.target,
                        parameters={"port": port, "scheme": service},
                        priority=70,
                    )
                )
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="SQLInjection",
                        target=state.target,
                        parameters={"port": port, "scheme": service},
                        priority=65,
                    )
                )

            # FTP tasks
            elif service == "ftp":
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="FTPAnonymous",
                        target=state.target,
                        parameters={"port": port},
                        priority=60,
                    )
                )

            # Redis tasks
            elif service == "redis":
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="RedisExploit",
                        target=state.target,
                        parameters={"port": port},
                        priority=75,
                    )
                )

            # Docker/K8s tasks
            elif port in (2375, 2376, 6443, 10250):
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="ContainerBreakout",
                        target=state.target,
                        parameters={"port": port},
                        priority=80,
                    )
                )

            # RDP tasks
            elif service in ("ms-wbt-server", "rdp"):
                tasks.append(
                    AttackTask(
                        task_id=self._new_task_id(),
                        phase=AttackPhase.EXPLOITATION,
                        module_name="RDPExploit",
                        target=state.target,
                        parameters={"port": port},
                        priority=70,
                    )
                )

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

        logger.info(f"Attack state loaded from {path} ({loaded_states} states, {loaded_tasks} tasks)")
        return loaded_states > 0 or loaded_tasks > 0

    def stop(self) -> None:
        """Gracefully stop the orchestrator."""
        self._running = False
        logger.info("Orchestrator stop signal received")


# Bind phase handlers (preserve self._phase_* call sites without inheritance)
import tools.campaign.phases as _phases  # noqa: E402

AutonomousOrchestrator._phase_local_takeover = _phases._phase_local_takeover  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_reconnaissance = _phases._phase_reconnaissance  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_exploitation = _phases._phase_exploitation  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_privilege_escalation = _phases._phase_privilege_escalation  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_lateral_movement = _phases._phase_lateral_movement  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_validation = _phases._phase_validation  # type: ignore[attr-defined]
AutonomousOrchestrator._extract_persistence_marker = _phases._extract_persistence_marker  # type: ignore[attr-defined]
AutonomousOrchestrator._module_context = _phases._module_context  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_persistence = _phases._phase_persistence  # type: ignore[attr-defined]
AutonomousOrchestrator._run_adaptive_rounds = _phases._run_adaptive_rounds  # type: ignore[attr-defined]
AutonomousOrchestrator._schedule_vuln_chain = _phases._schedule_vuln_chain  # type: ignore[attr-defined]
