"""Campaign persistence — checkpoint/timeline + orchestrator glue."""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from tools.attack_modules import get_module
from tools.attack_ui import get_ui
from tools.campaign.planner import PlannerMixin
from tools.campaign.state import AggressionLevel, AttackPhase, AttackState, AttackTask
from tools.exceptions import _EXC_GROUP_CATCH
from tools.logging_setup import get_logger
from tools.recon_pipeline import ReconConfig, ReconPipeline

logger = get_logger()
ui = get_ui()


class PersistenceMixin:
    _PERSISTENCE_MARKER_RE = re.compile(r"PERSISTENCE_INSTALLED:\s*(\S+)", re.IGNORECASE)

    def _extract_persistence_marker(self, output_text: str) -> str | None:
        m = self._PERSISTENCE_MARKER_RE.search(str(output_text or ""))
        return m.group(1).lower() if m else None

    async def _phase_persistence(self, state: AttackState) -> None:
        if not state.access_achieved:
            return
        logger.info(f"[PERSIST] Starting persistence against {state.target}")
        ui.phase_change("persistence")
        state.current_phase = AttackPhase.PERSISTENCE
        from tools.campaign.state import _report_autonomous_progress

        _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
        state.add_timeline_event("phase_start", "Persistence phase started")
        os_family = (state.recon_result.os_family if state.recon_result else "") or ""
        mod_names: list[str] = []
        if "windows" in os_family.lower():
            mod_names.append("WindowsPersistence")
        else:
            mod_names.append("LinuxPersistence")
        web_services = {"http", "https"}
        if state.recon_result and any((s.service or "").lower() in web_services for s in state.recon_result.services):
            mod_names.append("WebShellPersistence")
        if not getattr(self, "_tool_executor", None):
            state.add_timeline_event(
                "persistence_skipped", "No tool_executor wired -- persistence scripts not dispatched"
            )
            logger.info("[PERSIST] No tool_executor; persistence scripts not dispatched")
            return
        ctx = self._module_context(state)  # type: ignore[attr-defined]
        for mod_name in mod_names:
            module = get_module(mod_name)
            if module is None:
                state.add_timeline_event("persistence_skip", f"Module {mod_name} unavailable")
                continue
            try:
                mresult_dict = await asyncio.to_thread(module.run, ctx) or {}
            except _EXC_GROUP_CATCH as exc:
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
            )  # type: ignore[attr-defined]
            self._tasks[task.task_id] = task  # type: ignore[attr-defined]
            try:
                out = await asyncio.to_thread(self._tool_executor, script, {"target": state.target, "module": mod_name})  # type: ignore[attr-defined]
            except _EXC_GROUP_CATCH as exc:
                from tools.campaign.state import TaskStatus

                task.status = TaskStatus.FAILED
                task.error = str(exc)
                state.add_timeline_event("persistence_err", f"{mod_name} dispatch: {exc}")
                continue
            marker = self._extract_persistence_marker(str(out or ""))
            if marker:
                from tools.campaign.state import TaskStatus

                state.persistence_established.append(marker)
                task.status = TaskStatus.COMPLETED
                task.result = {"status": "success", "persistence": marker}
                state.add_timeline_event(
                    "persistence_established",
                    f"{mod_name} installed persistence via {marker}",
                    {"module": mod_name, "method": marker},
                )
            else:
                from tools.campaign.state import TaskStatus

                task.status = TaskStatus.FAILED
                task.error = "no PERSISTENCE_INSTALLED marker in dispatch output"
                state.add_timeline_event(
                    "persistence_failed", f"{mod_name} dispatch did not confirm persistence", {"module": mod_name}
                )


class AutonomousOrchestrator(PlannerMixin, PersistenceMixin):
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
        self._experience_store = experience_store
        if self._experience_store is None:
            try:
                from db import get_default_db
                from tools.experience_store import ExperienceStore

                self._experience_store = ExperienceStore(get_default_db())
            except _EXC_GROUP_CATCH:
                self._experience_store = None
        self._semantic_memory = semantic_memory
        if self._semantic_memory is None and bool(mission_config.get("semantic_memory", False)):
            try:
                from db import get_default_db
                from tools.semantic_memory import SemanticMemoryManager

                _ollama_cfg = mission_config.get("ollama", {}) or {}
                _embed_host = _ollama_cfg.get("embed_host") or _ollama_cfg.get("host", "https://api.ollama.com")
                self._semantic_memory = SemanticMemoryManager(
                    db=get_default_db(),
                    ollama_host=_embed_host,
                    embedding_model=str(mission_config.get("embedding_model", "nomic-embed-text")),
                )
            except _EXC_GROUP_CATCH as exc:
                logger.debug("SemanticMemoryManager wiring skipped: %r", exc)
                self._semantic_memory = None
        try:
            from tools.opsec import OpsecManager
            from tools.opsec import configure as _opsec_configure

            self._opsec = OpsecManager.from_config(mission_config or {})
            _primary_target = (mission_config or {}).get("target") or os.environ.get("EXPLOIT_TARGET", "")
            _ua_profile = self._opsec.profile
            if _primary_target:
                _ua_profile = self._opsec.resolve_for_target(_primary_target).profile
            _opsec_configure(_ua_profile)
        except _EXC_GROUP_CATCH:
            self._opsec = None
        from tools.campaign.executor import AttackModuleExecutor

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
        self._prereq_tasks_added = 0
        self._prereq_recovery_cap = max(1, int(self._max_module_failures))
        self._max_pivot_depth = int(mission_config.get("max_pivot_depth", 0))
        self._persistence_enabled = bool(mission_config.get("persistence_phase", False))
        self._checkpoint_every = max(0, int(mission_config.get("checkpoint_every", 0) or 0))
        self._adaptive_replan = bool(mission_config.get("adaptive_replan", False))
        self._auto_local_exploit_suggester = bool(
            mission_config.get("msf_auto_les", False)
            or ((mission_config.get("msf") or {}).get("auto_local_exploit_suggester", False))
        )
        self._dedup_targets = bool(mission_config.get("dedup_targets", False))
        self._skip_non_routable = bool(mission_config.get("skip_non_routable", False))
        self._hard_target_max_rounds = max(0, int(mission_config.get("hard_target_max_rounds", 0) or 0))
        self._original_target = ""
        self._resolved_ip = ""

    def _preflight_targets(self, targets: list[str]) -> list[str]:
        if not targets:
            return []
        from tools.mcp_shared import _check_allowlist
        from tools.validation_utils import is_local_target as _is_local
        from tools.validation_utils import is_private_or_local_target, resolve_target_to_ip

        seen_ips: set[str] = set()
        kept: list[str] = []
        for target in targets:
            target = (target or "").strip()
            if not target:
                continue
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
            resolved = resolve_target_to_ip(target)
            effective = resolved or target
            if self._skip_non_routable and is_private_or_local_target(effective):
                if not _is_local(effective):
                    state = self.get_state(target)
                    state.add_timeline_event(
                        "target_skipped_non_routable",
                        f"Target {target} is non-routable ({effective}); skipping network campaign",
                        {"target": target, "resolved_ip": effective or ""},
                    )
                    logger.info(f"[PREFLIGHT] {target} non-routable -- skipping")
                    continue
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

    async def run_autonomous_campaign(
        self, targets: list[str], *, resume: bool = False, original_target: str = "", resolved_ip: str = ""
    ) -> dict[str, Any]:
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
        targets = self._preflight_targets(targets)
        for target in targets:
            if not self._running:
                break
            try:
                result = await self._attack_target(target)
            except _EXC_GROUP_CATCH as exc:
                logger.exception(f"Crash-bounded: _attack_target({target}) raised {exc}")
                state = self.get_state(target)
                state.add_timeline_event("target_crash", f"Target {target} aborted: {exc}", {"error": str(exc)})
                result = {"status": "crashed", "error": str(exc), "state": state.to_dict()}
            results[target] = result
            completed += 1
            if self._checkpoint_every > 0 and completed % self._checkpoint_every == 0:
                try:
                    self.save_state()
                    logger.info(f"[CHECKPOINT] Saved attack state after {completed} target(s)")
                except _EXC_GROUP_CATCH as exc:
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

    def save_state(self, path: Path | None = None) -> Path:
        save_path = path or self._workspace / "attack_states.json"
        data = {
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "states": {t: s.to_dict() for t, s in self._states.items()},
            "tasks": {tid: t.to_dict() for tid, t in self._tasks.items()},
            "task_counter": self._task_counter,
        }
        save_path.write_text(json.dumps(data, indent=2, default=str))
        logger.info(f"Attack state saved to {save_path}")
        return save_path

    def load_state(self, path: Path) -> bool:
        if not path.exists():
            logger.info(f"load_state: no state file at {path} (fresh start)")
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (_EXC_GROUP_CATCH, ValueError, OSError) as exc:  # type: ignore
            logger.warning(f"load_state: corrupt state file {path} ({exc}); starting fresh")
            return False
        if not isinstance(data, dict):
            logger.warning(f"load_state: {path} is not a JSON object; starting fresh")
            return False
        states_data = data.get("states", {}) or {}
        tasks_data = data.get("tasks", {}) or {}
        try:
            self._task_counter = int(data.get("task_counter", 0))
        except _EXC_GROUP_CATCH:
            self._task_counter = 0
        loaded_states = 0
        loaded_tasks = 0
        for target, sdict in states_data.items():
            if not isinstance(sdict, dict):
                continue
            try:
                self._states[str(target)] = AttackState.from_dict(sdict)
                loaded_states += 1
            except _EXC_GROUP_CATCH as exc:
                logger.warning(f"load_state: skipping state for {target} ({exc})")
        for tid, tdict in tasks_data.items():
            if not isinstance(tdict, dict):
                continue
            try:
                self._tasks[str(tid)] = AttackTask.from_dict(tdict)
                loaded_tasks += 1
            except _EXC_GROUP_CATCH as exc:
                logger.warning(f"load_state: skipping task {tid} ({exc})")
        logger.info(f"Attack state loaded from {path} ({loaded_states} states, {loaded_tasks} tasks)")
        return loaded_states > 0 or loaded_tasks > 0

    def stop(self) -> None:
        self._running = False
        logger.info("Orchestrator stop signal received")
