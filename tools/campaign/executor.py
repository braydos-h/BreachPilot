"""Campaign executor — AttackModuleExecutor with target-lock and MCP-safe catches."""

from __future__ import annotations

import asyncio
import inspect
import re
import time
from typing import Any, Callable

from tools.attack_modules import AttackModule, ModuleContext, ModuleResult, _module_target_signature, get_module
from tools.attack_ui import get_ui
from tools.campaign.state import (
    AggressionLevel,
    AttackState,
    AttackTask,
    TaskStatus,
    _report_autonomous_progress,
)
from tools.exceptions import _EXC_GROUP_CATCH
from tools.logging_setup import get_logger

logger = get_logger()
ui = get_ui()


class AttackModuleExecutor:
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
        self._experience_store = experience_store
        self._opsec = opsec_manager
        self._semantic_memory = semantic_memory
        self._tool_executor = tool_executor
        self._blackboard: dict[str, Any] = blackboard if blackboard is not None else {}
        self._mission_config: dict[str, Any] = mission_config or {}
        self._model_client = model_client
        self._critic = critic_agent
        self._reflection = reflection_agent
        self._action_count = 0

    async def execute(self, task: AttackTask, state: AttackState) -> dict[str, Any]:
        task.status = TaskStatus.RUNNING
        task.started_at = time.monotonic()
        self._action_count += 1
        action_num = self._action_count
        logger.info(f"Executing {task.module_name} against {task.target} (attempt {task.retry_count + 1})")
        ui.action_status(action_num=action_num, tool=task.module_name, target=task.target, phase=task.phase.value)
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
        if self._risk_controller:
            if not self._risk_controller.can_proceed():
                task.status = TaskStatus.BLOCKED
                task.error = "Risk budget exhausted"
                return {"success": False, "error": task.error, "blocked": True}
        critic_decision = await asyncio.to_thread(self._run_critic, task)
        if critic_decision is not None:
            decision = critic_decision.get("decision", "approve")
            if decision == "deny":
                task.status = TaskStatus.BLOCKED
                task.error = f"Critic denied: {critic_decision.get('reasoning', '')}"
                state.add_timeline_event("critic_deny", task.error)
                self._record_failure_on_blackboard(task.module_name)
                return {"success": False, "error": task.error, "blocked": True, "critic": critic_decision}
            if decision == "modify":
                self._apply_critic_modifications(task, critic_decision.get("modifications", {}))
                state.add_timeline_event(
                    "critic_modify", f"Critic modified {task.module_name}: {critic_decision.get('reasoning', '')}"
                )
        module = get_module(task.module_name)
        if not module:
            task.status = TaskStatus.FAILED
            task.error = f"Module {task.module_name} not found"
            state.record_failure(task.module_name, task.error)
            self._record_failure_on_blackboard(task.module_name)
            return {"success": False, "error": task.error}
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
            access_achieved=state.access_achieved,
            privilege_level=state.privilege_level,
            sessions=([{"shell": state.shell_type}] if state.access_achieved and state.shell_type else []),
            phase=state.current_phase.value,
            evidence_refs=list(state.loot)[-10:],
        )
        if self._opsec is not None:
            try:
                mgr = self._opsec
                resolver = getattr(self._opsec, "resolve_for_target", None)
                if resolver is not None and task.target:
                    mgr = resolver(task.target)
                await mgr.acquire_pacing(task.aggression.value)
            except _EXC_GROUP_CATCH as exc:  # noqa: BLE001
                logger.debug(f"OPSEC pacing skipped for {task.module_name}: {exc}")
        try:
            timeout = task.parameters.get("timeout", 300)
            module_run = asyncio.to_thread(module.run, ctx)
            try:
                result = await asyncio.wait_for(module_run, timeout=timeout)
            except asyncio.TimeoutError:
                if inspect.iscoroutine(module_run):
                    module_run.close()
                raise
            mresult = ModuleResult.to_result(result)
            dispatch_failure = False
            if self._tool_executor is not None and mresult.status not in ("info",):
                dispatch_out = await self._dispatch_module_artifact(module, mresult, ctx, task, state)
                if dispatch_out is not None:
                    output, classification = dispatch_out
                    if classification.get("evidence"):
                        mresult.evidence.extend(classification["evidence"])
                    outcome = str(classification.get("outcome", "unknown")).lower()
                    if outcome == "compromise":
                        if classification.get("shell_type"):
                            mresult.shell_type = str(classification["shell_type"])
                        if classification.get("privilege_level"):
                            mresult.privilege_level = str(classification["privilege_level"])
                        state.add_timeline_event(
                            "compromise_verified",
                            f"{task.module_name} produced verified shell ({mresult.shell_type or 'shell'}) against {task.target}",
                            {"outcome": outcome, "evidence": classification.get("evidence", [])},
                        )
                    elif outcome == "cred_dump":
                        mresult.credentials_found.append(
                            f"dump:{task.module_name}:{classification.get('evidence', ['creds'])[0]}"
                        )
                        state.add_timeline_event(
                            "cred_dump_verified",
                            f"{task.module_name} produced a credential dump against {task.target}",
                            {"evidence": classification.get("evidence", [])},
                        )
                    elif outcome == "failure":
                        dispatch_failure = True
                        if not mresult.note:
                            mresult.note = "Dispatched artifact reported failure markers"
                        state.add_timeline_event(
                            "dispatch_failure",
                            f"{task.module_name} dispatch output signalled failure",
                            {"evidence": classification.get("evidence", [])},
                        )
            result = mresult.to_dict()
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
                except _EXC_GROUP_CATCH:  # noqa: BLE001
                    logger.debug(f"ExperienceStore record skipped for {module.name}")
            task.result = result
            _succeeded = result.get("status") in ("success", "exploited", "script_generated") and not dispatch_failure
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
                await asyncio.to_thread(self._record_lesson_on_success, task, state, result)
            else:
                task.error = result.get("note", "Module did not achieve exploitation")
                state.record_failure(task.module_name, task.error)
                state.add_timeline_event("failure", f"{task.module_name} did not achieve exploitation")
                self._record_failure_on_blackboard(task.module_name)
            await asyncio.to_thread(self._run_reflection, task, state, {"success": _succeeded, "result": result})
            return {"success": _succeeded, "result": result}
        except asyncio.TimeoutError:
            task.status = TaskStatus.FAILED
            task.error = f"Timeout after {timeout}s"
            state.record_failure(task.module_name, task.error)
            state.add_timeline_event("timeout", task.error)
            logger.warning(f"Module {task.module_name} timed out against {task.target}")
            self._record_failure_on_blackboard(task.module_name)
            return {"success": False, "error": task.error, "timeout": True}
        except _EXC_GROUP_CATCH as exc:
            task.status = TaskStatus.FAILED
            task.error = str(exc)
            state.record_failure(task.module_name, task.error)
            state.add_timeline_event("error", f"Exception in {task.module_name}: {task.error}")
            logger.exception(f"Module {task.module_name} failed against {task.target}")
            self._record_failure_on_blackboard(task.module_name)
            return {"success": False, "error": task.error}

    async def _dispatch_module_artifact(
        self, module: AttackModule, mresult: ModuleResult, ctx: ModuleContext, task: AttackTask, state: AttackState
    ) -> tuple[str, dict[str, Any]] | None:
        executor = self._tool_executor
        if executor is None:
            return None
        command = mresult.suggested_command or ""
        if not command:
            script_text = mresult.script
            if not script_text:
                try:
                    script_text = module.generate_python_script(ctx) or ""
                except _EXC_GROUP_CATCH:
                    script_text = ""
            if script_text:
                try:
                    modules_dir = ctx.workspace / "modules"
                    modules_dir.mkdir(parents=True, exist_ok=True)
                    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{module.name}_{ctx.target_ip}.py")
                    script_path = modules_dir / safe_name
                    script_path.write_text(script_text, encoding="utf-8")
                    command = f"python {script_path} {ctx.target_ip}"
                except _EXC_GROUP_CATCH as exc:
                    state.add_timeline_event("dispatch_write_err", f"Failed to write script for {module.name}: {exc}")
                    return None
        if not command:
            return None
        try:
            output = await asyncio.to_thread(executor, command, {"target": task.target})
        except _EXC_GROUP_CATCH as exc:
            state.add_timeline_event(
                "dispatch_err", f"{module.name} dispatch raised: {exc}", {"command": command[:200]}
            )
            return None
        output_text = str(output or "")
        state.add_timeline_event(
            "module_dispatch",
            f"Dispatched {module.name} artifact ({len(output_text)} bytes output)",
            {"command": command[:200], "output_len": len(output_text)},
        )
        try:
            from tools.exploit_agent.outcome_classify import classify_exploit_result

            classification = classify_exploit_result(output_text)
        except _EXC_GROUP_CATCH:
            classification = {"outcome": "unknown", "shell_type": "", "privilege_level": "", "evidence": []}
        return output_text, classification

    def _run_critic(self, task: AttackTask) -> dict[str, Any] | None:
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
            result = self._critic.run({"task_id": task.task_id, "proposed_action": proposed}, context)
            if result and result.output:
                return dict(result.output)
        except _EXC_GROUP_CATCH as exc:
            logger.warning("Critic pre-check raised for %s (failing open): %r", task.module_name, exc)
        return None

    def _apply_critic_modifications(self, task: AttackTask, modifications: dict[str, Any]) -> None:
        if not modifications:
            return
        risk_level = modifications.get("risk_level")
        if risk_level == "medium" and task.aggression == AggressionLevel.MAXIMUM:
            task.aggression = AggressionLevel.AGGRESSIVE
            task.parameters["critic_risk_downgrade"] = "high->medium"
        elif risk_level == "low" and task.aggression in (AggressionLevel.MAXIMUM, AggressionLevel.AGGRESSIVE):
            task.aggression = AggressionLevel.NORMAL
            task.parameters["critic_risk_downgrade"] = "->low"
        if modifications.get("require_mutation"):
            task.parameters["critic_require_mutation"] = True
        logger.info("Critic modify applied to %s: %s", task.module_name, modifications)

    def _record_failure_on_blackboard(self, module_name: str) -> None:
        bb = self._blackboard
        if not bb:
            return
        if hasattr(bb, "extend_list"):
            bb.extend_list("failed_modules", [module_name])
        else:
            failed = bb.setdefault("failed_modules", [])
            if module_name not in failed:
                failed.append(module_name)

    def _record_success_on_blackboard(self, module_name: str) -> None:
        bb = self._blackboard
        if not bb:
            return
        if hasattr(bb, "remove_from_list"):
            bb.remove_from_list("failed_modules", module_name)
            bb.append_to("successful_modules", module_name)
        else:
            failed = bb.get("failed_modules")
            if failed and module_name in failed:
                failed.remove(module_name)
            worked = bb.setdefault("successful_modules", [])
            if module_name not in worked:
                worked.append(module_name)

    def _run_reflection(self, task: AttackTask, state: AttackState, result: dict[str, Any]) -> None:
        if self._reflection is None:
            return
        inner = result.get("result") if isinstance(result, dict) else None
        status = inner.get("status", "") if isinstance(inner, dict) else ""
        success = bool(result.get("success")) and status in ("success", "exploited", "script_generated", "info")
        battle_entry = {
            "tool": task.module_name,
            "target": task.target,
            "success": success,
            "summary": str(status),
            "error": result.get("error", ""),
        }
        try:
            self._reflection.run(
                {"task_id": task.task_id, "battle_log": [battle_entry], "session_state": state.to_dict()},
                {"memory": None, "model_client": self._model_client, "blackboard": self._blackboard},
            )
        except _EXC_GROUP_CATCH as exc:
            logger.warning("Reflection post-check raised for %s (continuing): %r", task.module_name, exc)

    def _record_lesson_on_success(self, task: AttackTask, state: AttackState, result: dict[str, Any]) -> None:
        if self._semantic_memory is None:
            return
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
        except _EXC_GROUP_CATCH as exc:
            logger.debug("store_lesson skipped for %s: %r", task.module_name, exc)
