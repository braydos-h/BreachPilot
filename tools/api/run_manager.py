"""RunManager: owns the single active run, MCP session, and tool-call serialization.

v1 supports one live run at a time (HTTP 409 on a second). This matches the
fixed MCP port, process-global ``EXPLOIT_TARGET`` env, plugin registry, and
shared UI state. The manager:

- Creates a run row + ``start_confirm`` decision on ``POST /runs``.
- Transitions to ``queued`` -> ``running`` when the decision is answered.
- Owns the ``asyncio.Task`` running ``AssessmentService.execute``.
- Serializes manual tool calls (``POST /runs/{id}/tools/{name}/calls``) through
  the live MCP ``ClientSession`` with a per-run ``asyncio.Lock``.
- On cancel/shutdown: deny decisions, cancel the task, close the MCP session,
  terminate the process tree, flush events, mark the run accurately.
"""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tools.api.decision_broker import DecisionBroker
from tools.api.errors import APIError
from tools.api.event_broker import EventBrokerRegistry, RunEventBroker
from tools.api.persistence import ApiPersistence
from tools.api.session_titler import generate_session_title
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.run_service.models import (
    Decision,
    DecisionKind,
    RunPreview,
    RunRequest,
    RunResult,
    RunState,
)
from tools.run_service.providers import (
    ApiApprovalProvider,
    ApiDecisionProvider,
    ApiEventSink,
    CancellationToken,
)

if TYPE_CHECKING:
    from tools.run_service.service import Callables


class RunHandle:
    """Runtime state for one active run."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.task: asyncio.Task[Any] | None = None
        self.cancellation = CancellationToken()
        self.decision_broker: DecisionBroker | None = None
        self.event_broker: RunEventBroker | None = None
        self.mcp_session: Any = None
        self.exploit_policy: Any = None
        self.tool_schemas: list[dict[str, Any]] = []
        self.tool_lock = asyncio.Lock()
        self.preview: RunPreview | None = None
        self.request: RunRequest | None = None
        # Frozen config snapshot captured at prepare() time so the preview's
        # permission/budgets/destructive verdicts stay valid even if the
        # operator PATCHes /config between confirmation and execution.
        self.config_snapshot: dict[str, Any] | None = None


class RunManager:
    """Single-active-run manager."""

    def __init__(
        self,
        persistence: ApiPersistence,
        event_registry: EventBrokerRegistry,
        *,
        config: dict[str, Any],
        config_path: Path,
        callables: "Callables | None" = None,
    ) -> None:
        self._persistence = persistence
        self._events = event_registry
        self._config = config
        self._config_path = config_path
        self._callables = callables
        self._active: RunHandle | None = None
        self._lifecycle_lock = asyncio.Lock()

    @property
    def has_active(self) -> bool:
        return self._active is not None

    @property
    def config(self) -> dict[str, Any]:
        return self._config

    @property
    def config_path(self) -> Path:
        return self._config_path

    @property
    def active(self) -> RunHandle | None:
        return self._active

    async def create_run(self, request: RunRequest) -> tuple[str, RunPreview, Decision | None]:
        """Prepare a run and create a start_confirm decision (if needed).

        Returns ``(run_id, preview, decision_or_none)``. The decision is None
        when ``request.yes`` is True (skip gate) or the run is non-destructive
        with no required confirmation.
        """
        async with self._lifecycle_lock:
            return await self._create_run_locked(request)

    async def _create_run_locked(
        self, request: RunRequest,
    ) -> tuple[str, RunPreview, Decision | None]:
        if self._active is not None:
            raise APIError("conflict", "A run is already active. Cancel it first.", status_code=409)

        request.config_path = self._config_path
        request.reports_dir = self._persistence.reports_dir
        from tools.run_service import AssessmentService
        service = AssessmentService(config=self._config, callables=self._callables)
        preview = await service.prepare(request)

        # Persist the run row.
        self._persistence.create_run(
            run_id=preview.run_id,
            request=_request_to_dict(request),
            preview=_preview_to_dict(preview),
        )

        # Create event broker for this run.
        event_broker = self._events.get_or_create(preview.run_id)
        handle = RunHandle(preview.run_id)
        handle.preview = preview
        handle.request = request
        # Freeze the config that produced this preview so execution sees the
        # same permission/budgets/destructive verdict the operator confirmed.
        handle.config_snapshot = copy.deepcopy(self._config)
        handle.event_broker = event_broker
        handle.decision_broker = DecisionBroker(preview.run_id, self._persistence)
        self._active = handle

        try:
            return await self._setup_handle_locked(handle, request, preview)
        except BaseException:
            handle.decision_broker.cancel_all()
            event_broker.close()
            self._active = None
            self._persistence.update_run_state(
                preview.run_id, RunState.FAILED.value,
                error="Run setup failed.",
            )
            raise

    async def _setup_handle_locked(
        self, handle: RunHandle, request: RunRequest, preview: RunPreview,
    ) -> tuple[str, RunPreview, Decision | None]:
        decision = None
        if not request.yes:
            self._persistence.update_run_state(preview.run_id, RunState.AWAITING_CONFIRMATION.value)
            await handle.event_broker.emit("state", {"state": RunState.AWAITING_CONFIRMATION.value})
            decision = Decision(
                id="", run_id=preview.run_id, kind=DecisionKind.START_CONFIRM,
                prompt_text="Proceed?" if not preview.destructive else "DESTRUCTIVE mode — confirm to proceed.",
                required_text=preview.required_confirmation_text,
            )
            did = await handle.decision_broker.create(decision)
            await handle.event_broker.emit("approval", {
                "decision_id": did,
                "kind": "start_confirm",
                "prompt_text": decision.prompt_text,
                "required_text": decision.required_text,
            })
        else:
            self._persistence.update_run_state(preview.run_id, RunState.QUEUED.value)
            await handle.event_broker.emit("state", {"state": RunState.QUEUED.value})
            handle.task = asyncio.create_task(self._execute_run(handle))
        return preview.run_id, preview, decision

    async def confirm_and_start(self, run_id: str, decision_id: str, answer: str) -> None:
        """Resolve the start_confirm decision and kick off execution."""
        async with self._lifecycle_lock:
            handle = self._require_active(run_id)
            if handle.task is not None:
                raise APIError("conflict", "Run execution has already started.", status_code=409)
            if handle.preview and handle.preview.destructive:
                valid = answer == handle.preview.required_confirmation_text
            else:
                valid = answer.strip().lower() in {"y", "yes"}
            if not valid:
                raise APIError("invalid_confirmation", "Confirmation text does not match.", status_code=400)
            self._persistence.update_run_state(run_id, RunState.QUEUED.value)
            await handle.event_broker.emit("state", {"state": RunState.QUEUED.value})
            if not handle.decision_broker or not handle.decision_broker.resolve(decision_id, answer):
                raise APIError("decision_not_found", "Decision not found or already answered.", status_code=404)
            handle.task = asyncio.create_task(self._execute_run(handle))

    async def _execute_run(self, handle: RunHandle) -> None:
        """Run ``AssessmentService.execute`` in the background."""
        from tools.run_service import AssessmentService
        # Use the frozen config snapshot captured at prepare() time so the
        # confirmed preview (permission/destructive/budgets) stays accurate.
        service = AssessmentService(config=handle.config_snapshot, callables=self._callables)

        decision_provider = ApiDecisionProvider(
            handle.run_id, handle.decision_broker, handle.event_broker.emit,
        )
        event_sink = ApiEventSink(handle.run_id, handle.event_broker)
        approval_provider = ApiApprovalProvider(
            handle.run_id, decision_provider, handle.preview.target_ip,
        )

        try:
            self._persistence.update_run_state(handle.run_id, RunState.RUNNING.value)
            await handle.event_broker.emit("state", {"state": RunState.RUNNING.value})
            result = await service.execute(
                handle.request, handle.preview,
                decision_provider=decision_provider,
                event_sink=event_sink,
                cancellation=handle.cancellation,
                config=handle.config_snapshot,
                approval_provider=approval_provider,
                session_attach=lambda session, schemas, policy: self.set_mcp_session(
                    handle.run_id, session, schemas, policy,
                ),
            )
            state = RunState.COMPLETED.value if not result.error else RunState.FAILED.value
            result_dict = _result_to_dict(result)
            self._persistence.update_run_state(
                handle.run_id, state, error=result.error,
                result=result_dict,
            )
            await handle.event_broker.emit("state", {"state": state, "result": result_dict})
            await self._maybe_title_run(handle, result_dict)
        except asyncio.CancelledError:
            self._persistence.update_run_state(handle.run_id, RunState.CANCELLED.value)
            await handle.event_broker.emit("state", {"state": RunState.CANCELLED.value})
            raise
        except _EXC_GROUP_CATCH as exc:
            # Catch BaseExceptionGroup too (MCP subprocess death raises it,
            # and it is NOT a subclass of Exception). Without this the run
            # would stay "running" forever. See tools/exceptions.py.
            self._persistence.update_run_state(handle.run_id, RunState.FAILED.value, error=str(exc))
            await handle.event_broker.emit("error", {"message": str(exc)})
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            await self._maybe_title_run(handle, {"error": str(exc)})
        finally:
            if handle.decision_broker:
                handle.decision_broker.cancel_all()
            handle.event_broker.close()
            async with self._lifecycle_lock:
                if self._active is handle:
                    self._active = None

    async def _maybe_title_run(
        self, handle: "RunHandle", result_dict: dict[str, Any],
    ) -> None:
        """Ask gemma4:31b-cloud for a session title; persist on success.

        Best-effort: any failure (ollama unreachable, missing pkg, parse
        error, empty response) is logged at DEBUG and swallowed. Skips
        runs that already have a title (e.g. resumed runs keep the parent's
        title). Fires after the run state is persisted + emitted so a slow
        or failing titler never delays the state transition.
        """
        try:
            existing = self._persistence.get_run(handle.run_id) or {}
            if existing.get("title"):
                return
            host = str(
                (self._config.get("ollama") or {}).get("host")
                or "https://api.ollama.com"
            )
            request_dict = _request_to_dict(handle.request) if handle.request else {}
            title = await generate_session_title(
                result_dict, request_dict, host=host,
            )
            if title:
                self._persistence.update_run_title(handle.run_id, title)
                await handle.event_broker.emit("title", {"title": title})
        except Exception as exc:  # best-effort — never propagate
            import logging as _logging
            _logging.getLogger(__name__).debug(
                "session title persistence failed for %s: %s", handle.run_id, exc,
            )

    async def cancel_run(self, run_id: str) -> None:
        """Cooperative cancellation: set the flag + cancel the task."""
        async with self._lifecycle_lock:
            handle = self._require_active(run_id)
            event_error: Exception | None = None
            try:
                self._persistence.update_run_state(run_id, RunState.CANCELLING.value)
                await handle.event_broker.emit("state", {"state": RunState.CANCELLING.value})
            except Exception as exc:
                event_error = exc
            handle.cancellation.cancel()
            if handle.decision_broker:
                handle.decision_broker.cancel_all()
            task = handle.task
            if task is None:
                try:
                    self._persistence.update_run_state(run_id, RunState.CANCELLED.value)
                    if event_error is None:
                        await handle.event_broker.emit("state", {"state": RunState.CANCELLED.value})
                finally:
                    handle.event_broker.close()
                    self._active = None
                if event_error is not None:
                    raise event_error
                return
            task.cancel()

        timeout = max(0.0, float(
            self._config.get("api", {}).get("shutdown_timeout_seconds", 15)
        ))
        _, pending = await asyncio.wait({task}, timeout=timeout)
        if pending:
            raise APIError("cancel_timeout", "Run cancellation timed out.", status_code=504)
        if event_error is not None:
            raise event_error

    async def answer_decision(self, run_id: str, decision_id: str, answer: str) -> dict[str, Any]:
        """Answer a pending decision (goal_select or tool_approval)."""
        handle = self._require_active(run_id)
        if handle.decision_broker is None:
            raise APIError("no_decisions", "No decision broker for this run.", status_code=400)
        decision = self._persistence.get_decision(decision_id)
        if decision is None or decision["run_id"] != run_id or decision["status"] != "pending":
            raise APIError("decision_not_found", "Decision not found or already answered.", status_code=404)
        if decision["kind"] == DecisionKind.START_CONFIRM.value:
            await self.confirm_and_start(run_id, decision_id, answer)
            return {"decision_id": decision_id, "status": "answered"}
        ok = handle.decision_broker.resolve(decision_id, answer)
        if not ok:
            raise APIError("decision_not_found", "Decision not found or already answered.", status_code=404)
        await handle.event_broker.emit("approval", {
            "decision_id": decision_id, "status": "answered", "answer": answer,
        })
        if not any(
            row["status"] == "pending"
            for row in self._persistence.list_decisions(run_id)
        ):
            self._persistence.update_run_state(run_id, RunState.RUNNING.value)
            await handle.event_broker.emit("state", {"state": RunState.RUNNING.value})
        return {"decision_id": decision_id, "status": "answered"}

    async def list_decisions(self, run_id: str) -> list[dict[str, Any]]:
        if self._persistence.get_run(run_id) is None:
            raise APIError("not_found", "Run not found.", status_code=404)
        return self._persistence.list_decisions(run_id)

    async def call_tool(self, run_id: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Policy-gated REST bridge for manual WebUI tool calls."""
        handle = self._require_active(run_id)
        if handle.mcp_session is None:
            raise APIError("no_session", "MCP session is not open.", status_code=409)
        if handle.exploit_policy is None:
            raise APIError("no_policy", "Exploit policy is not available.", status_code=409)
        if not any(
            (schema.get("function") or {}).get("name") == tool_name
            for schema in handle.tool_schemas
        ):
            raise APIError("tool_not_found", "Unknown MCP tool.", status_code=404)
        async with handle.tool_lock:
            approved = await handle.exploit_policy.approve_action(
                tool_name,
                json.dumps(arguments, sort_keys=True, default=str),
                "Manual WebUI tool call",
            )
            if not approved:
                raise APIError("tool_denied", "Exploit policy denied the tool call.", status_code=403)
            try:
                result = await handle.mcp_session.call_tool(tool_name, arguments=arguments)
            except _EXC_GROUP_CATCH as exc:
                # BaseExceptionGroup from MCP subprocess death is not an Exception.
                if _is_exception_group(exc):
                    _log_nested_exceptions(exc)
                raise APIError("tool_error", "MCP tool call failed.", status_code=500) from exc
        # Extract text content.
        text = _extract_text(result)
        return {"tool": tool_name, "result": text}

    def get_tool_schemas(self, run_id: str) -> list[dict[str, Any]]:
        handle = self._active
        if handle is None or handle.run_id != run_id:
            return []
        return handle.tool_schemas

    def set_mcp_session(
        self, run_id: str, session: Any, schemas: list[dict[str, Any]], policy: Any,
    ) -> None:
        """Called by the service when the MCP session opens."""
        handle = self._active
        if handle is not None and handle.run_id == run_id:
            handle.mcp_session = session
            handle.tool_schemas = schemas
            handle.exploit_policy = policy

    async def shutdown(self) -> None:
        """Clean up on daemon shutdown: cancel active run, flush events."""
        try:
            if self._active:
                await self.cancel_run(self._active.run_id)
        finally:
            self._events.close_all()

    def _require_active(self, run_id: str) -> RunHandle:
        handle = self._active
        if handle is None or handle.run_id != run_id:
            raise APIError("not_found", "No active run with that id.", status_code=404)
        return handle


def _extract_text(result: Any) -> str:
    """Pull textual content from an MCP call_tool result."""
    def _get(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    blocks = _get(result, "content", []) or []
    parts: list[str] = []
    for block in blocks:
        t = _get(block, "text", None)
        if t is not None:
            parts.append(str(t))
    return "\n".join(p for p in parts if p).strip()


def _request_to_dict(req: RunRequest) -> dict[str, Any]:
    return {
        "target": req.target, "mode": req.mode, "goal_name": req.goal_name,
        "custom_goal": req.custom_goal, "recon_first": req.recon_first,
        "model_alias": req.model_alias, "swarm": req.swarm,
        "parallel_swarm": req.parallel_swarm, "critic": req.critic,
        "reflection": req.reflection, "adaptive_exploits": req.adaptive_exploits,
        "long_session": req.long_session, "multi_model_consult": req.multi_model_consult,
        "observer_mode": req.observer_mode, "ultrathink": req.ultrathink,
        "skills_mode": req.skills_mode,
        "skills_include": req.skills_include,
        "skills_exclude": req.skills_exclude,
        "skills_no_reselect": req.skills_no_reselect,
        "debug": req.debug,
        "plain": req.plain,
        "json_output": req.json_output,
        "resume_source": req.resume_source,
        "kind": req.kind.value,
    }


def _preview_to_dict(p: RunPreview) -> dict[str, Any]:
    return {
        "run_id": p.run_id, "target_ip": p.target_ip, "original_target": p.original_target,
        "resolved_ip": p.resolved_ip, "resolved_domain": p.resolved_domain,
        "mode": p.mode, "goal_name": p.goal_name, "goal_description": p.goal_description,
        "model_alias": p.model_alias, "model_label": p.model_label,
        "transport_summary": p.transport_summary, "permission": p.permission,
        "attack_mode": p.attack_mode, "swarm": p.swarm, "parallel_swarm": p.parallel_swarm,
        "multi_model": p.multi_model, "destructive": p.destructive,
        "required_confirmation_text": p.required_confirmation_text,
        "budgets": p.budgets, "skill_activations": p.skill_activations,
        "skill_errors": p.skill_errors, "resumed_from": p.resumed_from,
    }


def _result_to_dict(r: RunResult) -> dict[str, Any]:
    return {
        "run_id": r.run_id, "target_ip": r.target_ip, "mode": r.mode,
        "goal_name": r.goal_name, "goal_description": r.goal_description,
        "total_actions": r.total_actions, "workspace": r.workspace,
        "audit_path": r.audit_path, "records": r.records, "messages": r.messages,
        "error": r.error, "swarm_result": r.swarm_result,
        "active_skills": r.active_skills, "outcome_summary": r.outcome_summary,
        "telemetry": r.telemetry, "safety_review": r.safety_review,
        "reports_dir": r.reports_dir, "summary_path": r.summary_path,
        "run_json_path": r.run_json_path,
    }
