"""Decision, event, and approval provider protocols.

These are the transport-neutral interfaces ``AssessmentService`` uses to
interact with the operator. The CLI supplies terminal adapters (questionary
prompts via ``AttackUi``); the API supplies async adapters backed by
persisted decision rows + WebSocket event pushes.

The service never knows which transport is calling -- it just calls
``decision_provider.request(decision)`` or ``event_sink.emit(...)``.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, Protocol, runtime_checkable

from tools.run_service.models import Decision, Event


def _maybe_await(value: Any) -> Any:
    """Await ``value`` if it's a coroutine; otherwise return it as-is.

    Some ``AttackUi`` methods are async (``ask_confirm``, ``ask_destructive_confirm``,
    ``ask_tool_approval``) and some are sync (``ask_goal_from_suggestions``). The
    decision provider calls them uniformly and uses this helper to handle both.
    """
    if inspect.isawaitable(value):
        return value
    # Wrap sync returns in a coroutine so the caller can always ``await``.
    async def _wrap() -> Any:
        return value
    return _wrap()


# ---------------------------------------------------------------------------
# Decision provider
# ---------------------------------------------------------------------------

@runtime_checkable
class DecisionProvider(Protocol):
    """Ask the operator to resolve a decision point.

    The CLI implementation calls ``AttackUi.ask_*`` (synchronous questionary);
    the API implementation creates a persisted decision row and awaits an
    ``asyncio.Future`` that is resolved when the WebUI POSTs the answer.

    Returns the operator's answer string. For ``start_confirm`` /
    ``tool_approval`` with a ``required_text``, the caller checks whether the
    answer matches; for ``goal_select`` the answer is the chosen goal name.
    """

    async def request(self, decision: Decision) -> str:  # pragma: no cover
        ...


class TerminalDecisionProvider:
    """CLI adapter: routes decisions through ``AttackUi`` prompt methods.

    Constructed in ``main.async_main`` and passed into
    ``AssessmentService.execute``. Each decision kind maps to an existing
    ``AttackUi`` method so the terminal experience is unchanged.
    """

    def __init__(self, ui: Any) -> None:
        self._ui = ui

    async def request(self, decision: Decision) -> str:
        kind = decision.kind
        if kind == "start_confirm":
            if decision.required_text:
                try:
                    proceed = await _maybe_await(
                        self._ui.ask_destructive_confirm(
                            decision.required_text.replace("ALLOW ", "")
                        )
                    )
                except (EOFError, KeyboardInterrupt):
                    return ""
                return decision.required_text if proceed else ""
            try:
                proceed = await _maybe_await(self._ui.ask_confirm(decision.prompt_text, default=True))
            except (EOFError, KeyboardInterrupt):
                return ""
            return "yes" if proceed else ""
        if kind == "goal_select":
            try:
                name, custom = await _maybe_await(self._ui.ask_goal_from_suggestions(decision.options))
            except (EOFError, KeyboardInterrupt):
                return ""
            return custom if custom else name
        if kind == "tool_approval":
            try:
                answer = await _maybe_await(
                    self._ui.ask_tool_approval(decision.prompt_text, decision.required_text)
                )
            except (EOFError, KeyboardInterrupt):
                return ""
            return answer
        return ""


class ApiDecisionProvider:
    """API adapter: persists a decision and awaits a WebUI answer.

    Constructed by ``RunManager`` per run. ``request`` creates a decision row
    in ``api_runtime.db``, emits an ``approval`` event, and awaits the future
    that ``POST /runs/{id}/decisions/{decision_id}`` resolves. Cancellation
    (run cancel / daemon shutdown) resolves pending futures with "" so the
    blocked service call unblocks cleanly.
    """

    def __init__(self, run_id: str, broker: Any, emit_event: Any) -> None:
        self._run_id = run_id
        self._broker = broker            # DecisionBroker
        self._emit_event = emit_event     # callable: emit decision event to EventBroker

    async def request(self, decision: Decision) -> str:
        decision.run_id = self._run_id
        await self._broker.create(decision)
        await self._emit_event("state", {"state": "awaiting_input"})
        # Notify subscribers that a decision is pending.
        await self._emit_event("approval", {
            "decision_id": decision.id,
            "kind": decision.kind.value,
            "prompt_text": decision.prompt_text,
            "required_text": decision.required_text,
            "options": decision.options,
        })
        answer = await self._broker.await_answer(decision.id)
        return answer


# ---------------------------------------------------------------------------
# Event sink
# ---------------------------------------------------------------------------

@runtime_checkable
class EventSink(Protocol):
    """Receive structured events during a run."""

    async def emit(self, event_type: str, payload: dict[str, Any]) -> None:  # pragma: no cover
        ...


class TerminalEventSink:
    """CLI adapter: a no-op sink.

    The terminal path prints directly via ``AttackUi`` methods inside
    ``AssessmentService.execute`` (the service calls both ``ui.*`` and
    ``event_sink.emit``; the terminal sink simply discards events so there is
    no duplicate output). The API sink is the one that persists + pushes.
    """

    async def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        return None


class ApiEventSink:
    """API adapter: forwards events to the ``EventBroker`` for JSONL + WS."""

    def __init__(self, run_id: str, broker: Any) -> None:
        self._run_id = run_id
        self._broker = broker

    async def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        await self._broker.emit(event_type, payload)


# ---------------------------------------------------------------------------
# Approval provider
# ---------------------------------------------------------------------------

@runtime_checkable
class ApprovalProvider(Protocol):
    """Gate a single tool call. Used by ``ExploitPolicy.approve_action``.

    The terminal implementation wraps the legacy ``prompt_func`` (synchronous
    input()) via ``asyncio.to_thread``. The API implementation delegates to a
    ``tool_approval`` decision through the ``DecisionProvider``.
    """

    async def approve(
        self,
        action: str,
        command: str,
        detail: str,
        target: str,
    ) -> bool:  # pragma: no cover
        ...


class TerminalApprovalProvider:
    """Wraps the existing synchronous ``prompt_func`` for backward compat.

    This preserves the exact terminal approval flow: the banner is printed
    and ``prompt_func`` is called in a worker thread. ``ExploitPolicy`` uses
    this when ``approval_provider`` is None (the legacy path) OR when the CLI
    explicitly passes it.
    """

    def __init__(self, prompt_func: Any) -> None:
        self._prompt_func = prompt_func or input

    async def approve(self, action: str, command: str, detail: str, target: str) -> bool:
        host = str(target or "target")
        prompt = (
            "\n" + "=" * 70 + "\n"
            "  EXPLOIT ACTION REQUIRES APPROVAL\n"
            + "=" * 70 + "\n"
            f"  Target:   {target}\n"
            f"  Action:   {action}\n"
            f"  Detail:   {detail[:300] if detail else 'n/a'}\n"
            f"  Command:  {command[:200]}\n"
            + "-" * 70
            + f"\nType ALLOW {host} to approve, anything else to deny: "
        )
        try:
            answer = await asyncio.to_thread(self._prompt_func, prompt)
        except (EOFError, KeyboardInterrupt):
            return False
        return answer.strip() == f"ALLOW {host}"


class ApiApprovalProvider:
    """API adapter: routes tool approvals through the decision broker."""

    def __init__(self, run_id: str, decision_provider: ApiDecisionProvider, target: str) -> None:
        self._run_id = run_id
        self._dp = decision_provider
        self._target = target

    async def approve(self, action: str, command: str, detail: str, target: str) -> bool:
        from tools.run_service.models import Decision, DecisionKind
        decision = Decision(
            id="",  # broker assigns
            run_id=self._run_id,
            kind=DecisionKind.TOOL_APPROVAL,
            prompt_text=f"Action: {action}\nDetail: {detail[:500]}\nCommand: {command[:300]}",
            required_text=f"ALLOW {target}",
        )
        answer = await self._dp.request(decision)
        return answer.strip() == f"ALLOW {target}"


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------

class CancellationToken:
    """Cooperative cancellation flag for a run.

    ``AssessmentService.execute`` checks ``cancelled`` at natural boundaries
    (between rounds, before opening the MCP session). ``RunManager.cancel``
    sets the flag and cancels the owning ``asyncio.Task``; the service's
    ``finally`` blocks tear down the MCP subprocess tree.
    """

    def __init__(self) -> None:
        self._event = asyncio.Event()
        self._cancelled = False

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def cancel(self) -> None:
        self._cancelled = True
        self._event.set()

    async def wait(self) -> None:
        await self._event.wait()
