"""Decision broker: bridges API decision rows to the ``DecisionProvider``.

When the service calls ``ApiDecisionProvider.request(decision)``, the broker
creates a decision row in ``api_runtime.db``, emits an ``approval`` event,
and awaits an ``asyncio.Future``. ``POST /runs/{id}/decisions/{decision_id}``
resolves that future with the operator's answer. Cancellation (run cancel /
daemon shutdown) resolves pending futures with "" so the blocked service
unblocks cleanly.
"""

from __future__ import annotations

import asyncio

from tools.api.persistence import ApiPersistence
from tools.run_service.models import Decision, DecisionKind, RunState


class DecisionBroker:
    """Manages pending decisions for one run."""

    def __init__(self, run_id: str, persistence: ApiPersistence) -> None:
        self._run_id = run_id
        self._persistence = persistence
        self._pending: dict[str, asyncio.Future[str]] = {}

    async def create(self, decision: Decision) -> str:
        """Persist a decision row and register an awaitable future."""
        did = self._persistence.create_decision(
            {
                "id": decision.id,
                "run_id": self._run_id,
                "kind": decision.kind.value,
                "prompt_text": decision.prompt_text,
                "required_text": decision.required_text,
                "options": decision.options,
            }
        )
        decision.id = did
        decision.run_id = self._run_id
        loop = asyncio.get_running_loop()
        self._pending[did] = loop.create_future()
        if decision.kind != DecisionKind.START_CONFIRM:
            self._persistence.update_run_state(
                self._run_id,
                RunState.AWAITING_INPUT.value,
            )
        return did

    async def await_answer(self, decision_id: str) -> str:
        """Block until the decision is answered or cancelled."""
        fut = self._pending.get(decision_id)
        if fut is None:
            return ""
        try:
            return await fut
        finally:
            self._pending.pop(decision_id, None)

    def resolve(self, decision_id: str, answer: str) -> bool:
        """Resolve a pending decision future with the operator's answer."""
        fut = self._pending.get(decision_id)
        if fut is None or fut.done():
            return False
        row = self._persistence.answer_decision(decision_id, answer)
        if row is None or row["status"] != "answered":
            return False
        fut.set_result(answer)
        return True

    def cancel_all(self) -> None:
        """Resolve all pending futures with "" (cancellation)."""
        self._persistence.expire_pending_decisions(self._run_id)
        for fut in self._pending.values():
            if not fut.done():
                fut.set_result("")
        self._pending.clear()
