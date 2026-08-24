"""Tests for API persistence: run state transitions, decision lifecycle, recovery."""

from __future__ import annotations

import pytest

from tools.api.decision_broker import DecisionBroker
from tools.api.persistence import ApiPersistence
from tools.run_service.models import Decision, DecisionKind


@pytest.fixture
def persistence(tmp_path):
    return ApiPersistence(tmp_path / "reports")


def test_create_and_get_run(persistence):
    persistence.create_run(
        run_id="r-001",
        request={"target": "10.0.0.50"},
        preview={"target_ip": "10.0.0.50"},
    )
    run = persistence.get_run("r-001")
    assert run is not None
    assert run["state"] == "draft"
    assert run["request_json"]["target"] == "10.0.0.50"


def test_update_run_state(persistence):
    persistence.create_run(run_id="r-002", request={}, preview={})
    persistence.update_run_state("r-002", "running")
    run = persistence.get_run("r-002")
    assert run["state"] == "running"


def test_update_run_state_with_result(persistence):
    persistence.create_run(run_id="r-003", request={}, preview={})
    persistence.update_run_state("r-003", "completed", result={"total_actions": 5})
    run = persistence.get_run("r-003")
    assert run["state"] == "completed"
    assert run["result_json"]["total_actions"] == 5


def test_list_runs(persistence):
    persistence.create_run(run_id="r-a", request={}, preview={})
    persistence.create_run(run_id="r-b", request={}, preview={})
    runs = persistence.list_runs()
    assert len(runs) == 2


def test_get_active_run_none(persistence):
    assert persistence.get_active_run() is None


def test_get_active_run(persistence):
    persistence.create_run(run_id="r-active", request={}, preview={})
    persistence.update_run_state("r-active", "running")
    active = persistence.get_active_run()
    assert active is not None
    assert active["id"] == "r-active"


def test_recover_interrupted(persistence):
    """On startup, live runs are marked interrupted; pending decisions expired."""
    persistence.create_run(run_id="r-live", request={}, preview={})
    persistence.update_run_state("r-live", "running")
    persistence.create_decision(
        {
            "id": "",
            "run_id": "r-live",
            "kind": "tool_approval",
            "prompt_text": "allow?",
            "required_text": "ALLOW 10.0.0.50",
        }
    )
    persistence.recover_interrupted()
    run = persistence.get_run("r-live")
    assert run["state"] == "interrupted"


def test_recover_awaiting_confirmation(persistence):
    persistence.create_run(run_id="r-waiting", request={}, preview={})
    persistence.update_run_state("r-waiting", "awaiting_confirmation")
    persistence.recover_interrupted()
    assert persistence.get_run("r-waiting")["state"] == "interrupted"


def test_create_and_answer_decision(persistence):
    persistence.create_run(run_id="r-dec", request={}, preview={})
    did = persistence.create_decision(
        {
            "id": "",
            "run_id": "r-dec",
            "kind": "start_confirm",
            "prompt_text": "proceed?",
            "required_text": "ALLOW 10.0.0.50",
        }
    )
    assert did.startswith("dec-")
    decisions = persistence.list_decisions("r-dec")
    assert len(decisions) == 1
    assert decisions[0]["status"] == "pending"
    # Answer it.
    answered = persistence.answer_decision(did, "ALLOW 10.0.0.50")
    assert answered is not None
    assert answered["status"] == "answered"
    assert answered["answer"] == "ALLOW 10.0.0.50"


def test_answer_nonexistent_decision(persistence):
    result = persistence.answer_decision("nonexistent", "yes")
    assert result is None


def test_expire_pending_decisions(persistence):
    persistence.create_run(run_id="r-exp", request={}, preview={})
    persistence.create_decision({"id": "", "run_id": "r-exp", "kind": "tool_approval"})
    persistence.expire_pending_decisions("r-exp")
    decisions = persistence.list_decisions("r-exp")
    assert decisions[0]["status"] == "expired"


def test_decision_waiter_cancellation_propagates(persistence):
    persistence.create_run(run_id="r-cancel", request={}, preview={})

    async def _run():
        broker = DecisionBroker("r-cancel", persistence)
        decision = Decision(
            id="",
            run_id="r-cancel",
            kind=DecisionKind.GOAL_SELECT,
            prompt_text="Choose",
        )
        await broker.create(decision)
        assert persistence.get_run("r-cancel")["state"] == "awaiting_input"
        waiter = asyncio.create_task(broker.await_answer(decision.id))
        await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter

    import asyncio

    asyncio.run(_run())
