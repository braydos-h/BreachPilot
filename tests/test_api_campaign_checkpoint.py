"""API-level tests for the CAMPAIGN_NEXT_STEP decision (Flow A checkpoint).

Verifies the full persisted-decision / state-transition flow:
  - A run that surfaces a checkpoint creates a ``campaign_next_step`` decision
    row in api_runtime.db and transitions the run to ``awaiting_input``.
  - Answering the decision resolves the future, transitions the run back to
    ``running``, and ultimately to a terminal state.
  - ``finish`` → completed; ``cancel`` → cancelled (not failed).

These tests drive RunManager directly (async) with a fake AssessmentService
whose ``execute`` calls the checkpoint hook, mirroring the test_run_manager.py
pattern. The TestClient sync wrapper would require polling for the background
task to reach the awaiting_input state, which is brittle; the async path is
deterministic.
"""

from __future__ import annotations

import asyncio

import pytest

from tools.api.event_broker import EventBrokerRegistry
from tools.api.persistence import ApiPersistence
from tools.api.run_manager import RunManager
from tools.run_service.models import (
    DecisionKind,
    RunPreview,
    RunRequest,
    RunResult,
    RunState,
)


def _preview(run_id: str, target: str, tmp_path) -> RunPreview:
    return RunPreview(
        run_id=run_id,
        reports_dir=tmp_path / target,
        config_path=tmp_path / "config.yaml",
        target_ip=target,
        original_target=target,
        resolved_ip=None,
        resolved_domain=None,
        mode="attack",
        goal_name="recon_only",
        goal_description="test",
        model_alias="glm",
        model_label="glm",
        transport_summary="http",
        permission="full_access",
        attack_mode=True,
        swarm=False,
        parallel_swarm=False,
        multi_model=False,
        destructive=False,
        required_confirmation_text="",
    )


class _CheckpointService:
    """Fake AssessmentService that calls the checkpoint hook once during execute.

    ``execute`` signature mirrors the real one but only the kwargs needed for
    the checkpoint flow are used. It calls ``decision_provider.request`` with a
    CAMPAIGN_NEXT_STEP decision (via the hook closure the real service builds),
    but here we simulate the loop: call the hook, then return a RunResult whose
    ``cancelled`` flag reflects the operator's choice.

    To keep the test deterministic, ``execute`` is given the
    ``decision_provider`` directly and builds the Decision inline — exactly
    what the real AssessmentService._checkpoint_hook closure does.
    """

    def __init__(self, **kwargs):
        pass

    async def prepare(self, request: RunRequest) -> RunPreview:
        return _preview(f"run-{request.target}", request.target, _tmp)

    async def execute(self, request, preview, *, decision_provider, event_sink, cancellation, **kw):
        from tools.run_service.models import Decision, DecisionKind
        # Simulate the loop surfacing a no-path checkpoint.
        decision = Decision(
            id="", run_id=preview.run_id, kind=DecisionKind.CAMPAIGN_NEXT_STEP,
            prompt_text="NO VERIFIED ACCESS YET\nTarget: 10.0.0.50",
            options=[
                {"action": "continue", "label": "Continue"},
                {"action": "finish", "label": "Finish"},
                {"action": "cancel", "label": "Cancel"},
            ],
        )
        answer = await decision_provider.request(decision)
        # The answer encodes the operator's choice.
        cancelled = answer.startswith("cancel")
        return RunResult(
            run_id=preview.run_id, target_ip=preview.target_ip, mode=preview.mode,
            goal_name=preview.goal_name, goal_description=preview.goal_description,
            cancelled=cancelled,
        )


_tmp_path = None


@pytest.fixture(autouse=True)
def _capture_tmp(request):
    global _tmp
    _tmp = request.getfixturevalue("tmp_path")
    yield


def _make_manager(tmp_path, monkeypatch):
    monkeypatch.setattr("tools.run_service.AssessmentService", _CheckpointService)
    persistence = ApiPersistence(tmp_path / "reports")
    return RunManager(
        persistence,
        EventBrokerRegistry(tmp_path / "reports"),
        config={"api": {"max_concurrent_runs": 1}},
        config_path=tmp_path / "config.yaml",
    )


@pytest.mark.asyncio
async def test_campaign_checkpoint_decision_persists_and_transitions(tmp_path, monkeypatch):
    """A checkpoint during execute creates a campaign_next_step decision row;
    answering it transitions awaiting_input → running → completed."""
    manager = _make_manager(tmp_path, monkeypatch)
    run_id, _preview_obj, _dec = await manager.create_run(RunRequest(target="10.0.0.50", yes=True))
    # The run started (yes=True skips start_confirm). Wait for the checkpoint
    # decision to appear (the background task calls decision_provider.request
    # which creates the row + transitions to awaiting_input).
    decision = await _await_decision(manager, run_id, DecisionKind.CAMPAIGN_NEXT_STEP.value)
    assert decision["kind"] == DecisionKind.CAMPAIGN_NEXT_STEP.value
    assert decision["status"] == "pending"
    # The run should be awaiting_input.
    run = manager._persistence.get_run(run_id)
    assert run["state"] == RunState.AWAITING_INPUT.value
    # Answer "finish" → the run unblocks and completes.
    await manager.answer_decision(run_id, decision["id"], "finish")
    await _await_terminal(manager, run_id)
    run = manager._persistence.get_run(run_id)
    assert run["state"] == RunState.COMPLETED.value


@pytest.mark.asyncio
async def test_cancel_at_checkpoint_marks_cancelled(tmp_path, monkeypatch):
    """Answering 'cancel' at a checkpoint transitions the run to cancelled."""
    manager = _make_manager(tmp_path, monkeypatch)
    run_id, _, _ = await manager.create_run(RunRequest(target="10.0.0.50", yes=True))
    decision = await _await_decision(manager, run_id, DecisionKind.CAMPAIGN_NEXT_STEP.value)
    await manager.answer_decision(run_id, decision["id"], "cancel")
    await _await_terminal(manager, run_id)
    run = manager._persistence.get_run(run_id)
    assert run["state"] == RunState.CANCELLED.value
    assert run.get("result_json", {}).get("cancelled") is True


# ── helpers ───────────────────────────────────────────────────────────────────


async def _await_decision(manager: RunManager, run_id: str, kind: str, timeout: float = 5.0):
    """Poll until a pending decision of ``kind`` exists for ``run_id``."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        rows = manager._persistence.list_decisions(run_id)
        for row in rows:
            if row["kind"] == kind and row["status"] == "pending":
                return row
        await asyncio.sleep(0.02)
    raise AssertionError(f"no pending {kind} decision for {run_id} within {timeout}s")


async def _await_terminal(manager: RunManager, run_id: str, timeout: float = 5.0):
    """Poll until the run reaches a terminal state."""
    terminal = {RunState.COMPLETED.value, RunState.FAILED.value, RunState.CANCELLED.value, RunState.INTERRUPTED.value}
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        run = manager._persistence.get_run(run_id)
        if run and run["state"] in terminal:
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"run {run_id} did not reach terminal state within {timeout}s (state={manager._persistence.get_run(run_id)['state']})")
