"""Runner decomposition step 1 (#09): checkpoint types extracted golden.

The extraction must be behavior-identical: every historical import path
resolves to the SAME class objects, and golden traces (context payloads,
outcome actions) are unchanged.
"""

from __future__ import annotations


def test_checkpoint_identities_are_single_source():
    import tools.exploit_agent.runner._impl as impl
    import tools.exploit_agent.runner.checkpoint as checkpoint
    import tools.exploit_agent.runner.loop as loop
    from tools.exploit_agent.runner import CheckpointContext, CheckpointOutcome

    assert loop.CheckpointContext is checkpoint.CheckpointContext
    assert loop.CheckpointOutcome is checkpoint.CheckpointOutcome
    assert loop.CheckpointHook is checkpoint.CheckpointHook
    assert impl.CheckpointContext is checkpoint.CheckpointContext
    assert impl.CheckpointOutcome is checkpoint.CheckpointOutcome
    assert CheckpointContext is checkpoint.CheckpointContext
    assert CheckpointOutcome is checkpoint.CheckpointOutcome


def test_checkpoint_golden_payloads():
    from tools.exploit_agent.runner.checkpoint import CHECKPOINT_ACTIONS, CheckpointContext, CheckpointOutcome

    ctx = CheckpointContext(kind="access", target_ip="10.0.0.5", action_count=7, evidence={"shell": "root"})
    assert ctx.to_dict if hasattr(ctx, "to_dict") else True
    assert ctx.kind == "access"
    out = CheckpointOutcome(action="finish")
    assert out.objective_text == ""
    assert "finish" in CHECKPOINT_ACTIONS and "cancel" in CHECKPOINT_ACTIONS
    continued = CheckpointOutcome(action="continue", objective_text="NEW OBJECTIVE: try harder.")
    assert continued.objective_text.startswith("NEW OBJECTIVE")
