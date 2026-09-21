"""p2-01: runner split — old + new import paths resolve; fail-open contracts hold."""

from __future__ import annotations


def test_old_and_new_paths_resolve_to_same_objects():
    import tools.exploit_agent.runner._impl as impl
    from tools.exploit_agent.runner import helpers, memory_shim, safety_hooks

    for name in (
        "_emit",
        "_deep_error",
        "_resolve_attacker_os",
        "_mission_goal_line",
        "_check_final_verdict",
        "_resolve_allowed_targets",
    ):
        assert getattr(impl, name) is getattr(helpers, name), name
    for name in (
        "_build_killchain_machine",
        "_should_snapshot_for_action",
        "_build_snapshot_manager",
        "_counterfactual_enabled",
    ):
        assert getattr(impl, name) is getattr(safety_hooks, name), name
    for name in (
        "_InMemoryExperienceStore",
        "_load_attack_memory_settings",
        "_configured_role",
        "_debug_enabled",
        "_debug_print",
    ):
        assert getattr(impl, name) is getattr(memory_shim, name), name


def test_loop_and_package_root_seams_still_work():
    from tools.exploit_agent import _sync_patchable_symbols  # noqa: F401
    from tools.exploit_agent.runner import loop, safety_hooks

    assert loop._should_snapshot_for_action is safety_hooks._should_snapshot_for_action
    assert loop._build_snapshot_manager is safety_hooks._build_snapshot_manager
    assert loop._build_killchain_machine is safety_hooks._build_killchain_machine
    assert loop.run_exploit_agent is not None


def test_snapshot_decision_fail_open(monkeypatch):
    """A broken tools.snapshots must degrade to False, never raise."""
    import tools.snapshots as snapshots
    from tools.exploit_agent.runner.safety_hooks import _should_snapshot_for_action

    monkeypatch.setattr(snapshots, "should_snapshot", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert _should_snapshot_for_action("run_exploit_terminal", "rm -rf /", {"snapshots": {"enabled": True}}) is False


def test_snapshot_manager_fail_open(monkeypatch):
    """An unavailable SnapshotManager must degrade to None, never raise."""
    import sys

    from tools.exploit_agent.runner.safety_hooks import _build_snapshot_manager

    monkeypatch.setitem(sys.modules, "tools.snapshots", None)
    assert _build_snapshot_manager({"snapshots": {"enabled": True}}, None) is None


def test_killchain_fail_open(monkeypatch):
    """A broken killchain import with enabled config must degrade to None."""
    import sys

    from tools.exploit_agent.runner.safety_hooks import _build_killchain_machine

    assert _build_killchain_machine({"killchain": {"enabled": False}}, None) is None
    monkeypatch.setitem(sys.modules, "tools.killchain", None)
    assert _build_killchain_machine({"killchain": {"enabled": True}}, None) is None


def test_counterfactual_toggle():
    from tools.exploit_agent.runner.safety_hooks import _counterfactual_enabled

    assert _counterfactual_enabled({"replay_simulator": {"counterfactual": True}}) is True
    assert _counterfactual_enabled({"replay_simulator": {"counterfactual": False}}) is False
    assert _counterfactual_enabled(None) is False
