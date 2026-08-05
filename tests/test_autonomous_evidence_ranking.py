"""Tests for evidence-aware module ranking in the autonomous path.

Regression: the autonomous orchestrator built a ``ModuleContext`` that
dropped service version + CPE + the full per-service CVE list, AND never
passed an ``experience_store`` to ``find_modules``. The dormant Bayesian
ranking at ``registry.py:205-328`` therefore always read an empty version
and a neutral 0.5 confidence -- historical wins/losses never moved the
ranking. These tests pin the corrected wiring: version reaches the context,
the experience store is threaded through, and ranked vs service-specific
tasks are deduplicated by (module_name, port).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from tools.autonomous_orchestrator import AttackPhase, AttackState, AutonomousOrchestrator
from tools.recon_pipeline import HostReconResult, ServiceInfo


def _orchestrator(tmp_path: Path, *, experience_store=None) -> AutonomousOrchestrator:
    return AutonomousOrchestrator(
        mission_config={"program_name": "test", "objective": "test"},
        workspace_root=tmp_path,
        tool_executor=lambda name, args: "exit_code=0",
        experience_store=experience_store,
    )


def _state_with_versioned_ssh() -> AttackState:
    recon = HostReconResult(
        target_ip="10.0.0.5",
        os_family="linux",
        services=[
            ServiceInfo(
                port=22,
                protocol="tcp",
                service="ssh",
                version="8.5p1",
                cpe=["cpe:/a:openbsd:openssh:8.5p1"],
                banner="SSH-2.0-OpenSSH_8.5p1",
                scripts={"openssh_cves": "CVE-2024-6387"},
            ),
        ],
        open_ports=[22],
    )
    state = AttackState(target="10.0.0.5", original_target="10.0.0.5")
    state.recon_result = recon
    return state


def test_module_context_carries_version_and_cpe(tmp_path):
    """The orchestrator's _module_context must carry version + CPE + banner,
    not just service name + port (the audit flagged version was dropped)."""
    orch = _orchestrator(tmp_path)
    state = _state_with_versioned_ssh()
    ctx = orch._module_context(state)
    assert ctx.services
    svc = ctx.services[0]
    assert svc["version"] == "8.5p1"
    assert "cpe" in svc and svc["cpe"]
    assert "banner" in svc


def test_module_context_carries_cves_from_scripts(tmp_path):
    """CVEs attached to a service's scripts (e.g. openssh_cves) reach ctx.cves."""
    orch = _orchestrator(tmp_path)
    state = _state_with_versioned_ssh()
    ctx = orch._module_context(state)
    assert "CVE-2024-6387" in ctx.cves


def test_orchestrator_threads_experience_store_into_find_modules(tmp_path, monkeypatch):
    """find_modules must receive the orchestrator's experience_store so the
    dormant Bayesian boost/demotion actually fires (audit: it never did)."""
    import pytest

    captured: dict = {}

    class _SpyStore:
        def get_all_confidences(self, sig):
            return {}

    def _spy_find_modules(ctx, experience_store=None):
        captured["ctx"] = ctx
        captured["store"] = experience_store
        return []

    monkeypatch.setattr(
        "tools.autonomous_orchestrator.find_modules", _spy_find_modules
    )
    orch = _orchestrator(tmp_path, experience_store=_SpyStore())
    state = _state_with_versioned_ssh()

    import asyncio

    asyncio.run(orch._phase_exploitation(state, skip_failed=False))
    assert captured["store"] is not None
    assert hasattr(captured["store"], "get_all_confidences")


def test_orchestrator_builds_default_experience_store_when_none_passed(tmp_path):
    """When no store is supplied, the orchestrator builds a default-backed one
    so ranking is never silently static on a fresh install."""
    orch = _orchestrator(tmp_path, experience_store=None)
    assert orch._experience_store is not None


def test_dedupe_drops_duplicate_service_task(tmp_path, monkeypatch):
    """A service-specific task that duplicates a ranked module (same name +
    port) must be dropped, not executed twice (audit: no dedupe existed)."""
    from tools.autonomous_orchestrator import AttackTask

    # Return one fake ranked module named SSHBruteForce on port 22.
    fake_mod = MagicMock()
    fake_mod.name = "SSHBruteForce"
    fake_mod.target_services = ["ssh"]
    fake_mod.to_json.return_value = {}

    def _fake_find(ctx, experience_store=None):
        return [(80, fake_mod)]

    monkeypatch.setattr(
        "tools.autonomous_orchestrator.find_modules", _fake_find
    )
    # Make _create_service_specific_tasks return a matching SSHBruteForce task
    # on port 22/tcp -- it should be dropped as a duplicate.
    orch = _orchestrator(tmp_path)
    state = _state_with_versioned_ssh()

    def _service_tasks(state):
        return [AttackTask(
            task_id="DUP-1",
            phase=AttackPhase.EXPLOITATION,
            module_name="SSHBruteForce",
            target=state.target,
            parameters={"port": "22/tcp", "version": "8.5p1"},
            priority=75,
        )]

    monkeypatch.setattr(orch, "_create_service_specific_tasks", _service_tasks)

    # Spy on _execute_task_batch to capture the deduped task list.
    captured_tasks: list = []
    async def _capture_batch(tasks, state):
        captured_tasks.extend(tasks)
    monkeypatch.setattr(orch, "_execute_task_batch", _capture_batch)

    import asyncio
    asyncio.run(orch._phase_exploitation(state, skip_failed=False))

    # The ranked SSHBruteForce task is present, the duplicate service task is dropped.
    ssh_tasks = [t for t in captured_tasks if t.module_name == "SSHBruteForce"]
    assert len(ssh_tasks) == 1, f"expected 1 SSHBruteForce, got {len(ssh_tasks)}"
