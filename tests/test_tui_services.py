"""Tests for TUI ServiceRegistry with no active mission."""

from __future__ import annotations

import tempfile
from pathlib import Path


def test_service_registry_no_mission():
    """ServiceRegistry with no active mission should report correctly."""
    from tui.services import ServiceRegistry, DashboardStats

    with tempfile.TemporaryDirectory() as tmpdir:
        svc = ServiceRegistry(Path(tmpdir))

        # No mission should be active
        assert not svc.has_active_mission
        assert svc.mission_name == ""
        assert svc.mission_risk_profile == ""
        assert svc.mission_id is None

        # Dashboard stats should show error
        stats = svc.get_dashboard_stats()
        assert isinstance(stats, DashboardStats)
        assert stats.error == "No active mission."
        assert not stats.mission_active

        # check_scope should return a denied result
        result = svc.check_scope("example.com", "recon")
        assert result is not None
        assert not result.allowed
        assert "No active mission" in result.reason


def test_service_registry_list_missions_empty():
    """Listing missions with no missions should return empty list."""
    from tui.services import ServiceRegistry

    with tempfile.TemporaryDirectory() as tmpdir:
        svc = ServiceRegistry(Path(tmpdir))
        missions = svc.list_missions()
        assert isinstance(missions, list)
        assert len(missions) == 0


def test_service_registry_reload():
    """Reload should work without errors on empty DB."""
    from tui.services import ServiceRegistry

    with tempfile.TemporaryDirectory() as tmpdir:
        svc = ServiceRegistry(Path(tmpdir))
        # Should not raise
        svc.reload()
        assert not svc.has_active_mission


def test_service_registry_workspace_creation():
    """ServiceRegistry should create workspace directory if missing."""
    from tui.services import ServiceRegistry

    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir) / "nested" / "workspace"
        assert not ws.exists()
        svc = ServiceRegistry(ws)
        assert ws.exists()
        assert svc.workspace_root == ws.resolve()


def test_dashboard_stats_default_values():
    """DashboardStats should have sensible defaults."""
    from tui.services import DashboardStats

    stats = DashboardStats()
    assert stats.mission_active is False
    assert stats.mission_name == ""
    assert stats.tasks_pending == 0
    assert stats.tasks_running == 0
    assert stats.tasks_blocked == 0
    assert stats.tasks_completed == 0
    assert stats.tasks_failed == 0
    assert stats.findings_candidates == 0
    assert stats.findings_report_ready == 0
    assert stats.swarm_active is False
    assert stats.swarm_agent_count == 0
    assert stats.swarm_running_count == 0
    assert stats.swarm_access_achieved is False
    assert stats.next_task is None
    assert stats.last_action == ""
    assert stats.error == ""


def test_service_registry_exposes_swarm_property():
    """ServiceRegistry should expose a swarm property returning a SwarmStateSnapshot."""
    from tui.services import ServiceRegistry, SwarmStateSnapshot

    with tempfile.TemporaryDirectory() as tmpdir:
        svc = ServiceRegistry(Path(tmpdir))
        snapshot = svc.swarm
        assert isinstance(snapshot, SwarmStateSnapshot)
        assert snapshot.active is False
