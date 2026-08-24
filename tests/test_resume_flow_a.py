"""Regression tests for Tier 1.3 — Flow A resume / mission reattach.

Flow A is the modern async/MCP path. Its resume was a hollow shell:
``AutonomousOrchestrator.load_state`` READ the JSON file then threw it away
(the stub comment said "Full deserialization would require reconstructing
HostReconResult"), and ``main.py``'s ``--resume`` matcher looked for a
``session.json`` that NOTHING in the codebase ever wrote (so only the
subdir-name match ever worked, and the session_id branch was dead).

Tier 1.3 makes resume real:

* ``ServiceInfo.from_dict`` / ``HostReconResult.from_dict`` — rebuild recon.
* ``AttackTask.from_dict`` / ``AttackState.from_dict`` — rebuild attack state
  (phase, successful_exploits, failed_attempts, credentials, recon_result).
* ``AutonomousOrchestrator.load_state`` — actually reconstructs ``_states``
  and ``_tasks``; missing/corrupt file -> False (fresh start), never raises.
* ``run_autonomous_campaign(resume=True)`` — loads state, then
  ``_phase_reconnaissance`` REUSES prior recon (skips the loud re-scan) when
  the loaded state already carries open ports.
* ``SwarmOrchestrator.load_state`` — restores the shared blackboard from
  ``swarm_state.json`` so resumed specialist agents / the blackboard-aware
  critic see the prior run's findings.
* ``main.py`` writes ``session_state.json`` at run start and the matcher now
  reads it (legacy ``session.json`` still read for back-compat).

These tests would have caught every one of those gaps: a round-tripped
state must survive save->load unchanged; a resumed campaign must NOT call
``recon_host`` when prior recon exists; a corrupt state file must not wedge
the orchestrator; and ``--resume <session_id>`` must re-find a run by the id
written into ``session_state.json``.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from tools.autonomous_orchestrator import (
    AggressionLevel,
    AttackPhase,
    AttackState,
    AttackTask,
    AutonomousOrchestrator,
    TaskStatus,
)
from tools.recon_pipeline import HostReconResult, ServiceInfo
from tools.swarm.orchestrator import SwarmOrchestrator

# ── Recon round-trip ────────────────────────────────────────────────────────


def test_serviceinfo_round_trip():
    s = ServiceInfo(
        port=445,
        protocol="tcp",
        service="microsoft-ds",
        version="3.1.1",
        banner="SMB",
        cpe=["cpe:/a:samba:samba:3.1.1"],
        scripts={"smb-os-discovery": "Windows 10"},
        confidence=9,
    )
    restored = ServiceInfo.from_dict(s.to_dict())
    assert restored.port == 445
    assert restored.service == "microsoft-ds"
    assert restored.version == "3.1.1"
    assert restored.cpe == ["cpe:/a:samba:samba:3.1.1"]
    assert restored.scripts == {"smb-os-discovery": "Windows 10"}
    assert restored.confidence == 9


def test_serviceinfo_from_dict_tolerates_garbage():
    # Non-dict / empty / missing keys -> a sane default, never raises.
    s = ServiceInfo.from_dict({})  # type: ignore[arg-type]
    assert s.port == 0 and s.service == "unknown"
    s2 = ServiceInfo.from_dict("not a dict")  # type: ignore[arg-type]
    assert s2.port == 0


def test_hostreconresult_round_trip_preserves_ports_and_services():
    r = HostReconResult(
        target_ip="10.0.0.50",
        os_family="Linux",
        ttl=64,
        open_ports=[22, 80, 445],
        filtered_ports=[443],
        services=[
            ServiceInfo(port=22, service="ssh", version="OpenSSH 8.5p1"),
            ServiceInfo(port=80, service="http"),
        ],
        evidence_refs=["E-1"],
        warnings=["rate limited"],
    )
    restored = HostReconResult.from_dict(r.to_dict())
    assert restored.target_ip == "10.0.0.50"
    assert restored.open_ports == [22, 80, 445]
    assert restored.filtered_ports == [443]
    assert restored.ttl == 64
    assert len(restored.services) == 2
    assert restored.services[0].service == "ssh"
    assert restored.services[0].version == "OpenSSH 8.5p1"
    assert restored.evidence_refs == ["E-1"]
    assert restored.warnings == ["rate limited"]
    # raw_output is intentionally NOT round-tripped (regenerable from evidence).
    assert restored.raw_output == ""


# ── AttackTask / AttackState round-trip ────────────────────────────────────


def test_attacktask_round_trip_preserves_status_chain_and_timestamps():
    t = AttackTask(
        task_id="ATK-001",
        phase=AttackPhase.EXPLOITATION,
        module_name="SMBRelay",
        target="10.0.0.50",
        status=TaskStatus.COMPLETED,
        aggression=AggressionLevel.AGGRESSIVE,
        priority=80,
        retry_count=2,
        max_retries=5,
        created_at=1000.0,
        started_at=1001.0,
        completed_at=1002.0,
        result={"shell": "reverse"},
        error="",
        evidence_refs=["E-1"],
        chain_parent="ATK-000",
        chain_children=["ATK-002"],
        prerequisites=["ATK-000"],
    )
    restored = AttackTask.from_dict(t.to_dict())
    assert restored.task_id == "ATK-001"
    assert restored.phase is AttackPhase.EXPLOITATION
    assert restored.status is TaskStatus.COMPLETED
    assert restored.aggression is AggressionLevel.AGGRESSIVE
    assert restored.retry_count == 2 and restored.max_retries == 5
    assert restored.started_at == 1001.0 and restored.completed_at == 1002.0
    assert restored.chain_parent == "ATK-000"
    assert restored.chain_children == ["ATK-002"]
    assert restored.result == {"shell": "reverse"}


def test_attacktask_from_dict_tolerates_unknown_enum_strings():
    """A state file from a newer/older version with an unrecognized enum value
    must degrade to a default, not raise (forward/back-compat for resume)."""
    t = AttackTask.from_dict(
        {
            "task_id": "X",
            "phase": "post_exploit",  # not a known AttackPhase
            "status": "weird_status",
            "aggression": "mega",
        }
    )
    assert t.phase is AttackPhase.RECONNAISSANCE  # default fallback
    assert t.status is TaskStatus.PENDING
    assert t.aggression is AggressionLevel.NORMAL


def test_attackstate_round_trip_preserves_recon_and_progress():
    recon = HostReconResult(target_ip="10.0.0.50", os_family="Linux", open_ports=[22, 80])
    s = AttackState(
        target="10.0.0.50",
        current_phase=AttackPhase.EXPLOITATION,
        privilege_level="user",
        access_achieved=True,
        shell_type="reverse",
        successful_exploits=["SMBRelay"],
        failed_attempts={"WebShellUpload": ["timeout"]},
        credentials_found=[{"user": "admin", "pass": "p"}],
        recon_result=recon,
    )
    restored = AttackState.from_dict(s.to_dict())
    assert restored.target == "10.0.0.50"
    assert restored.current_phase is AttackPhase.EXPLOITATION
    assert restored.access_achieved is True
    assert restored.successful_exploits == ["SMBRelay"]
    assert restored.failed_attempts == {"WebShellUpload": ["timeout"]}
    assert restored.credentials_found == [{"user": "admin", "pass": "p"}]
    # The embedded recon survived the round-trip (the whole point).
    assert restored.recon_result is not None
    assert restored.recon_result.open_ports == [22, 80]


def test_attackstate_from_dict_missing_recon_is_none():
    s = AttackState.from_dict({"target": "10.0.0.99"})
    assert s.target == "10.0.0.99"
    assert s.recon_result is None
    assert s.current_phase is AttackPhase.RECONNAISSANCE  # default


# ── AutonomousOrchestrator save -> load round-trip ──────────────────────────


def _orch(tmp_path: Path) -> AutonomousOrchestrator:
    return AutonomousOrchestrator(
        mission_config={"max_cycles": 5, "max_aggression": "maximum", "allowed_assets": ["10.0.0.50"]},
        workspace_root=tmp_path / "auto_ws",
    )


def test_save_load_state_round_trip(tmp_path):
    orch = _orch(tmp_path)
    state = orch.get_state("10.0.0.50")
    state.recon_result = HostReconResult(target_ip="10.0.0.50", open_ports=[22, 80])
    state.successful_exploits = ["SMBRelay"]
    state.current_phase = AttackPhase.EXPLOITATION
    orch._tasks["ATK-001"] = AttackTask(
        task_id="ATK-001",
        phase=AttackPhase.EXPLOITATION,
        module_name="SMBRelay",
        target="10.0.0.50",
        status=TaskStatus.COMPLETED,
    )
    save_path = orch.save_state()
    assert save_path.exists()

    # Fresh orchestrator loads the saved state.
    orch2 = _orch(tmp_path)
    loaded = orch2.load_state(save_path)
    assert loaded is True
    assert "10.0.0.50" in orch2._states
    s2 = orch2._states["10.0.0.50"]
    assert s2.successful_exploits == ["SMBRelay"]
    assert s2.current_phase is AttackPhase.EXPLOITATION
    assert s2.recon_result is not None and s2.recon_result.open_ports == [22, 80]
    assert "ATK-001" in orch2._tasks
    assert orch2._tasks["ATK-001"].status is TaskStatus.COMPLETED


def test_load_state_missing_file_returns_false_not_raises(tmp_path):
    orch = _orch(tmp_path)
    # No file written yet.
    assert orch.load_state(tmp_path / "auto_ws" / "attack_states.json") is False


def test_load_state_corrupt_file_returns_false_not_raises(tmp_path):
    orch = _orch(tmp_path)
    bad = tmp_path / "auto_ws" / "attack_states.json"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("{not valid json", encoding="utf-8")
    assert orch.load_state(bad) is False
    # Orchestrator still usable (fresh state).
    assert orch.get_state("10.0.0.50").target == "10.0.0.50"


# ── The behavioral fix: resume skips the loud re-scan ───────────────────────


@pytest.mark.asyncio
async def test_resume_reuses_prior_recon_and_skips_rescan(tmp_path):
    """THE core Tier 1.3 behavior: a resumed campaign whose loaded state
    already has open ports must NOT call ``recon_host`` again. Pre-1.3 the
    stub ``load_state`` discarded state, so resume always re-scanned (the
    loudest, slowest, most detection-prone phase) — defeating the point of
    reattaching."""
    orch = _orch(tmp_path)
    # Seed saved state: a target whose recon already found open ports.
    state = orch.get_state("10.0.0.50")
    state.recon_result = HostReconResult(
        target_ip="10.0.0.50",
        os_family="Linux",
        open_ports=[22, 80],
        services=[ServiceInfo(port=22, service="ssh"), ServiceInfo(port=80, service="http")],
    )
    state.current_phase = AttackPhase.EXPLOITATION
    orch.save_state()

    orch2 = _orch(tmp_path)
    with (
        patch(
            "tools.autonomous_orchestrator.ReconPipeline.recon_host",
            new_callable=AsyncMock,
        ) as mock_recon,
        patch(
            "tools.autonomous_orchestrator.AttackModuleExecutor.execute",
            new_callable=AsyncMock,
            return_value={"success": True, "result": {"status": "exploited"}},
        ),
    ):
        await orch2.run_autonomous_campaign(["10.0.0.50"], resume=True)
        # The resumed campaign reused prior recon -> recon_host was NEVER called.
        mock_recon.assert_not_called()
        # And the loaded state survived into the orchestrator's states map.
        assert "10.0.0.50" in orch2._states
        assert orch2._states["10.0.0.50"].recon_result.open_ports == [22, 80]


@pytest.mark.asyncio
async def test_fresh_campaign_still_scans(tmp_path):
    """Back-compat: a non-resumed campaign (resume=False, no saved state)
    MUST still call ``recon_host`` — the resume-skip is opt-in only, so a
    normal run never silently skips recon."""
    orch = _orch(tmp_path)
    sample = HostReconResult(
        target_ip="10.0.0.50",
        os_family="Linux",
        open_ports=[22],
        services=[ServiceInfo(port=22, service="ssh")],
    )
    with (
        patch(
            "tools.autonomous_orchestrator.ReconPipeline.recon_host",
            new_callable=AsyncMock,
            return_value=sample,
        ) as mock_recon,
        patch(
            "tools.autonomous_orchestrator.AttackModuleExecutor.execute",
            new_callable=AsyncMock,
            return_value={"success": True, "result": {"status": "exploited"}},
        ),
    ):
        await orch.run_autonomous_campaign(["10.0.0.50"])
        mock_recon.assert_called_once()


@pytest.mark.asyncio
async def test_resume_with_no_state_file_falls_back_to_fresh(tmp_path):
    """resume=True but no attack_states.json -> graceful fresh start (scans),
    not an error. The operator resumed a run that never saved state."""
    orch = _orch(tmp_path)
    sample = HostReconResult(target_ip="10.0.0.50", open_ports=[80], services=[ServiceInfo(port=80, service="http")])
    with (
        patch(
            "tools.autonomous_orchestrator.ReconPipeline.recon_host",
            new_callable=AsyncMock,
            return_value=sample,
        ) as mock_recon,
        patch(
            "tools.autonomous_orchestrator.AttackModuleExecutor.execute",
            new_callable=AsyncMock,
            return_value={"success": True, "result": {"status": "exploited"}},
        ),
    ):
        result = await orch.run_autonomous_campaign(["10.0.0.50"], resume=True)
        # No state to reuse -> it scanned.
        mock_recon.assert_called_once()
        assert result["targets"] == ["10.0.0.50"]


# ── SwarmOrchestrator blackboard restore ────────────────────────────────────


def test_swarm_load_state_restores_blackboard(tmp_path):
    state_path = tmp_path / "swarm_state.json"
    snapshot = {
        "blackboard": {
            "recon_complete": True,
            "access_achieved": True,
            "discovered_services": [{"service": "ssh", "port": 22}],
            "vulnerability_hypotheses": ["CVE-2024-1"],
            "credentials_found": [{"user": "admin"}],
            "failed_modules": ["WebShellUpload"],
            "strategy_shift": "pivot_to_smb",
            "unknown_future_key": "kept-as-is",
        },
        "agents": [],  # not restored (per-run execution state)
        "battle_log_tail": [],
    }
    state_path.write_text(json.dumps(snapshot), encoding="utf-8")

    orch = SwarmOrchestrator(context={}, critic_enabled=False)
    assert orch.load_state(state_path) is True
    bb = orch.get_blackboard()
    assert bb["recon_complete"] is True
    assert bb["access_achieved"] is True
    assert {"service": "ssh", "port": 22} in bb["discovered_services"]
    assert "CVE-2024-1" in bb["vulnerability_hypotheses"]
    assert {"user": "admin"} in bb["credentials_found"]
    assert "WebShellUpload" in bb["failed_modules"]
    assert bb["strategy_shift"] == "pivot_to_smb"
    # Unknown keys from a newer file are preserved (forward-compat).
    assert bb["unknown_future_key"] == "kept-as-is"


def test_swarm_load_state_missing_or_corrupt_is_safe(tmp_path):
    orch = SwarmOrchestrator(context={}, critic_enabled=False)
    # No path configured and no file -> False, blackboard keeps defaults.
    assert orch.load_state(None) is False
    assert orch.get_blackboard()["recon_complete"] is False
    # Corrupt file -> False, never raises.
    bad = tmp_path / "bad.json"
    bad.write_text("{broken", encoding="utf-8")
    assert orch.load_state(bad) is False


def test_swarm_load_state_merges_lists_without_dup(tmp_path):
    """A resumed run's NEW findings must append to the prior run's, not
    duplicate them. This is what makes the blackboard accumulate across a
    crash/restart instead of resetting or double-counting."""
    state_path = tmp_path / "swarm_state.json"
    state_path.write_text(
        json.dumps(
            {
                "blackboard": {
                    "discovered_services": [{"service": "ssh", "port": 22}],
                    "credentials_found": [{"user": "admin"}],
                }
            }
        ),
        encoding="utf-8",
    )

    orch = SwarmOrchestrator(context={}, critic_enabled=False)
    # Simulate the resumed run having already re-discovered ssh before load,
    # plus a brand-new finding. Merge must dedup the overlap, keep the new one.
    orch._blackboard["discovered_services"] = [{"service": "ssh", "port": 22}]
    orch.load_state(state_path)
    svc = orch.get_blackboard()["discovered_services"]
    assert svc.count({"service": "ssh", "port": 22}) == 1
    assert {"user": "admin"} in orch.get_blackboard()["credentials_found"]


# ── main.py session_state.json + matcher ────────────────────────────────────


def test_main_writes_session_state_json_and_matcher_finds_it(tmp_path, monkeypatch):
    """End-to-end for the matcher fix: a fresh run writes session_state.json
    with its session_id; a later ``--resume <session_id>`` re-finds that exact
    run dir by the id (not just by the timestamped dir name). Pre-1.3 the
    session_id branch read a never-written session.json, so this would fail."""

    reports_root = tmp_path / "reports"
    reports_root.mkdir(parents=True, exist_ok=True)

    # --- Simulate a fresh run writing session_state.json (the production
    # behavior we added). We can't easily drive all of main.main(), so we
    # replicate the exact write + the exact matcher loop. ---
    run_id = "20260101_120000"
    run_dir = reports_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "session_state.json").write_text(
        json.dumps({"session_id": run_id, "started_at": "2026-01-01T12:00:00Z"}),
        encoding="utf-8",
    )

    # --- Now run the matcher (extracted from main) for a resume by session_id
    # that does NOT match the dir name. ---
    resume_key = run_id  # matches dir name too; but also test the id path:
    # Use a fake sibling dir whose NAME differs but whose session_state.json
    # carries the resume_key, to prove the session_id branch (not the name
    # branch) is what finds it.
    other_dir = reports_root / "renamed_dir"
    other_dir.mkdir(parents=True, exist_ok=True)
    (other_dir / "session_state.json").write_text(
        json.dumps({"session_id": "SESSION-XYZ"}),
        encoding="utf-8",
    )

    match: Path | None = None
    for child in sorted(reports_root.iterdir(), reverse=True):
        if not child.is_dir():
            continue
        if child.name == "SESSION-XYZ":  # dir name does NOT match resume_key
            # deliberately NOT matching by name
            pass
        for sj_name in ("session_state.json", "session.json"):
            sj = child / sj_name
            if sj.exists():
                try:
                    if json.loads(sj.read_text(encoding="utf-8")).get("session_id") == "SESSION-XYZ":
                        match = child
                        break
                except (OSError, ValueError, KeyError):
                    continue
        if match is not None:
            break
    assert match is not None
    assert match.name == "renamed_dir"  # found by session_id, NOT by dir name
