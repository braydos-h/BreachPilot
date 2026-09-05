"""Phase 5 — wasted-effort avoidance: pre-flight reachability probe, campaign
target preflight (scope / non-routable / dedup), and the hard-target cutoff.

All three capabilities are opt-in (default off), so the default single-IP
campaign is byte-identical to before. These tests pin the opt-in behavior:

1. ``probe_reachable`` (tools/socket_scan.py) — tri-state verdict: True when
    any probe port connects, False ONLY when every probe port is definitively
    refused over a COMMON_PORTS-sized sample, None when ambiguous
    (timeout/filtered) OR all-refused on a small probe set (e.g. [80, 443]).
    Refused means the host is UP, so a small-sample refused verdict must NOT
    skip a host (it can still be attackable on an unprobed port).
2. ``_preflight_targets`` (tools/autonomous_orchestrator.py) — drops
   out-of-scope targets, non-routable targets (except the operator's own
   host), and duplicates by resolved IP; records each skip as a timeline event.
3. Hard-target cutoff — ``_run_adaptive_rounds`` gives up after
   ``hard_target_max_rounds`` rounds with no access instead of burning the
   full ``max_cycles`` budget.

All network I/O is mocked — no live Nmap, no live sockets.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tools.autonomous_orchestrator import (
    AttackState,
    AutonomousOrchestrator,
)
from tools.recon_pipeline import HostReconResult, ServiceInfo
from tools.socket_scan import probe_reachable

# ── Fakes ───────────────────────────────────────────────────────────────────


class _ScopeResult:
    allowed: bool = True
    reason: str = "test-allow"


class _AllowScopeGate:
    def check_scope(self, *, asset, action_type=None, tool_name=None, risk_level=None):
        return _ScopeResult()


def _orch(tmp_path: Path, *, mission_config: dict[str, Any] | None = None) -> AutonomousOrchestrator:
    return AutonomousOrchestrator(
        mission_config=mission_config or {},
        workspace_root=tmp_path,
        tool_executor=None,
        scope_gate=_AllowScopeGate(),
    )


def _timeline_types(state: AttackState) -> list[str]:
    return [e["event_type"] for e in state.timeline]


# ── 1. probe_reachable tri-state ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_probe_reachable_open_port(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any probe port that connects -> True (host answers)."""
    monkeypatch.setattr(
        "tools.socket_scan._connect_status",
        lambda target, port, timeout: "open" if port == 80 else "refused",
    )
    assert await probe_reachable("10.0.0.5", [80, 443]) is True


@pytest.mark.asyncio
async def test_probe_reachable_all_refused_small_sample_falls_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """All-refused on a 2-port probe set -> None (NOT False).

    Refused means the host is UP (an RST is an answer) -- 80/443 closed says
    nothing about port 22. Only a COMMON_PORTS-sized all-refused sample may
    skip the full scan."""
    monkeypatch.setattr(
        "tools.socket_scan._connect_status",
        lambda target, port, timeout: "refused",
    )
    assert await probe_reachable("10.0.0.5", [80, 443]) is None


@pytest.mark.asyncio
async def test_probe_reachable_all_refused_full_sample_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """All-refused over a COMMON_PORTS-sized sample -> False (skip justified)."""
    from tools.socket_scan import COMMON_PORTS

    monkeypatch.setattr(
        "tools.socket_scan._connect_status",
        lambda target, port, timeout: "refused",
    )
    assert await probe_reachable("10.0.0.5", list(COMMON_PORTS)) is False


@pytest.mark.asyncio
async def test_probe_reachable_ambiguous_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Timeout/filtered -> None. The caller must NOT skip the host: a
    firewalled host can still be attackable on a port the probe didn't cover."""
    monkeypatch.setattr(
        "tools.socket_scan._connect_status",
        lambda target, port, timeout: "unknown",
    )
    assert await probe_reachable("10.0.0.5", [80, 443]) is None


@pytest.mark.asyncio
async def test_probe_reachable_mixed_refused_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """One refused + one timeout -> None (ambiguous, not unreachable)."""
    monkeypatch.setattr(
        "tools.socket_scan._connect_status",
        lambda target, port, timeout: "refused" if port == 80 else "unknown",
    )
    assert await probe_reachable("10.0.0.5", [80, 443]) is None


# ── 2. _preflight_targets ──────────────────────────────────────────────────


def test_preflight_off_by_default_passes_through(tmp_path: Path) -> None:
    """All filters default off -> the target list is unchanged."""
    orch = _orch(tmp_path)
    assert orch._preflight_targets(["10.0.0.5", "10.0.0.6"]) == ["10.0.0.5", "10.0.0.6"]


def test_preflight_dedup_by_resolved_ip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """dedup_targets: hosts resolving to the same IP collapse to one entry."""
    monkeypatch.setattr(
        "tools.validation_utils.resolve_target_to_ip",
        lambda host: "10.0.0.5" if host == "lab.example.com" else host,
    )
    orch = _orch(tmp_path, mission_config={"dedup_targets": True})
    kept = orch._preflight_targets(["10.0.0.5", "lab.example.com"])
    assert kept == ["10.0.0.5"]
    assert "target_dedup" in _timeline_types(orch.get_state("lab.example.com"))


def test_preflight_keeps_unresolvable_domain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A domain that fails DNS is kept verbatim -- it may be attackable by name."""
    monkeypatch.setattr(
        "tools.validation_utils.resolve_target_to_ip",
        lambda host: None,
    )
    orch = _orch(tmp_path, mission_config={"dedup_targets": True})
    assert orch._preflight_targets(["dead.example.com"]) == ["dead.example.com"]


def test_preflight_skips_non_routable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """skip_non_routable: link-local/reserved addresses are dropped."""
    monkeypatch.setattr(
        "tools.validation_utils.resolve_target_to_ip",
        lambda host: host,
    )
    monkeypatch.setattr(
        "tools.validation_utils.is_local_target",
        lambda ip: False,
    )
    orch = _orch(tmp_path, mission_config={"skip_non_routable": True})
    kept = orch._preflight_targets(["169.254.169.254", "8.8.8.8"])
    assert kept == ["8.8.8.8"]
    assert "target_skipped_non_routable" in _timeline_types(orch.get_state("169.254.169.254"))


def test_preflight_keeps_operator_own_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The operator's own host is NOT dropped by skip_non_routable -- it has
    its own local-takeover path in _attack_target."""
    monkeypatch.setattr(
        "tools.validation_utils.resolve_target_to_ip",
        lambda host: host,
    )
    monkeypatch.setattr(
        "tools.validation_utils.is_local_target",
        lambda ip: ip == "127.0.0.1",
    )
    orch = _orch(tmp_path, mission_config={"skip_non_routable": True})
    assert orch._preflight_targets(["127.0.0.1"]) == ["127.0.0.1"]


def test_preflight_skips_out_of_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A target not in the allowlist is dropped before any scan fires."""
    monkeypatch.setattr(
        "tools.mcp_shared._check_allowlist",
        lambda target, config: (target == "10.0.0.5", "ok" if target == "10.0.0.5" else "not authorized"),
    )
    orch = _orch(tmp_path, mission_config={"dedup_targets": True})
    kept = orch._preflight_targets(["10.0.0.5", "10.0.0.6"])
    assert kept == ["10.0.0.5"]
    assert "target_skipped_out_of_scope" in _timeline_types(orch.get_state("10.0.0.6"))


# ── 3. Hard-target cutoff ───────────────────────────────────────────────────


def _recon_linux_http() -> HostReconResult:
    return HostReconResult(
        target_ip="10.0.0.5",
        os_family="linux",
        services=[ServiceInfo(port=80, protocol="tcp", service="http")],
        open_ports=[80],
    )


@pytest.mark.asyncio
async def test_hard_target_cutoff_gives_up_after_n_rounds(tmp_path: Path) -> None:
    """hard_target_max_rounds=2: after 2 rounds with no access, the adaptive
    loop gives up instead of burning the full max_cycles budget."""
    orch = _orch(
        tmp_path,
        mission_config={"adaptive_replan": True, "max_cycles": 50, "hard_target_max_rounds": 2},
    )

    async def _recon(state: AttackState) -> None:
        state.recon_result = _recon_linux_http()

    async def _exploit_noop(state: AttackState, *, skip_failed: bool = False) -> None:
        # Create a novel task each round so the no-novel-candidate stop does
        # NOT fire -- the hard-target cutoff is for the case where there IS
        # plenty to try but it all keeps failing.
        from tools.autonomous_orchestrator import AttackPhase, AttackTask

        task = AttackTask(
            task_id=orch._new_task_id(),
            phase=AttackPhase.EXPLOITATION,
            module_name="FakeModule",
            target=state.target,
        )
        orch._tasks[task.task_id] = task
        return None  # never achieves access

    async def _noop(state: AttackState) -> None:
        return None

    orch._phase_reconnaissance = _recon  # type: ignore[assignment]
    orch._phase_exploitation = _exploit_noop  # type: ignore[assignment]
    orch._phase_privilege_escalation = _noop  # type: ignore[assignment]
    orch._phase_lateral_movement = _noop  # type: ignore[assignment]
    orch._phase_validation = _noop  # type: ignore[assignment]

    state = orch.get_state("10.0.0.5")
    await orch._run_adaptive_rounds(state, 0)

    assert state.hard_target_rounds == 2
    assert "hard_target_give_up" in _timeline_types(state)


@pytest.mark.asyncio
async def test_hard_target_cutoff_off_by_default(tmp_path: Path) -> None:
    """hard_target_max_rounds=0 (default): the loop stops only on the existing
    no-novel-candidate stop, never via hard_target_give_up."""
    orch = _orch(tmp_path, mission_config={"adaptive_replan": True, "max_cycles": 50})

    async def _recon(state: AttackState) -> None:
        state.recon_result = _recon_linux_http()

    async def _exploit_noop(state: AttackState, *, skip_failed: bool = False) -> None:
        return None

    async def _noop(state: AttackState) -> None:
        return None

    orch._phase_reconnaissance = _recon  # type: ignore[assignment]
    orch._phase_exploitation = _exploit_noop  # type: ignore[assignment]
    orch._phase_privilege_escalation = _noop  # type: ignore[assignment]
    orch._phase_lateral_movement = _noop  # type: ignore[assignment]
    orch._phase_validation = _noop  # type: ignore[assignment]

    state = orch.get_state("10.0.0.5")
    await orch._run_adaptive_rounds(state, 0)

    assert "hard_target_give_up" not in _timeline_types(state)
    assert "adaptive_stop" in _timeline_types(state)


# ── 4. Pipeline preflight skip discipline ────────────────────────────────────


@pytest.mark.asyncio
async def test_pipeline_refused_on_two_ports_still_full_scans(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refused on the default [80, 443] probe set must NOT skip the full scan.

    Even when the probe reports False outright, the pipeline only honors the
    skip for a COMMON_PORTS-sized sample -- refused = host UP."""
    from tools.recon.config import ReconConfig
    from tools.recon.pipeline import ReconPipeline

    async def fake_probe(target, ports=None, timeout=1.0):
        return False

    monkeypatch.setattr("tools.recon.pipeline.probe_reachable", fake_probe)

    scanned: list[str] = []

    async def fake_scan(target):
        scanned.append(target)
        result = HostReconResult(target_ip=target)
        result.open_ports = [22]
        return result

    async def fake_enumerate(result):
        return result

    pipe = ReconPipeline(ReconConfig(preflight_probe=True))  # default ports [80, 443]
    monkeypatch.setattr(pipe._primary, "scan_host", fake_scan)
    monkeypatch.setattr(pipe._secondary, "enumerate_host", fake_enumerate)

    result = await pipe.recon_host("10.0.0.5")
    assert scanned == ["10.0.0.5"], "small-sample refused verdict must fall through to the full scan"
    assert result.open_ports == [22]


@pytest.mark.asyncio
async def test_pipeline_refused_full_sample_skips_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """All-refused over a COMMON_PORTS-sized sample DOES skip the full scan."""
    from tools.recon.config import ReconConfig
    from tools.recon.pipeline import ReconPipeline
    from tools.socket_scan import COMMON_PORTS

    async def fake_probe(target, ports=None, timeout=1.0):
        return False

    monkeypatch.setattr("tools.recon.pipeline.probe_reachable", fake_probe)

    async def fake_scan(target):  # pragma: no cover - must not run
        raise AssertionError("full scan must be skipped")

    pipe = ReconPipeline(ReconConfig(preflight_probe=True, preflight_ports=list(COMMON_PORTS)))
    monkeypatch.setattr(pipe._primary, "scan_host", fake_scan)

    result = await pipe.recon_host("10.0.0.5")
    assert result.open_ports == []
    assert any("preflight" in e for e in result.errors)
