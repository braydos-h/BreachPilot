"""Phase 6.2+ -- target-aware OPSEC: off for local/private IPs, on for public.

Covers:
- ``tools.validation_utils.is_private_or_local_target`` (local vs public
  classification, extra local_cidrs, parse-error safety).
- ``OpsecProfile.resolve_for_target`` / ``OpsecManager.resolve_for_target``
  (local target -> disabled profile; public -> unchanged; preserves the
  target-awareness knobs so per-task re-resolution of a public pivot works).
- ``OpsecProfile.from_config`` / ``to_dict`` round-trip for the new keys.
- ``AttackModuleExecutor.execute`` wiring: a local target yields no pacing
  sleep; a public target does. Confirms the operator intent -- "OPSEC off for
  local IPs, on for public IPs, AI chooses attacks for public" -- bites at the
  per-action chokepoint.
"""

from __future__ import annotations

import pytest

from tools.autonomous_orchestrator import (
    AggressionLevel,
    AttackModuleExecutor,
    AttackPhase,
    AttackState,
    AttackTask,
)
from tools.opsec import OpsecManager, OpsecProfile, configure, process_user_agent
from tools.validation_utils import is_private_or_local_target

# ---------------------------------------------------------------------------
# is_private_or_local_target
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "::1",
        "localhost",
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.5",
        "169.254.1.1",  # link-local
        "fc00::1",  # IPv6 ULA
        "fe80::1",  # IPv6 link-local
        "0.0.0.0",
    ],
)
def test_is_private_or_local_target_true_for_local(ip: str) -> None:
    assert is_private_or_local_target(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2001:4860:4860::8888"])
def test_is_private_or_local_target_false_for_public(ip: str) -> None:
    assert is_private_or_local_target(ip) is False


def test_is_private_or_local_target_extra_cidrs() -> None:
    # A public IP that the operator marks as local via extra_local_cidrs.
    assert is_private_or_local_target("203.0.113.10", ["203.0.113.0/24"]) is True
    # Without the override it is whatever ipaddress says (203.0.113/24 is
    # documentation space -> is_private True in CPython), so just assert the
    # override path is accepted and a clearly-public IP stays public.
    assert is_private_or_local_target("8.8.8.8", ["203.0.113.0/24"]) is False
    # CIDR containment, not just exact match.
    assert is_private_or_local_target("100.64.0.5", ["100.64.0.0/10"]) is True


def test_is_private_or_local_target_safe_defaults() -> None:
    assert is_private_or_local_target("") is False
    assert is_private_or_local_target(None) is False  # type: ignore[arg-type]
    assert is_private_or_local_target("not-an-ip") is False
    assert is_private_or_local_target("example.com") is False


def test_is_private_or_local_target_is_not_is_local_target() -> None:
    # 10.0.0.50 is a private network IP but NOT the operator's own host, so the
    # existing is_local_target() returns False for it. The new classifier must
    # return True -- they are distinct semantics.
    from tools.validation_utils import is_local_target

    assert is_local_target("10.0.0.50") is False
    assert is_private_or_local_target("10.0.0.50") is True


# ---------------------------------------------------------------------------
# OpsecProfile.resolve_for_target
# ---------------------------------------------------------------------------


def _enabled_profile() -> OpsecProfile:
    return OpsecProfile(
        enabled=True,
        ua_rotation=True,
        doh=True,
        min_gap_seconds=1.5,
        jitter_seconds=0.5,
        rate_per_minute=30,
        quiet_command_patterns=("masscan", "nuclei"),
        noise_budget=10,
        local_targets_off=True,
        local_cidrs=("203.0.113.0/24",),
        public_autonomy=True,
    )


def test_resolve_for_target_local_yields_disabled_profile() -> None:
    p = _enabled_profile()
    resolved = p.resolve_for_target("10.0.0.50")
    assert resolved is not p
    assert resolved.enabled is False
    assert resolved.ua_rotation is False
    assert resolved.doh is False
    assert resolved.min_gap_seconds == 0.0
    assert resolved.jitter_seconds == 0.0
    assert resolved.rate_per_minute == 0
    assert resolved.quiet_command_patterns == ()
    assert resolved.noise_budget == 0


def test_resolve_for_target_local_preserves_target_awareness_knobs() -> None:
    # The disabled profile must keep local_targets_off / local_cidrs /
    # public_autonomy so a later re-resolution against a public pivot target
    # from THIS resolved profile re-enables correctly.
    p = _enabled_profile()
    resolved = p.resolve_for_target("10.0.0.50")
    assert resolved.local_targets_off is True
    assert resolved.local_cidrs == ("203.0.113.0/24",)
    assert resolved.public_autonomy is True
    # And re-resolving the disabled profile against a public IP returns it
    # unchanged (it is already disabled; the base profile is what carries the
    # enabled posture -- see OpsecManager.resolve_for_target for the base path).
    assert resolved.resolve_for_target("8.8.8.8") is resolved


def test_resolve_for_target_public_returns_self_unchanged() -> None:
    p = _enabled_profile()
    assert p.resolve_for_target("8.8.8.8") is p


def test_resolve_for_target_local_cidr_match_treated_as_local() -> None:
    p = _enabled_profile()
    # 203.0.113.9 is in the configured local_cidrs -> local -> disabled.
    resolved = p.resolve_for_target("203.0.113.9")
    assert resolved is not p
    assert resolved.enabled is False


def test_resolve_for_target_local_targets_off_disabled_returns_self() -> None:
    p = _enabled_profile()
    p.local_targets_off = False
    # Opt-out: even a local target keeps the configured posture.
    assert p.resolve_for_target("10.0.0.50") is p


def test_resolve_for_target_missing_target_returns_self() -> None:
    p = _enabled_profile()
    assert p.resolve_for_target("") is p
    assert p.resolve_for_target(None) is p  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# from_config / to_dict round-trip for the new keys
# ---------------------------------------------------------------------------


def test_from_config_reads_target_aware_keys() -> None:
    cfg = {
        "opsec": {
            "enabled": True,
            "local_targets_off": False,
            "local_cidrs": ["10.99.0.0/16"],
            "public_autonomy": False,
        }
    }
    p = OpsecProfile.from_config(cfg)
    assert p.local_targets_off is False
    assert p.local_cidrs == ("10.99.0.0/16",)
    assert p.public_autonomy is False


def test_from_config_defaults_target_aware_keys() -> None:
    p = OpsecProfile.from_config({})
    assert p.local_targets_off is True
    assert p.local_cidrs == ()
    assert p.public_autonomy is True


def test_to_dict_round_trips_target_aware_keys() -> None:
    p = _enabled_profile()
    d = p.to_dict()
    assert d["local_targets_off"] is True
    assert d["local_cidrs"] == ["203.0.113.0/24"]
    assert d["public_autonomy"] is True
    rt = OpsecProfile.from_config({"opsec": d})
    assert rt.local_targets_off == p.local_targets_off
    assert rt.local_cidrs == p.local_cidrs
    assert rt.public_autonomy == p.public_autonomy


# ---------------------------------------------------------------------------
# OpsecManager.resolve_for_target
# ---------------------------------------------------------------------------


def test_manager_resolve_for_target_public_returns_self() -> None:
    mgr = OpsecManager(_enabled_profile())
    assert mgr.resolve_for_target("8.8.8.8") is mgr


def test_manager_resolve_for_target_local_returns_new_manager_sharing_rng() -> None:
    calls: list[float] = []
    rng = lambda: 0.25  # noqa: E731
    mgr = OpsecManager(_enabled_profile(), rng=rng, sleep_fn=lambda d: calls.append(d))
    resolved = mgr.resolve_for_target("10.0.0.50")
    assert resolved is not mgr
    assert resolved.profile.enabled is False
    # Injected callables are shared with the resolved manager.
    assert resolved._rng is rng
    assert resolved._sleep_fn is mgr._sleep_fn


def test_resolved_disabled_manager_no_pacing_no_quiet_block() -> None:
    mgr = OpsecManager(_enabled_profile())
    local_mgr = mgr.resolve_for_target("192.168.1.10")
    # Pacing collapses to 0 for a disabled profile.
    assert local_mgr.pacing_delay("stealth") == 0.0
    # Quiet-blocking is off even for a command that matches a pattern.
    assert local_mgr.is_quiet_blocked("nmap -sS -Pn masscan 10.0.0.5") is False
    # UA rotation is off -> fixed default UA.
    assert local_mgr.user_agent() == "BreachPilot/1.0"
    # The public-resolved manager keeps pacing on.
    pub_mgr = mgr.resolve_for_target("8.8.8.8")
    assert pub_mgr.pacing_delay("stealth") > 0.0


# ---------------------------------------------------------------------------
# Process-global UA follows the primary target
# ---------------------------------------------------------------------------


def test_process_user_agent_follows_resolved_profile() -> None:
    try:
        # Local target -> disabled profile -> no UA rotation -> default arg.
        local_profile = _enabled_profile().resolve_for_target("10.0.0.50")
        configure(local_profile)
        assert process_user_agent("BreachPilot-OSINT/1.0") == "BreachPilot-OSINT/1.0"
        # Public target -> configured profile with ua_rotation -> pool UA.
        configure(_enabled_profile())
        ua = process_user_agent("BreachPilot-OSINT/1.0")
        assert ua != "BreachPilot-OSINT/1.0"
        assert "BreachPilot" not in ua  # a rotated browser UA, not the default
    finally:
        # Reset the process-global so other tests are unaffected.
        from tools import opsec as _opsec_mod

        _opsec_mod._process_manager = None


# ---------------------------------------------------------------------------
# AttackModuleExecutor wiring -- the per-action chokepoint
# ---------------------------------------------------------------------------


def _info_task(target: str, aggression: AggressionLevel = AggressionLevel.STEALTH) -> AttackTask:
    # detection_coverage_probe is a registered info module (no dispatch, no
    # shell_type/privilege_level) -- ideal for exercising the pacing chokepoint
    # without triggering real exploit dispatch. Mirrors test_opsec_orchestrator_wiring.
    return AttackTask(
        task_id="T-OPSEC-TGT",
        phase=AttackPhase.EXPLOITATION,
        module_name="detection_coverage_probe",
        target=target,
        aggression=aggression,
    )


@pytest.mark.asyncio
async def test_executor_no_pacing_for_local_target() -> None:
    sleeps: list[float] = []
    profile = OpsecProfile(
        enabled=True,
        min_gap_seconds=1.0,
        jitter_seconds=0.0,
        local_targets_off=True,
    )
    mgr = OpsecManager(profile, sleep_fn=lambda d: sleeps.append(d))
    executor = AttackModuleExecutor(opsec_manager=mgr)
    state = AttackState(target="10.0.0.50")
    await executor.execute(_info_task("10.0.0.50"), state)
    # Local/private target -> resolved disabled profile -> pacing_delay 0 -> no sleep.
    assert sleeps == []


@pytest.mark.asyncio
async def test_executor_pacing_for_public_target() -> None:
    sleeps: list[float] = []
    profile = OpsecProfile(
        enabled=True,
        min_gap_seconds=1.0,
        jitter_seconds=0.0,
        local_targets_off=True,
    )
    mgr = OpsecManager(profile, sleep_fn=lambda d: sleeps.append(d))
    executor = AttackModuleExecutor(opsec_manager=mgr)
    state = AttackState(target="8.8.8.8")
    await executor.execute(_info_task("8.8.8.8"), state)
    # Public target -> configured profile -> pacing delay > 0 -> sleep invoked.
    assert len(sleeps) == 1
    assert sleeps[0] > 0.0


@pytest.mark.asyncio
async def test_executor_local_targets_off_false_paces_even_local() -> None:
    sleeps: list[float] = []
    profile = OpsecProfile(
        enabled=True,
        min_gap_seconds=1.0,
        jitter_seconds=0.0,
        local_targets_off=False,  # operator opted out of the local-off rule
    )
    mgr = OpsecManager(profile, sleep_fn=lambda d: sleeps.append(d))
    executor = AttackModuleExecutor(opsec_manager=mgr)
    state = AttackState(target="10.0.0.50")
    await executor.execute(_info_task("10.0.0.50"), state)
    # Opt-out: local target still gets paced per the configured profile.
    assert len(sleeps) == 1
    assert sleeps[0] > 0.0
