"""Tests for tools/opsec.py -- the OPSEC manager.

OPSEC here hardens the agent's own behavior (pacing, UA rotation, DoH,
quiet-command blocking, noise scoring). It is NOT active evasion: no log
clearing, no EDR defeat, no audit-trail mutation. These tests are hermetic --
no real network, no real sleep -- using injected fakes for rng / fetch_fn /
rate_limiter / sleep_fn / socket resolver.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from tools.opsec import (
    _DEFAULT_PROFILE,
    AGGRESSION_FACTOR,
    OpsecManager,
    OpsecProfile,
    configure,
    process_user_agent,
)

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class CounterRng:
    """Deterministic rng returning sequential values from a list, looping."""

    def __init__(self, values: list[float]) -> None:
        self._values = values
        self._i = 0
        self.calls = 0

    def __call__(self) -> float:
        v = self._values[self._i % len(self._values)]
        self._i += 1
        self.calls += 1
        return v


class FakeRateLimiter:
    """Records acquire calls; never actually waits."""

    def __init__(self) -> None:
        self.acquires: list[tuple[str, float]] = []

    async def acquire(self, key: str, cost: float = 1.0) -> None:
        self.acquires.append((key, cost))


class FakeAsyncSleep:
    """Records the delays we would have slept; does not really sleep.

    Returns a coroutine to mimic ``asyncio.sleep`` so the ``await`` path in
    ``acquire_pacing`` exercises the await-branch when injected via sleep_fn.
    """

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


def make_canned_fetch(payload: dict, *, raise_on: int | None = None) -> Any:
    """Return a fetch_fn that returns canned DoH JSON bytes.

    ``raise_on`` -- if set, the Nth call raises to exercise the fallback path.
    """
    calls = {"n": 0}
    raw = json.dumps(payload).encode("utf-8")

    def fetch(url: str, headers: dict[str, str]) -> bytes:
        calls["n"] += 1
        if raise_on is not None and calls["n"] == raise_on:
            raise OSError("simulated DoH failure")
        return raw

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


# ---------------------------------------------------------------------------
# OpsecProfile.from_config / to_dict
# ---------------------------------------------------------------------------


def test_profile_from_config_missing_opsec_block_defaults():
    p = OpsecProfile.from_config({})
    assert p.enabled is False
    assert p.ua_rotation is False
    assert p.doh is False
    assert p.doh_provider == "cloudflare"
    assert p.min_gap_seconds == 0.0
    assert p.jitter_seconds == 0.0
    assert p.rate_per_minute == 0
    assert p.quiet_command_patterns == ()
    assert p.noise_budget == 0


def test_profile_from_config_empty_opsec_block_defaults():
    p = OpsecProfile.from_config({"opsec": {}})
    assert p.enabled is False
    assert p.quiet_command_patterns == ()


def test_profile_from_config_reads_each_key():
    cfg = {
        "opsec": {
            "enabled": True,
            "ua_rotation": True,
            "doh": True,
            "doh_provider": "google",
            "min_gap_seconds": 2.5,
            "jitter_seconds": 0.75,
            "rate_per_minute": 12,
            "quiet_command_patterns": ["hydra", "masscan"],
            "noise_budget": 5,
        }
    }
    p = OpsecProfile.from_config(cfg)
    assert p.enabled is True
    assert p.ua_rotation is True
    assert p.doh is True
    assert p.doh_provider == "google"
    assert p.min_gap_seconds == 2.5
    assert p.jitter_seconds == 0.75
    assert p.rate_per_minute == 12
    assert p.quiet_command_patterns == ("hydra", "masscan")
    assert p.noise_budget == 5


def test_profile_to_dict_round_trip():
    p = OpsecProfile(
        enabled=True,
        ua_rotation=True,
        doh=True,
        doh_provider="google",
        min_gap_seconds=1.5,
        jitter_seconds=0.5,
        rate_per_minute=20,
        quiet_command_patterns=("a", "b"),
        noise_budget=3,
    )
    d = p.to_dict()
    assert d["enabled"] is True
    assert d["quiet_command_patterns"] == ["a", "b"]
    # Feeding the dict back through from_config reconstructs an equal profile.
    p2 = OpsecProfile.from_config({"opsec": d})
    assert p2 == p


def test_profile_from_config_tolerates_none_cfg():
    p = OpsecProfile.from_config(None)  # type: ignore[arg-type]
    assert p.enabled is False
    assert p.doh_provider == "cloudflare"


# ---------------------------------------------------------------------------
# user_agent
# ---------------------------------------------------------------------------


def test_user_agent_fixed_default_when_rotation_off():
    mgr = OpsecManager(OpsecProfile(ua_rotation=False))
    assert mgr.user_agent() == "NetAttackAi/1.0"


def test_user_agent_rotates_across_pool_when_on():
    # rng returns evenly spaced fractions so we hit successive pool indices.
    pool = OpsecManager._UA_POOL
    n = len(pool)
    values = [i / n for i in range(n)]  # 0, 1/n, ..., (n-1)/n
    rng = CounterRng(values)
    mgr = OpsecManager(OpsecProfile(ua_rotation=True), rng=rng)
    seen = [mgr.user_agent() for _ in range(n)]
    # Every returned UA must be a pool member...
    assert all(ua in pool for ua in seen)
    # ...and across n draws with distinct fractions we hit n distinct UAs.
    assert len(set(seen)) == n


def test_user_agent_rotation_deterministic_with_injected_rng():
    mgr = OpsecManager(OpsecProfile(ua_rotation=True), rng=lambda: 0.0)
    # rng==0 -> index 0 always.
    assert mgr.user_agent() == OpsecManager._UA_POOL[0]
    assert mgr.user_agent() == OpsecManager._UA_POOL[0]


# ---------------------------------------------------------------------------
# pacing_delay
# ---------------------------------------------------------------------------


@pytest.fixture
def paced_profile() -> OpsecProfile:
    return OpsecProfile(enabled=True, min_gap_seconds=10.0, jitter_seconds=0.0)


def test_pacing_delay_ordering_stealth_normal_aggressive_maximum(paced_profile):
    mgr = OpsecManager(paced_profile, rng=lambda: 0.5)
    s = mgr.pacing_delay("stealth")
    n = mgr.pacing_delay("normal")
    a = mgr.pacing_delay("aggressive")
    m = mgr.pacing_delay("maximum")
    assert s > n > a > m
    assert s == pytest.approx(20.0)  # 10 * 2.0
    assert n == pytest.approx(10.0)  # 10 * 1.0
    assert a == pytest.approx(5.0)  # 10 * 0.5
    assert m == 0.0  # 10 * 0.0


def test_pacing_delay_unknown_aggression_defaults_to_normal_factor(paced_profile):
    mgr = OpsecManager(paced_profile, rng=lambda: 0.0)
    assert mgr.pacing_delay("bogus") == pytest.approx(10.0)
    assert AGGRESSION_FACTOR.get("bogus", 1.0) == 1.0


def test_pacing_delay_jitter_non_negative(paced_profile):
    p = OpsecProfile(enabled=True, min_gap_seconds=10.0, jitter_seconds=4.0)
    mgr = OpsecManager(p, rng=lambda: 0.25)
    # 10 * 1.0 + 4 * 0.25 = 11.0
    assert mgr.pacing_delay("normal") == pytest.approx(11.0)
    # Even with rng==0, jitter is 0 -> delay equals base.
    mgr0 = OpsecManager(p, rng=lambda: 0.0)
    assert mgr0.pacing_delay("normal") == pytest.approx(10.0)


def test_pacing_delay_disabled_profile_zero_when_no_gap():
    p = OpsecProfile(enabled=False, min_gap_seconds=0.0)
    mgr = OpsecManager(p, rng=lambda: 0.99)
    assert mgr.pacing_delay("stealth") == 0.0


# ---------------------------------------------------------------------------
# acquire_pacing
# ---------------------------------------------------------------------------


def test_acquire_pacing_with_rate_limiter_and_sleep():
    p = OpsecProfile(enabled=True, min_gap_seconds=6.0, rate_per_minute=10)
    rl = FakeRateLimiter()
    sleep = FakeAsyncSleep()
    mgr = OpsecManager(p, rate_limiter=rl, sleep_fn=sleep, rng=lambda: 0.0)

    asyncio.run(mgr.acquire_pacing("normal"))
    assert rl.acquires == [("opsec", 1.0)]
    assert sleep.delays == [6.0]


def test_acquire_pacing_no_rate_limiter_just_sleeps():
    p = OpsecProfile(enabled=True, min_gap_seconds=3.0)
    sleep = FakeAsyncSleep()
    mgr = OpsecManager(p, sleep_fn=sleep, rng=lambda: 0.0)
    asyncio.run(mgr.acquire_pacing("aggressive"))
    # No rate limiter -> no acquires, but the delay (3 * 0.5 = 1.5) is slept.
    assert sleep.delays == [1.5]


def test_acquire_pacing_zero_delay_does_not_sleep():
    p = OpsecProfile(enabled=True, min_gap_seconds=0.0, rate_per_minute=0)
    sleep = FakeAsyncSleep()
    mgr = OpsecManager(p, sleep_fn=sleep, rng=lambda: 0.0)
    asyncio.run(mgr.acquire_pacing("maximum"))
    assert sleep.delays == []


# ---------------------------------------------------------------------------
# score_command_noise
# ---------------------------------------------------------------------------


def test_score_noise_noisy_commands_score_positive_with_reasons():
    mgr = OpsecManager(OpsecProfile(enabled=True))
    for cmd in ["nmap -T5 10.0.0.5", "masscan 10.0.0.0/24", "hydra -L users.txt", "nmap --script=vuln 10.0.0.5"]:
        r = mgr.score_command_noise(cmd)
        assert r["score"] > 0, (cmd, r)
        assert r["noisy"] is True
        assert len(r["reasons"]) == r["score"]


def test_score_noise_benign_commands_score_zero():
    mgr = OpsecManager(OpsecProfile(enabled=True))
    for cmd in ["ls -la", "cat /etc/hosts", "whoami", "id"]:
        r = mgr.score_command_noise(cmd)
        assert r["score"] == 0, (cmd, r)
        assert r["noisy"] is False
        assert r["reasons"] == []


def test_score_noise_empty_command_zero():
    mgr = OpsecManager(OpsecProfile(enabled=True))
    assert mgr.score_command_noise("") == {"score": 0, "reasons": [], "noisy": False}


def test_score_noise_case_insensitive():
    mgr = OpsecManager(OpsecProfile(enabled=True))
    r = mgr.score_command_noise("NMAP -T5 target")
    assert r["score"] > 0
    assert r["noisy"] is True


# ---------------------------------------------------------------------------
# is_quiet_blocked
# ---------------------------------------------------------------------------


def test_is_quiet_blocked_matches_only_when_enabled():
    p_off = OpsecProfile(enabled=False, quiet_command_patterns=("hydra",))
    mgr_off = OpsecManager(p_off)
    assert mgr_off.is_quiet_blocked("hydra -L users.txt") is False

    p_on = OpsecProfile(enabled=True, quiet_command_patterns=("hydra", "masscan"))
    mgr_on = OpsecManager(p_on)
    assert mgr_on.is_quiet_blocked("hydra -L users.txt") is True
    assert mgr_on.is_quiet_blocked("masscan 10.0.0.0/24") is True


def test_is_quiet_blocked_no_match_returns_false():
    p = OpsecProfile(enabled=True, quiet_command_patterns=("hydra",))
    mgr = OpsecManager(p)
    assert mgr.is_quiet_blocked("nmap -sV 10.0.0.5") is False
    assert mgr.is_quiet_blocked("") is False


def test_is_quiet_blocked_case_insensitive():
    p = OpsecProfile(enabled=True, quiet_command_patterns=("Hydra",))
    mgr = OpsecManager(p)
    assert mgr.is_quiet_blocked("HYDRA -L users.txt") is True


# ---------------------------------------------------------------------------
# suggest_low_noise_alternative
# ---------------------------------------------------------------------------


def test_suggest_rewrites_t5_and_t4():
    mgr = OpsecManager(OpsecProfile(enabled=True))
    assert mgr.suggest_low_noise_alternative("nmap -T5 10.0.0.5") == "nmap -T2 10.0.0.5"
    assert mgr.suggest_low_noise_alternative("nmap -T4 10.0.0.5") == "nmap -T2 10.0.0.5"


def test_suggest_rewrites_masscan_and_ffuf():
    mgr = OpsecManager(OpsecProfile(enabled=True))
    assert mgr.suggest_low_noise_alternative("masscan 10.0.0.0/24 -p1-65535") == "nmap -sS -Pn 10.0.0.0/24 -p1-65535"
    assert (
        mgr.suggest_low_noise_alternative("ffuf -u https://x/FUZZ -w wl.txt") == "nmap -sV -u https://x/FUZZ -w wl.txt"
    )


def test_suggest_returns_none_for_benign():
    mgr = OpsecManager(OpsecProfile(enabled=True))
    assert mgr.suggest_low_noise_alternative("ls -la") is None
    assert mgr.suggest_low_noise_alternative("cat /etc/hosts") is None
    assert mgr.suggest_low_noise_alternative("") is None


# ---------------------------------------------------------------------------
# doh_resolve
# ---------------------------------------------------------------------------


def _doh_payload(ips: list[str]) -> dict:
    return {
        "Status": 0,
        "Answer": [{"name": "example.com", "type": 1, "TTL": 60, "data": ip} for ip in ips],
    }


def test_doh_resolve_with_canned_fetch_returns_parsed_ips(monkeypatch):
    # Make sure system resolver is NOT touched on the happy path.
    monkeypatch.setattr(
        "tools.opsec.socket.getaddrinfo", lambda *a, **k: pytest.fail("system resolver must not be used")
    )
    p = OpsecProfile(enabled=True, doh=True, doh_provider="cloudflare")
    fetch = make_canned_fetch(_doh_payload(["93.184.216.34", "93.184.216.35"]))
    mgr = OpsecManager(p, fetch_fn=fetch)
    assert mgr.doh_resolve("example.com") == ["93.184.216.34", "93.184.216.35"]


def test_doh_resolve_dedupes(monkeypatch):
    monkeypatch.setattr(
        "tools.opsec.socket.getaddrinfo", lambda *a, **k: pytest.fail("system resolver must not be used")
    )
    p = OpsecProfile(enabled=True, doh=True, doh_provider="google")
    fetch = make_canned_fetch(_doh_payload(["1.2.3.4", "1.2.3.4", "5.6.7.8"]))
    mgr = OpsecManager(p, fetch_fn=fetch)
    assert mgr.doh_resolve("dup.example") == ["1.2.3.4", "5.6.7.8"]


def test_doh_resolve_fetch_failure_falls_back_to_system(monkeypatch):
    p = OpsecProfile(enabled=True, doh=True, doh_provider="cloudflare")
    fetch = make_canned_fetch(_doh_payload(["9.9.9.9"]), raise_on=1)
    monkeypatch.setattr(
        "tools.opsec.socket.getaddrinfo",
        lambda host, *a, **k: [
            (0, 0, 0, "", ("203.0.113.10", 0)),
        ],
    )
    mgr = OpsecManager(p, fetch_fn=fetch)
    # fetch raises -> falls back to system resolver -> never raises.
    assert mgr.doh_resolve("fail.example") == ["203.0.113.10"]


def test_doh_resolve_when_doh_off_uses_system_resolver(monkeypatch):
    p = OpsecProfile(enabled=True, doh=False)
    called = {"n": 0}

    def fake_getaddrinfo(host, *a, **k):
        called["n"] += 1
        return [
            (0, 0, 0, "", ("10.0.0.55", 0)),
            (0, 0, 0, "", ("10.0.0.55", 0)),  # dup, should be deduped
        ]

    monkeypatch.setattr("tools.opsec.socket.getaddrinfo", fake_getaddrinfo)
    mgr = OpsecManager(p)
    assert mgr.doh_resolve("target.local") == ["10.0.0.55"]
    assert called["n"] == 1


def test_doh_resolve_bad_provider_falls_back(monkeypatch):
    p = OpsecProfile(enabled=True, doh=True, doh_provider="bogus")
    monkeypatch.setattr(
        "tools.opsec.socket.getaddrinfo",
        lambda host, *a, **k: [
            (0, 0, 0, "", ("198.51.100.7", 0)),
        ],
    )
    mgr = OpsecManager(p, fetch_fn=lambda url, headers: pytest.fail("fetch must not be called for bad provider"))
    assert mgr.doh_resolve("bad.example") == ["198.51.100.7"]


def test_doh_resolve_total_failure_returns_empty(monkeypatch):
    p = OpsecProfile(enabled=True, doh=True, doh_provider="cloudflare")
    fetch = make_canned_fetch(_doh_payload([]), raise_on=1)
    monkeypatch.setattr("tools.opsec.socket.getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(OSError("no dns")))
    mgr = OpsecManager(p, fetch_fn=fetch)
    assert mgr.doh_resolve("nope.example") == []


# ---------------------------------------------------------------------------
# from_config factory
# ---------------------------------------------------------------------------


def test_manager_from_config_builds_profile_and_forwards_kwargs():
    cfg = {"opsec": {"enabled": True, "ua_rotation": True, "rate_per_minute": 5}}
    rng = CounterRng([0.0])
    mgr = OpsecManager.from_config(cfg, rng=rng)
    assert mgr.profile.enabled is True
    assert mgr.profile.ua_rotation is True
    assert mgr.profile.rate_per_minute == 5
    assert mgr._rng is rng


# ---------------------------------------------------------------------------
# process-global UA rotation
# ---------------------------------------------------------------------------


def test_process_user_agent_unconfigured_returns_default():
    # The module starts unconfigured (or configured off). Reset to be safe.
    import tools.opsec as opsec_mod

    opsec_mod._process_manager = None
    assert process_user_agent("NetAttackAi-OSINT/1.0") == "NetAttackAi-OSINT/1.0"
    assert process_user_agent() == "NetAttackAi/1.0"


def test_process_user_agent_after_configure_with_rotation_returns_pool_ua():
    import tools.opsec as opsec_mod

    opsec_mod._process_manager = None
    p = OpsecProfile(enabled=True, ua_rotation=True)
    configure(p, rng=lambda: 0.0)
    ua = process_user_agent("NetAttackAi-OSINT/1.0")
    assert ua in OpsecManager._UA_POOL
    assert ua != "NetAttackAi-OSINT/1.0"
    # Cleanup so other tests see the unconfigured state.
    opsec_mod._process_manager = None


def test_process_user_agent_after_configure_without_rotation_returns_default():
    import tools.opsec as opsec_mod

    opsec_mod._process_manager = None
    p = OpsecProfile(enabled=True, ua_rotation=False)
    configure(p)
    assert process_user_agent("MyUA/2.0") == "MyUA/2.0"
    opsec_mod._process_manager = None


def test_default_profile_is_off():
    assert _DEFAULT_PROFILE.enabled is False
    assert _DEFAULT_PROFILE.ua_rotation is False
