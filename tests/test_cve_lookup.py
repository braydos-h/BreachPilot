"""Tests for tools/cve_lookup.py NVD API wrapper."""

from __future__ import annotations

import json
from unittest.mock import patch
import pytest

from tools.cve_lookup import (
    CVESearchSettings,
    CVEEntry,
    NVDClient,
    format_cve_results,
)


SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL"
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "description": [
                            {"lang": "en", "value": "CWE-502"}
                        ]
                    }
                ],
                "published": "2021-12-10T00:00:00.000",
                "references": [
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}
                ]
            }
        }
    ]
}


def test_parse_cve_entry():
    client = NVDClient(CVESearchSettings())
    entries = client._parse(SAMPLE_NVD_RESPONSE)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.cve_id == "CVE-2021-44228"
    assert entry.cvss_score == 10.0
    assert entry.severity == "CRITICAL"
    assert entry.cwe == "CWE-502"
    assert entry.published == "2021-12-10"
    assert "JNDI" in entry.description


def test_format_cve_results():
    entry = CVEEntry(
        cve_id="CVE-2021-44228",
        description="Log4j RCE",
        cvss_score=10.0,
        severity="CRITICAL",
        cwe="CWE-502",
        published="2021-12-10",
        references=["https://example.com"],
    )
    text = format_cve_results([entry], "log4j 2.14")
    assert "CVE-2021-44228" in text
    assert "10.0" in text
    assert "CWE-502" in text


def test_format_empty_results():
    text = format_cve_results([], "unknown thing")
    assert "No CVEs found" in text


@pytest.mark.asyncio
async def test_search_rate_limit_and_cache():
    client = NVDClient(CVESearchSettings(rate_limit_seconds=0.1))
    with patch.object(client, "_fetch_sync", return_value=[]) as mock_fetch:
        await client.search("test")
        await client.search("test")  # should be cached
        mock_fetch.assert_called_once()


@pytest.mark.asyncio
async def test_disabled_client_returns_empty():
    client = NVDClient(CVESearchSettings(enabled=False))
    result = await client.search("anything")
    assert result == []


# ── Tier 1.2: CircuitBreaker graceful degradation ───────────────────────────


@pytest.mark.asyncio
async def test_circuit_opens_after_threshold_failures_then_short_circuits():
    """After N consecutive fetch failures the breaker opens and search()
    returns [] WITHOUT calling NVD (graceful degradation, no hammering)."""
    # threshold=3, no rate-limit sleep, fresh queries each call (different key)
    # so the cache never serves a hit and the fetch path runs every time.
    client = NVDClient(CVESearchSettings(
        circuit_failure_threshold=3, rate_limit_seconds=0.0,
    ))
    call_count = 0
    def boom(query):
        nonlocal call_count
        call_count += 1
        raise RuntimeError("NVD HTTP 503: down")
    with patch.object(client, "_fetch_sync", side_effect=boom):
        # First 3 failing calls: breaker CLOSED, fetch attempted, raises.
        for i in range(3):
            with pytest.raises(RuntimeError):
                await client.search(f"q{i}")
        assert call_count == 3, "each failing call hit NVD"
        # Breaker is now OPEN. The 4th call must short-circuit to [] and NOT
        # call NVD at all.
        result = await client.search("q3")
        assert result == []
        assert call_count == 3, "circuit open must not call NVD"


@pytest.mark.asyncio
async def test_circuit_success_resets_failure_count():
    """A successful fetch while CLOSED resets the failure counter so a later
    single failure does not trip the breaker prematurely.

    threshold=2 is chosen so the test is NON-VACUOUS: with a correct
    record_success (resets count) the sequence boom(1)->ok(0)->boom2(1) stays
    CLOSED, but with a broken no-reset record_success it would be
    boom(1)->ok(1)->boom2(2) >= threshold -> OPEN. The closed/open outcome
    therefore differs between a working and a broken reset, so the assertion
    actually guards the reset invariant."""
    client = NVDClient(CVESearchSettings(
        circuit_failure_threshold=2, rate_limit_seconds=0.0,
    ))
    calls = []
    def fetch(query):
        calls.append(query)
        if query.startswith("boom"):
            raise RuntimeError("down")
        return []
    with patch.object(client, "_fetch_sync", side_effect=fetch):
        with pytest.raises(RuntimeError):
            await client.search("boom")
        await client.search("ok")        # success -> record_success resets count to 0
        with pytest.raises(RuntimeError):
            await client.search("boom2")  # failure count back to 1 (< threshold 2)
        # Breaker must still be CLOSED: the success reset prevented two
        # consecutive failures from accumulating. (A no-op record_success
        # would leave count=2 -> OPEN, failing this assertion.)
        assert client._breaker.get_state() == "closed"
        # A successful call still works (proves breaker never opened).
        await client.search("ok2")
        assert calls.count("ok2") == 1


@pytest.mark.asyncio
async def test_circuit_does_not_cache_empty_degradation():
    """When the breaker is OPEN, the [] short-circuit must NOT be cached --
    otherwise a recovered NVD would keep serving stale empties."""
    client = NVDClient(CVESearchSettings(
        circuit_failure_threshold=1, rate_limit_seconds=0.0,
    ))
    with patch.object(client, "_fetch_sync", side_effect=RuntimeError("down")):
        with pytest.raises(RuntimeError):
            await client.search("q")  # 1 failure trips threshold=1 -> OPEN
    # Now OPEN: short-circuits to [] without caching.
    assert await client.search("q") == []
    assert "q" not in client._cache, "degraded [] must not be cached"


def test_search_sync_circuit_opens_sync_path():
    """The synchronous wrapper gets the same breaker protection."""
    client = NVDClient(CVESearchSettings(
        circuit_failure_threshold=2, rate_limit_seconds=0.0,
    ))
    with patch.object(client, "_fetch_sync", side_effect=RuntimeError("down")):
        for i in range(2):
            with pytest.raises(RuntimeError):
                client.search_sync(f"s{i}")
    assert client.search_sync("s2") == []  # OPEN -> graceful []


def test_build_cve_search_threads_breaker_config_through():
    """The production config->settings builder must read the circuit-breaker
    knobs from the cve_lookup config block (regression for the wiring gap that
    left the operator-facing knobs silently inert)."""
    from tools.mcp_shared import build_cve_search

    config = {"cve_lookup": {
        "circuit_failure_threshold": 2,
        "circuit_recovery_timeout": 30.0,
    }}
    client = build_cve_search(config)
    assert client._breaker.failure_threshold == 2
    assert client._breaker.recovery_timeout == 30.0


def test_build_cve_search_defaults_when_keys_absent():
    """A config without the breaker keys still yields the dataclass defaults."""
    from tools.mcp_shared import build_cve_search

    client = build_cve_search({})  # no cve_lookup block at all
    assert client._breaker.failure_threshold == 5
    assert client._breaker.recovery_timeout == 60.0


# ── Tier 1.8: shared RateLimiter wiring ────────────────────────────────────


def test_nvd_client_no_limiter_uses_per_instance_throttle():
    """Back-compat: NVDClient constructed without a shared limiter keeps the
    per-instance _lock + _last_request_time throttle (the pre-1.8 path used by
    vuln_agent and direct construction)."""
    client = NVDClient(CVESearchSettings())
    assert client._rate_limiter is None
    assert client._lock is not None
    assert client._last_request_time == 0.0


def test_nvd_client_with_limiter_uses_it_not_per_instance(monkeypatch):
    """When a shared limiter is provided, search_sync throttles through it
    (acquire_sync) instead of the per-instance time.sleep block."""
    from tools.reliability import RateLimiter

    client = NVDClient(CVESearchSettings(), rate_limiter=RateLimiter(1000.0, burst=1))
    assert client._rate_limiter is not None

    acquired: list[str] = []
    real_acquire_sync = client._rate_limiter.acquire_sync
    def spy_acquire_sync(key, cost=1.0):
        acquired.append(key)
        return real_acquire_sync(key, cost)
    monkeypatch.setattr(client._rate_limiter, "acquire_sync", spy_acquire_sync)

    # Cache-miss path: _fetch_sync is stubbed to raise so we only exercise the
    # throttle-then-fetch ordering; the limiter acquire happens BEFORE fetch.
    monkeypatch.setattr(client, "_fetch_sync", lambda q: (_ for _ in ()).throw(RuntimeError("boom")))

    with pytest.raises(RuntimeError, match="boom"):
        client.search_sync("nginx 1.18.0")
    assert acquired == ["nvd"], "shared limiter was not acquired with the 'nvd' key"


def test_build_cve_search_wires_shared_limiter_from_config():
    """build_cve_search reads search_rate_limit_per_minute and wires a shared
    RateLimiter into the NVDClient (making the previously-unused mission/config
    search-rate budget live)."""
    from tools.mcp_shared import build_cve_search, _SHARED_NVD_LIMITERS

    _SHARED_NVD_LIMITERS.clear()
    client = build_cve_search({"cve_lookup": {"search_rate_limit_per_minute": 30}})
    assert client._rate_limiter is not None
    # 30/min = 0.5/sec.
    assert client._rate_limiter._rate == pytest.approx(0.5)


def test_build_cve_search_zero_disables_shared_limiter():
    """search_rate_limit_per_minute=0 disables the shared limiter (falls back
    to per-instance rate_limit_seconds) -- operator opt-out."""
    from tools.mcp_shared import build_cve_search, _SHARED_NVD_LIMITERS

    _SHARED_NVD_LIMITERS.clear()
    client = build_cve_search({"cve_lookup": {"search_rate_limit_per_minute": 0}})
    assert client._rate_limiter is None


def test_build_cve_search_default_limiter_when_key_absent():
    """Default (key absent) wires the 10/min limiter (the ~6s NVD gap)."""
    from tools.mcp_shared import build_cve_search, _SHARED_NVD_LIMITERS

    _SHARED_NVD_LIMITERS.clear()
    client = build_cve_search({})
    assert client._rate_limiter is not None
    assert client._rate_limiter._rate == pytest.approx(10.0 / 60.0)


def test_build_cve_search_limiter_is_process_wide_singleton():
    """Two build_cve_search calls with the SAME rate share ONE limiter object
    (the whole point: concurrent MCP requests share one NVD budget, not one
    per NVDClient instance). Different rates get different limiters."""
    from tools.mcp_shared import build_cve_search, _SHARED_NVD_LIMITERS

    _SHARED_NVD_LIMITERS.clear()
    c1 = build_cve_search({"cve_lookup": {"search_rate_limit_per_minute": 20}})
    c2 = build_cve_search({"cve_lookup": {"search_rate_limit_per_minute": 20}})
    c3 = build_cve_search({"cve_lookup": {"search_rate_limit_per_minute": 40}})
    assert c1._rate_limiter is c2._rate_limiter  # same rate -> shared singleton
    assert c1._rate_limiter is not c3._rate_limiter  # different rate -> separate
