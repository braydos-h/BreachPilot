"""Regression tests for the Tier 1.8 shared ``RateLimiter`` (token bucket).

Covers the loop-agnostic token-bucket primitive in ``tools/reliability.py``:
burst-then-throttle behavior, the ``from_min_gap`` / ``from_per_minute``
constructors, per-key isolation, the sync path mirroring the async path,
reservation semantics (reserve-then-sleep, no re-acquire), cost > 1, the
rate=0 edge (infinite wait, reservation undone), reset, and -- the key
property that justifies a ``threading.Lock`` instead of an ``asyncio.Lock`` --
that bucket state persists across separate event loops (the swarm calls
``run_exploit_agent`` via ``asyncio.run``, which spins a fresh loop).

Timing assertions use generous lower bounds (the wait is a *minimum*) and
``monotonic`` clocks so they are not flaky on slow CI.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from tools.reliability import RateLimiter

# ── Constructors ────────────────────────────────────────────────────────────


def test_from_min_gap():
    lim = RateLimiter.from_min_gap(0.1)  # 10/s, burst 1
    assert lim._rate == pytest.approx(10.0)
    assert lim._burst == 1.0
    # First acquire immediate, second must wait ~0.1s.
    assert lim._reserve("k") == 0.0
    assert lim._reserve("k") == pytest.approx(0.1, abs=0.02)


def test_from_per_minute():
    lim = RateLimiter.from_per_minute(120)  # 120/min = 2/s, burst 1
    assert lim._rate == pytest.approx(2.0)
    assert lim._reserve("k") == 0.0
    # Deficit 1 token at 2/s -> 0.5s wait.
    assert lim._reserve("k") == pytest.approx(0.5, abs=0.02)


def test_constructor_validates():
    with pytest.raises(ValueError):
        RateLimiter(-1, 1)
    with pytest.raises(ValueError):
        RateLimiter(10, 0)
    with pytest.raises(ValueError):
        RateLimiter.from_min_gap(0)
    with pytest.raises(ValueError):
        RateLimiter.from_per_minute(0)


# ── Burst + throttle ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_burst_then_throttle_async():
    """burst=2: the first 2 acquires are immediate; the 3rd waits >= 1/rate."""
    lim = RateLimiter(rate_per_second=20.0, burst=2)  # 0.05s gap after burst
    t0 = time.monotonic()
    await lim.acquire("k")
    await lim.acquire("k")
    burst_time = time.monotonic() - t0
    assert burst_time < 0.03  # burst consumed immediately (slack for scheduling)

    t1 = time.monotonic()
    await lim.acquire("k")  # over budget -> wait ~0.05s
    waited = time.monotonic() - t1
    assert waited >= 0.04  # minimum wait enforced


def test_burst_then_throttle_sync():
    lim = RateLimiter(rate_per_second=20.0, burst=2)
    assert lim._reserve("k") == 0.0
    assert lim._reserve("k") == 0.0
    # Third reserves negative -> wait 1/20 = 0.05.
    assert lim._reserve("k") == pytest.approx(0.05, abs=0.01)


# ── Keyed isolation ────────────────────────────────────────────────────────


def test_keyed_isolation():
    lim = RateLimiter(rate_per_second=10.0, burst=1)
    assert lim._reserve("a") == 0.0
    assert lim._reserve("b") == 0.0  # independent bucket
    # "a" is now empty; "b" is empty too, but they don't share a deficit.
    assert lim._reserve("a") == pytest.approx(0.1, abs=0.02)
    assert lim._reserve("b") == pytest.approx(0.1, abs=0.02)


# ── Sync mirrors async ──────────────────────────────────────────────────────


def test_sync_acquire_sleeps():
    lim = RateLimiter(rate_per_second=10.0, burst=1)
    lim.acquire_sync("k")  # immediate
    t0 = time.monotonic()
    lim.acquire_sync("k")  # waits ~0.1s
    assert time.monotonic() - t0 >= 0.08


# ── Reservation semantics (no re-acquire needed) ───────────────────────────


def test_reserve_charges_exactly_once_per_call():
    """Each ``_reserve`` charges exactly ``cost`` (1) tokens -- no double-charge,
    no lost charge. With burst=1 and rate=10/s, consecutive over-budget calls
    (run back-to-back, so the inter-call refill is ~0) must accumulate debt
    LINEARLY: 0.1, 0.2, 0.3. If a call double-charged (cost 2) the third would
    be 0.4+; if a call lost its charge it would stay 0.1. This is the
    "reserve-then-sleep, no re-acquire" invariant -- one charge per call."""
    lim = RateLimiter(rate_per_second=10.0, burst=1)  # 0.1s/token
    assert lim._reserve("k") == 0.0                          # burst token
    assert lim._reserve("k") == pytest.approx(0.1, abs=0.02)  # 1 token debt
    assert lim._reserve("k") == pytest.approx(0.2, abs=0.03)  # 2 tokens debt
    assert lim._reserve("k") == pytest.approx(0.3, abs=0.03)  # 3 tokens debt (linear)


def test_sleeping_the_returned_wait_pays_exactly_one_debt():
    """The reserve-then-sleep model: ``_reserve`` returns the wait that earns
    the reserved token; sleeping it pays that one debt. After sleeping enough
    to cover one token of debt, the NEXT reserve owes one fresh token (not
    two) -- confirming the sleep paid exactly one charge (no re-acquire)."""
    lim = RateLimiter(rate_per_second=10.0, burst=1)
    lim._reserve("k")  # burst -> 0
    lim._reserve("k")  # debt 1 (bucket -1)
    # Two outstanding debts would be -2 without any sleep.
    assert lim._reserve("k") == pytest.approx(0.2, abs=0.03)  # bucket -2
    # Sleep enough to pay exactly one token of debt (refill is lazy -- applied
    # on the next _reserve). After paying one, bucket -1, so the next reserve
    # owes one MORE (total debt 2 again) -> wait 0.2, NOT 0.3 (would mean the
    # sleep paid nothing) and NOT 0.1 (would mean the sleep paid two).
    time.sleep(0.1)
    assert lim._reserve("k") == pytest.approx(0.2, abs=0.03)


# ── Cost > 1 ───────────────────────────────────────────────────────────────


def test_cost_greater_than_one():
    lim = RateLimiter(rate_per_second=10.0, burst=2)
    # burst 2, cost 2 -> tokens 0 -> immediate.
    assert lim._reserve("k", cost=2) == 0.0
    # bucket 0, cost 2 -> -2 -> wait 2/10 = 0.2.
    assert lim._reserve("k", cost=2) == pytest.approx(0.2, abs=0.02)


# ── rate=0 edge ─────────────────────────────────────────────────────────────


def test_rate_zero_returns_inf_and_restores_reservation():
    """A zero-rate limiter can grant the initial burst but then can never
    refill. _reserve must return inf (not a finite/zero wait that would hang
    the caller for a misleadingly short time) AND undo the reservation so the
    bucket stays at 0 (empty) instead of going to -1 (which would be a
    permanent debt the bucket could never pay off -- starvation). The burst
    token was already consumed by the first reserve, so the bucket is at 0
    (empty, not refillable); a reset re-fills the burst so the next call is
    immediate again."""
    lim = RateLimiter(rate_per_second=0.0, burst=1)
    assert lim._reserve("k") == 0.0            # burst token consumed -> bucket 0
    assert lim._reserve("k") == float("inf")   # no refill possible -> inf
    with lim._lock:
        tokens, _ = lim._buckets["k"]
    assert tokens == 0.0  # undo kept the bucket at 0, NOT -1 (no starvation debt)
    # Still empty (burst spent, rate 0): another call is also inf, not 0.
    assert lim._reserve("k") == float("inf")
    # A reset refills the burst -> immediacy restored.
    lim.reset("k")
    assert lim._reserve("k") == 0.0


# ── Reset ──────────────────────────────────────────────────────────────────


def test_reset_key_and_all():
    lim = RateLimiter(rate_per_second=10.0, burst=1)
    lim._reserve("a")
    lim._reserve("b")
    lim.reset("a")
    assert lim._reserve("a") == 0.0  # "a" reset -> immediate
    # "b" still drained -> waits.
    assert lim._reserve("b") == pytest.approx(0.1, abs=0.02)
    lim.reset()
    assert lim._reserve("a") == 0.0
    assert lim._reserve("b") == 0.0


# ── Cross-loop state persistence (the reason for threading.Lock) ────────────


def test_bucket_state_persists_across_event_loops():
    """The whole point of ``threading.Lock`` + ``asyncio.sleep`` (vs an
    ``asyncio.Lock``) is that ONE limiter instance is shared across loops.
    The swarm calls ``run_exploit_agent`` via ``asyncio.run`` (a fresh loop),
    so a loop-bound primitive would raise 'attached to a different loop'.
    Here a single limiter is acquired in two SEPARATE loops and the bucket
    state (the first acquire's deficit) must carry over to the second."""
    lim = RateLimiter(rate_per_second=10.0, burst=1)  # 0.1s gap

    async def first():
        await lim.acquire("shared")  # consumes the burst token

    async def second():
        t0 = time.monotonic()
        await lim.acquire("shared")  # must wait ~0.1s -- deficit from first loop
        return time.monotonic() - t0

    asyncio.run(first())          # loop 1
    waited = asyncio.run(second())  # loop 2 (fresh event loop)
    assert waited >= 0.08  # the first loop's reservation carried across


def test_concurrent_acquires_do_not_corrupt_bucket():
    """Two coroutines acquiring the same key concurrently must both be
    serialized by the lock and each wait its turn (no lost reservation)."""
    lim = RateLimiter(rate_per_second=50.0, burst=1)  # 0.02s gap

    async def one():
        await lim.acquire("k")

    async def main():
        t0 = time.monotonic()
        await asyncio.gather(one(), one(), one())
        return time.monotonic() - t0

    elapsed = asyncio.run(main())
    # 3 acquires, burst 1 -> 2 throttled waits of ~0.02s each -> >= 0.03s total.
    assert elapsed >= 0.03
