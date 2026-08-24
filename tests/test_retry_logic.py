"""Tests for reliability.py — retry, timeout, circuit breaker, and error handling.

Tests:
- Retry decorator with sync and async functions
- Timeout wrapper
- Tool fallback chain
- Circuit breaker state transitions
- Async execution pool
- Error tracking and failure reasoning
- Graceful degradation
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.reliability import (
    _KILL_SIGNAL,
    AsyncExecutionPool,
    CircuitBreaker,
    CircuitState,
    ErrorRecord,
    ErrorTracker,
    GracefulDegradation,
    ToolFallback,
    safe_execute,
    with_retry,
    with_timeout,
    with_timeout_sync,
)

# ── Retry Decorator Tests ────────────────────────────────────────────────────

class TestWithRetry:
    def test_sync_success_first_try(self) -> None:
        call_count = 0

        @with_retry(max_retries=2, backoff=0.1)
        def success_func() -> str:
            nonlocal call_count
            call_count += 1
            return "success"

        result = success_func()
        assert result == "success"
        assert call_count == 1

    def test_sync_retry_then_success(self) -> None:
        call_count = 0

        @with_retry(max_retries=2, backoff=0.1)
        def flaky_func() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Temporary failure")
            return "success"

        result = flaky_func()
        assert result == "success"
        assert call_count == 2

    def test_sync_exhaust_retries(self) -> None:
        call_count = 0

        @with_retry(max_retries=2, backoff=0.1)
        def always_fail() -> str:
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Permanent failure")

        with pytest.raises(ConnectionError, match="Permanent failure"):
            always_fail()
        assert call_count == 3  # Initial + 2 retries

    def test_sync_specific_exception(self) -> None:
        call_count = 0

        @with_retry(max_retries=2, backoff=0.1, exceptions=(ValueError,))
        def raise_type_error() -> None:
            nonlocal call_count
            call_count += 1
            raise TypeError("Should not be caught")

        with pytest.raises(TypeError):
            raise_type_error()
        assert call_count == 1  # No retries for uncaught exception

    def test_sync_on_retry_callback(self) -> None:
        retry_calls: list[tuple[Exception, int]] = []

        def on_retry(exc: Exception, attempt: int) -> None:
            retry_calls.append((exc, attempt))

        call_count = 0

        @with_retry(max_retries=2, backoff=0.1, on_retry=on_retry)
        def flaky() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("fail")
            return "ok"

        flaky()
        assert len(retry_calls) == 1
        assert retry_calls[0][1] == 1

    def test_sync_on_exhausted_callback(self) -> None:
        exhausted_calls: list[Exception] = []

        def on_exhausted(exc: Exception) -> None:
            exhausted_calls.append(exc)

        @with_retry(max_retries=1, backoff=0.1, on_exhausted=on_exhausted)
        def always_fail() -> None:
            raise ConnectionError("fail")

        with pytest.raises(ConnectionError):
            always_fail()
        assert len(exhausted_calls) == 1

    @pytest.mark.asyncio
    async def test_async_success_first_try(self) -> None:
        call_count = 0

        @with_retry(max_retries=2, backoff=0.1)
        async def async_success() -> str:
            nonlocal call_count
            call_count += 1
            return "success"

        result = await async_success()
        assert result == "success"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_async_retry_then_success(self) -> None:
        call_count = 0

        @with_retry(max_retries=2, backoff=0.1)
        async def async_flaky() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Temporary failure")
            return "success"

        result = await async_flaky()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_async_exhaust_retries(self) -> None:
        call_count = 0

        @with_retry(max_retries=2, backoff=0.1)
        async def async_always_fail() -> str:
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Permanent failure")

        with pytest.raises(ConnectionError):
            await async_always_fail()
        assert call_count == 3


# ── Timeout Tests ────────────────────────────────────────────────────────────

class TestWithTimeout:
    @pytest.mark.asyncio
    async def test_timeout_success(self) -> None:
        async def quick_task() -> str:
            return "done"

        result = await with_timeout(quick_task(), timeout=5.0)
        assert result == "done"

    @pytest.mark.asyncio
    async def test_timeout_failure(self) -> None:
        async def slow_task() -> str:
            await asyncio.sleep(10)
            return "done"

        with pytest.raises(TimeoutError, match="Operation timed out"):
            await with_timeout(slow_task(), timeout=0.1)

    @pytest.mark.asyncio
    async def test_timeout_custom_message(self) -> None:
        async def slow_task() -> str:
            await asyncio.sleep(10)
            return "done"

        with pytest.raises(TimeoutError, match="Custom timeout"):
            await with_timeout(slow_task(), timeout=0.1, timeout_message="Custom timeout")

    @pytest.mark.asyncio
    async def test_timeout_callback(self) -> None:
        callback_called = False

        def on_timeout() -> None:
            nonlocal callback_called
            callback_called = True

        async def slow_task() -> str:
            await asyncio.sleep(10)
            return "done"

        with pytest.raises(TimeoutError):
            await with_timeout(slow_task(), timeout=0.1, on_timeout=on_timeout)
        assert callback_called is True


# ── Tool Fallback Tests ────────────────────────────────────────────────────────

class TestToolFallback:
    def test_init_checks_tools(self) -> None:
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = ["/usr/bin/nmap", None, None]
            fallback = ToolFallback(["nmap", "rustscan", "masscan"])
            assert fallback.get_available_tools() == ["nmap"]

    def test_no_tools_available(self) -> None:
        with patch("shutil.which", return_value=None):
            fallback = ToolFallback(["nmap", "rustscan"])
            result = fallback.execute_sync(["-p-", "target"])
            assert result.success is False
            assert "No tools available" in result.error

    def test_sync_first_tool_succeeds(self) -> None:
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = ["/usr/bin/nmap", "/usr/bin/rustscan"]
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="nmap output",
                    stderr="",
                )
                fallback = ToolFallback(["nmap", "rustscan"])
                result = fallback.execute_sync(["-p-", "target"])
                assert result.success is True
                assert result.tool_name == "nmap"
                assert result.stdout == "nmap output"

    def test_sync_fallback_to_second_tool(self) -> None:
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = ["/usr/bin/nmap", "/usr/bin/rustscan"]
            with patch("subprocess.run") as mock_run:
                # First call fails, second succeeds
                mock_run.side_effect = [
                    MagicMock(returncode=1, stdout="", stderr="nmap failed"),
                    MagicMock(returncode=0, stdout="rustscan output", stderr=""),
                ]
                fallback = ToolFallback(["nmap", "rustscan"])
                result = fallback.execute_sync(["-p-", "target"])
                assert result.success is True
                assert result.tool_name == "rustscan"
                assert result.stdout == "rustscan output"

    def test_sync_all_tools_fail(self) -> None:
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = ["/usr/bin/nmap", "/usr/bin/rustscan"]
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = [
                    MagicMock(returncode=1, stdout="", stderr="nmap failed"),
                    MagicMock(returncode=1, stdout="", stderr="rustscan failed"),
                ]
                fallback = ToolFallback(["nmap", "rustscan"])
                result = fallback.execute_sync(["-p-", "target"])
                assert result.success is False
            assert "All tools failed" in result.error

    @pytest.mark.asyncio
    async def test_async_first_tool_succeeds(self) -> None:
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = ["/usr/bin/nmap", "/usr/bin/rustscan"]
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_proc = AsyncMock()
                mock_proc.returncode = 0
                mock_proc.communicate.return_value = (b"nmap output", b"")
                mock_exec.return_value = mock_proc

                fallback = ToolFallback(["nmap", "rustscan"])
                result = await fallback.execute_async(["-p-", "target"])
                assert result.success is True
                assert result.tool_name == "nmap"

    @pytest.mark.asyncio
    async def test_async_timeout(self) -> None:
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = ["/usr/bin/nmap"]
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_proc = AsyncMock()
                mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
                mock_proc.returncode = None
                mock_exec.return_value = mock_proc

                fallback = ToolFallback(["nmap"], timeout=0.1)
                result = await fallback.execute_async(["-p-", "target"])
                assert result.success is False
                assert "timed out" in result.error.lower()


# ── Circuit Breaker Tests ────────────────────────────────────────────────────

class TestCircuitBreaker:
    def test_initial_state(self) -> None:
        cb = CircuitBreaker("nmap", failure_threshold=3, recovery_timeout=30)
        assert cb.can_execute() is True
        assert cb.get_state() == "closed"

    def test_record_success(self) -> None:
        cb = CircuitBreaker("nmap")
        cb.record_success()
        assert cb._failure_count == 0
        assert cb.can_execute() is True

    def test_record_failure_opens_circuit(self) -> None:
        cb = CircuitBreaker("nmap", failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert cb.can_execute() is True  # Not yet open
        cb.record_failure()
        assert cb.can_execute() is False  # Circuit open
        assert cb.get_state() == "open"

    def test_half_open_after_timeout(self) -> None:
        cb = CircuitBreaker("nmap", failure_threshold=1, recovery_timeout=0.1)
        cb.record_failure()
        assert cb.can_execute() is False
        # Wait for recovery timeout
        import time
        time.sleep(0.2)
        assert cb.can_execute() is True  # Half-open
        assert cb.get_state() == "half_open"

    def test_half_open_success_closes(self) -> None:
        cb = CircuitBreaker("nmap", failure_threshold=1, recovery_timeout=0.1, half_open_max_calls=2)
        cb.record_failure()
        import time
        time.sleep(0.2)
        assert cb.can_execute() is True
        cb.record_success()
        cb.record_success()
        assert cb.get_state() == "closed"
        assert cb.can_execute() is True

    def test_half_open_failure_reopens(self) -> None:
        cb = CircuitBreaker("nmap", failure_threshold=1, recovery_timeout=0.1)
        cb.record_failure()
        import time
        time.sleep(0.2)
        assert cb.can_execute() is True
        cb.record_failure()
        assert cb.get_state() == "open"

    def test_half_open_max_calls(self) -> None:
        cb = CircuitBreaker("nmap", failure_threshold=1, recovery_timeout=0.1, half_open_max_calls=2)
        cb.record_failure()
        import time
        time.sleep(0.2)
        assert cb.can_execute() is True  # First half-open call
        assert cb.can_execute() is True  # Second half-open call
        assert cb.can_execute() is False  # Max calls reached


# ── Async Execution Pool Tests ───────────────────────────────────────────────

class TestAsyncExecutionPool:
    @pytest.mark.asyncio
    async def test_execute_single(self) -> None:
        pool = AsyncExecutionPool(max_concurrency=2)

        async def task() -> str:
            return "done"

        result = await pool.execute(task())
        assert result == "done"
        assert pool.active_count == 0

    @pytest.mark.asyncio
    async def test_execute_many(self) -> None:
        pool = AsyncExecutionPool(max_concurrency=2)

        async def task(n: int) -> int:
            await asyncio.sleep(0.01)
            return n

        results = await pool.execute_many([task(i) for i in range(5)])
        assert len(results) == 5
        assert all(r == i for i, r in enumerate(results))

    @pytest.mark.asyncio
    async def test_execute_many_with_exceptions(self) -> None:
        pool = AsyncExecutionPool(max_concurrency=2)

        async def good_task() -> str:
            return "ok"

        async def bad_task() -> str:
            raise ValueError("fail")

        results = await pool.execute_many([good_task(), bad_task()])
        assert results[0] == "ok"
        assert isinstance(results[1], ValueError)

    @pytest.mark.asyncio
    async def test_cancel_all(self) -> None:
        pool = AsyncExecutionPool(max_concurrency=5)

        async def slow_task() -> str:
            await asyncio.sleep(10)
            return "done"

        # Start tasks but don't await them
        tasks = [asyncio.create_task(pool.execute(slow_task())) for _ in range(3)]
        await asyncio.sleep(0.1)
        assert pool.active_count > 0

        await pool.cancel_all()
        assert pool.active_count == 0

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        pool = AsyncExecutionPool(max_concurrency=2)

        async def slow_task() -> str:
            await asyncio.sleep(10)
            return "done"

        with pytest.raises(TimeoutError):
            await pool.execute(slow_task(), timeout=0.1)


# ── Error Tracker Tests ──────────────────────────────────────────────────────

class TestErrorTracker:
    def test_record_error(self) -> None:
        tracker = ErrorTracker()
        tracker.record(
            component="recon",
            operation="nmap_scan",
            error=ConnectionError("Connection refused"),
            context={"target": "10.0.0.50"},
            recovery_action="retry",
        )
        summary = tracker.get_error_summary()
        assert summary["total_errors"] == 1
        assert summary["error_counts"]["ConnectionError"] == 1

    def test_multiple_errors(self) -> None:
        tracker = ErrorTracker()
        for _ in range(3):
            tracker.record("recon", "nmap_scan", ConnectionError("fail"))
        for _ in range(2):
            tracker.record("exploit", "ssh_brute", TimeoutError("timeout"))

        summary = tracker.get_error_summary()
        assert summary["total_errors"] == 5
        assert summary["error_counts"]["ConnectionError"] == 3
        assert summary["error_counts"]["TimeoutError"] == 2

    def test_most_common_errors(self) -> None:
        tracker = ErrorTracker()
        for _ in range(5):
            tracker.record("recon", "nmap_scan", ConnectionError("fail"))
        for _ in range(2):
            tracker.record("exploit", "ssh_brute", TimeoutError("timeout"))

        summary = tracker.get_error_summary()
        most_common = summary["most_common"]
        assert most_common[0] == ("ConnectionError", 5)
        assert most_common[1] == ("TimeoutError", 2)

    def test_failure_reasoning_timeout(self) -> None:
        tracker = ErrorTracker()
        for _ in range(3):
            tracker.record("recon", "nmap_scan", TimeoutError("timeout"))

        reasoning = tracker.get_failure_reasoning("nmap_scan")
        assert "TimeoutError" in reasoning
        assert "increasing timeout" in reasoning.lower()

    def test_failure_reasoning_connection_refused(self) -> None:
        tracker = ErrorTracker()
        for _ in range(3):
            tracker.record("recon", "nmap_scan", ConnectionRefusedError("refused"))

        reasoning = tracker.get_failure_reasoning("nmap_scan")
        assert "ConnectionRefusedError" in reasoning
        assert "blocking" in reasoning.lower()

    def test_max_records(self) -> None:
        tracker = ErrorTracker(max_records=5)
        for i in range(10):
            tracker.record("recon", "scan", ConnectionError(f"fail {i}"))

        summary = tracker.get_error_summary()
        assert summary["total_errors"] == 5  # Only kept last 5

    def test_error_record_to_dict(self) -> None:
        record = ErrorRecord(
            timestamp="2024-01-01T00:00:00Z",
            component="recon",
            operation="nmap_scan",
            error_type="ConnectionError",
            error_message="Connection refused",
            recovery_action="retry",
            success=False,
        )
        d = record.to_dict()
        assert d["component"] == "recon"
        assert d["error_type"] == "ConnectionError"
        assert d["recovery_action"] == "retry"


# ── Graceful Degradation Tests ─────────────────────────────────────────────────

class TestGracefulDegradation:
    def test_get_tool_substitution_nmap(self) -> None:
        subs = GracefulDegradation.get_tool_substitution("nmap")
        assert "rustscan" in subs
        assert "masscan" in subs

    def test_get_tool_substitution_unknown(self) -> None:
        subs = GracefulDegradation.get_tool_substitution("unknown_tool")
        assert subs == []

    def test_degrade_scan_type(self) -> None:
        assert GracefulDegradation.degrade_scan_type("maximum") == "aggressive"
        assert GracefulDegradation.degrade_scan_type("aggressive") == "normal"
        assert GracefulDegradation.degrade_scan_type("normal") == "stealth"
        assert GracefulDegradation.degrade_scan_type("stealth") == "stealth"

    def test_reduce_scope_timeout(self) -> None:
        original = ["10.0.0.50:80", "10.0.0.50:443", "10.0.0.50:9999"]
        reduced = GracefulDegradation.reduce_scope(original, "timeout after 300s")
        assert len(reduced) <= len(original)
        # Should keep common ports
        assert any("80" in r or "443" in r for r in reduced)

    def test_reduce_scope_rate_limit(self) -> None:
        original = ["10.0.0.50", "10.0.0.51", "10.0.0.52"]
        reduced = GracefulDegradation.reduce_scope(original, "rate limit exceeded")
        assert len(reduced) == 1


# ── Safe Execute Tests ───────────────────────────────────────────────────────

class TestSafeExecute:
    @pytest.mark.asyncio
    async def test_safe_execute_success(self) -> None:
        async def good_task() -> str:
            return "success"

        result = await safe_execute(good_task, timeout=5.0, max_retries=1)
        assert result == "success"

    @pytest.mark.asyncio
    async def test_safe_execute_retry_then_success(self) -> None:
        call_count = 0

        async def flaky_task() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("fail")
            return "success"

        result = await safe_execute(flaky_task, timeout=5.0, max_retries=2)
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_safe_execute_fallback(self) -> None:
        async def always_fail() -> str:
            raise ConnectionError("fail")

        result = await safe_execute(
            always_fail,
            timeout=1.0,
            max_retries=1,
            fallback_value="fallback",
        )
        assert result == "fallback"

    @pytest.mark.asyncio
    async def test_safe_execute_with_error_tracker(self) -> None:
        tracker = ErrorTracker()

        async def always_fail() -> str:
            raise ConnectionError("fail")

        result = await safe_execute(
            always_fail,
            timeout=1.0,
            max_retries=0,
            fallback_value="fallback",
            error_tracker=tracker,
            component="test",
            operation="test_op",
        )
        assert result == "fallback"
        assert tracker.get_error_summary()["total_errors"] == 1

    @pytest.mark.asyncio
    async def test_safe_execute_timeout(self) -> None:
        async def slow_task() -> str:
            await asyncio.sleep(10)
            return "done"

        result = await safe_execute(
            slow_task,
            timeout=0.1,
            max_retries=0,
            fallback_value="timeout_fallback",
        )
        assert result == "timeout_fallback"


# ── Tier 1.2: BaseExceptionGroup safety ────────────────────────────────────
# anyio task groups (MCP stdio_client) raise BaseExceptionGroup on subprocess
# death — NOT a subclass of Exception. with_retry / safe_execute must catch it
# so wrapping an MCP call doesn't let a subprocess death crash the caller.


class TestExceptionGroupSafety:
    def test_with_retry_catches_exception_group(self) -> None:
        """with_retry's default exceptions tuple must include BaseExceptionGroup,
        so a wrapped MCP stdio death is retried (call_count > 1), not propagated
        on the first attempt."""
        call_count = 0

        @with_retry(max_retries=2, backoff=0.001, jitter=False)
        def raises_group() -> str:
            nonlocal call_count
            call_count += 1
            raise ExceptionGroup("subprocess died", [ValueError("boom")])

        with pytest.raises(BaseExceptionGroup):
            raises_group()
        # Caught + retried 3x (initial + 2 retries) then re-raised. If the
        # default didn't catch BaseExceptionGroup, call_count would be 1.
        assert call_count == 3

    def test_with_retry_explicit_exceptions_still_narrow(self) -> None:
        """An explicit narrow exceptions tuple must NOT catch a BaseExceptionGroup
        (callers opt out of the broad default)."""
        call_count = 0

        @with_retry(max_retries=2, backoff=0.001, exceptions=(ValueError,))
        def raises_group() -> str:
            nonlocal call_count
            call_count += 1
            raise ExceptionGroup("subprocess died", [ValueError("boom")])

        with pytest.raises(BaseExceptionGroup):
            raises_group()
        assert call_count == 1  # not caught by (ValueError,) → propagated first try

    @pytest.mark.asyncio
    async def test_safe_execute_catches_exception_group(self) -> None:
        """safe_execute must catch BaseExceptionGroup and return the fallback,
        not let a wrapped MCP death crash the caller."""
        calls = 0

        async def boom() -> str:
            nonlocal calls
            calls += 1
            raise ExceptionGroup("mcp subprocess died", [RuntimeError("x")])

        result = await safe_execute(
            boom, timeout=5, max_retries=1, fallback_value="FALLBACK",
        )
        assert result == "FALLBACK"
        # Caught + retried (initial + 1 retry = 2 calls). If not caught, the
        # BaseExceptionGroup would have escaped on the first call.
        assert calls == 2


# ── H11 / M16 / M17 regression tests ────────────────────────────────────────


class TestWithTimeoutSyncNonBlocking:
    """H11: with_timeout_sync must NOT block past the timeout. The previous
    implementation used the executor as a context manager, so on timeout the
    ``with`` block's ``__exit__`` ran ``executor.shutdown(wait=True)`` — which
    JOINS the worker that is still sleeping, blocking the caller until the
    long-sleeping func eventually finishes."""

    def test_raises_within_margin_despite_long_sleep(self) -> None:
        import time

        def slow_func() -> str:
            time.sleep(5.0)
            return "done"

        start = time.monotonic()
        with pytest.raises(TimeoutError):
            with_timeout_sync(slow_func, timeout=0.2)
        elapsed = time.monotonic() - start
        # Must return well under the 5s sleep. Allow a generous margin for CI
        # scheduling but far below 5s — if the worker were joined we'd see
        # ~5s here.
        assert elapsed < 2.0, (
            f"with_timeout_sync blocked for {elapsed:.2f}s — worker thread "
            "was joined instead of being abandoned (H11 regression)"
        )

    def test_success_returns_value_and_shuts_down_cleanly(self) -> None:
        def quick_func(x: int, y: int) -> int:
            return x + y

        result = with_timeout_sync(quick_func, 2, 3, timeout=5.0)
        assert result == 5

    def test_worker_thread_is_not_joined_after_timeout(self) -> None:
        """The worker thread must still be alive (not joined) right after the
        timeout fires — proving the caller was released without waiting."""
        import threading
        import time

        worker_started = threading.Event()
        worker_done = threading.Event()

        def slow_func() -> str:
            worker_started.set()
            time.sleep(1.0)
            worker_done.set()
            return "done"

        worker_threads_before = set(threading.enumerate())

        with pytest.raises(TimeoutError):
            with_timeout_sync(slow_func, timeout=0.1)

        # The worker thread must still be running (started but not done), and
        # it must NOT have been joined — joined threads drop out of
        # threading.enumerate() once they finish, but right now it should be
        # alive.
        assert worker_started.is_set(), "worker never started"
        assert not worker_done.is_set(), (
            "worker finished within the timeout window — test is invalid"
        )
        new_threads = set(threading.enumerate()) - worker_threads_before
        assert any(t.is_alive() for t in new_threads), (
            "worker thread was joined/killed before finishing — H11 regression"
        )
        # Let the worker finish so we don't leak a thread into other tests.
        worker_done.wait(timeout=5.0)


class TestCircuitBreakerHalfOpenReset:
    """M16: a failure in HALF_OPEN must reset success_count (and half_open_calls)
    so a subsequent recovery window does not CLOSE prematurely on a stale
    partial count."""

    def test_failure_in_half_open_resets_success_count(self) -> None:
        import time

        cb = CircuitBreaker(
            "nmap", failure_threshold=1, recovery_timeout=0.05, half_open_max_calls=3
        )
        # Trip to OPEN.
        cb.record_failure()
        assert cb.get_state() == "open"

        # Wait → can_execute transitions OPEN -> HALF_OPEN and resets
        # success_count to 0.
        time.sleep(0.1)
        assert cb.can_execute() is True
        assert cb.get_state() == "half_open"
        assert cb._success_count == 0

        # Accumulate two successes in HALF_OPEN (below the close threshold of 3).
        cb.record_success()
        cb.record_success()
        assert cb._success_count == 2
        assert cb.get_state() == "half_open"

        # A failure flips HALF_OPEN -> OPEN and MUST reset success_count so the
        # stale count of 2 cannot combine with the next HALF_OPEN window's
        # successes to CLOSE early.
        cb.record_failure()
        assert cb.get_state() == "open"
        assert cb._success_count == 0, (
            "success_count was not reset on HALF_OPEN->OPEN (M16 regression)"
        )
        assert cb._half_open_calls == 0

    def test_subsequent_success_does_not_prematurely_close(self) -> None:
        """After HALF_OPEN->OPEN with a stale success_count carried over, a
        single success in the next HALF_OPEN window would have CLOSED the
        breaker prematurely. Verify it does not."""
        import time

        cb = CircuitBreaker(
            "nmap", failure_threshold=1, recovery_timeout=0.05, half_open_max_calls=3
        )
        cb.record_failure()
        time.sleep(0.1)
        assert cb.can_execute() is True  # -> HALF_OPEN
        cb.record_success()
        cb.record_success()  # success_count == 2, still half_open
        cb.record_failure()  # -> OPEN, must reset success_count

        # New recovery window.
        time.sleep(0.1)
        assert cb.can_execute() is True  # -> HALF_OPEN again
        assert cb._success_count == 0
        cb.record_success()  # success_count == 1
        assert cb.get_state() == "half_open", (
            "breaker CLOSED after a single success following a half-open "
            "failure — M16 regression (stale success_count not reset)"
        )

    def test_open_to_half_open_resets_success_count(self) -> None:
        """Defense-in-depth: the OPEN->HALF_OPEN transition in can_execute must
        also reset success_count so a leftover from a prior cycle can't apply."""
        import time

        cb = CircuitBreaker(
            "nmap", failure_threshold=1, recovery_timeout=0.05, half_open_max_calls=2
        )
        # Force a stale success_count directly (simulating a prior partial
        # half-open cycle that was interrupted).
        cb._state = CircuitState.OPEN
        cb._last_failure_time = time.monotonic() - 1.0
        cb._success_count = 99

        assert cb.can_execute() is True  # OPEN -> HALF_OPEN
        assert cb.get_state() == "half_open"
        assert cb._success_count == 0, (
            "can_execute did not reset success_count on OPEN->HALF_OPEN "
            "(M16 defense-in-depth regression)"
        )


class TestToolFallbackDeadlineAndProcessGroup:
    """M17: execute_async must use a single deadline (not a fresh full timeout
    for spawn + communicate), start the child in a new session, and kill the
    whole process group on timeout."""

    @pytest.mark.asyncio
    async def test_uses_single_deadline_not_double_timeout(self) -> None:
        """If spawn + communicate each got the full timeout independently, the
        worst-case wall time would be ~2x timeout. With a single deadline, the
        communicate wait_for is bounded by (deadline - now), which is small once
        spawn consumed most of the budget."""

        with patch("shutil.which", side_effect=["/usr/bin/nmap"]):
            # Record every timeout handed to asyncio.wait_for during this call.
            wait_for_timeouts: list[float] = []
            original_wait_for = asyncio.wait_for

            async def spy_wait_for(coro, timeout=None, **kw):
                wait_for_timeouts.append(timeout)
                return await original_wait_for(coro, timeout=timeout, **kw)

            class FakeProc(AsyncMock):
                def __init__(self) -> None:
                    super().__init__()
                    self.returncode = 0
                    self.communicate = AsyncMock(return_value=(b"out", b""))

            async def fake_spawn(*cmd, **kwargs):
                # Simulate spawn consuming most of the 0.4s budget so the
                # communicate remainder is small.
                await asyncio.sleep(0.35)
                return FakeProc()

            with patch("asyncio.create_subprocess_exec", side_effect=fake_spawn):
                with patch("asyncio.wait_for", side_effect=spy_wait_for):
                    fallback = ToolFallback(["nmap"], timeout=0.4)
                    result = await fallback.execute_async(["-p-", "target"])

            # Two wait_for calls: [spawn_timeout, communicate_timeout].
            assert len(wait_for_timeouts) == 2, (
                f"expected 2 wait_for calls, got {wait_for_timeouts}"
            )
            spawn_timeout, communicate_timeout = wait_for_timeouts
            # Spawn gets (close to) the full budget.
            assert spawn_timeout is not None and spawn_timeout > 0.3
            # With a single deadline, communicate gets the REMAINDER after the
            # 0.35s spawn — well under the full 0.4s. The M17 bug gave
            # communicate a fresh full timeout (~0.4); the fix bounds it to the
            # deadline remainder (~0.05).
            assert communicate_timeout is not None and communicate_timeout < 0.2, (
                f"communicate got timeout={communicate_timeout}s — single "
                "deadline not applied (M17 regression; expected remainder < 0.2s)"
            )
            assert result.success is True

    @pytest.mark.asyncio
    async def test_start_new_session_passed_to_subprocess_exec(self) -> None:
        captured_kwargs: dict[str, Any] = {}

        with patch("shutil.which", side_effect=["/usr/bin/nmap"]):
            async def fake_spawn(*cmd, **kwargs):
                captured_kwargs.update(kwargs)
                proc = AsyncMock()
                proc.returncode = 0
                proc.communicate = AsyncMock(return_value=(b"out", b""))
                return proc

            with patch("asyncio.create_subprocess_exec", side_effect=fake_spawn):
                fallback = ToolFallback(["nmap"], timeout=5.0)
                await fallback.execute_async(["-p-", "target"])

        assert captured_kwargs.get("start_new_session") is True, (
            "start_new_session=True was not passed to create_subprocess_exec "
            "(M17 regression)"
        )

    @pytest.mark.asyncio
    async def test_kill_process_uses_killpg_for_process_group(self) -> None:
        """_kill_process must os.killpg the whole process group (using the
        child's pgid) rather than only calling proc.kill() on the parent."""
        mock_proc = AsyncMock()
        mock_proc.pid = 4242

        killpg_calls: list[tuple[int, int]] = []
        getpgid_calls: list[int] = []

        # Inject POSIX process-group primitives (absent on Windows) so the
        # killpg branch is exercised on every platform.
        with patch("os.getpgid", side_effect=lambda pid: (getpgid_calls.append(pid) or pid), create=True):
            with patch("os.killpg", side_effect=lambda pgid, sig: killpg_calls.append((pgid, sig)), create=True):
                await ToolFallback._kill_process(mock_proc)

        assert getpgid_calls == [4242], (
            "os.getpgid was not called with the proc pid (M17 regression)"
        )
        assert killpg_calls and killpg_calls[0][0] == 4242, (
            "os.killpg was not called with the process group id (M17 regression)"
        )
        # Signal is the platform's most-forceful (SIGKILL on POSIX, SIGTERM on
        # Windows where the branch is only reached under test injection).
        assert killpg_calls[0][1] == _KILL_SIGNAL
        # When killpg succeeds, the parent-only fallback (proc.kill) must NOT
        # be invoked.
        mock_proc.kill.assert_not_called()
        # proc is still reaped.
        mock_proc.wait.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_execute_async_invokes_kill_process_on_timeout(self) -> None:
        """execute_async's timeout branch must call _kill_process so the spawned
        child (and its group) is torn down rather than leaked."""
        with patch("shutil.which", side_effect=["/usr/bin/nmap"]):
            mock_proc = AsyncMock()
            mock_proc.returncode = None
            mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())

            with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
                with patch.object(ToolFallback, "_kill_process", new=AsyncMock()) as kill_spy:
                    fallback = ToolFallback(["nmap"], timeout=0.05)
                    result = await fallback.execute_async(["-p-", "target"])

            assert result.success is False
            assert "timed out" in result.error.lower()
            kill_spy.assert_awaited()

    @pytest.mark.asyncio
    async def test_kill_process_falls_back_to_proc_kill_when_killpg_unavailable(self) -> None:
        """If os.killpg raises (e.g. group already gone / not supported),
        _kill_process must fall back to proc.kill() and still await
        proc.wait()."""
        mock_proc = AsyncMock()
        mock_proc.returncode = None
        mock_proc.pid = 99

        with patch("os.getpgid", side_effect=ProcessLookupError("no such process"), create=True):
            # killpg should never be reached because getpgid raised first.
            with patch("os.killpg", side_effect=AssertionError("killpg must not be called when getpgid raises"), create=True):
                await ToolFallback._kill_process(mock_proc)

        # Fall-back path: proc.kill() was called.
        mock_proc.kill.assert_called_once()
        mock_proc.wait.assert_awaited_once()
