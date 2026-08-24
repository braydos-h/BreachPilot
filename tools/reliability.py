"""Reliability and error-handling framework for the autonomous security agent.

Provides:
- Retry decorators with exponential backoff
- Timeout wrappers
- Tool fallback chains
- Circuit breaker pattern for failing tools
- Async-safe execution patterns
- Structured logging integration
- Graceful degradation

Usage::
    from tools.reliability import with_retry, with_timeout, ToolFallback, CircuitBreaker

    @with_retry(max_retries=3, backoff=2.0)
    async def my_async_function():
        ...

    fallback = ToolFallback(["nmap", "rustscan", "masscan"])
    result = await fallback.execute("-p- target_ip")
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import math
import signal
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, ParamSpec, TypeVar

from tools.exceptions import _EXC_GROUP_CATCH
from tools.logging_setup import get_logger

logger = get_logger()

# Most forceful termination signal available on the platform. POSIX has
# SIGKILL; Windows only has SIGTERM (the killpg branch is skipped on Windows
# anyway since os.getpgid/os.killpg don't exist there, but the constant must
# still resolve so importing/evaluating this module never fails).
_KILL_SIGNAL: int = getattr(signal, "SIGKILL", signal.SIGTERM)

T = TypeVar("T")
P = ParamSpec("P")

# ---------------------------------------------------------------------------
# Retry decorator
# ---------------------------------------------------------------------------


def with_retry(
    *,
    max_retries: int = 3,
    backoff: float = 2.0,
    max_backoff: float = 60.0,
    exceptions: tuple[type[BaseException], ...] = _EXC_GROUP_CATCH,
    on_retry: Callable[[BaseException, int], None] | None = None,
    on_exhausted: Callable[[BaseException], None] | None = None,
    jitter: bool = True,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Decorator that retries a function on failure with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        backoff: Base backoff multiplier
        max_backoff: Maximum backoff in seconds
        exceptions: Tuple of exception types to catch and retry. The default is
            ``_EXC_GROUP_CATCH`` (``(Exception, BaseExceptionGroup)`` on 3.11+):
            anyio task groups raise ``BaseExceptionGroup`` on subprocess death,
            which is NOT a subclass of ``Exception`` — so a bare ``except Exception``
            would miss it and let MCP ``stdio_client`` deaths crash the caller.
            Pass an explicit ``exceptions`` tuple to narrow this for a specific use.
        on_retry: Callback called on each retry with (exception, attempt_number)
        on_exhausted: Callback called when all retries are exhausted
        jitter: Add random jitter to backoff to prevent thundering herd
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        is_async = inspect.iscoroutinefunction(func)

        if is_async:

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                last_exception: BaseException | None = None
                for attempt in range(max_retries + 1):
                    try:
                        return await func(*args, **kwargs)
                    except exceptions as exc:
                        last_exception = exc
                        if attempt >= max_retries:
                            break
                        delay = min(backoff * (2**attempt), max_backoff)
                        if jitter:
                            import random

                            delay = delay * (0.5 + random.random())
                        logger.warning(
                            f"Retry {attempt + 1}/{max_retries} for {func.__name__} after {delay:.1f}s: {exc}"
                        )
                        if on_retry:
                            on_retry(exc, attempt + 1)
                        await asyncio.sleep(delay)

                if on_exhausted:
                    on_exhausted(last_exception)
                raise last_exception

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                last_exception: BaseException | None = None
                for attempt in range(max_retries + 1):
                    try:
                        return func(*args, **kwargs)
                    except exceptions as exc:
                        last_exception = exc
                        if attempt >= max_retries:
                            break
                        delay = min(backoff * (2**attempt), max_backoff)
                        if jitter:
                            import random

                            delay = delay * (0.5 + random.random())
                        logger.warning(
                            f"Retry {attempt + 1}/{max_retries} for {func.__name__} after {delay:.1f}s: {exc}"
                        )
                        if on_retry:
                            on_retry(exc, attempt + 1)
                        time.sleep(delay)

                if on_exhausted:
                    on_exhausted(last_exception)
                raise last_exception

            return sync_wrapper

    return decorator


# ---------------------------------------------------------------------------
# Timeout wrapper
# ---------------------------------------------------------------------------


async def with_timeout(
    coro: Coroutine[Any, Any, T],
    timeout: float,
    *,
    timeout_message: str = "Operation timed out",
    on_timeout: Callable[[], None] | None = None,
) -> T:
    """Execute a coroutine with a timeout.

    Args:
        coro: Coroutine to execute
        timeout: Timeout in seconds
        timeout_message: Message for the TimeoutError
        on_timeout: Callback called on timeout

    Returns:
        Result of the coroutine

    Raises:
        TimeoutError: If the coroutine exceeds the timeout
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        if on_timeout:
            on_timeout()
        logger.error(f"Timeout after {timeout}s: {timeout_message}")
        raise TimeoutError(f"{timeout_message} (timeout={timeout}s)")


def with_timeout_sync(
    func: Callable[P, T],
    *args: P.args,
    timeout: float,
    **kwargs: P.kwargs,
) -> T:
    """Execute a synchronous function with a timeout using a thread pool.

    Args:
        func: Function to execute
        *args: Positional arguments
        timeout: Timeout in seconds
        **kwargs: Keyword arguments

    Returns:
        Result of the function
    """
    import concurrent.futures

    # Do NOT use the executor as a context manager: the ``with`` block calls
    # ``executor.shutdown(wait=True)`` on exit, which JOINS the worker thread.
    # If ``func`` is still running (timeout fired before it finished), that
    # join blocks the caller until ``func`` returns — defeating the whole
    # point of the timeout. Construct the executor directly, and on timeout
    # shut it down with ``wait=False, cancel_futures=True`` so the worker is
    # NOT joined and the caller is released immediately.
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(func, *args, **kwargs)
    try:
        result = future.result(timeout=timeout)
        executor.shutdown(wait=True)
        return result
    except concurrent.futures.TimeoutError:
        logger.error(f"Sync timeout after {timeout}s: {func.__name__}")
        # Release the caller without waiting for the worker. ``cancel_futures``
        # cancels any pending futures (none here, but defense-in-depth); the
        # long-running worker is left to terminate on its own.
        executor.shutdown(wait=False, cancel_futures=True)
        raise TimeoutError(f"{func.__name__} timed out after {timeout}s")


# ---------------------------------------------------------------------------
# Tool fallback chain
# ---------------------------------------------------------------------------


@dataclass
class ToolResult:
    """Result from a tool execution attempt."""

    success: bool
    tool_name: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "tool_name": self.tool_name,
            "stdout": self.stdout[:5000] if self.stdout else "",
            "stderr": self.stderr[:2000] if self.stderr else "",
            "exit_code": self.exit_code,
            "duration": self.duration,
            "error": self.error,
        }


class ToolFallback:
    """Execute a command using a fallback chain of tools.

    Usage::
        fallback = ToolFallback(["nmap", "rustscan", "masscan"])
        result = await fallback.execute_async(["-p-", "target_ip"])
    """

    def __init__(
        self,
        tools: list[str],
        *,
        check_availability: bool = True,
        timeout: float = 300.0,
        max_retries: int = 2,
    ) -> None:
        self._tools = tools
        self._check_availability = check_availability
        self._timeout = timeout
        self._max_retries = max_retries
        self._available_tools: dict[str, bool] = {}

        if check_availability:
            self._check_tools()

    @staticmethod
    async def _kill_process(proc: Any) -> None:
        """Kill the process AND any children it spawned.

        ``proc.kill()`` only signals the single child process the supervisor
        created. If the tool forked helpers (nmap does, msfvenom does), those
        children survive and keep running until the test/host exits. With
        ``start_new_session=True`` the child is its own session/process-group
        leader, so on POSIX we can take the whole group down with
        ``os.killpg``. On Windows (no ``os.getpgid``/``os.killpg``) we fall back
        to killing just the parent process — descendants are reaped by the OS
        when the session ends.
        """
        import os

        killpg = getattr(os, "killpg", None)
        getpgid = getattr(os, "getpgid", None)

        # Best-effort: on POSIX, kill the entire process group first so
        # descendants die with the parent. Guard everything — these calls must
        # never raise and mask the timeout we are already handling.
        if killpg is not None and getpgid is not None:
            try:
                pgid = getpgid(proc.pid)
                killpg(pgid, _KILL_SIGNAL)
            except (ProcessLookupError, PermissionError, OSError):
                # Group already gone, or we don't have permission — fall back
                # to killing just the parent process.
                try:
                    kill_result = proc.kill()
                    if inspect.isawaitable(kill_result):
                        await kill_result
                except Exception:
                    pass
            except Exception:
                # Non-fatal: proc.wait() below will reap what it can.
                pass
        else:
            # Windows / platform without process groups — kill just the parent.
            try:
                kill_result = proc.kill()
                if inspect.isawaitable(kill_result):
                    await kill_result
            except Exception:
                pass

        # Reap the parent so we don't leak a zombie. Guarded because the
        # process group kill may have already torn it down.
        try:
            await proc.wait()
        except Exception:
            pass

    def _check_tools(self) -> None:
        """Check which tools are available on the system."""
        import shutil

        for tool in self._tools:
            self._available_tools[tool] = shutil.which(tool) is not None
            if self._available_tools[tool]:
                logger.debug(f"Tool available: {tool}")
            else:
                logger.warning(f"Tool not available: {tool}")

    def get_available_tools(self) -> list[str]:
        """Return list of available tools."""
        return [t for t in self._tools if self._available_tools.get(t, False)]

    async def execute_async(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> ToolResult:
        """Execute command with fallback chain asynchronously."""
        available = self.get_available_tools()

        if not available:
            return ToolResult(
                success=False,
                tool_name="none",
                error=f"No tools available from: {self._tools}",
            )

        last_error = ""
        for tool in available:
            cmd = [tool] + args
            start = time.monotonic()
            # Use a single deadline for the whole per-tool attempt (spawn +
            # communicate) so a spawn that consumes part of the budget does
            # not give communicate a fresh full timeout. Previously both calls
            # got ``self._timeout`` independently, so worst-case wall time was
            # ~2x the configured timeout. ``start_new_session=True`` makes the
            # child a process-group leader so ``_kill_process`` can take down
            # the whole group (nmap/msfvenom spawn helpers that would survive
            # a bare ``proc.kill()``).
            deadline = start + self._timeout
            proc = None

            try:
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=env,
                        cwd=cwd,
                        start_new_session=True,
                    ),
                    timeout=max(0.0, deadline - time.monotonic()),
                )
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=max(0.0, deadline - time.monotonic()),
                )
                duration = time.monotonic() - start
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")

                if proc.returncode == 0:
                    logger.info(f"Tool {tool} succeeded in {duration:.1f}s")
                    return ToolResult(
                        success=True,
                        tool_name=tool,
                        stdout=stdout,
                        stderr=stderr,
                        exit_code=0,
                        duration=duration,
                    )
                else:
                    last_error = f"{tool} exited {proc.returncode}: {stderr[:500]}"
                    logger.warning(f"Tool {tool} failed: {last_error}")

            except asyncio.TimeoutError:
                last_error = f"{tool} timed out after {self._timeout}s"
                logger.warning(last_error)
                if proc and proc.returncode is None:
                    try:
                        await self._kill_process(proc)
                    except Exception:
                        pass

            except Exception as exc:
                last_error = f"{tool} exception: {exc}"
                logger.warning(last_error)

        return ToolResult(
            success=False,
            tool_name=available[-1] if available else "none",
            error=f"All tools failed. Last error: {last_error}",
            stderr=last_error,
        )

    def execute_sync(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> ToolResult:
        """Execute command with fallback chain synchronously."""
        import subprocess

        available = self.get_available_tools()

        if not available:
            return ToolResult(
                success=False,
                tool_name="none",
                error=f"No tools available from: {self._tools}",
            )

        last_error = ""
        for tool in available:
            cmd = [tool] + args
            start = time.monotonic()

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                    env=env,
                    cwd=cwd,
                )
                duration = time.monotonic() - start

                if result.returncode == 0:
                    logger.info(f"Tool {tool} succeeded in {duration:.1f}s")
                    return ToolResult(
                        success=True,
                        tool_name=tool,
                        stdout=result.stdout,
                        stderr=result.stderr,
                        exit_code=0,
                        duration=duration,
                    )
                else:
                    last_error = f"{tool} exited {result.returncode}: {result.stderr[:500]}"
                    logger.warning(f"Tool {tool} failed: {last_error}")

            except subprocess.TimeoutExpired:
                last_error = f"{tool} timed out after {self._timeout}s"
                logger.warning(last_error)

            except Exception as exc:
                last_error = f"{tool} exception: {exc}"
                logger.warning(last_error)

        return ToolResult(
            success=False,
            tool_name=available[-1] if available else "none",
            error=f"All tools failed. Last error: {last_error}",
            stderr=last_error,
        )


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class CircuitState(Enum):
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject fast
    HALF_OPEN = "half_open"  # Testing if recovered


@dataclass
class CircuitBreaker:
    """Circuit breaker pattern for failing tools/services.

    Usage::
        breaker = CircuitBreaker("nmap", failure_threshold=5, recovery_timeout=60)
        if breaker.can_execute():
            try:
                result = await run_nmap()
                breaker.record_success()
            except Exception:
                breaker.record_failure()
        else:
            # Circuit is open, use fallback
            result = await run_rustscan()
    """

    name: str
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_max_calls: int = 3

    _state: CircuitState = field(default=CircuitState.CLOSED, repr=False)
    _failure_count: int = field(default=0, repr=False)
    _success_count: int = field(default=0, repr=False)
    _last_failure_time: float = field(default=0.0, repr=False)
    _half_open_calls: int = field(default=0, repr=False)

    def can_execute(self) -> bool:
        """Check if execution is allowed."""
        if self._state == CircuitState.CLOSED:
            return True
        elif self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 1  # Count transition as first half-open call
                # Defense-in-depth: a stale success_count from a prior HALF_OPEN
                # cycle could let a single success in this new HALF_OPEN window
                # reach the threshold and CLOSE prematurely. Reset it here.
                self._success_count = 0
                logger.info(f"Circuit breaker {self.name} entering HALF_OPEN state")
                return True
            logger.debug(f"Circuit breaker {self.name} is OPEN, rejecting")
            return False
        elif self._state == CircuitState.HALF_OPEN:
            if self._half_open_calls < self.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False
        return True

    def record_success(self) -> None:
        """Record a successful execution."""
        self._failure_count = 0
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.half_open_max_calls:
                self._state = CircuitState.CLOSED
                self._success_count = 0
                logger.info(f"Circuit breaker {self.name} CLOSED (recovered)")
        else:
            self._success_count = 0

    def record_failure(self) -> None:
        """Record a failed execution."""
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            # Reset half-open bookkeeping so the next recovery window starts
            # clean. If _success_count carried over, a stale partial count from
            # the failed HALF_OPEN cycle could combine with successes in the
            # NEXT HALF_OPEN window to CLOSE prematurely after fewer than
            # half_open_max_calls successes.
            self._success_count = 0
            self._half_open_calls = 0
            logger.warning(f"Circuit breaker {self.name} OPEN (half-open failure)")
        elif self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN
            logger.warning(f"Circuit breaker {self.name} OPEN after {self._failure_count} failures")

    def get_state(self) -> str:
        """Get current circuit state as string."""
        return self._state.value


# ---------------------------------------------------------------------------
# Async-safe execution pool
# ---------------------------------------------------------------------------


class AsyncExecutionPool:
    """Pool for executing async tasks with concurrency control and cancellation."""

    def __init__(self, max_concurrency: int = 5) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._tasks: set[asyncio.Task[Any]] = set()

    async def execute(
        self,
        coro: Coroutine[Any, Any, T],
        *,
        timeout: float | None = None,
        task_name: str = "",
    ) -> T:
        """Execute a coroutine with concurrency control."""
        async with self._semaphore:
            task = asyncio.create_task(coro, name=task_name or None)
            self._tasks.add(task)
            try:
                if timeout:
                    return await asyncio.wait_for(task, timeout=timeout)
                return await task
            finally:
                self._tasks.discard(task)

    async def execute_many(
        self,
        coros: list[Coroutine[Any, Any, T]],
        *,
        timeout: float | None = None,
        return_exceptions: bool = True,
    ) -> list[T | Exception]:
        """Execute multiple coroutines with concurrency control."""

        async def run_with_limit(coro: Coroutine[Any, Any, T]) -> T | Exception:
            try:
                return await self.execute(coro, timeout=timeout)
            except Exception as exc:
                if return_exceptions:
                    return exc
                raise

        return await asyncio.gather(
            *[run_with_limit(c) for c in coros],
            return_exceptions=return_exceptions,
        )

    async def cancel_all(self) -> None:
        """Cancel all running tasks in the pool."""
        for task in list(self._tasks):
            if not task.done():
                task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    @property
    def active_count(self) -> int:
        """Number of currently active tasks."""
        return sum(1 for t in self._tasks if not t.done())


# ---------------------------------------------------------------------------
# Shared rate limiter (token bucket, keyed, loop-agnostic)
# ---------------------------------------------------------------------------


class RateLimiter:
    """Async + sync token-bucket rate limiter, keyed by string key.

    A single instance can be shared across concurrent callers AND across
    event loops / threads -- e.g. the swarm orchestrator's loop and the fresh
    loop ``run_exploit_agent`` runs in via ``asyncio.run()``. This is why the
    bucket math is guarded by a ``threading.Lock`` and the wait is done with
    ``asyncio.sleep`` / ``time.sleep``: an ``asyncio.Lock`` / ``Semaphore`` is
    bound to the loop that created it and raises "Future attached to a
    different loop" if shared into another loop, so it is the wrong primitive
    for a cross-loop shared limiter.

    Token-bucket semantics: each key has a bucket of capacity ``burst`` that
    refills at ``rate_per_second`` tokens/sec. ``acquire`` reserves ``cost``
    tokens; if the bucket goes negative it sleeps exactly long enough for the
    refill to cover the deficit, so callers are throttled to the configured
    rate while permitting short bursts up to ``burst``.

    Tier 1.8: makes ``mission.yaml``'s previously-unconsumed
    ``search_rate_limit_per_minute`` budget real and shared across concurrent
    NVD/web-search calls, and is the primitive a future orchestrator-level
    rate budget (Tier 1.9) builds on.
    """

    def __init__(self, rate_per_second: float, burst: int = 1) -> None:
        if rate_per_second < 0:
            raise ValueError("rate_per_second must be >= 0")
        if burst < 1:
            raise ValueError("burst must be >= 1")
        self._rate = float(rate_per_second)
        self._burst = float(burst)
        # key -> (tokens, last_refill_monotonic)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_min_gap(cls, min_gap_seconds: float, burst: int = 1) -> "RateLimiter":
        """Build a limiter enforcing at least ``min_gap_seconds`` between
        acquires (rate = 1/min_gap, burst 1). Convenient for NVD's ~6s gap."""
        if min_gap_seconds <= 0:
            raise ValueError("min_gap_seconds must be > 0")
        return cls(1.0 / min_gap_seconds, burst=burst)

    @classmethod
    def from_per_minute(cls, per_minute: float, burst: int = 1) -> "RateLimiter":
        """Build a limiter from a per-minute rate (e.g. mission.yaml's
        ``search_rate_limit_per_minute``)."""
        if per_minute <= 0:
            raise ValueError("per_minute must be > 0")
        return cls(per_minute / 60.0, burst=burst)

    def _reserve(self, key: str, cost: float = 1.0) -> float:
        """Reserve ``cost`` tokens for ``key`` under the lock. Returns the
        seconds the caller must wait (0 if a token was immediately available).

        The token is reserved (bucket may go negative) BEFORE returning, so
        the caller MUST sleep the returned duration before proceeding and does
        NOT need to re-acquire -- this is what makes the wait deterministic
        (reserve-then-sleep, not poll-unless-available)."""
        with self._lock:
            now = time.monotonic()
            tokens, last = self._buckets.get(key, (self._burst, now))
            # Refill since last touch, capped at burst.
            tokens = min(self._burst, tokens + (now - last) * self._rate)
            tokens -= cost
            if tokens >= 0:
                self._buckets[key] = (tokens, now)
                return 0.0
            if self._rate <= 0:
                # No refill ever -- a negative bucket could never recover, so
                # undo the reservation to avoid permanently starving the key.
                self._buckets[key] = (tokens + cost, now)
                return math.inf
            self._buckets[key] = (tokens, now)
            return (-tokens) / self._rate

    async def acquire(self, key: str, cost: float = 1.0) -> None:
        """Async acquire: reserve then await the computed wait. Safe to call
        from any event loop -- the only asyncio primitive used is
        ``asyncio.sleep``, which binds to whichever loop is running."""
        wait = self._reserve(key, cost)
        if wait > 0:
            await asyncio.sleep(wait)

    def acquire_sync(self, key: str, cost: float = 1.0) -> None:
        """Sync acquire: reserve then ``time.sleep`` the computed wait."""
        wait = self._reserve(key, cost)
        if wait > 0:
            time.sleep(wait)

    def reset(self, key: str | None = None) -> None:
        """Clear bucket state for ``key`` (or all keys when ``None``)."""
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)


# ---------------------------------------------------------------------------
# Structured error logging
# ---------------------------------------------------------------------------


@dataclass
class ErrorRecord:
    """Structured error record for analysis and reporting."""

    timestamp: str
    component: str
    operation: str
    error_type: str
    error_message: str
    stack_trace: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    recovery_action: str = ""
    success: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "component": self.component,
            "operation": self.operation,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "stack_trace": self.stack_trace,
            "context": self.context,
            "recovery_action": self.recovery_action,
            "success": self.success,
        }


class ErrorTracker:
    """Track and analyze errors for failure reasoning."""

    def __init__(self, max_records: int = 1000) -> None:
        self._records: list[ErrorRecord] = []
        self._max_records = max_records
        self._error_counts: dict[str, int] = {}

    def record(
        self,
        component: str,
        operation: str,
        error: BaseException,
        *,
        context: dict[str, Any] | None = None,
        recovery_action: str = "",
        success: bool = False,
    ) -> None:
        """Record an error occurrence."""
        import traceback
        from datetime import datetime, timezone

        error_type = type(error).__name__
        self._error_counts[error_type] = self._error_counts.get(error_type, 0) + 1

        record = ErrorRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            component=component,
            operation=operation,
            error_type=error_type,
            error_message=str(error),
            stack_trace="".join(traceback.format_exception(type(error), error, error.__traceback__)),
            context=context or {},
            recovery_action=recovery_action,
            success=success,
        )

        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records.pop(0)

        logger.error(f"[{component}] {operation} failed: {error_type}: {error}. Recovery: {recovery_action}")

    def get_error_summary(self) -> dict[str, Any]:
        """Get summary of recorded errors."""
        return {
            "total_errors": len(self._records),
            "error_counts": self._error_counts,
            "most_common": sorted(
                self._error_counts.items(),
                key=lambda x: x[1],
                reverse=True,
            )[:10],
            "recent_failures": [r.to_dict() for r in self._records[-10:]],
        }

    def get_failure_reasoning(self, operation: str) -> str:
        """Generate failure reasoning for a specific operation."""
        relevant = [r for r in self._records if r.operation == operation]
        if not relevant:
            return f"No failure history for operation: {operation}"

        error_types = {}
        for r in relevant:
            error_types[r.error_type] = error_types.get(r.error_type, 0) + 1

        most_common = max(error_types, key=error_types.get)
        count = error_types[most_common]

        reasoning = f"Operation '{operation}' failed {len(relevant)} times. "
        reasoning += f"Most common error: {most_common} ({count} occurrences). "

        # Suggest mitigation
        mitigations = {
            "TimeoutError": "Consider increasing timeout or reducing scope.",
            "ConnectionRefusedError": "Target may be down or blocking connections.",
            "PermissionError": "Insufficient privileges. Try with elevated permissions.",
            "FileNotFoundError": "Required tool or file is missing. Check installation.",
            "OSError": "System-level error. Check disk space and permissions.",
        }
        reasoning += mitigations.get(most_common, "Review error details and adjust parameters.")

        return reasoning


# ---------------------------------------------------------------------------
# Graceful degradation helpers
# ---------------------------------------------------------------------------


class GracefulDegradation:
    """Helpers for graceful degradation when tools/services fail."""

    @staticmethod
    def get_tool_substitution(tool_name: str) -> list[str]:
        """Get fallback tool chain for a given tool."""
        substitutions: dict[str, list[str]] = {
            "nmap": ["rustscan", "masscan", "zmap"],
            "rustscan": ["nmap", "masscan"],
            "masscan": ["nmap", "rustscan"],
            "nikto": ["nuclei", "gobuster"],
            "feroxbuster": ["gobuster", "dirb", "wfuzz"],
            "gobuster": ["feroxbuster", "dirb"],
            "nuclei": ["nikto", "custom_fuzzer"],
            "sqlmap": ["manual_injection", "custom_fuzzer"],
            "hydra": ["medusa", "ncrack", "patator"],
            "enum4linux": ["smbclient", "rpcclient"],
            "ldapsearch": ["python-ldap", "custom_ldap"],
        }
        return substitutions.get(tool_name, [])

    @staticmethod
    def degrade_scan_type(aggression: str) -> str:
        """Reduce scan aggression level for stealth/reliability."""
        levels = ["maximum", "aggressive", "normal", "stealth"]
        if aggression in levels:
            idx = levels.index(aggression)
            if idx < len(levels) - 1:
                return levels[idx + 1]
        return "stealth"

    @staticmethod
    def reduce_scope(original_scope: list[str], failure_reason: str) -> list[str]:
        """Reduce scan scope based on failure reason."""
        if "timeout" in failure_reason.lower():
            # Reduce to top ports only
            return [s for s in original_scope if any(p in s for p in ["80", "443", "22", "445", "3389"])]
        elif "rate limit" in failure_reason.lower():
            # Reduce to single target
            return original_scope[:1]
        return original_scope


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


async def safe_execute(
    coro_factory: Callable[[], Coroutine[Any, Any, T]],
    *,
    timeout: float = 300.0,
    max_retries: int = 2,
    fallback_value: T | None = None,
    error_tracker: ErrorTracker | None = None,
    component: str = "unknown",
    operation: str = "unknown",
) -> T | None:
    """Execute a coroutine safely with retry, timeout, and fallback.

    Args:
        coro_factory: Callable that returns a coroutine to execute
        timeout: Timeout in seconds
        max_retries: Maximum retry attempts
        fallback_value: Value to return on total failure
        error_tracker: Optional error tracker for recording failures
        component: Component name for error tracking
        operation: Operation name for error tracking

    Returns:
        Result of coroutine or fallback_value on failure
    """
    for attempt in range(max_retries + 1):
        try:
            return await with_timeout(coro_factory(), timeout)
        except _EXC_GROUP_CATCH as exc:
            # Tier 1.2: catch BaseExceptionGroup too — a wrapped MCP stdio call
            # can raise one on subprocess death, and bare `except Exception`
            # would let it propagate and crash the caller.
            logger.warning(f"safe_execute failed (attempt {attempt + 1}/{max_retries + 1}): {exc}")
            if error_tracker:
                error_tracker.record(
                    component=component,
                    operation=operation,
                    error=exc,
                    recovery_action="retry" if attempt < max_retries else "fallback",
                    success=False,
                )
            if attempt < max_retries:
                await asyncio.sleep(2**attempt)

    logger.error(f"safe_execute exhausted all retries for {operation}")
    return fallback_value
