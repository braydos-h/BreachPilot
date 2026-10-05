"""Shared exception-handling helpers for MCP-safe catch blocks.

Any code that wraps MCP SDK calls (stdio_client, streamable_http_client,
ClientSession.initialize, session.call_tool, etc.) MUST use
``_EXC_GROUP_CATCH`` instead of bare ``except Exception`` because anyio
task groups raise ``BaseExceptionGroup`` on subprocess death, which is
*not* a subclass of ``Exception``.
"""

from __future__ import annotations

import asyncio
import sys
import traceback
from typing import Callable, TypeGuard


def _is_exception_group(exc: BaseException) -> TypeGuard[BaseExceptionGroup]:
    """Check if an exception is an ExceptionGroup / BaseExceptionGroup (PEP 654)."""
    if isinstance(exc, BaseExceptionGroup):
        return True
    attr = getattr(exc, "exceptions", None)
    return isinstance(attr, tuple)


def _find_cancellation(exc: BaseException) -> asyncio.CancelledError | None:
    """Return a nested asyncio cancellation, if an exception group contains one.

    MCP task-group teardown can combine cancellation with a transport error.
    Callers may handle the transport failure, but must preserve cancellation
    instead of returning a normal result or soft-failure sentinel.
    """
    if isinstance(exc, asyncio.CancelledError):
        return exc
    if _is_exception_group(exc):
        for nested in exc.exceptions:
            cancellation = _find_cancellation(nested)
            if cancellation is not None:
                return cancellation
    return None


def _reraise_if_cancelled(exc: BaseException) -> None:
    """Propagate cancellation found inside ``exc`` instead of soft-failing it."""
    cancellation = _find_cancellation(exc)
    if cancellation is not None:
        raise cancellation from exc


def _log_nested_exceptions(
    exc: BaseException,
    *,
    prefix: str = "",
    redact: Callable[[str], str] | None = None,
) -> None:
    """Recursively log every exception inside an ExceptionGroup / BaseExceptionGroup."""
    if _is_exception_group(exc):
        for i, nested in enumerate(exc.exceptions):
            _log_nested_exceptions(nested, prefix=f"{prefix}  [{i}] ", redact=redact)
    else:
        try:
            lines = traceback.format_exception(type(exc), exc, exc.__traceback__)
        except Exception as fmt_exc:
            detail = redact(str(fmt_exc)) if redact is not None else repr(fmt_exc)
            print(f"{prefix}<unformattable exception {type(exc).__name__}: {detail}>")
            return
        for line in lines:
            rendered = line.rstrip()
            print(f"{prefix}{redact(rendered) if redact is not None else rendered}")


if sys.version_info >= (3, 11):
    _EXC_GROUP_CATCH: tuple[type[BaseException], ...] = (Exception, BaseExceptionGroup)
else:
    _EXC_GROUP_CATCH = (Exception,)
