"""Shared exception-handling helpers for MCP-safe catch blocks.

Any code that wraps MCP SDK calls (stdio_client, streamable_http_client,
ClientSession.initialize, session.call_tool, etc.) MUST use
``_EXC_GROUP_CATCH`` instead of bare ``except Exception`` because anyio
task groups raise ``BaseExceptionGroup`` on subprocess death, which is
*not* a subclass of ``Exception``.
"""
from __future__ import annotations

import sys
import traceback


def _is_exception_group(exc: BaseException) -> bool:
    """Check if an exception is an ExceptionGroup / BaseExceptionGroup (PEP 654)."""
    if isinstance(exc, BaseExceptionGroup):
        return True
    return hasattr(exc, "exceptions") and isinstance(exc.exceptions, tuple)


def _log_nested_exceptions(exc: BaseException, *, prefix: str = "") -> None:
    """Recursively log every exception inside an ExceptionGroup / BaseExceptionGroup."""
    if _is_exception_group(exc):
        group = exc  # type: ignore[union-attr]
        for i, nested in enumerate(group.exceptions):
            _log_nested_exceptions(nested, prefix=f"{prefix}  [{i}] ")
    else:
        try:
            lines = traceback.format_exception(type(exc), exc, exc.__traceback__)
        except Exception as fmt_exc:
            print(f"{prefix}<unformattable exception {type(exc).__name__}: {fmt_exc!r}>")
            return
        for line in lines:
            print(f"{prefix}{line.rstrip()}")


if sys.version_info >= (3, 11):
    _EXC_GROUP_CATCH: tuple[type[BaseException], ...] = (Exception, BaseExceptionGroup)
else:
    _EXC_GROUP_CATCH = (Exception,)
