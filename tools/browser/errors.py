"""Browser-agent exception hierarchy — fail-closed by contract.

Mirrors the sandbox exception discipline (``tools/sandbox/exceptions.py``):
any browser failure MUST surface as a typed error that callers can classify
into a :class:`tools.browser.models.BrowserFailureClass`; there is no
fallback that silently continues as if a browser existed.

These are exceptions only. The serialized error payload lives in
``tools.browser.models.BrowserError`` (dataclass) — the two are distinct
types on purpose: exceptions are control flow, the dataclass is the
audit/evidence record.
"""

from __future__ import annotations

__all__ = [
    "BrowserBackendError",
    "BrowserBackendUnavailable",
    "BrowserBackendNotImplemented",
    "BrowserTransitionError",
    "BrowserSessionNotFound",
    "browser_error_from_exception",
]


class BrowserBackendError(Exception):
    """Base class for every browser-backend failure."""

    #: Stable code string (``BrowserFailureClass.value``) for result blocks.
    code: str = "unknown"


class BrowserBackendUnavailable(BrowserBackendError):
    """No browser backend is configured/installed — fail closed, ask operator."""

    code = "tool_unavailable"

    def __init__(self, message: str = "") -> None:
        super().__init__(
            message
            or "no browser backend is configured (browser.enabled is false or backend is 'none'); "
            "browser capabilities are declared but not available"
        )


class BrowserBackendNotImplemented(BrowserBackendError):
    """The backend seam exists but this backend has not implemented the operation.

    Raised by the abstract ``BrowserBackend`` base methods so the
    architecture works while intentionally deferring implementation —
    never by launching a real browser.
    """

    code = "tool_unavailable"

    def __init__(self, method: str, backend_id: str = "") -> None:
        super().__init__(
            f"browser backend {backend_id!r} has not implemented {method}() — "
            "browser execution is not available in this build (deferred implementation)"
        )


class BrowserTransitionError(BrowserBackendError):
    """An illegal session lifecycle transition was requested."""

    code = "invalid_transition"


class BrowserSessionNotFound(BrowserBackendError):
    """The referenced session id is unknown to the manager."""

    code = "session_not_found"


def browser_error_from_exception(exc: BaseException) -> tuple[str, str]:
    """Map an exception onto ``(failure_class_value, message)`` for results.

    Uses the browser backend error hierarchy first, then the global failure
    taxonomy classifiers so browser failures speak the same recovery
    vocabulary as every other tool outcome.
    """
    from tools.browser.errors import BrowserBackendError as _BBE

    if isinstance(exc, _BBE):
        return exc.code, str(exc)
    try:
        from tools.failure_taxonomy import classify_failure

        cls = classify_failure(str(exc))
        return cls.value, str(exc)
    except Exception:  # noqa: BLE001 — taxonomy is best-effort; never mask the original
        try:
            return "unknown", str(exc)
        except Exception:  # noqa: BLE001 — even str() may raise; never mask the caller
            return "unknown", "<unprintable browser exception>"