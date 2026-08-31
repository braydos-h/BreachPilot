"""Browser-agent preparation layer (architecture-only; execution deferred).

Design: ``docs/browser-agent-design.md``.

This package is the future home of the browser-native web agent. It
currently contains ZERO browser-execution capability by design:

- ``models``      — provider/engine-neutral typed schemas (sessions, actions,
                    observations, artifacts, network events, storage, results).
- ``errors``      — fail-closed exception hierarchy for the browser seam.
- ``interfaces``  — ``BrowserBackend`` ABC: the ONLY seam a future engine
                    (Playwright/CDP/Selenium adapter) may cross. No Playwright,
                    Selenium, subprocess, socket, or browser launch exists here.
- ``capabilities``— stable ``browser.*`` capability vocabulary, all reported
                    UNAVAILABLE until a backend is configured.
- ``manager``     — ``BrowserManager``: session registry, lifecycle state
                    validation, run-scoped ownership, backend injection seam.
                    With no backend injected every action fails closed.

Guarantees for this preparation build:

- importing ``tools.browser`` imports no browser package (asserted by tests),
- ``BrowserManager(config).available()`` is False for every stock config,
- sensitive material (cookies, storage values, tokens) redacts by default at
  every serialization surface that feeds logs/audit.
"""

from __future__ import annotations

from tools.browser.capabilities import (
    BROWSER_CAPABILITIES,
    BrowserCapability,
    browser_available,
    browser_capabilities,
    browser_capability_names,
    unmet_requirements,
)
from tools.browser.errors import (
    BrowserBackendError,
    BrowserBackendNotImplemented,
    BrowserBackendUnavailable,
    BrowserSessionNotFound,
    BrowserTransitionError,
    browser_error_from_exception,
)
from tools.browser.interfaces import BrowserBackend
from tools.browser.manager import BrowserManager
from tools.browser.models import (
    REDACTED,
    BrowserAction,
    BrowserActionKind,
    BrowserArtifact,
    BrowserArtifactKind,
    BrowserCookie,
    BrowserError,
    BrowserEventDirection,
    BrowserFailureClass,
    BrowserNetworkEvent,
    BrowserObservation,
    BrowserObservationKind,
    BrowserPageState,
    BrowserResult,
    BrowserSession,
    BrowserSessionId,
    BrowserSessionState,
    BrowserStorageKind,
    BrowserStorageSnapshot,
    new_session_id,
    redact_value,
    validate_session_transition,
)

__all__ = [
    "BROWSER_CAPABILITIES",
    "BrowserAction",
    "BrowserActionKind",
    "BrowserArtifact",
    "BrowserArtifactKind",
    "BrowserBackend",
    "BrowserBackendError",
    "BrowserBackendNotImplemented",
    "BrowserBackendUnavailable",
    "BrowserCapability",
    "BrowserCookie",
    "BrowserError",
    "BrowserEventDirection",
    "BrowserFailureClass",
    "BrowserManager",
    "BrowserNetworkEvent",
    "BrowserObservation",
    "BrowserObservationKind",
    "BrowserPageState",
    "BrowserResult",
    "BrowserSession",
    "BrowserSessionId",
    "BrowserSessionNotFound",
    "BrowserSessionState",
    "BrowserStorageKind",
    "BrowserStorageSnapshot",
    "BrowserTransitionError",
    "REDACTED",
    "browser_available",
    "browser_capabilities",
    "browser_capability_names",
    "browser_error_from_exception",
    "new_session_id",
    "redact_value",
    "unmet_requirements",
    "validate_session_transition",
]
