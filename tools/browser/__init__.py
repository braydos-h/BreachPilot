"""Browser-native web agent (Playwright engine behind the prepared seam).

Design: ``docs/browser-agent-design.md``.

- ``models``      — provider/engine-neutral typed schemas (sessions, actions,
                    observations, artifacts, network events, storage, results).
- ``errors``      — fail-closed exception hierarchy for the browser seam.
- ``interfaces``  — ``BrowserBackend`` ABC: the ONLY seam the engine crosses.
- ``playwright_backend`` — Chromium-via-Playwright adapter (optional
                    ``browser`` extra). The only module allowed to import the
                    Playwright SDK; translates everything into ``models.*``.
- ``sandbox_launcher`` — contained execution: one Chromium op per docker exec
                    inside the sandbox worker netns (no host fallback).
- ``_pw_probe``   — import-safe SDK/Chromium probes (never launches).
- ``capabilities``— stable ``browser.*`` vocabulary + runtime availability.
- ``manager``     — ``BrowserManager``: session registry, lifecycle, run
                    ownership, and the async execution funnel.

Guarantees:

- importing ``tools.browser`` imports no browser package (asserted by tests;
  the backend registers at call time, never at import),
- stock installs (disabled / ``backend: none`` / no SDK) report unavailable,
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
    browser_runtime_available,
    get_backend,
    register_playwright_backend,
    unmet_requirements,
)
from tools.browser.errors import (
    BrowserBackendError,
    BrowserBackendNotImplemented,
    BrowserBackendUnavailable,
    BrowserCrashed,
    BrowserNavigationFailed,
    BrowserScopeBlocked,
    BrowserScriptError,
    BrowserSessionNotFound,
    BrowserTimeout,
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
    "BrowserCrashed",
    "BrowserError",
    "BrowserEventDirection",
    "BrowserFailureClass",
    "BrowserManager",
    "BrowserNavigationFailed",
    "BrowserNetworkEvent",
    "BrowserObservation",
    "BrowserObservationKind",
    "BrowserPageState",
    "BrowserResult",
    "BrowserScopeBlocked",
    "BrowserScriptError",
    "BrowserSession",
    "BrowserSessionId",
    "BrowserSessionNotFound",
    "BrowserSessionState",
    "BrowserStorageKind",
    "BrowserStorageSnapshot",
    "BrowserTimeout",
    "BrowserTransitionError",
    "REDACTED",
    "browser_available",
    "browser_capabilities",
    "browser_capability_names",
    "browser_error_from_exception",
    "browser_runtime_available",
    "get_backend",
    "new_session_id",
    "redact_value",
    "register_playwright_backend",
    "unmet_requirements",
    "validate_session_transition",
]
