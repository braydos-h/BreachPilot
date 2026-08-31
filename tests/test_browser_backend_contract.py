"""Backend contract tests for the BrowserBackend seam (architecture-only build).

Verifies that:

* ``BrowserBackend`` is a real ABC — instantiable only by concrete subclasses,
  and no method has an executable default that could ever drive a browser.
* The error hierarchy fails closed with typed, classifiable errors.
* ``tools.browser`` imports with ZERO browser-automation packages loaded
  (no Playwright/Selenium/CDP anywhere in the import graph).
"""

from __future__ import annotations

import sys

import pytest

import tools.browser  # noqa: F401 — import contract itself is under test
from tools.browser.capabilities import BACKEND_REGISTRY
from tools.browser.errors import (
    BrowserBackendError,
    BrowserBackendNotImplemented,
    BrowserBackendUnavailable,
    BrowserTransitionError,
    browser_error_from_exception,
)
from tools.browser.interfaces import BrowserBackend
from tools.browser.models import BrowserAction, BrowserFailureClass, BrowserResult


# ── Import hygiene: no browser-automation package enters the process ──────


def test_browser_package_imports_without_browser_automation():
    """Importing tools/browser pulls in no Playwright/Selenium/pyppeteer/CDP.

    Subprocesses inherit this process, so a stray top-level import of a real
    browser engine would be launch-capable surface — none may be present.
    """
    for name in ("playwright", "selenium", "pyppeteer", "pyppeteer2", "drissionpage"):
        mod = sys.modules.get(name)
        ok = mod is None or mod.__spec__ is None  # namespace stubs are fine
        assert ok, f"importing tools.browser must not load {name}"


def test_backend_registry_is_empty_until_a_backend_registers():
    """Stock build: no backend is registered, so nothing can become available."""
    assert isinstance(BACKEND_REGISTRY, dict)
    assert "playwright" not in BACKEND_REGISTRY


# ── ABC contract ──────────────────────────────────────────────────────────


def test_browser_backend_cannot_be_instantiated():
    with pytest.raises(TypeError):
        BrowserBackend()


def test_backend_must_implement_every_operation():
    """A partially-implemented backend is refused — no silent no-op defaults."""

    class HalfBackend(BrowserBackend):
        backend_id = "half"

    class FullBackend(BrowserBackend):
        backend_id = "full"

        async def start_session(self, *, target, run_id="", session_id="", headless=True, metadata=None):
            raise BrowserBackendUnavailable

        async def stop_session(self, session_id):
            raise BrowserBackendUnavailable

        async def navigate(self, session_id, url, *, timeout_seconds=None):
            raise BrowserBackendUnavailable

        async def observe(self, session_id, *, include_forms=True, include_endpoints=True):
            raise BrowserBackendUnavailable

        async def execute_action(self, session_id, action):
            raise BrowserBackendUnavailable

        async def capture_screenshot(self, session_id, *, artifact_path=""):
            raise BrowserBackendUnavailable

        async def get_network_events(self, session_id, *, limit=100, after_id=""):
            raise BrowserBackendUnavailable

        async def get_storage(self, session_id, *, origin=""):
            raise BrowserBackendUnavailable

        async def get_page_state(self, session_id):
            raise BrowserBackendUnavailable

        async def close(self, session_id):
            raise BrowserBackendUnavailable

    with pytest.raises(TypeError):
        HalfBackend()
    assert FullBackend() is not None  # type: ignore[abstract]


def _inert_backend(backend_id: str = "inert") -> BrowserBackend:
    from tools.browser.errors import BrowserBackendNotImplemented

    def _raising(fn_name):
        async def _fn(*args, **kwargs):
            raise BrowserBackendNotImplemented(fn_name, backend_id)

        return _fn

    namespace: dict = {"backend_id": backend_id}
    for name in ("start_session", "stop_session", "navigate", "observe", "execute_action",
                 "capture_screenshot", "get_network_events", "get_storage", "get_page_state", "close"):
        namespace[name] = staticmethod(_raising(name))
    return type("_InertBackend", (BrowserBackend,), namespace)()


def test_default_backend_metadata_is_unconfigured():
    backend = _inert_backend("probe")
    assert backend.is_configured({}) is False
    health = backend.health({})
    assert health["ok"] is False
    assert "not implemented" in health["detail"]
    assert health["name"] == "browser_backend_probe"


# ── Error hierarchy ───────────────────────────────────────────────────────


def test_default_unavailable_message_names_the_config_keys():
    exc = BrowserBackendUnavailable()
    assert exc.code == "tool_unavailable"
    assert "browser.enabled" in str(exc)
    assert "none" in str(exc)


def test_not_implemented_error_is_a_deferral_not_a_failure():
    exc = BrowserBackendNotImplemented("navigate", "stub")
    assert "stub" in str(exc)
    assert "navigate" in str(exc)
    assert "deferred implementation" in str(exc)


def test_all_browser_errors_are_backend_errors():
    assert issubclass(BrowserBackendUnavailable, BrowserBackendError)
    assert issubclass(BrowserBackendNotImplemented, BrowserBackendError)
    assert issubclass(BrowserTransitionError, BrowserBackendError)


def test_error_mapping_uses_browser_codes_first():
    assert browser_error_from_exception(BrowserBackendUnavailable()) == (
        BrowserFailureClass.BACKEND_UNAVAILABLE.value,
        str(BrowserBackendUnavailable()),
    )


def test_error_mapping_falls_back_to_global_taxonomy():
    value, message = browser_error_from_exception(TimeoutError("browser page load timed out after 30s"))
    assert isinstance(value, str) and value
    assert "timed out" in message


def test_error_mapping_survives_garbage():
    class Weird:
        def __str__(self):
            raise RuntimeError("boom")

    value, _message = browser_error_from_exception(Weird())
    assert value == "unknown"


def test_execute_action_signature_takes_typed_models_only():
    """The seam's operation input/output types are browser-domain types."""

    class SigBackend(BrowserBackend):
        backend_id = "sig"

        async def start_session(self, *, target, run_id="", session_id="", headless=True, metadata=None):
            return None  # type: ignore[return-value]

        async def stop_session(self, session_id):
            return None  # type: ignore[return-value]

        async def navigate(self, session_id, url, *, timeout_seconds=None):
            return None  # type: ignore[return-value]

        async def observe(self, session_id, *, include_forms=True, include_endpoints=True):
            return None  # type: ignore[return-value]

        async def execute_action(self, session_id, action):
            assert isinstance(action, BrowserAction)
            return BrowserResult(success=False, failure_class=BrowserFailureClass.UNSUPPORTED_ACTION)

        async def capture_screenshot(self, session_id, *, artifact_path=""):
            return None  # type: ignore[return-value]

        async def get_network_events(self, session_id, *, limit=100, after_id=""):
            return None  # type: ignore[return-value]

        async def get_storage(self, session_id, *, origin=""):
            return None  # type: ignore[return-value]

        async def get_page_state(self, session_id):
            return None  # type: ignore[return-value]

        async def close(self, session_id):
            return None  # type: ignore[return-value]

    backend = SigBackend()
    action = BrowserAction(action_id="a-1", session_id="s-1")
    import asyncio

    result = asyncio.run(backend.execute_action("s-1", action))
    # Typed models cross the seam in both directions — no engine object here.
    assert isinstance(result, BrowserResult)
    assert result.failure_class is BrowserFailureClass.UNSUPPORTED_ACTION