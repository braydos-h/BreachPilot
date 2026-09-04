"""Browser capability metadata — declared contracts, gated availability.

The capability model in BreachPilot is the attack-module ``requires``/
``produces`` composition system (``tools/attack_modules/base.py::
capability_record``), not a global executable-capability registry. This
module adds the *browser capability vocabulary* at that same metadata level:

- stable ``browser.*`` capability names for planner reasoning and future
  benchmark ``requires_capabilities`` scenario metadata,
- an availability rule that reports every browser capability **unavailable**
  until a browser backend is enabled + registered + runnable (``browser.enabled``
  + ``backend`` + a registry entry whose ``is_configured`` passes AND a host
  SDK or a sandbox worker to run it in),
- :func:`unmet_requirements` used by future benchmark scenario classification.

Contracts:

- Declared is NOT available. A capability listed here never implies
  executable behavior; consumers must consult :func:`browser_capabilities`
  rather than hard-coding names.
- No prompt section references these capabilities while they are
  unavailable — prompts must never instruct the model to use tooling that
  cannot run (design doc §planner integration).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tools.browser.interfaces import BrowserBackend

__all__ = [
    "BROWSER_CAPABILITIES",
    "BrowserCapability",
    "BACKEND_REGISTRY",
    "browser_capability_names",
    "browser_capabilities",
    "browser_available",
    "browser_runtime_available",
    "backend_configured",
    "get_backend",
    "register_playwright_backend",
    "unmet_requirements",
]


@dataclass(frozen=True)
class BrowserCapability:
    """One declared browser capability (metadata contract, not an executor)."""

    name: str
    description: str
    #: Deferred actions this capability is currently gated behind (None =
    #: the capability is simply not implemented by any backend yet).
    depends_on: tuple[str, ...] = field(default_factory=tuple)
    #: Whether the capability changes target state (planner-cost hint).
    read_only: bool = False


#: The full browser capability vocabulary. Names are stable contracts:
#: scenario manifests, planner records and audit rows may reference them
#: verbatim from day one.
BROWSER_CAPABILITIES: dict[str, BrowserCapability] = {
    cap.name: cap
    for cap in (
        BrowserCapability(
            "browser.navigate",
            "Open URLs in an authenticated browser session (redirect/SPA aware).",
            read_only=False,
        ),
        BrowserCapability(
            "browser.dom.inspect",
            "Harvest compact DOM snapshots and indicators from the live page.",
            read_only=True,
        ),
        BrowserCapability(
            "browser.javascript.execute",
            "Execute JavaScript in the page context and capture the return value.",
            read_only=False,
        ),
        BrowserCapability(
            "browser.network.observe",
            "Capture request/response records (headers, digests, timing).",
            read_only=True,
        ),
        BrowserCapability(
            "browser.network.replay",
            "Replay/mutate captured requests under the same target lock.",
            read_only=False,
        ),
        BrowserCapability(
            "browser.storage.read",
            "Harvest cookies and localStorage/sessionStorage for the origin.",
            read_only=True,
        ),
        BrowserCapability(
            "browser.form.inspect",
            "Discover and metadata-fingerprint forms and their fields.",
            read_only=True,
        ),
        BrowserCapability(
            "browser.form.submit",
            "Submit forms (mutating: requires browser.allow_mutating_actions + target lock).",
            read_only=False,
        ),
        BrowserCapability(
            "browser.screenshot",
            "Persist page screenshots as hashed artifacts.",
            read_only=True,
        ),
        BrowserCapability(
            "browser.endpoint.discover",
            "Discover REST/GraphQL endpoints from traffic and script refs.",
            read_only=True,
        ),
    )
}


def browser_capability_names() -> tuple[str, ...]:
    """All capability names, in declaration order (stable for tests/docs)."""
    return tuple(BROWSER_CAPABILITIES)


#: Registered browser backends by id. EMPTY until a backend module registers
#: itself at call time via :func:`register_playwright_backend` — never at
#: import, so stock imports stay engine-free and stock installs always report
#: unavailable. Registration alone never implies runnable (see
#: :func:`browser_runtime_available`).
BACKEND_REGISTRY: dict[str, BrowserBackend] = {}


def get_backend(backend_id: str) -> BrowserBackend | None:
    """Return the registered backend for ``backend_id`` (None when absent)."""
    return BACKEND_REGISTRY.get(backend_id)


def register_playwright_backend(config: dict[str, Any] | None = None) -> bool:
    """Register the Playwright backend (call-time, never import-time).

    Returns True when the backend module imported and registered; False when
    the optional ``browser`` extra is missing (fail closed — capabilities stay
    unavailable and the caller should surface the install hint).
    """
    if "playwright" in BACKEND_REGISTRY:
        return True
    try:
        from tools.browser.playwright_backend import PlaywrightBackend
    except ImportError:
        return False
    BACKEND_REGISTRY["playwright"] = PlaywrightBackend(config)
    return True


def _sandbox_execution_possible(config: dict[str, Any] | None) -> bool:
    """Whether contained browser execution is configured (worker at runtime)."""
    try:
        from tools.sandbox.models import SandboxConfig

        return bool(SandboxConfig.from_config(config).enabled)
    except Exception:  # noqa: BLE001 — config probing never raises
        return False


def backend_configured(backend_id: str, config: dict[str, Any] | None = None) -> bool:
    """Whether ``backend_id`` names a registered backend that reports ready.

    Deliberately requires BOTH a registry entry and the backend's own
    ``is_configured`` verdict against the REAL config — a configured-but-
    uninstalled backend name in config.yaml can never make capabilities appear
    available (fail closed).
    """
    backend = BACKEND_REGISTRY.get(backend_id)
    if backend is None:
        return False
    try:
        return bool(backend.is_configured(config if config is not None else {}))
    except Exception:  # noqa: BLE001 — a backend probe never breaks availability
        return False


def browser_runtime_available(config: dict[str, Any] | None = None) -> bool:
    """Single availability rule: enabled + registered + runnable somewhere.

    Runnable means the host SDK is present (``is_configured``) OR a sandbox
    worker is configured to run it contained (image presence is verified at
    execution time, like every other sandboxed tool — the worker, not the
    host, owns Chromium there). ``browser.backend: playwright`` alone never
    flips this (fail closed).
    """
    cfg = (config or {}).get("browser", {}) or {}
    backend = str(cfg.get("backend", "none") or "none")
    enabled = bool(cfg.get("enabled", False))
    if not (enabled and backend != "none"):
        return False
    if backend not in BACKEND_REGISTRY:
        return False
    if backend_configured(backend, config):
        return True
    return _sandbox_execution_possible(config)


def browser_capabilities(config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Machine-readable capability records: name/description/read_only/available.

    ``available`` is True for every entry only when browser execution is
    actually runnable (see :func:`browser_runtime_available`); per-capability
    refinement (a backend advertising a subset) is a future step — the
    backend's ``capabilities`` tuple is recorded for it.
    """
    available = browser_runtime_available(config)
    return [
        {
            "name": cap.name,
            "description": cap.description,
            "read_only": cap.read_only,
            "available": available,
        }
        for cap in BROWSER_CAPABILITIES.values()
    ]


def browser_available(config: dict[str, Any] | None = None) -> bool:
    """Whether ANY browser capability is executable right now."""
    return browser_runtime_available(config)


def unmet_requirements(required: list[str] | tuple[str, ...] | None, config: dict[str, Any] | None = None) -> list[str]:
    """Which of ``required`` capability names are unavailable for this config.

    Used by benchmark scenario metadata (``requires_capabilities``): a
    scenario whose requirements cannot be met is detectable — and later
    skippable/classifiable — without ever attempting a browser launch.
    Unknown capability names are reported unmet too (nothing provides them).
    """
    if not required:
        return []
    if browser_runtime_available(config):
        # With a real backend, refinement lands with the backend registry
        # (per-capability support + declared-vs-implemented) — deferred.
        return [r for r in required if r not in BROWSER_CAPABILITIES]
    return list(required)
