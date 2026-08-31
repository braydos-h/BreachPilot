"""Browser capability metadata — declared contracts, all unavailable today.

The capability model in BreachPilot is the attack-module ``requires``/
``produces`` composition system (``tools/attack_modules/base.py::
capability_record``), not a global executable-capability registry. This
module adds the *browser capability vocabulary* at that same metadata level:

- stable ``browser.*`` capability names for planner reasoning and future
  benchmark ``requires_capabilities`` scenario metadata,
- an availability rule that reports every browser capability **unavailable**
  until a browser backend is configured (``browser.enabled`` + ``backend``
  + a backend that reports ``is_configured`` — no backend exists yet),
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
            "Submit forms (deferred: requires the action-execution backend).",
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


#: Registered browser backends by id. EMPTY in this build — the Playwright
#: backend (future PR) registers itself here, which is the ONLY way a
#: ``browser.*`` capability can become available. Nothing registers at import
#: time, so stock installs always report unavailable.
BACKEND_REGISTRY: dict[str, BrowserBackend] = {}


def backend_configured(backend_id: str, config: dict[str, Any] | None = None) -> bool:
    """Whether ``backend_id`` names a registered backend that reports ready.

    Deliberately requires BOTH a registry entry and the backend's own
    ``is_configured`` verdict — a configured-but-uninstalled backend name in
    config.yml can never make capabilities appear available (fail closed).
    """
    del config  # backend adapters read their own config via provider_config-style seams
    backend = BACKEND_REGISTRY.get(backend_id)
    return bool(backend) and bool(backend.is_configured({}))


def browser_capabilities(config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Machine-readable capability records: name/description/read_only/available.

    ``available`` is False for every entry unless browser execution is
    actually configured (never true in this build — no backend exists).
    """
    cfg = (config or {}).get("browser", {}) or {}
    backend = str(cfg.get("backend", "none") or "none")
    enabled = bool(cfg.get("enabled", False))
    available = bool(enabled and backend != "none" and backend_configured(backend, cfg))
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
    """Whether ANY browser capability is executable (False in this build)."""
    return any(bool(c["available"]) for c in browser_capabilities(config))


def unmet_requirements(required: list[str] | tuple[str, ...] | None, config: dict[str, Any] | None = None) -> list[str]:
    """Which of ``required`` capability names are unavailable for this config.

    Used by benchmark scenario metadata (``requires_capabilities``): a
    scenario whose requirements cannot be met is detectable — and later
    skippable/classifiable — without ever attempting a browser launch.
    Unknown capability names are reported unmet too (nothing provides them).
    """
    cfg = (config or {}).get("browser", {}) or {}
    backend = str(cfg.get("backend", "none") or "none")
    enabled = bool(cfg.get("enabled", False))
    available = bool(enabled and backend != "none" and backend_configured(backend, cfg))
    if not required:
        return []
    if available:
        # With a real backend, refinement lands with the backend registry
        # (per-capability support + declared-vs-implemented) — deferred.
        return [r for r in required if r not in BROWSER_CAPABILITIES]
    return list(required)