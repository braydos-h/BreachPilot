"""Browser-agent domain models — provider-neutral, engine-neutral schemas only.

This module is the SINGLE shared vocabulary for the future browser-native
web agent (design: ``docs/browser-agent-design.md``). It contains pure data:
typed models for browser sessions, actions, observations, artifacts, network
events, storage snapshots and structured results.

Invariants (mirrors ``tools/benchmark/models.py`` house style):

- Pure data + enums + JSON serialization. No I/O, no subprocess, no sockets,
  no imports of playwright/selenium/any browser package — importable on any
  platform with zero behavior change for existing users.
- Deterministic ``to_dict``: hand-rolled dicts in dataclass-field order
  (enums serialized via ``.value``), never ``json.dumps(..., sort_keys=...)``
  ordering or dict iteration. ``to_dict`` twice on the same object yields
  identical key order and values.
- Tolerant ``from_dict``: unknown enum strings fall back to safe defaults and
  missing keys take field defaults, so a payload written by a newer/older
  version never breaks a reader (``tools/campaign/state.py`` convention).
- Secrets are NEVER serialized unredacted. Model fields may hold sensitive
  material in memory (cookie values, storage entries); every serialization
  surface has a redacted variant (``to_redacted_dict``) that structurally
  masks values. The default ``to_dict`` for models carrying secret material
  already redacts — a caller must opt IN to raw values via
  ``to_dict(redact=False)``.
- ``BrowserFailureClass`` names browser-specific failures and maps onto the
  global ``tools.failure_taxonomy.FailureClass`` taxonomy where the concepts
  overlap — the planner/recovery loop reads the mapped global class.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import Any

from tools.failure_taxonomy import FailureClass as GlobalFailureClass

__all__ = [
    "BrowserSessionId",
    "BrowserSessionState",
    "BrowserActionKind",
    "BrowserAction",
    "BrowserObservationKind",
    "BrowserObservation",
    "BrowserPageState",
    "BrowserNetworkEvent",
    "BrowserEventDirection",
    "BrowserCookie",
    "BrowserStorageKind",
    "BrowserStorageSnapshot",
    "BrowserArtifact",
    "BrowserArtifactKind",
    "BrowserFailureClass",
    "BrowserError",
    "BrowserResult",
    "new_session_id",
    "redact_value",
    "REDACTED",
]

# ---------------------------------------------------------------------------
# Redaction (single source: tools.kernel.audit)
# ---------------------------------------------------------------------------

REDACTED = "***REDACTED***"

#: Secret-shaped *keys* browser serialization must structurally mask (headers,
#: storage entries, payload dicts). Complements — never replaces — the shared
#: kernel redactor (``tools/kernel/audit.py``): its ``_SECRET_ARG_NAMES`` +
#: regex table stays the single source for content masking; these names add
#: the browser-specific header/cookie/storage vocabulary on top.
_SECRET_BROWSER_KEYS = frozenset(
    {
        "authorization",
        "proxy_authorization",
        "cookie",
        "cookie_value",
        "set_cookie",
        "cookies",
        "session",
        "session_id",
        "sessionid",
        "session_token",
        "session_key",
        "auth",
        "auth_token",
        "access_token",
        "refresh_token",
        "id_token",
        "bearer",
        "csrf",
        "csrf_token",
        "xsrf_token",
        "api_key",
        "apikey",
        "password",
        "secret",
        "token",
        "jwt",
        "value",  # storage-snapshot entry values are credential material
        "sessionstorage",
        "localstorage",
    }
)

#: JSON/document bodies frequently carry ``"password": "..."``-style secrets
#: the kernel regex table (KEY=value lines) cannot see — browser request body
#: samples are exactly that shape.
_JSON_SECRET_RE = re.compile(
    r'("[^"]*(?:password|passwd|passphrase|secret|token|api[_-]?key|authorization|auth|'
    r'cookie|session|jwt)[^"]*"\s*:\s*)("[^"]*"|\[?[^,}\]]+)'
)


def _is_secret_key(key: Any) -> bool:
    """Whether a dict/header key names secret material (header-name aware)."""
    normalized = str(key).lower().replace("-", "_").replace(" ", "_")
    if normalized.startswith("x_"):
        normalized = normalized[2:]
    return normalized in _SECRET_BROWSER_KEYS


def _mask_body(text: str) -> str:
    """Mask credential-shaped content in a body sample (kernel table + JSON)."""
    from tools.kernel.audit import _mask_secret_content

    return _mask_secret_content(_JSON_SECRET_RE.sub(rf'\1"{REDACTED}"', text))


def _redact_structure(value: Any) -> Any:
    """Recursively redact browser payloads: secret-named keys, lists, strings."""
    from tools.kernel.audit import _mask_secret_content

    if isinstance(value, dict):
        return {k: (REDACTED if _is_secret_key(k) else _redact_structure(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_structure(v) for v in value]
    if isinstance(value, str):
        return _mask_secret_content(value)
    return value


def redact_value(value: Any) -> Any:
    """Mask secret material via the shared audit redactors.

    Reuses ``tools.kernel.audit._mask_secret_content`` (URL creds, bearer
    headers, KEY=value lines, ...) as the single content-masking table, and
    adds a structural walk over browser payloads (nested lists + the browser
    header/cookie/storage key vocabulary above).
    """
    return _redact_structure(value)


# ---------------------------------------------------------------------------
# Identifiers / enums
# ---------------------------------------------------------------------------

BrowserSessionId = str  # opaque id, e.g. "bs-0001-3fa9c2d1e2f3" (see new_session_id)


def new_session_id(seq: int) -> BrowserSessionId:
    """Allocate a fresh, non-guessable session id (``bs-<seq>-<rand12>``)."""
    import uuid

    return f"bs-{max(0, int(seq)):04d}-{uuid.uuid4().hex[:12]}"


class BrowserSessionState(str, enum.Enum):
    """Lifecycle states of one browser session (see manager transition map)."""

    PENDING = "pending"  # requested, not yet started
    STARTING = "starting"  # backend is launching the worker/session
    READY = "ready"  # running, idle — safe to navigate
    ACTIVE = "active"  # executing an action / observation
    SUSPENDED = "suspended"  # parked (e.g. between planner steps)
    STOPPING = "stopping"  # graceful close in progress
    CLOSED = "closed"  # terminal: fully stopped, resources released
    FAILED = "failed"  # terminal: backend failed to start/died


class BrowserActionKind(str, enum.Enum):
    """What a future browser action does. Schema-only for now.

    No code in this change can execute any of these — they name the actions
    the future backend will implement so capability metadata, audit rows and
    planner records are stable from day one.
    """

    NAVIGATE = "navigate"
    OBSERVE = "observe"
    EXECUTE_JS = "execute_js"
    SCREENSHOT = "screenshot"
    GET_NETWORK_EVENTS = "get_network_events"
    GET_STORAGE = "get_storage"
    DISCOVER_FORMS = "discover_forms"
    DISCOVER_ENDPOINTS = "discover_endpoints"
    REPLAY_REQUEST = "replay_request"  # request replay/mutation — deferred
    SUBMIT_FORM = "submit_form"  # deferred: never executed by preparation work
    WAIT = "wait"
    CLOSE = "close"


class BrowserObservationKind(str, enum.Enum):
    """What an observation harvested from a page represents."""

    PAGE_STATE = "page_state"  # URL/title/DOM summary snapshot
    DOM = "dom"  # DOM indicator / selector discovery
    FORMS = "forms"  # discovered form metadata
    ENDPOINTS = "endpoints"  # REST/GraphQL endpoints discovered
    NETWORK = "network"  # captured network request/response events
    STORAGE = "storage"  # cookie / localStorage / sessionStorage
    CONSOLE = "console"  # console output (opt-in capture)
    SCREENSHOT = "screenshot"  # screenshot artifact metadata
    SCRIPTS = "scripts"  # JS bundle references


class BrowserEventDirection(str, enum.Enum):
    REQUEST = "request"
    RESPONSE = "response"


class BrowserStorageKind(str, enum.Enum):
    COOKIES = "cookies"
    LOCAL_STORAGE = "local_storage"
    SESSION_STORAGE = "session_storage"


class BrowserArtifactKind(str, enum.Enum):
    SCREENSHOT = "screenshot"
    PAGE_HTML = "page_html"
    HAR = "har"
    LOG = "log"
    DATA = "data"  # structured JSON (forms, endpoints, ...)


class BrowserFailureClass(str, enum.Enum):
    """Why a browser action failed (or could not run).

    Values that overlap the global taxonomy reuse its exact strings
    (``tools/failure_taxonomy.FailureClass``); browser-specific classes add
    the session/lifecycle concepts. ``failure_class()`` returns the global
    class for the planner/recovery loop when a mapping exists.
    """

    BACKEND_UNAVAILABLE = "tool_unavailable"  # global: no backend configured/installed
    SESSION_NOT_FOUND = "session_not_found"
    INVALID_TRANSITION = "invalid_transition"
    SCOPE_BLOCKED = "scope_blocked"  # global: scope_blocked
    AUTH_REQUIRED = "auth_failed"  # global: auth_failed
    NAVIGATION_FAILED = "navigation_failed"
    SCRIPT_ERROR = "script_error"
    NETWORK_ERROR = "transport_error"  # global: transport_error
    TIMEOUT = "timeout"  # global: timeout
    UNEXPECTED_OUTPUT = "unexpected_output"  # global: unexpected_output
    UNSUPPORTED_ACTION = "unsupported_target"  # global: unsupported_target
    UNKNOWN = "unknown"  # global: unknown

    def failure_class(self) -> GlobalFailureClass | None:
        """Map onto the global failure taxonomy (None = browser-only class)."""
        try:
            return GlobalFailureClass(self.value)
        except ValueError:
            return None


# Session lifecycle validation (single source used by tools/browser/manager.py).
_ALLOWED_SESSION_TRANSITIONS: dict[BrowserSessionState, frozenset[BrowserSessionState]] = {
    BrowserSessionState.PENDING: frozenset(
        {
            BrowserSessionState.STARTING,
            BrowserSessionState.STOPPING,
            BrowserSessionState.FAILED,
            BrowserSessionState.CLOSED,
        }
    ),
    BrowserSessionState.STARTING: frozenset(
        {
            BrowserSessionState.READY,
            BrowserSessionState.FAILED,
            BrowserSessionState.CLOSED,
            BrowserSessionState.STOPPING,
        }
    ),
    BrowserSessionState.READY: frozenset(
        {
            BrowserSessionState.ACTIVE,
            BrowserSessionState.SUSPENDED,
            BrowserSessionState.STOPPING,
            BrowserSessionState.FAILED,
            BrowserSessionState.CLOSED,
        }
    ),
    BrowserSessionState.ACTIVE: frozenset(
        {
            BrowserSessionState.READY,
            BrowserSessionState.SUSPENDED,
            BrowserSessionState.STOPPING,
            BrowserSessionState.FAILED,
            BrowserSessionState.CLOSED,
        }
    ),
    BrowserSessionState.SUSPENDED: frozenset(
        {
            BrowserSessionState.READY,
            BrowserSessionState.ACTIVE,
            BrowserSessionState.STOPPING,
            BrowserSessionState.CLOSED,
            BrowserSessionState.FAILED,
        }
    ),
    BrowserSessionState.STOPPING: frozenset({BrowserSessionState.CLOSED, BrowserSessionState.FAILED}),
    BrowserSessionState.CLOSED: frozenset(set()),
    BrowserSessionState.FAILED: frozenset(set()),
}


def validate_session_transition(current: BrowserSessionState, new: BrowserSessionState) -> None:
    """Raise ``BrowserTransitionError`` when ``current -> new`` is illegal."""
    from tools.browser.errors import BrowserTransitionError

    if new not in _ALLOWED_SESSION_TRANSITIONS[current]:
        raise BrowserTransitionError(f"invalid browser session transition {current.value!r} -> {new.value!r}")


# ---------------------------------------------------------------------------
# Action / result models
# ---------------------------------------------------------------------------


@dataclass
class BrowserAction:
    """One requested browser operation (schema only — nothing executes it).

    ``kind`` selects the operation; free-form operation inputs (URL, selector,
    JS expression, replay payload, ...) live in ``parameters`` until the
    backend layer types them. The action is the audit+evidence anchor: audit
    rows reference ``action_id`` and results carry it back.
    """

    action_id: str
    session_id: BrowserSessionId
    kind: BrowserActionKind = BrowserActionKind.NAVIGATE
    parameters: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: float | None = None
    run_id: str = ""  # owning run
    target_ip: str = ""  # locked target this action is scoped to
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "session_id": self.session_id,
            "kind": self.kind.value,
            "parameters": dict(self.parameters),
            "timeout_seconds": self.timeout_seconds,
            "run_id": self.run_id,
            "target_ip": self.target_ip,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "BrowserAction":
        data = data or {}
        return cls(
            action_id=str(data.get("action_id", "") or ""),
            session_id=str(data.get("session_id", "") or ""),
            kind=_enum(BrowserActionKind, data.get("kind"), BrowserActionKind.NAVIGATE),
            parameters=dict(data.get("parameters") or {}),
            timeout_seconds=data.get("timeout_seconds"),
            run_id=str(data.get("run_id", "") or ""),
            target_ip=str(data.get("target_ip", "") or ""),
            metadata=dict(data.get("metadata") or {}),
            created_at=str(data.get("created_at", "") or ""),
        )


@dataclass
class BrowserError:
    """Structured failure payload carried inside a :class:`BrowserResult`.

    NOT an exception — exceptions live in :mod:`tools.browser.errors`; this is
    the serializable error record embedded in results/audit payload.
    """

    failure_class: BrowserFailureClass = BrowserFailureClass.UNKNOWN
    message: str = ""
    source: str = ""  # "backend" | "manager" | "policy" | ""
    retryable: bool | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "failure_class": self.failure_class.value,
            "message": self.message,
            "source": self.source,
            "retryable": self.retryable,
            "detail": dict(self.detail),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "BrowserError":
        data = data or {}
        return cls(
            failure_class=_enum(BrowserFailureClass, data.get("failure_class"), BrowserFailureClass.UNKNOWN),
            message=str(data.get("message", "") or ""),
            source=str(data.get("source", "") or ""),
            retryable=data.get("retryable"),
            detail=dict(data.get("detail") or {}),
        )


@dataclass
class BrowserResult:
    """Structured result of one browser action (or manager operation).

    Compatible with BreachPilot's structured-result philosophy
    (``tools/attack_modules/base.py::ModuleResult``): ``failure_class`` uses
    the failure taxonomy vocabulary, ``retryable``/``confidence`` are
    planner hints, ``produced_artifacts`` carries artifact ids/paths,
    ``evidence_refs`` the stable evidence references
    (``exploit_audit:<target>:<attempt_id>`` / ``browser_artifact:<id>``
    conventions), and ``follow_ups`` suggested next actions.
    """

    success: bool = False
    failure_class: BrowserFailureClass = BrowserFailureClass.UNKNOWN
    retryable: bool | None = None
    confidence: float | None = None
    action_id: str = ""
    session_id: BrowserSessionId = ""
    produced_artifacts: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    follow_ups: list[str] = field(default_factory=list)
    error: BrowserError | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "failure_class": self.failure_class.value,
            "retryable": self.retryable,
            "confidence": self.confidence,
            "action_id": self.action_id,
            "session_id": self.session_id,
            "produced_artifacts": list(self.produced_artifacts),
            "evidence_refs": list(self.evidence_refs),
            "follow_ups": list(self.follow_ups),
            "error": self.error.to_dict() if self.error is not None else None,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "BrowserResult":
        data = data or {}
        error_raw = data.get("error")
        return cls(
            success=bool(data.get("success", False)),
            failure_class=_enum(BrowserFailureClass, data.get("failure_class"), BrowserFailureClass.UNKNOWN),
            retryable=data.get("retryable"),
            confidence=data.get("confidence"),
            action_id=str(data.get("action_id", "") or ""),
            session_id=str(data.get("session_id", "") or ""),
            produced_artifacts=[str(v) for v in (data.get("produced_artifacts") or [])],
            evidence_refs=[str(v) for v in (data.get("evidence_refs") or [])],
            follow_ups=[str(v) for v in (data.get("follow_ups") or [])],
            error=BrowserError.from_dict(error_raw) if isinstance(error_raw, dict) else None,
            metadata=dict(data.get("metadata") or {}),
        )


# ---------------------------------------------------------------------------
# Session model
# ---------------------------------------------------------------------------


@dataclass
class BrowserSession:
    """Metadata for one managed browser session (no live handle).

    The manager owns these records; a backend keeps any engine-specific
    connection object private and NEVER exposes it here. ``to_dict()`` is the
    serialized shape shared with the manager registry / (future) API.
    """

    session_id: BrowserSessionId
    state: BrowserSessionState = BrowserSessionState.PENDING
    run_id: str = ""  # owning run (session ownership by run)
    target_ip: str = ""  # locked target the session is scoped to
    original_target: str = ""  # domain/host form if the operator passed one
    backend_id: str = ""  # "none" until a backend is configured
    started_at: str = ""
    closed_at: str = ""
    last_url: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, *, redact: bool = True) -> dict[str, Any]:
        del redact  # session metadata is secret-free by design; flag kept for symmetry
        return {
            "session_id": self.session_id,
            "state": self.state.value,
            "run_id": self.run_id,
            "target_ip": self.target_ip,
            "original_target": self.original_target,
            "backend_id": self.backend_id,
            "started_at": self.started_at,
            "closed_at": self.closed_at,
            "last_url": self.last_url,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "BrowserSession":
        data = data or {}
        return cls(
            session_id=str(data.get("session_id", "") or ""),
            state=_enum(BrowserSessionState, data.get("state"), BrowserSessionState.PENDING),
            run_id=str(data.get("run_id", "") or ""),
            target_ip=str(data.get("target_ip", "") or ""),
            original_target=str(data.get("original_target", "") or ""),
            backend_id=str(data.get("backend_id", "") or ""),
            started_at=str(data.get("started_at", "") or ""),
            closed_at=str(data.get("closed_at", "") or ""),
            last_url=str(data.get("last_url", "") or ""),
            metadata=dict(data.get("metadata") or {}),
        )


# ---------------------------------------------------------------------------
# Observation models (compact evidence / planning inputs)
# ---------------------------------------------------------------------------


@dataclass
class BrowserPageState:
    """Compact snapshot of the page the session is on.

    This is the planning surface: discovered forms, discovered API/GraphQL
    endpoints, JS bundle refs, DOM indicators and (redacted) storage state
    become compact evidence — raw HTML never enters prompts or stores.
    """

    session_id: BrowserSessionId
    url: str = ""
    final_url: str = ""  # after redirects — what actually served
    status_code: int | None = None
    title: str = ""
    dom_summary: str = ""  # bounded text summary — never raw HTML
    forms: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)  # DOM indicators (framework/tech markers)
    authenticated: bool | None = None  # authenticated navigation state, when known
    graphql_endpoints: list[str] = field(default_factory=list)
    observed_at: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "title": self.title,
            "dom_summary": self.dom_summary,
            "forms": list(self.forms),
            "endpoints": list(self.endpoints),
            "scripts": list(self.scripts),
            "indicators": list(self.indicators),
            "authenticated": self.authenticated,
            "graphql_endpoints": list(self.graphql_endpoints),
            "observed_at": self.observed_at,
            "evidence_refs": list(self.evidence_refs),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "BrowserPageState":
        data = data or {}
        return cls(
            session_id=str(data.get("session_id", "") or ""),
            url=str(data.get("url", "") or ""),
            final_url=str(data.get("final_url", "") or ""),
            status_code=data.get("status_code"),
            title=str(data.get("title", "") or ""),
            dom_summary=str(data.get("dom_summary", "") or ""),
            forms=[f for f in (data.get("forms") or []) if isinstance(f, dict)],
            endpoints=[e for e in (data.get("endpoints") or []) if isinstance(e, dict)],
            scripts=[str(s) for s in (data.get("scripts") or [])],
            indicators=[str(i) for i in (data.get("indicators") or [])],
            authenticated=data.get("authenticated"),
            graphql_endpoints=[str(g) for g in (data.get("graphql_endpoints") or [])],
            observed_at=str(data.get("observed_at", "") or ""),
            evidence_refs=[str(v) for v in (data.get("evidence_refs") or [])],
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class BrowserNetworkEvent:
    """One captured request/response pair record.

    Header/bodies are payload material: headers MUST go through
    ``to_redacted_dict`` before they can land in logs/audit; large bodies are
    represented by digest + size, content optionally sampled and redacted.
    """

    event_id: str
    session_id: BrowserSessionId
    direction: BrowserEventDirection = BrowserEventDirection.REQUEST
    method: str = ""
    url: str = ""
    status_code: int | None = None
    content_type: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    body_size: int | None = None
    body_sha256: str = ""
    body_sample: str = ""  # optional truncated body — treat as sensitive
    replayable: bool = False  # future: whether the request can be replayed/mutated
    timing_ms: float | None = None
    observed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "session_id": self.session_id,
            "direction": self.direction.value,
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "request_headers": dict(self.request_headers),
            "response_headers": dict(self.response_headers),
            "body_size": self.body_size,
            "body_sha256": self.body_sha256,
            "body_sample": self.body_sample,
            "replayable": self.replayable,
            "timing_ms": self.timing_ms,
            "observed_at": self.observed_at,
        }

    def to_redacted_dict(self) -> dict[str, Any]:
        """Header values + body sample masked (Authorization/cookies/tokens).

        Secret-named headers (Cookie, Set-Cookie, Authorization, ...) are
        redacted WHOLESALE — cookie values in particular are not matched by
        the kernel content regexes, so key-aware structural masking is the
        only reliable guarantee here.
        """
        d = self.to_dict()
        d["request_headers"] = {
            k: (REDACTED if _is_secret_key(k) else _mask_body(str(v))) for k, v in d["request_headers"].items()
        }
        d["response_headers"] = {
            k: (REDACTED if _is_secret_key(k) else _mask_body(str(v))) for k, v in d["response_headers"].items()
        }
        d["body_sample"] = _mask_body(d["body_sample"]) if d["body_sample"] else ""
        # URL userinfo (https://user:pass@host) is credential material too.
        d["url"] = _mask_body(d["url"])
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "BrowserNetworkEvent":
        data = data or {}
        return cls(
            event_id=str(data.get("event_id", "") or ""),
            session_id=str(data.get("session_id", "") or ""),
            direction=_enum(BrowserEventDirection, data.get("direction"), BrowserEventDirection.REQUEST),
            method=str(data.get("method", "") or ""),
            url=str(data.get("url", "") or ""),
            status_code=data.get("status_code"),
            content_type=str(data.get("content_type", "") or ""),
            request_headers={str(k): str(v) for k, v in (data.get("request_headers") or {}).items()},
            response_headers={str(k): str(v) for k, v in (data.get("response_headers") or {}).items()},
            body_size=data.get("body_size"),
            body_sha256=str(data.get("body_sha256", "") or ""),
            body_sample=str(data.get("body_sample", "") or ""),
            replayable=bool(data.get("replayable", False)),
            timing_ms=data.get("timing_ms"),
            observed_at=str(data.get("observed_at", "") or ""),
        )


@dataclass
class BrowserCookie:
    """One browser cookie. ``value`` is SECRET material — redacted by default."""

    name: str
    domain: str = ""
    path: str = ""
    value: str = ""  # sensitive
    secure: bool = False
    http_only: bool = False
    same_site: str = ""
    expires_at: str = ""

    def to_dict(self, *, redact: bool = True) -> dict[str, Any]:
        d = {
            "name": self.name,
            "domain": self.domain,
            "path": self.path,
            "value": self.value,
            "secure": self.secure,
            "http_only": self.http_only,
            "same_site": self.same_site,
            "expires_at": self.expires_at,
        }
        if redact and self.value:
            d["value"] = REDACTED
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "BrowserCookie":
        data = data or {}
        return cls(
            name=str(data.get("name", "") or ""),
            domain=str(data.get("domain", "") or ""),
            path=str(data.get("path", "") or ""),
            value=str(data.get("value", "") or ""),
            secure=bool(data.get("secure", False)),
            http_only=bool(data.get("http_only", False)),
            same_site=str(data.get("same_site", "") or ""),
            expires_at=str(data.get("expires_at", "") or ""),
        )


@dataclass
class BrowserStorageSnapshot:
    """Cookies / localStorage / sessionStorage harvest for one origin.

    Values are treated as credential material: discovery flows MUST route
    recovered tokens through the credential store
    (``tools/credential_store.py``), never into logs or generic metadata.
    ``to_redacted_dict`` masks every value while keeping key structure.
    """

    origin: str = ""
    storage_kind: BrowserStorageKind = BrowserStorageKind.SESSION_STORAGE
    session_id: BrowserSessionId = ""
    entries: list[dict[str, str]] = field(default_factory=list)  # {"key", "value"}
    collected_at: str = ""

    def to_dict(self, *, redact: bool = True) -> dict[str, Any]:
        entries = list(self.entries)
        if redact:
            entries = [{k: (REDACTED if k == "value" and v else v) for k, v in e.items()} for e in entries]
        return {
            "origin": self.origin,
            "storage_kind": self.storage_kind.value,
            "session_id": self.session_id,
            "entries": entries,
            "collected_at": self.collected_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "BrowserStorageSnapshot":
        data = data or {}
        return cls(
            origin=str(data.get("origin", "") or ""),
            storage_kind=_enum(BrowserStorageKind, data.get("storage_kind"), BrowserStorageKind.SESSION_STORAGE),
            session_id=str(data.get("session_id", "") or ""),
            entries=[dict(e) for e in (data.get("entries") or []) if isinstance(e, dict)],
            collected_at=str(data.get("collected_at", "") or ""),
        )


@dataclass
class BrowserArtifact:
    """A persisted browser artifact (screenshot, HAR, page HTML, log).

    ``evidence_type`` names the legacy EvidenceStore bucket the artifact maps
    to (``legacy/evidence.py::_EVIDENCE_SUBDIRS`` — screenshot/file/...), so
    evidence promotion keeps a single stable convention.
    """

    artifact_id: str
    session_id: BrowserSessionId
    kind: BrowserArtifactKind = BrowserArtifactKind.LOG
    path: str = ""  # workspace-relative artifact path
    sha256: str = ""
    size_bytes: int | None = None
    content_type: str = ""
    action_id: str = ""
    evidence_type: str = "file"  # legacy EvidenceStore evidence_type key
    created_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "session_id": self.session_id,
            "kind": self.kind.value,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "content_type": self.content_type,
            "action_id": self.action_id,
            "evidence_type": self.evidence_type,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "BrowserArtifact":
        data = data or {}
        return cls(
            artifact_id=str(data.get("artifact_id", "") or ""),
            session_id=str(data.get("session_id", "") or ""),
            kind=_enum(BrowserArtifactKind, data.get("kind"), BrowserArtifactKind.LOG),
            path=str(data.get("path", "") or ""),
            sha256=str(data.get("sha256", "") or ""),
            size_bytes=data.get("size_bytes"),
            content_type=str(data.get("content_type", "") or ""),
            action_id=str(data.get("action_id", "") or ""),
            evidence_type=str(data.get("evidence_type", "file") or "file"),
            created_at=str(data.get("created_at", "") or ""),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class BrowserObservation:
    """One compact observation harvested by a browser action.

    ``payload`` holds the kind-specific compact payload (PAGE_STATE carries a
    ``BrowserPageState.to_dict()``, NETWORK a redacted events list, ...).
    ``sensitive=True`` observations serialize redacted via
    :func:`redact_value`; generic audit metadata only ever receives the
    compact/digest form (see ``to_audit_dict``).
    """

    observation_id: str
    session_id: BrowserSessionId
    kind: BrowserObservationKind = BrowserObservationKind.PAGE_STATE
    url: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    sensitive: bool = False
    action_id: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    observed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "session_id": self.session_id,
            "kind": self.kind.value,
            "url": self.url,
            "payload": dict(self.payload),
            "sensitive": self.sensitive,
            "action_id": self.action_id,
            "evidence_refs": list(self.evidence_refs),
            "metadata": dict(self.metadata),
            "observed_at": self.observed_at,
        }

    def to_redacted_dict(self) -> dict[str, Any]:
        d = self.to_dict()
        if self.sensitive:
            d["payload"] = redact_value(self.payload) if self.payload else {}
            # Structural masking for observation payloads that carry storage,
            # header or network material: secret-named keys (including inside
            # nested lists) + credential-shaped text, via the kernel table.
        d["url"] = redact_value(d["url"])
        d["metadata"] = dict(self.metadata)  # metadata is caller-owned, never auto-redacted
        return d

    def to_audit_dict(self) -> dict[str, Any]:
        """Compact digest safe for generic audit metadata (no secret flow).

        Drops the payload entirely, emitting only counts — the same contract
        as ``tools/mcp_tools/assessment_state.py::get_evidence``
        ("raw command/args are never emitted, they may contain secrets").
        """
        return {
            "observation_id": self.observation_id,
            "kind": self.kind.value,
            "sensitive": self.sensitive,
            "payload_digest": {
                "keys": sorted(self.payload) if isinstance(self.payload, dict) else [],
                "field_count": len(self.payload) if isinstance(self.payload, dict) else 0,
            },
            "evidence_refs": list(self.evidence_refs),
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "BrowserObservation":
        data = data or {}
        return cls(
            observation_id=str(data.get("observation_id", "") or ""),
            session_id=str(data.get("session_id", "") or ""),
            kind=_enum(BrowserObservationKind, data.get("kind"), BrowserObservationKind.PAGE_STATE),
            url=str(data.get("url", "") or ""),
            payload=dict(data.get("payload") or {}),
            sensitive=bool(data.get("sensitive", False)),
            action_id=str(data.get("action_id", "") or ""),
            evidence_refs=[str(v) for v in (data.get("evidence_refs") or [])],
            metadata=dict(data.get("metadata") or {}),
            observed_at=str(data.get("observed_at", "") or ""),
        )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _enum(enum_cls: type, value: Any, default: Any) -> Any:  # noqa: ANN401 — tolerant reader
    """Tolerant enum coercion: unknown strings fall back to ``default``.

    (``tools/campaign/state.py`` convention — a payload written by a
    newer/older version never breaks a reader.)
    """
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        try:
            return enum_cls(value)
        except ValueError:
            return default
    return default
