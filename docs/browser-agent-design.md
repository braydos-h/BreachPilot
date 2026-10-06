# Browser-Native Web Agent — Architecture & Integration Design

> **Status: implemented (Phase 1 read-only + Phase 2 mutating).** The Playwright backend behind the
> prepared interfaces is live: `tools/browser/playwright_backend.py` (Chromium via
> the sandbox browser worker image), `tools/browser/sandbox_launcher.py` (one Chromium
> op per docker exec inside the worker netns — no host fallback), the async
> `BrowserManager` funnel, conditional `tools/mcp_tools/browser.py` tools, gated
> planner briefings, and doctor/API/config plumbing. Request replay
> (`browser_replay`: captured `event_id` as base, explicit url/method/headers/body
> overrides, final URL host re-checked) and form submission (`browser_submit`:
> fill by field name + submit, form-action host re-checked) are live behind the
> explicit lab opt-in `browser.allow_mutating_actions` (default off — without it
> both return `BLOCKED`). Playwright and Chromium are required in the browser
> worker image; the host process does not launch Chromium.

This document is the contract the implementation followed (originally written
for the PR *"Implement Playwright BrowserBackend behind the prepared browser
interfaces"*): the engine landed without replacing the domain vocabulary, the
manager boundary, the capability names, or the audit shape. The backend lives
at `tools/browser/playwright_backend.py` (flat, per repo layout — not
`tools/browser/backends/`). Browser execution always uses the configured
sandbox worker; host Playwright and Chromium never enable host execution.

---

## 1. Why a browser seam at all

Modern web targets are JS-first: SPAs render after navigation, auth flows live
in cookies/`localStorage`/bearer headers, endpoints hide behind bundles. A
terminal-only agent cannot even *load* the app. The browser agent extends
BreachPilot with an authenticated, observed, evidence-producing browser view of
the locked target — under the same policy regime as every other tool:

- target-IP allowlist lock (`@require_allowlist` / `_target_lock_block`),
- mission ScopeGate consult,
- required sandbox containment in the browser worker,
- full JSONL audit + evidence traceability,
- secrets never in plaintext logs.

The non-goals of the seam are as important as the goals. It is NOT shell
escape, NOT a path around the sandbox, and NOT a replacement for
`run_web_scan`: the browser adds *session-aware* interaction (navigate →
observe → optionally act) on top of structured scanning.

## 2. Implemented browser surfaces

| Concern | State in this change | Where it lives |
|---|---|---|
| Domain models (session/action/observation/artifact/network/storage/result) | **Added** — pure data, deterministic serialization | `tools/browser/models.py` |
| `BrowserBackend` ABC (the one seam) | **Added** — abstract, 10 operations, no executable defaults | `tools/browser/interfaces.py` |
| `BrowserManager` (registry + lifecycle + fail-closed) | **Added** — owns sessions and delegates operations to the configured backend | `tools/browser/manager.py` |
| Failure taxonomy mapping to global `FailureClass` | **Added** | `tools/browser/models.py` |
| `browser.*` capability vocabulary + availability rule | **Added** — available only for a registered backend with the required browser worker configured | `tools/browser/capabilities.py` |
| Config block `browser:` | **Added** — `enabled: false`, `backend: none` | `tools/config/schema.py`, `config.yaml` |
| `/api/v1/capabilities` browser status block | **Added** — reports current availability; `/system/browser` reports read-only health | `tools/api/routes/system/diagnostics.py` |
| Benchmark `requires_capabilities` scenario metadata | **Added** — unavailable requirements skip trials as `CAPABILITY_UNAVAILABLE` before target provisioning | `tools/benchmark/models.py`, `tools/benchmark/runner.py` |
| Sandbox family audit — browser registered as **sandboxed** | **Added** | `tools/sandbox/family_audit.py` (`SANDBOXED_FAMILIES`) |
| Secret-redaction rules for browser material | **Added** — redacted-by-default serialization | `tools/browser/models.py` |
| Any browser subprocess / launch / navigation / JS execution | **Added** — Playwright backend, fail-closed when unconfigured | `tools/browser/playwright_backend.py`, `tools/browser/manager.py` |
| Backend registry entry | **Added** — `BACKEND_REGISTRY` + `register_playwright_backend` (call-time, never import-time) | `tools/browser/capabilities.py` |
| Playwright dependency, browser worker sandboxing, WebSocket/CDP transport | **Added** — browser worker image includes Playwright/Chromium; sandboxed launcher performs one Chromium op per docker exec, with no host fallback | `tools/browser/sandbox_launcher.py`, `docker/sandbox/Dockerfile.browser` |
| Async session-start funnel, planner briefing, WebUI status, benchmark skip-path classification | **Added** — contained funnel, availability-gated prompt, read-only health views, and capability shortfall classification | `tools/browser/manager.py`, `tools/mcp_tools/browser.py`, `tools/exploit_agent/prompt.py`, `tools/benchmark/runner.py` |

> Note: the table above is current — the backend, execution funnel, MCP tools
> (`tools/mcp_tools/browser.py`), sandbox registration, and mutating ops
> (`browser_submit` / `browser_replay` / `browser_execute_js` behind
> `browser.allow_mutating_actions`) have landed; see the Status header and
> `docs/mcp-tools.md` §Browser.

## 3. Domain models (`tools/browser/models.py`)

One shared vocabulary for the whole feature, engine-neutral by construction.
House style: pure data + enums + JSON, deterministic hand-rolled `to_dict`
(field order, `.value` for enums), tolerant `from_dict` that falls back to
safe defaults on unknown enum strings or missing keys (a payload written by a
newer/older never breaks a reader).

- **`BrowserSession`** — metadata only; never a live handle. `session_id`
  (`bs-<seq>-<rand12>`), lifecycle `state`, `run_id` (ownership), `target_ip`
  (the locked target), `backend_id`, timestamps, metadata.
- **`BrowserAction`** — one requested operation: `kind`
  (`BrowserActionKind`: navigate / observe / execute_js / screenshot /
  get_network_events / get_storage / discover_forms / discover_endpoints /
  replay_request / submit_form / wait / close) + free-form `parameters` +
  `run_id` + `target_ip`. `replay_request` and `submit_form` execute behind
  the explicit lab opt-in `browser.allow_mutating_actions` (Phase 2, landed;
  without it both return `BLOCKED`). `browser_replay` additionally refuses
  captured events whose `replayable` flag is False.
- **`BrowserObservation`** — compact harvest of one kind
  (`BrowserObservationKind`: page_state / dom / forms / endpoints / network /
  storage / console / screenshot / scripts). Carries `payload`, `sensitive`
  flag, `evidence_refs`. Serialization surfaces:
  - `to_dict()` — in-memory full shape,
  - `to_redacted_dict()` — payload redacted when `sensitive`,
  - `to_audit_dict()` — the ONLY form allowed into generic audit metadata:
    payload dropped entirely, digest of keys + counts only.
- **`BrowserPageState`** — planning surface: url/final_url (redirect-aware),
  status, title, bounded `dom_summary` (never raw HTML), forms, endpoints,
  scripts, framework indicators, `graphql_endpoints`.
- **`BrowserNetworkEvent`** — request/response record with headers, sizes +
  sha256 digests, optional truncated `body_sample` (treated as sensitive),
  `replayable` flag (True for http/https captures; `browser_replay` refuses
  non-replayable events).
- **`BrowserCookie` / `BrowserStorageSnapshot`** — credential material.
  `to_dict()` redacts values by DEFAULT; `to_dict(redact=False)` is the
  explicit opt-in for the credential-store path only (§6).
- **`BrowserArtifact`** — persisted artifact (screenshot/HAR/page_html/log/
  data) with sha256 and `evidence_type` mapping to the legacy EvidenceStore
  subdirectory keys (`legacy/evidence.py::_EVIDENCE_SUBDIRS`).
- **`BrowserResult`** — structured result at the same level as attack-module
  `ModuleResult`: `success`, `failure_class`, `retryable`, `confidence`,
  `action_id` / `session_id` anchors, `produced_artifacts`, `evidence_refs`
  (`exploit_audit:<target>:<attempt_id>` / `browser_artifact:<id>`
  conventions), `follow_ups` planner hints, typed `error`, metadata.
- **`BrowserError`** — serializable failure payload (a dataclass, NOT the
  exception; exceptions live in `errors.py`).
- **`BrowserFailureClass`** — failure vocabulary. Overlapping concepts reuse
  the exact global `tools/failure_taxonomy.FailureClass` strings
  (`tool_unavailable`, `scope_blocked`, `auth_failed`, `transport_error`,
  `timeout`, `unexpected_output`, `unsupported_target`, `unknown`);
  browser-specific classes (`session_not_found`, `invalid_transition`,
  `navigation_failed`, `script_error`) have no global mapping.
  `BrowserFailureClass.failure_class()` converts for the recovery loop.
- **Lifecycle** — `BrowserSessionState` (pending → starting → ready ↔ active,
  suspended; stopping → closed/failed terminal) validated by
  `validate_session_transition()` against an explicit transition map.

## 4. Backend seam (`tools/browser/interfaces.py`)

```python
class BrowserBackend(ABC):
    backend_id: str          # matches browser.backend config
    display_name: str
    capabilities: tuple[str, ...]   # browser.* names this backend provides

    def is_configured(self, config) -> bool: ...   # metadata only, default False
    def health(self, config) -> dict[str, Any]: ... # doctor-shaped, no side effects

    @abstractmethod
    async def start_session(*, target, run_id, session_id, headless, metadata) -> BrowserSession: ...
    @abstractmethod
    async def stop_session(session_id) -> BrowserResult: ...
    @abstractmethod
    async def navigate(session_id, url, *, timeout_seconds) -> BrowserResult: ...
    @abstractmethod
    async def observe(session_id, *, include_forms, include_endpoints) -> BrowserObservation: ...
    @abstractmethod
    async def execute_action(session_id, action) -> BrowserResult: ...
    @abstractmethod
    async def capture_screenshot(session_id, *, artifact_path) -> BrowserArtifact: ...
    @abstractmethod
    async def get_network_events(session_id, *, limit, after_id) -> list[BrowserNetworkEvent]: ...
    @abstractmethod
    async def get_storage(session_id, *, origin) -> BrowserStorageSnapshot: ...
    @abstractmethod
    async def get_page_state(session_id) -> BrowserPageState: ...
    @abstractmethod
    async def close(session_id) -> BrowserResult: ...
```

Rules (mirrors the provider seam, `tools/providers/base.py`):

1. **The ABC is the ONLY seam** the rest of BreachPilot may cross for browser
   control. "API-specific translation lives ENTIRELY inside the adapter" — no
   Playwright/Selenium/CDP object may leak across; backends translate at the
   boundary into the models above.
2. **No policy in the backend.** A backend never consults the allowlist
   itself; the live execution funnel is target-locked at the MCP layer and
   sandboxed. The backend is the engine adapter, not the policy.
3. **No executable defaults below `is_configured`/`health`.** Every operation
   is `@abstractmethod`, so a backend must consciously implement or reject
   each — a partially implemented backend cannot be instantiated (asserted by
   test), and there is no inherited behavior that could drive a browser.
4. Failures surface as `BrowserBackendError` subclasses
   (`tools/browser/errors.py`), typed and classifiable via
   `browser_error_from_exception()`; there is no fallback that silently
   pretends a browser exists.

## 5. Manager boundary (`tools/browser/manager.py`)

`BrowserManager(config, *, backend: BrowserBackend | None = None)` owns the
browser session lifecycle. It validates transitions, allocates session ids
(`new_session_id`), records metadata and run ownership, enforces session
limits, and delegates operations to its backend. The backend controls the
engine; the manager does not bypass the MCP allowlist or sandbox launcher.
Starting a session or delegating without an enabled backend or locked target
fails closed. The production MCP stack attaches a backend only after the
browser worker configuration passes the availability gate.

## 6. Capability metadata & availability (`tools/browser/capabilities.py`)

Stable `browser.*` names (contracts: scenario manifests, planner records, and
audit rows may reference them verbatim from day one):

```
browser.navigate          browser.form.inspect
browser.dom.inspect       browser.form.submit        (mutating: allow_mutating_actions)
browser.javascript.execute
browser.network.observe   browser.screenshot
browser.network.replay    (mutating: allow_mutating_actions) browser.endpoint.discover
browser.storage.read
```

Each record carries `name`, `description`, `read_only` (planner-cost hint),
and `available`. Availability rule — **declared is NOT available**:

```
available = browser.enabled AND backend == "playwright"
            AND backend in BACKEND_REGISTRY
            AND sandbox.enabled AND sandbox.image == browser.worker_image
```

The registry is populated at tool-registration time, never on import. Host
Playwright/Chromium presence does not grant execution. The matching worker
image is checked by the availability gate, then the launcher probes the
Playwright runtime inside that worker before creating a session. No prompt
section references these capabilities while they are unavailable; prompts
must never instruct the model to use tooling that cannot run.

`unmet_requirements(required, config)` returns which required names are
unavailable (all of them on a stock build, plus any unknown name — nothing
provides unknown names). `browser_available(config)` answers "can ANY
browser operation run" for the required worker configuration.

**Secrets rule (audit/evidence):** browser material is full of credential
material — cookie values, bearer tokens, `Authorization` headers, URL
credentials, localStorage/`sessionStorage` entries, request bodies. The
redaction single source stays `tools/kernel/audit.py`; `models.py` layers a
browser-specific structural pass on top:

- storage/cookie serialization redacts values by DEFAULT (opt-in raw only for
  `to_dict(redact=False)` credential-store paths),
- `BrowserNetworkEvent.to_redacted_dict()` redacts secret-named headers
  wholesale (Cookie/Set-Cookie/Authorization/…), masks `Authorization:
  Bearer …` / URL credentials / KEY=value lines via the kernel table, and
  masks JSON `"password": "…"`, `"token": "…"`-shaped content in body samples,
- `BrowserObservation.to_audit_dict()` (the only form allowed into generic
  audit metadata) **drops payloads entirely** — keys digest + counts only,
- recovered tokens/cookies must flow through the credential store
  (`tools/credential_store.py`), never into logs, config, or generic metadata.

Tests assert (with canary secrets) that no serialization surface leaks token
material into JSON-serializable output: `tests/test_browser_audit_redaction.py`.

Browser tools use `@require_allowlist("target")`, which enforces the target
lock and writes audit records by default (`audit=True`). The rows include the
tool, target, arguments, attempt id, and terminal result. Evidence and artifacts
retain their references; sensitive browser values remain redacted or omitted
from generic audit metadata.

## 7. Config (`browser:` block)

Defaults (schema + `config.yaml`; browser tools are OFF unless the operator
enables them and configures the required browser worker):

```yaml
browser:
  enabled: false            # master switch — stock installs never enable
  backend: none             # none | playwright (requires the browser worker)
  headless: true
  max_sessions: 2
  session_timeout_seconds: 300
  navigation_timeout_seconds: 30
  capture_screenshots: true
  capture_network: true
  capture_console: false
  persist_storage: false    # storage harvest goes to the credential store, never plaintext logs
```

The config validator checks this block's shape and values. A config file with
no `browser:` key loads the defaults above; capability registration and
execution stay disabled until the operator enables the browser and points
`sandbox.image` at the matching browser worker image.

### Enablement (operator)

```yaml
browser:
  enabled: true
  backend: playwright

sandbox:
  enabled: true
  image: breachpilot-sandbox:browser
```

Build the browser worker image and verify it with `python main.py --doctor`:

```bash
docker build -t breachpilot-sandbox:browser -f docker/sandbox/Dockerfile.browser docker/sandbox
```

Browser availability requires the feature to be enabled, the Playwright
backend to be registered, and the configured sandbox worker to be usable with
Playwright/Chromium installed. A host SDK or host Chromium installation does
not make browser execution available. `backend: playwright` alone never flips
the availability gate (fail closed).

Execution model:

All Chromium operations run one at a time through `docker exec` inside the
browser worker's network namespace. Missing or unusable containment returns a
structured `SANDBOX_*` block. There is no host execution mode or opt-out;
`sandbox.enabled: false` is rejected.

`browser.allow_mutating_actions: false` (default) keeps `browser_execute_js`,
`browser_submit`, and `browser_replay` returning `BLOCKED`; set it `true` only
as an explicit lab opt-in.

## 8. MCP / sandbox / policy integration

The package deliberately sits at `tools/browser/`, NOT under
`tools/mcp_tools/` — MCP tool discovery (`collect_tools()`) walks only
`tools/mcp_tools/` (`modules/`, `terminal/`, top-level files), so the
preparation package is invisible to tool discovery and can neither
auto-register tools nor trip the AST decorator gate.

`tools/sandbox/family_audit.py` registers the browser family in
`SANDBOXED_FAMILIES` (`target_touching: true`). Each Chromium operation runs
inside the browser worker netns, with the effective allowlist enforced by the
sandbox and URL-host checks at the MCP layer. The backend never applies or
bypasses the allowlist itself.

## 9. API + WebUI

`/api/v1/capabilities` returns a `browser` block with current availability:

```json
{"browser": {"enabled": false, "backend": "none", "available": false,
             "capabilities": [{"name": "...", "description": "...",
                               "read_only": true, "available": false}, ...]}}
```

Status remains read-only: `/system/browser` reports feature state, required
worker health and capabilities but never launches a browser. The WebUI shows
the contained-worker readiness, a build hint when unavailable, and the
capability list. Sessions are driven by the agent through MCP tools and live
in the MCP server process; the API does not expose browser-control endpoints
or list live sessions. The `browser` field is additive so older clients can
ignore it.

## 10. Benchmarks

`BenchmarkScenario` gains `requires_capabilities: list[str]` (default `[]` —
byte-identical behavior for existing manifests). XBEN manifests may declare:

```json
{"benchmark_id": "xben-9001", "oracle": {"flags": [...]},
 "requires_capabilities": ["browser.navigate", "browser.dom.inspect"]}
```

Before target provisioning, the benchmark runner uses
`tools.browser.capabilities.unmet_requirements` to classify scenarios with
unavailable requirements as `SKIPPED` / `CAPABILITY_UNAVAILABLE`. This avoids
starting a trial whose declared capabilities cannot run; existing scenarios
with the default empty requirement list are unaffected.

## 11. Implemented execution contract

The browser family is implemented and registered as sandboxed. The browser
worker image provides Playwright and Chromium; the MCP process does not run
Chromium on the operator host. Capability and doctor readiness must reflect
the contained worker, while session startup and each operation still handle
worker loss with a structured `SANDBOX_*` failure. Tests that pin this
contract include `tests/test_browser_sandbox_family.py`,
`tests/test_browser_capabilities.py`, `tests/test_browser_mcp_tools.py`, and
`tests/test_doctor_browser.py`.

## 12. Risks & mitigations

| Risk | Mitigation in this build |
|---|---|
| Someone wires a browser without containment | Capability and doctor readiness require the configured browser worker; launcher blocks worker/session failures with `SANDBOX_*`; sandbox family audit pins browser as contained |
| Secrets leak via logs/audit | redacted-by-default serialization, `to_audit_dict` drops payloads, canary-secret tests, credential-store rule |
| Capability becomes accidentally "available" | availability requires the registered backend and usable sandbox worker; host Playwright installation alone never enables execution |
| Prompt tells the model to use impossible tooling | Browser briefing is empty unless the configured sandbox worker passes the availability gate |
| Benchmark metrics drift from reality | capability shortfalls skip trials before target provisioning and are recorded as `CAPABILITY_UNAVAILABLE` |
| Backwards compatibility | Browser remains off in stock config; capability and API fields are additive, and the host process does not need to import Playwright to run non-browser features |
