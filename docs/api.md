# NetAttackAI WebUI API — v1 Reference

The local WebUI API daemon (`--demon` / `--daemon` / `--web`) exposes a versioned,
loopback-only REST + WebSocket API so the bundled WebUI (or third-party clients)
can drive assessments, answer decisions, stream live events, and invoke MCP tools
through a policy-gated gateway — all through the same `AssessmentService`
the CLI uses.

- **Base URL:** `http://127.0.0.1:8765` (default; `--api-port` to change)
- **API version:** `v1` (all routes under `/api/v1`)
- **Spec endpoints:** `GET /docs` (Swagger UI), `GET /openapi.json`
- **Auth:** Bearer token on every route except `GET /health`
- **Transport:** HTTP/1.1 + WebSocket; loopback-only bind (no public override in v1)
- **Concurrency:** one active run at a time (HTTP 409 on a second)
- **Persistence:** `reports/api_runtime.db` (SQLite; Flow B's `research.db` untouched)
- **Bundled WebUI:** `python main.py --web` builds `webui/dist/` (if needed), sets
  `api.serve_webui: true` in memory, and serves the SPA at `/` with a deep-link
  fallback. The SPA is a Vite + React + TypeScript app under `webui/`.

> Source: `app.py` (ASGI factory), `tools/api/` (services + routes), `tools/run_service/` (transport-neutral contracts).

---

## Table of Contents

1. [Security Model](#security-model)
2. [Error Shape](#error-shape)
3. [Run Lifecycle](#run-lifecycle)
4. [Auth](#auth)
   - [Bearer Token Auth](#bearer-token-auth)
   - [WebSocket Auth](#websocket-auth)
5. [System Routes](#system-routes)
   - [Health](#get-health)
   - [Capabilities](#get-capabilities)
   - [Config](#get-config)
   - [Patch Config](#patch-config)
   - [Secrets](#get-secrets)
   - [Put Secrets](#put-secrets)
   - [Models](#get-models)
   - [Plugins](#get-plugins)
   - [Skills](#get-skills)
   - [Search Skills](#get-skillssearch)
   - [Run Doctor](#post-diagnosticsdoctor)
   - [Run Self-Test](#post-diagnosticsself-test)
6. [Graph Explorer Routes](#graph-explorer-routes)
   - [Graph](#get-graph-runsrun_id)
   - [Summary](#get-graph-runsrun_idsummary)
   - [Conflicts](#get-graph-runsrun_idconflicts)
   - [Node](#get-graph-runsrun_idnodesnode_id)
   - [Neighbors](#get-graph-runsrun_idnodesnode_idneighbors)
   - [Paths](#get-graph-runsrun_idpaths)
7. [Run Routes](#run-routes)
   - [Create Run](#post-runs)
   - [List Runs](#get-runs)
   - [Get Run](#get-runsrun_id)
   - [Cancel Run](#post-runsrun_idcancel)
   - [Resume Run](#post-runsrun_idresume)
   - [List Tools](#get-runsrun_idtools)
   - [Call Tool](#post-runsrun_idtoolstool_namecalls)
7. [Decision Routes](#decision-routes)
   - [List Decisions](#get-runsrun_iddecisions)
   - [Answer Decision](#post-runsrun_iddecisionsdecision_id)
9. [Event Routes](#event-routes)
   - [Replay Events](#get-runsrun_idevents)
   - [WebSocket Stream](#ws-ws-v1runsrun_id)
10. [Data Models](#data-models)
11. [Event Types](#event-types)
12. [Config Reference](#config-reference)
13. [Persistence Schema](#persistence-schema)
14. [End-to-End Flow](#end-to-end-flow)

---

## Security Model

v1 is locked down by design. There is no public-bind path.

| Layer | Enforcement |
|-------|-------------|
| Bind | `assert_api_loopback` refuses any host not in `{127.0.0.1, localhost, ::1}`. `--api-host` is validated in `main._run_daemon` and re-validated in `create_app`. |
| HTTP auth | `BearerAuth` (FastAPI dependency) on every route except `GET /health`. Constant-time `hmac.compare_digest` comparison. Missing/invalid/malformed → `401`. |
| Token | 256-bit URL-safe, generated into `api.token_file` (default `.webui_secret_key`, gitignored) on first boot, or overridden via `NETATTACKAI_API_TOKEN` env. File perms `0o600` where supported. Never logged, never returned by any endpoint. |
| CORS | `CORSMiddleware` allows only loopback + `api.allowed_origins`. Credentials enabled. `allowed_origins` entries must be loopback HTTP(S) or the factory raises. |
| WebSocket origin | `is_loopback_origin` rejects `null`, non-loopback, schemes other than `http`/`https`, userinfo, query, fragment, non-root paths, out-of-range ports. Close `4403` on failure. |
| WebSocket auth | First message after accept must be `{"auth": "<token>"}`. Close `4401` on missing/invalid auth (5s timeout). |
| Config patch | `PATCH /config` re-validates `api.allowed_origins` is loopback-only before writing. |
| Secrets | `GET /secrets` returns only `configured`/`missing` status per provider key — values are write-only. |
| Redaction | `sanitize()` recursively redacts any dict value whose key matches `password|passwd|secret|token|api[_-]?key|auth|bearer|credential|private[_-]?key` (case-insensitive). Applied to config responses, event payloads, and any error details. |

**WebSocket close codes**

| Code | Meaning |
|------|---------|
| `1011` | Server not configured / event stream failed |
| `4400` | Invalid event cursor (`after` not a non-negative int) |
| `4401` | Missing/invalid auth message |
| `4403` | Origin not allowed |
| `4404` | Run not found |

---

## Error Shape

Every error response uses the same envelope. A `request_id` (UUID) is injected per request by middleware and echoed in the `X-Request-ID` response header so logs and client-side debugging share a correlation key.

```json
{
  "error": {
    "code": "conflict",
    "message": "A run is already active. Cancel it first.",
    "details": {},
    "request_id": "9b3f1c2a-..."
  }
}
```

| Handler | Code | HTTP | When |
|---------|------|------|------|
| `HTTPException` | `http_error` | (from exc) | FastAPI HTTP errors |
| `RequestValidationError` | `validation_error` | 422 | Pydantic body validation |
| `APIError` | (from exc) | (from exc) | Explicit `APIError` raises in services |
| `ValueError` | `value_error` | 400 | `ValueError` bubbled to route |
| `Exception` | `internal_error` | 500 | Unhandled (message is generic) |

Common `APIError` codes used by the run manager:

| Code | HTTP | Meaning |
|------|------|---------|
| `conflict` | 409 | A run is already active / execution already started |
| `not_found` | 404 | Run or decision not found |
| `invalid_confirmation` | 400 | Confirmation text did not match `required_confirmation_text` |
| `decision_not_found` | 404 | Decision not found or already answered |
| `no_decisions` | 400 | No decision broker for this run |
| `no_session` | 409 | MCP session is not open |
| `no_policy` | 409 | Exploit policy not available |
| `tool_not_found` | 404 | Unknown MCP tool name |
| `tool_denied` | 403 | Exploit policy denied the tool call |
| `tool_error` | 500 | MCP `call_tool` raised |
| `cancel_timeout` | 504 | Run cancellation timed out |
| `invalid_body` | 400 | Request body shape wrong |
| `invalid_secrets` | 400 | Secret names not configured / values empty |
| `config_invalid` | 400 | Config validation failed |

---

## Run Lifecycle

A run moves through these states (`tools/run_service/models.py:RunState`):

```
draft ──POST /runs──▶ awaiting_confirmation ──answer start_confirm──▶ queued ──▶ running
                                       │                                  │
                                       │                                  ├─▶ awaiting_input ──answer decision──▶ running
                                       │                                  │
                                       └─▶ (yes=true) ──▶ queued ──────────┤
                                                                          │
                          cancelled ◀──cancel── running/cancelling         │
                            │                                              │
                            ├──▶ completed                                 │
                            ├──▶ failed                                    │
                            └──▶ interrupted (daemon restarted mid-run)──┘
```

| State | Meaning |
|-------|---------|
| `draft` | Row created, not yet confirmed |
| `awaiting_confirmation` | Preview ready, waiting on `start_confirm` decision |
| `queued` | Confirmed, waiting for execution slot |
| `running` | Execution in progress |
| `awaiting_input` | Blocked on a `tool_approval` / `goal_select` decision |
| `cancelling` | Cancel requested, tearing down |
| `completed` | Finished successfully |
| `failed` | Finished with error |
| `cancelled` | Cancelled by operator |
| `interrupted` | Daemon restarted while run was live |

On daemon startup, `persistence.recover_interrupted()` marks any run in a live state (`draft`/`awaiting_confirmation`/`running`/`awaiting_input`/`queued`/`cancelling`) as `interrupted` and expires its pending decisions.

The **single-active-run** invariant is enforced by `RunManager`: a second `POST /runs` while one is live returns `409 conflict`. Cancel the active run first.

---

## Auth

### Bearer Token Auth

Every protected route uses `Authorization: Bearer <token>`. The token is loaded by `load_or_create_token`:

1. `NETATTACKAI_API_TOKEN` env var (if set, non-empty) — takes precedence.
2. `api.token_file` (default `.webui_secret_key`) — read if it exists.
3. Otherwise generate `secrets.token_urlsafe(32)` (256-bit), write to `token_file` with `0o600` perms (best-effort on Windows).

Invalid/missing bearer → `401`:

```json
{"detail": "Missing or invalid Authorization header. Expected: Bearer <token>"}
{"detail": "Invalid bearer token."}
```

### WebSocket Auth

WebSocket auth is a two-step handshake (`authenticate_websocket`):

1. **Origin check** (before accept): origin must pass `is_loopback_origin`. Fail → close `4403`.
2. **Auth message** (after accept, 5s timeout): first JSON message must be `{"auth": "<token>", "after": <int>}`.
   - `auth` compared with `hmac.compare_digest`. Fail → close `4401`.
   - `after` is the replay cursor (events with `sequence > after`). Must be a non-negative int (not bool). Fail → close `4400`.

A browser disconnect does **not** cancel the run — the in-memory ring buffer holds recent events for reconnect.

---

## System Routes

Source: `tools/api/routes/system.py`. Prefix `/api/v1`, tag `system`.

### `GET /health`

**Auth:** none.

Liveness probe.

**Response:** `200`
```json
{"version": "v1", "ready": true}
```

---

### `GET /capabilities`

**Auth:** bearer.

API features, supported run options, constraints, and tool groups.

**Response:** `200`
```json
{
  "api_version": "v1",
  "features": ["runs", "decisions", "events", "websocket", "tool_gateway", "config", "secrets"],
  "constraints": {
    "max_concurrent_runs": 1,
    "loopback_only": true,
    "manual_tool_calls": true
  },
  "run_options": {
    "modes": ["recon", "attack"],
    "kinds": ["agent", "manual"],
    "flags": ["swarm", "parallel_swarm", "critic", "reflection", "adaptive_exploits",
              "long_session", "multi_model_consult", "ultrathink", "recon_first"]
  }
}
```

---

### `GET /config`

**Auth:** bearer.

Return the current configuration, redacted by `sanitize()` (any key matching the secret pattern is replaced with `"[REDACTED]"`).

**Response:** `200` — the redacted config dict.

---

### `PATCH /config`

**Auth:** bearer.

Apply config changes atomically. Body is a partial config merged recursively into the current config (`_merge_config`), then validated.

**Validation:**
- `api.allowed_origins` (if present) must be a list of loopback HTTP(S) origins. Non-loopback → `400 config_invalid`.
- The merged config is run through `ConfigValidator`. Invalid → `400 config_invalid` with `details.errors`.

**Write:** atomic via temp file + `os.replace`.

**Response:** `200`
```json
{"status": "ok", "config": { /* redacted merged config */ }}
```

**Errors:** `400 invalid_body` (not a JSON object), `400 config_invalid`.

---

### `GET /secrets`

**Auth:** bearer.

Expose only configured/missing provider-key status. Secret values are write-only — this endpoint never returns them.

**Response:** `200`
```json
{
  "keys": {
    "OPENAI_API_KEY": "configured",
    "SERPAPI_API_KEY": "missing"
  }
}
```

Status is `"configured"` if the key is in the loaded key file or in the process env, else `"missing"`. Provider key env names come from `configured_api_key_env_names(config)`.

---

### `PUT /secrets`

**Auth:** bearer.

Write-only secret storage. Values are never returned by any endpoint.

**Request body:**
```json
{"secrets": {"OPENAI_API_KEY": "sk-..."}}
```

**Validation:**
- Body must be `{"secrets": {name: value}}`.
- Each `name` must be in `configured_api_key_env_names(config)`.
- Each `value` must be a non-empty string.

Invalid → `400 invalid_secrets`.

**Side effect:** written keys are also loaded into `os.environ` for the running daemon.

**Response:** `200`
```json
{"status": "ok", "written": ["OPENAI_API_KEY"]}
```

---

### `GET /models`

**Auth:** bearer.

List configured model aliases + metadata (provider-aware). The `provider`
field is the active chat/generate provider (`ollama` default or `chatgpt`);
when `chatgpt`, a `chatgpt` block with `default_model` / `context_window` /
`configured_models` is included.

**Response:** `200`
```json
{
  "provider": "ollama",
  "default_alias": "glm",
  "registry": { /* models.registry from config */ },
  "info": { /* models.info from config */ },
  "chatgpt": { "default_model": "gpt-5.2", "context_window": 128000, "configured_models": [] }
}
```

---

### `GET /models/live`

**Auth:** bearer.

Probe live, reachable models. Branches on `models.provider`:
- `ollama` — queries the Ollama daemon `/api/tags`; on failure (503) returns
  the configured `registry` models with `source: "registry"` and an `error`.
- `chatgpt` — **auto-starts** the local openai-oauth proxy via
  `ChatGptProxyManager.ensure_running` (only when signed in + `auto_start`;
  idempotent — a pre-existing proxy is reused and never stopped), then queries
  its `/v1/models`. On failure (not signed in, proxy wouldn't start, or
  `/v1/models` unreachable) returns a 503 with `source: "registry"` falling back
  to `chatgpt.models` / `chatgpt.default_model` and a human `error` (e.g.
  "Not signed in to ChatGPT — sign in via System → Models"). The WebUI model
  picker + System → Models use this list as the available models for both
  providers; switching provider invalidates the cache so it refetches
  immediately.

**Response:** `200` / `503` (fallback body still returned)
```json
{ "models": ["glm-5.2:cloud"], "source": "ollama", "error": null }
```

---

### `GET /providers`

**Auth:** bearer.

Return the active provider plus ChatGPT auth/proxy status. **Never includes
secrets** — `authenticated` is derived from the existence of
`~/.codex/auth.json` (file existence only, never read).

**Response:** `200`
```json
{
  "provider": "chatgpt",
  "chatgpt": {
    "enabled": true,
    "authenticated": true,
    "proxy_running": true,
    "host": "127.0.0.1",
    "port": 10531,
    "default_model": "gpt-5.2",
    "we_started": true
  }
}
```

---

### `POST /providers/chatgpt/login`

**Auth:** bearer.

Start a ChatGPT OAuth login (browser flow) on the server host and return the
login URL. Tokens stay in openai-oauth's `~/.codex/auth.json` — they never
enter the request, response, or config. The WebUI surfaces the URL as a link
(backend-driven OAuth; the browser SPA never handles raw tokens).

**Response:** `200`
```json
{ "ok": true, "url": "https://auth.openai.com/..." }
```

---

### `POST /providers/chatgpt/proxy/start`

**Auth:** bearer. Ensure the local openai-oauth proxy is running. Returns
`{ok, base_url?, reason?}`. Never spawns when not authenticated.

---

### `POST /providers/chatgpt/proxy/stop`

**Auth:** bearer. Stop the proxy **only if NetAttackAi started it**
(`we_started`); otherwise a no-op that leaves an operator-started proxy alone.
Returns `{ok, stopped}`.

---

### `GET /plugins`

**Auth:** bearer.

List discovered plugins. Returns `{"plugins": []}` on any error (defensive).

**Response:** `200`
```json
{"plugins": [ /* list_discovered_plugins() output */ ]}
```

---

### `GET /skills`

**Auth:** bearer.

List the runtime skills catalog (name, description, tags). Returns `{"skills": []}` on error.

**Response:** `200`
```json
{
  "skills": [
    {"name": "attacking-domains-end-to-end", "description": "...", "tags": ["domain", "recon"]}
  ]
}
```

---

### `GET /attack/modules`

**Auth:** bearer.

List the pre-packaged attack module catalog (read-only metadata). Returns `{"modules": []}` on error.

**Response:** `200`
```json
{
  "modules": [
    {
      "name": "Log4jRCE",
      "description": "Log4j JNDI injection RCE (CVE-2021-44228)",
      "family": "web",
      "target_services": ["http", "https"],
      "target_ports": [8080, 8443, 80, 443],
      "required_cves": ["CVE-2021-44228"],
      "destructive_ics": false
    }
  ]
}
```

---

### `GET /skills/search`

**Auth:** bearer.

Search runtime skills by query string. Empty `q` returns all (capped at 20).

**Query params:** `q` (string, default `""`).

**Response:** `200`
```json
{"results": [{"name": "...", "description": "..."}]}
```

---

### `POST /diagnostics/doctor`

**Auth:** bearer.

Run the environment self-check (`tools.doctor.run_doctor`).

**Response:** `200`
```json
{"exit_code": 0}
```

---

### `POST /diagnostics/self-test`

**Auth:** bearer.

Run the safe localhost smoke test (`tools.self_test.run_self_test`).

**Response:** `200`
```json
{"exit_code": 0}
```

---

## Graph Explorer Routes

Source: `tools/api/routes/graph_explorer.py` (backed by `tools/api/graph_service.py`).
Prefix `/api/v1/graph`, tag `graph-explorer`.

Read-only interactive investigation of the **Attack Graph v2** store that
`graph_builder` ingests per run from `reports/<run_id>/` (audit + enhanced
report artifacts). Scope-isolated per run (scope = run id); every query is
bounded; unknown node ids return `404`. All routes are gated behind
`api.graph_route: true` in `config.yaml` — when disabled, each returns
`404 graph_disabled`. Never touches a target; never mutates run artifacts.

**Bounds (authoritative ceilings, clamped server-side):**

| Parameter | Ceiling | Default |
|---|---|---|
| `limit` (graph) | 500 | 300 |
| `max_hops` (neighbors) | 4 | 1 |
| `max_nodes` (neighbors) | 200 | 50 |
| `max_length` (paths) | 8 | 4 |
| `max_paths` (paths) | 8 | 5 |

**Errors:** `graph_disabled` (404), `run_not_found` (404), `node_not_found` (404).

### `GET /graph/runs/{run_id}`

**Auth:** bearer.

Filtered nodes + edges for a run. Unknown enum values in `node_type`/`status`
are silently ignored (never raise).

| Param | Type | Default | Notes |
|---|---|---|---|
| `node_type` | repeated string | — | `NodeType` enum values (`ip`, `host`, `service`, `finding`, `evidence`, …) |
| `status` | repeated string | — | `NodeStatus` values (`confirmed`, `likely`, `suspected`, `unknown`, `refuted`, `exhausted`) |
| `q` | string | `""` | substring match on node value |
| `limit` | int | 300 | clamped to 1–500; `truncated` becomes `true` when hit |

```json
{
  "run_id": "r1",
  "scope": "run:r1",
  "nodes": [{
    "node_id": "run:r1|ip|10-0-0-5",
    "node_type": "ip",
    "value": "10.0.0.5",
    "scope": "run:r1",
    "properties": {},
    "confidence": 0.9,
    "first_seen": "2026-08-01T10:00:00Z",
    "last_seen": "2026-08-01T10:00:00Z",
    "evidence_refs": [],
    "observation_count": 0,
    "contradiction_count": 0,
    "status": "unknown",
    "source": "run"
  }],
  "edges": [{
    "edge_id": "…", "source_node_id": "…", "target_node_id": "…",
    "edge_type": "observed_on", "scope": "run:r1", "properties": {},
    "confidence": 0.5, "source": "nmap", "first_seen": "t", "last_seen": "t",
    "evidence_refs": [], "observation_count": 0, "contradiction_count": 0
  }],
  "total_nodes": 17,
  "truncated": false
}
```

`node_type` values are the real `tools/intelligence/graph/types.py::NodeType`
members — never invented: `asset`, `host`, `domain`, `ip`, `service`, `port`,
`endpoint`, `application`, `technology`, `version`, `identity`, `role`,
`credential_reference`, `trust_boundary`, `network_segment`,
`vulnerability_candidate`, `finding`, `hypothesis`, `evidence`, `capability`,
`security_control`, `observation`. Edge types: `resolves_to`, `hosts`,
`exposes`, `runs`, `depends_on`, `reachable_from`, `authenticates_to`,
`has_role`, `trusts`, `related_to`, `supported_by`, `contradicted_by`,
`derived_from`, `affected_by`, `protected_by`, `connected_to`, `same_as`,
`observed_on`.

### `GET /graph/runs/{run_id}/summary`

**Auth:** bearer.

Counts + stats chips for the run's **full** graph (independent of the filtered
view). `highest_degree_node` is `null` when the graph has no edges.

```json
{
  "run_id": "r1",
  "summary": {
    "nodes": { "ip": 1, "finding": 1 },
    "edges": { "affected_by": 1 },
    "total_nodes": 2,
    "total_edges": 1
  },
  "stats": {
    "hosts": 0, "domains": 0, "ips": 1, "services": 0, "findings": 1,
    "hypotheses": 0, "evidence": 0, "observations": 1,
    "vulnerability_candidates": 0,
    "confirmed": 1, "likely": 0, "refuted": 0,
    "highest_degree_node": {
      "node_id": "run:r1|ip|10.0.0.5", "value": "10.0.0.5",
      "node_type": "ip", "degree": 3
    },
    "conflict_count": 0
  }
}
```

### `GET /graph/runs/{run_id}/conflicts`

**Auth:** bearer.

Merge-engine conflicts observed while ingesting this run's artifacts — merge
conflicts are **never silently hidden**:

```json
{
  "run_id": "r1",
  "conflicts": [{
    "node_value": "10.0.0.5",
    "reason": "type conflict: proposed as host, existing as ip",
    "existing_confidence": 0.5,
    "proposed_confidence": 0.6,
    "node_id": "run:r1|ip|10.0.0.5",
    "scope": "run:r1",
    "built_at": "2026-08-01T10:00:00Z"
  }]
}
```

### `GET /graph/runs/{run_id}/nodes/{node_id}`

**Auth:** bearer.

Node details plus up to 100 connected edges and their neighbor nodes. Returns
`404 node_not_found` when the node is unknown or outside the run's scope.

```json
{
  "run_id": "r1",
  "node": { "…same shape as a graph node…" },
  "edges": [],
  "neighbors": []
}
```

### `GET /graph/runs/{run_id}/nodes/{node_id}/neighbors`

**Auth:** bearer.

Bounded BFS neighborhood **including the start node**. `max_hops` clamps to
1–4, `max_nodes` to 1–200. Returns `404 node_not_found` for an unknown start
node.

```json
{
  "run_id": "r1",
  "start_node": { "…" },
  "nodes": [],
  "edges": []
}
```

### `GET /graph/runs/{run_id}/paths`

**Auth:** bearer.

Bounded simple paths between two nodes. `max_length` clamps to 1–8,
`max_paths` to 1–8. Unknown endpoints return an empty `paths` array (no
error). Each path is a list of steps **starting at distance 1** (the start
node itself is not emitted); each step pairs the reached node with the edge
traversed to get there:

```json
{
  "run_id": "r1",
  "paths": [[
    { "distance": 1, "node": { "…" }, "edge": { "…" } },
    { "distance": 2, "node": { "…" }, "edge": { "…" } }
  ]]
}
```

---

## Run Routes

Source: `tools/api/routes/runs.py`. Prefix `/api/v1`, tag `runs`.

### `POST /runs`

**Auth:** bearer.

Create a run. Does **not** execute yet — it prepares a preview and (unless `yes=true`) creates a `start_confirm` decision the WebUI must answer before execution begins.

**Request body** (`RunCreateRequest`):

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `target` | string | *required* | Target IP or domain |
| `mode` | string | `"attack"` | `recon` \| `attack` |
| `goal` | string | `""` | Preset goal name |
| `custom_goal` | string | `""` | Free-text custom goal |
| `recon_first` | bool\|null | null | null = auto (recon-first when no goal) |
| `model` | string\|null | null | Model alias override |
| `swarm` | bool | false | Multi-agent swarm |
| `parallel_swarm` | bool | false | Parallel swarm dispatch |
| `critic` | bool | false | Critic pre-check |
| `reflection` | bool | false | Reflection agent |
| `adaptive_exploits` | bool | false | Adaptive exploit mutation |
| `long_session` | bool | false | Multi-hour attack mode |
| `multi_model_consult` | bool\|null | null | Peer model consultation |
| `observer_mode` | string | `"hybrid"` | Observer mode |
| `ultrathink` | bool | false | Deep reasoning |
| `skills` | string\|null | null | `on`/`off`/`hints`/`lookup` |
| `skills_include` | string[] | `[]` | Force-include skills |
| `skills_exclude` | string[] | `[]` | Force-exclude skills |
| `resume` | string | `""` | Run ID to resume from |
| `kind` | string | `"agent"` | `agent` \| `manual` |
| `yes` | bool | false | Skip the `start_confirm` gate |

**Response:** `201`
```json
{
  "run_id": "run-abc123def456",
  "preview": {
    "run_id": "run-abc123def456",
    "target_ip": "10.0.0.50",
    "mode": "attack",
    "goal_name": "backdoor",
    "model_alias": "glm",
    "permission": "full_access",
    "destructive": true,
    "required_confirmation_text": "ALLOW 10.0.0.50",
    "budgets": { /* commands/rounds/duration */ },
    "swarm": false
  },
  "state": "awaiting_confirmation",
  "decision": {
    "id": "dec-...",
    "kind": "start_confirm",
    "required_text": "ALLOW 10.0.0.50",
    "prompt_text": "DESTRUCTIVE mode — confirm to proceed."
  }
}
```

When `yes=true`, no `decision` is returned and `state` is `"queued"` (execution starts immediately).

**Errors:** `409 conflict` (a run is already active).

---

### `GET /runs`

**Auth:** bearer.

List run history. Each row includes an AI-generated `title` (empty string when
the titler hasn't run yet — e.g. an active or cancelled run).

**Query params:**

| Param | Type | Default | Range |
|-------|------|---------|-------|
| `limit` | int | 50 | 1–200 |
| `offset` | int | 0 | ≥ 0 |
| `sort` | string | `created_desc` | one of `created_desc`, `created_asc`, `title_asc`, `title_desc`, `state_asc`, `state_desc` |

**Response:** `200`
```json
{
  "runs": [
    {"id": "run-...", "state": "completed", "created_at": "2026-07-31T...", "title": "Recon scan of 10.0.0.50"}
  ],
  "sort": "created_desc"
}
```

---

### `POST /runs/{run_id}/title`

**Auth:** bearer.

Set or AI-regenerate a run's title. The titler model is `gemma4:31b-cloud`
(routed through the same Ollama host/API key as the main model).

**Body:**

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `title` | string \| null | null | Explicit title (max 200 chars). Takes precedence over `regen`. |
| `regen` | bool | false | If true and `title` is null/empty, ask the titler model for a fresh title from the run's result/request. |

**Response:** `200`
```json
{"run_id": "run-...", "title": "Recon scan of 10.0.0.50", "regenerated": true}
```

**Errors:** `404` (run not found). A titler failure (ollama unreachable, empty
response) returns `200` with the current title unchanged — never `5xx`.

---

### `GET /runs/{run_id}`

**Auth:** bearer.

Get run details: effective state, progress, pending decisions, artifacts, result, errors.

**Response:** `200`
```json
{
  "id": "run-...",
  "state": "running",
  "created_at": "...",
  "updated_at": "...",
  "request": { /* full RunRequest dict */ },
  "preview": { /* full RunPreview dict */ },
  "result": { /* full RunResult dict, empty until done */ },
  "error": "",
  "cancelled_at": "",
  "resumed_from": "",
  "decisions": [
    {"id": "dec-...", "kind": "start_confirm", "status": "answered", "answer": "ALLOW 10.0.0.50"}
  ]
}
```

**Errors:** `404 Run not found`.

---

### `POST /runs/{run_id}/cancel`

**Auth:** bearer.

Cooperative cancellation + guaranteed MCP/swarm child cleanup.

Sets the `CancellationToken`, cancels the owning `asyncio.Task`, and waits up to `api.shutdown_timeout_seconds` (default 15s) for the task to finish. Pending decisions are expired and resolved with `""` so the blocked service unblocks cleanly. The MCP subprocess tree is torn down in the service's `finally` blocks.

**Response:** `200`
```json
{"run_id": "run-...", "state": "cancelled"}
```

**Errors:** `404 not_found`, `504 cancel_timeout` (task did not finish in time).

---

### `POST /runs/{run_id}/resume`

**Auth:** bearer.

Create a new execution record linked by `resumed_from`, reusing existing report/session state. Copies the original run's request fields, sets `resume_source` to the original run ID, and forces `yes=false` (so the new run goes through the confirmation gate).

**Response:** `200`
```json
{
  "run_id": "run-new...",
  "resumed_from": "run-original...",
  "preview": {"run_id": "run-new...", "target_ip": "10.0.0.50"}
}
```

**Errors:** `404 Run not found` (original), `409 conflict` (a run is already active).

---

### `GET /runs/{run_id}/tools`

**Auth:** bearer.

Return the live MCP tool schemas (including plugin-contributed tools). Only meaningful while a run is active and the MCP session is open; returns `{"tools": []}` otherwise.

**Response:** `200`
```json
{"tools": [ /* MCP tool schemas (OpenAI-function-call shape) */ ]}
```

---

### `POST /runs/{run_id}/tools/{tool_name}/calls`

**Auth:** bearer.

Policy-gated REST bridge for manual WebUI tool calls. Serializes through the run's `tool_lock` (one manual call at a time per run) so it does not race with the agent loop.

**Request body** (`ToolCallRequest`):
```json
{"arguments": { /* tool arguments */ }}
```

**Flow:**
1. Require an active run with an open MCP session and a loaded exploit policy.
2. Validate `tool_name` exists in the live tool schemas.
3. Acquire `handle.tool_lock`.
4. Call `exploit_policy.approve_action(tool_name, json.dumps(arguments), "Manual WebUI tool call")`. Denied → `403 tool_denied`.
5. Call `mcp_session.call_tool(tool_name, arguments=arguments)`. Failure → `500 tool_error`.
6. Extract text content blocks from the MCP result.

**Response:** `200`
```json
{"tool": "run_exploit_terminal", "result": "...text content..."}
```

**Errors:** `404 not_found` (no active run), `409 no_session`/`no_policy`, `404 tool_not_found`, `403 tool_denied`, `500 tool_error`.

---

## Decision Routes

Source: `tools/api/routes/decisions.py`. Prefix `/api/v1`, tag `decisions`.

### `GET /runs/{run_id}/decisions`

**Auth:** bearer.

List pending/answered decisions for a run (oldest first).

**Response:** `200`
```json
{
  "decisions": [
    {
      "id": "dec-...",
      "run_id": "run-...",
      "kind": "start_confirm",
      "prompt_text": "DESTRUCTIVE mode — confirm to proceed.",
      "required_text": "ALLOW 10.0.0.50",
      "options_json": [],
      "status": "pending",
      "answer": "",
      "created_at": "...",
      "answered_at": ""
    }
  ]
}
```

---

### `POST /runs/{run_id}/decisions/{decision_id}`

**Auth:** bearer.

Answer a pending decision. Works for all three decision kinds:

| Kind | Expected `answer` |
|------|-------------------|
| `start_confirm` (non-destructive) | `"y"` or `"yes"` (case-insensitive) |
| `start_confirm` (destructive) | exact match to `required_confirmation_text` (e.g. `"ALLOW 10.0.0.50"`) |
| `goal_select` | the chosen goal name |
| `tool_approval` | `"ALLOW <target>"` to approve, anything else to deny |

**Request body** (`DecisionAnswer`):
```json
{"answer": "ALLOW 10.0.0.50"}
```

**Behavior:**
- For `start_confirm`: resolves the decision and kicks off execution (transitions `queued` → `running`). Invalid confirmation → `400 invalid_confirmation`.
- For `goal_select` / `tool_approval`: resolves the decision future the service is awaiting. If no decisions remain pending, transitions the run back to `running`.
- Emits an `approval` event with the answer.

**Response:** `200`
```json
{"decision_id": "dec-...", "status": "answered"}
```

**Errors:** `404 not_found` (run), `400 no_decisions`, `404 decision_not_found` (decision missing, wrong run, or already answered), `400 invalid_confirmation`, `409 conflict` (execution already started).

---

## Event Routes

Source: `tools/api/routes/events.py`. Prefix `/api/v1`, tag `events`.

### `GET /runs/{run_id}/events`

**Auth:** bearer.

Replay events for a run with `sequence > after`. Reads from the in-memory ring buffer if the cursor is within it, otherwise from `reports/<run_id>/events.jsonl`.

**Query params:**

| Param | Type | Default | Constraint |
|-------|------|---------|------------|
| `after` | int | 0 | ≥ 0 |

**Response:** `200`
```json
{
  "run_id": "run-...",
  "events": [
    {
      "sequence": 1,
      "timestamp": "2026-07-31T...",
      "run_id": "run-...",
      "type": "state",
      "payload": {"state": "running"}
    }
  ]
}
```

**Errors:** `404 Run not found`, `503 Event service unavailable`.

---

### `WS /ws/v1/runs/{run_id}`

**Auth:** WebSocket handshake (origin + auth message).

Live event delivery for a run. The first message must be `{"auth": "<token>", "after": <int>}`. `after` is the replay cursor — events with `sequence > after` are delivered first (replay), then live events stream.

A browser disconnect does **not** cancel the run. Reconnect is safe: the ring buffer holds recent events and JSONL is the authoritative store.

Heartbeats (`{"type": "heartbeat", "run_id": "..."}`) are sent every 30s of idle to keep the WS alive.

**Message shape (server → client):** the `Event` object (see [Data Models](#event)).

**Close codes:** see [Security Model](#security-model).

---

## Data Models

Source: `tools/run_service/models.py`.

### `RunRequest`

The transport-neutral description of an assessment the operator wants to run. Built from CLI args or from `POST /runs` JSON.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `target` | str | *required* | IP or domain |
| `mode` | `recon`\|`attack` | `"attack"` | |
| `goal_name` | str | `""` | Preset goal |
| `custom_goal` | str | `""` | Free-text goal |
| `recon_first` | bool\|None | None | None = auto |
| `model_alias` | str | `""` | |
| `config_path` | Path | `config.yaml` | Set by manager |
| `reports_dir` | Path | `reports` | Set by manager |
| `swarm` | bool | false | |
| `parallel_swarm` | bool | false | |
| `critic` | bool | false | |
| `reflection` | bool | false | |
| `adaptive_exploits` | bool | false | |
| `long_session` | bool | false | |
| `multi_model_consult` | bool\|None | None | |
| `observer_mode` | str | `"hybrid"` | |
| `ultrathink` | bool | false | |
| `debug` | bool | false | |
| `plain` | bool | false | |
| `json_output` | bool | false | |
| `yes` | bool | false | Skip start_confirm gate |
| `skills_mode` | str\|None | None | `on`/`off`/`hints`/`lookup` |
| `skills_include` | str[] | `[]` | |
| `skills_exclude` | str[] | `[]` | |
| `skills_no_reselect` | bool | false | |
| `resume_source` | str | `""` | Run ID |
| `kind` | `RunKind` | `AGENT` | `agent` \| `manual` |
| `interactive` | bool | false | API-only flag |

### `RunPreview`

Everything the operator sees at the ready-to-begin gate, computed by `AssessmentService.prepare` before any I/O side effects.

| Field | Type | Notes |
|-------|------|-------|
| `run_id` | str | |
| `reports_dir` | Path | |
| `config_path` | Path | |
| `target_ip` | str | Resolved/normalized |
| `original_target` | str | What the operator passed |
| `resolved_ip` | str\|None | For domain targets |
| `resolved_domain` | str\|None | For domain targets |
| `mode` | `recon`\|`attack` | |
| `goal_name` | str | |
| `goal_description` | str | |
| `model_alias` | str | |
| `model_label` | str | |
| `transport_summary` | str | |
| `permission` | str | `read_only`/`approve_only`/`full_access` |
| `attack_mode` | bool | |
| `swarm` | bool | |
| `parallel_swarm` | bool | |
| `multi_model` | bool | |
| `destructive` | bool | |
| `required_confirmation_text` | str | `""` for non-destructive; `"ALLOW <ip>"` for destructive |
| `budgets` | dict | commands/rounds/duration |
| `skill_activations` | list[dict] | |
| `skill_errors` | list[str] | |
| `resumed_from` | str | |

### `RunResult`

Sanitized, serializable outcome of a completed/failed run.

| Field | Type | Notes |
|-------|------|-------|
| `run_id` | str | |
| `target_ip` | str | |
| `mode` | `recon`\|`attack` | |
| `goal_name` | str | |
| `goal_description` | str | |
| `total_actions` | int | |
| `workspace` | str | |
| `audit_path` | str | |
| `records` | list[dict] | |
| `messages` | list[dict] | |
| `error` | str | |
| `swarm_result` | dict\|None | |
| `active_skills` | list[dict] | |
| `outcome_summary` | str | |
| `telemetry` | dict\|None | |
| `safety_review` | dict\|None | |
| `reports_dir` | str | |
| `summary_path` | str | |
| `run_json_path` | str | |

### `Decision`

A point where the run pauses for operator input.

| Field | Type | Notes |
|-------|------|-------|
| `id` | str | Assigned by broker |
| `run_id` | str | |
| `kind` | `DecisionKind` | `start_confirm` \| `goal_select` \| `tool_approval` |
| `prompt_text` | str | |
| `required_text` | str | Exact match required (e.g. `"ALLOW 10.0.0.50"`) |
| `options` | list[dict] | For `goal_select`: `[{name, description, ...}]` |
| `status` | `DecisionStatus` | `pending` \| `answered` \| `denied` \| `expired` |
| `answer` | str | |
| `created_at` | str | ISO UTC |
| `answered_at` | str | ISO UTC |

### `Event`

A structured event emitted during a run.

| Field | Type | Notes |
|-------|------|-------|
| `sequence` | int | Monotonic per run |
| `timestamp` | str | ISO UTC |
| `run_id` | str | |
| `type` | str | See [Event Types](#event-types) |
| `payload` | dict | Sanitized by `sanitize()` |

---

## Event Types

Constants from `tools/run_service/models.py`. All payloads are sanitized before persistence/WebSocket delivery.

| Type | Payload | When |
|------|---------|------|
| `state` | `{"state": <RunState>, "result"?: <RunResult dict>}` | Run state transition |
| `boot` | boot step info | MCP boot step (`[BOOT]`/`[OK]` markers) |
| `progress` | round/action/phase | Heartbeat |
| `goal_suggestions` | suggested goals | Recon-first goal suggestion |
| `assistant` | LLM output text | LLM response |
| `tool_request` | tool name + args | Agent decided to call a tool |
| `tool_start` | tool name | Tool call started |
| `tool_result` | tool name + result | Tool call finished |
| `approval` | `{"decision_id", "kind", "prompt_text", "required_text", "options"?, "status"?, "answer"?}` | Tool approval requested/answered |
| `swarm` | swarm progress | Swarm update |
| `artifact` | file path + kind | File written (report/audit/etc) |
| `completion` | completion info | Run completed |
| `error` | `{"message": ...}` | Run error |
| `heartbeat` | `{"run_id": ...}` | WS keepalive (every 30s idle) |

---

## Config Reference

The `api` block in `config.yaml`:

```yaml
api:
  enabled: true
  host: 127.0.0.1              # loopback-only in v1; no public-bind override
  port: 8765
  token_file: .webui_secret_key   # gitignored; created on first boot
  allowed_origins: []          # extra loopback origins for CORS/WS
  event_buffer_size: 256       # in-memory ring buffer per run
  shutdown_timeout_seconds: 15 # graceful shutdown wait
  serve_webui: false           # mount built webui/dist/ at / when true (--web sets this in memory)
```

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `enabled` | bool | true | |
| `host` | str | `127.0.0.1` | Must be loopback; `assert_api_loopback` enforces |
| `port` | int | 8765 | |
| `token_file` | str | `.webui_secret_key` | 256-bit token written here; `0o600` |
| `allowed_origins` | str[] | `[]` | Extra loopback HTTP(S) origins for CORS/WS |
| `event_buffer_size` | int | 256 | In-memory ring per run; ≥ 1 |
| `shutdown_timeout_seconds` | int | 15 | Graceful cancel wait before forcing cleanup |
| `serve_webui` | bool | false | Mount `webui/dist/` at `/` when true. `--web` sets this in memory only (never written to `config.yaml`). Requires `webui/dist/index.html` to exist. |

**Env overrides:**
- `NETATTACKAI_API_TOKEN` — bearer token (precedes `token_file`).
- `NETATTACKAI_API_KEY_FILE` — API key file path (for `GET/PUT /secrets`).

---

## Persistence Schema

`reports/api_runtime.db` (SQLite). Separate from Flow B's `research.db`. Thread-safe via a `threading.Lock` around every connection.

### `_migrations`
| Column | Type |
|--------|------|
| `version` | INTEGER PK |
| `applied_at` | TEXT |

### `runs`
| Column | Type | Default | Notes |
|--------|------|---------|-------|
| `id` | TEXT PK | | `run-<12hex>` |
| `created_at` | TEXT | | ISO UTC |
| `updated_at` | TEXT | | ISO UTC |
| `state` | TEXT | `draft` | `RunState` value |
| `request_json` | TEXT | `{}` | Serialized `RunRequest` |
| `preview_json` | TEXT | `{}` | Serialized `RunPreview` |
| `result_json` | TEXT | `{}` | Serialized `RunResult` |
| `resumed_from` | TEXT | `""` | Original run ID |
| `error` | TEXT | `""` | |
| `cancelled_at` | TEXT | `""` | Set when state → `cancelled` |

Indexes: `idx_runs_state` on `state`.

### `decisions`
| Column | Type | Default | Notes |
|--------|------|---------|-------|
| `id` | TEXT PK | | `dec-<12hex>` |
| `run_id` | TEXT | | FK → `runs(id)` ON DELETE CASCADE |
| `kind` | TEXT | | `DecisionKind` value |
| `prompt_text` | TEXT | `""` | |
| `required_text` | TEXT | `""` | |
| `options_json` | TEXT | `[]` | For `goal_select` |
| `status` | TEXT | `pending` | `DecisionStatus` value |
| `answer` | TEXT | `""` | |
| `created_at` | TEXT | | ISO UTC |
| `answered_at` | TEXT | `""` | ISO UTC |

Indexes: `idx_decisions_run_id` on `run_id`.

**Recovery on startup:** `recover_interrupted()` marks live runs `interrupted` and expires their pending decisions in one transaction.

---

## End-to-End Flow

A typical WebUI session against the API:

1. **Create run** — `POST /runs` with target + mode + flags.
   - Service prepares a `RunPreview` (resolves target, computes permission/destructive flag, budgets).
   - If `yes=false` (default): creates a `start_confirm` decision, run enters `awaiting_confirmation`. Response includes the `decision` the WebUI must answer.
   - If `yes=true`: run enters `queued` and execution starts immediately.

2. **(Optional) Confirm** — `POST /runs/{id}/decisions/{decision_id}` with the answer.
   - Destructive runs require the exact `required_confirmation_text` (e.g. `"ALLOW 10.0.0.50"`).
   - Non-destructive runs accept `"y"`/`"yes"`.
   - On success: run transitions `queued` → `running`, the `asyncio.Task` running `AssessmentService.execute` starts.

3. **Stream events** — open `WS /ws/v1/runs/{run_id}` with `{"auth": "<token>", "after": 0}`.
   - Replay events with `sequence > after` first, then live events.
   - Reconnect any time with the last `sequence` you saw as `after` — the ring buffer + JSONL cover the gap.
   - A disconnect does **not** cancel the run.

4. **Answer mid-run decisions** — `POST /runs/{id}/decisions/{decision_id}`.
   - `goal_select`: choose a goal from recon suggestions.
   - `tool_approval`: `"ALLOW <target>"` to approve (only under `approve_only` policy; `full_access` auto-approves).
   - Run transitions back to `running` when no decisions remain pending.

5. **(Optional) Manual tool calls** — `POST /runs/{id}/tools/{tool_name}/calls`.
   - Policy-gated, serialized through the run's `tool_lock`.
   - Requires the MCP session to be open (run must be `running`).

6. **Cancel** — `POST /runs/{id}/cancel`.
   - Cooperative: sets the `CancellationToken`, cancels the task, waits up to `shutdown_timeout_seconds`.
   - Pending decisions expired and resolved with `""`; MCP subprocess tree torn down.

7. **Poll or stream to completion** — final `state` event is `completed` or `failed` (with `result` and `error` payloads). `GET /runs/{id}` returns the full result.

### Resume

`POST /runs/{id}/resume` creates a new run with `resume_source` set to the original run ID, reusing existing report/session state. The new run goes through the normal confirmation gate (`yes=false`).

### Manual mode

`kind: "manual"` runs do **not** run the agent loop — they only expose the MCP tool gateway (`POST /runs/{id}/tools/{tool_name}/calls`). The WebUI drives tool calls directly.