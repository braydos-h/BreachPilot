# Run Service & API Layer — Architecture

The run service (`tools/run_service/`) is the transport-neutral engine the CLI
and the WebUI API daemon share; the API layer (`tools/api/`) is the
loopback-only REST + WebSocket gateway that lets the WebUI drive that engine.
`main.async_main` (CLI) and `RunManager` (API) both build an
`AssessmentService`, but supply different providers: the CLI adapters are
backed by `AttackUi` questionary prompts, the API adapters by persisted
decision rows + WebSocket event pushes. The service never knows which one is
calling.

- **HTTP surface:** see [docs/api.md](api.md) for full endpoint reference.
- **Daemon entry:** `app.py` (ASGI factory at repo root) → `tools/api/`.
- **Transport-neutral contracts:** `tools/run_service/models.py` +
  `tools/run_service/providers.py`.

---

## Table of Contents

1. [File-by-File Map](#file-by-file-map)
2. [Run Lifecycle](#run-lifecycle)
3. [RunManager Responsibilities](#runmanager-responsibilities)
4. [Persistence](#persistence)
5. [Providers](#providers)
   - [Decision / Event / Approval Providers](#decision--event--approval-providers)
   - [Model / LLM Providers](#model--llm-providers)
6. [Event Broker & WebSocket Transport](#event-broker--websocket-transport)
7. [Decision Broker & Approval Flow](#decision-broker--approval-flow)
8. [Session Titling](#session-titling)
9. [Auth & Error Shape](#auth--error-shape)
10. [Connection to the Exploit Agent](#connection-to-the-exploit-agent)
11. [How the WebUI Consumes It](#how-the-webui-consumes-it)
12. [Config Keys](#config-keys)

---

## File-by-File Map

| File | Role |
|------|------|
| `tools/run_service/__init__.py` | Public exports for the whole `run_service` package (`AssessmentService`, providers, models, event constants) (`__init__.py:11-50`) |
| `tools/run_service/models.py` | Transport-neutral dataclasses + enums: `RunState`, `RunKind`, `DecisionKind`, `DecisionStatus`, `RunRequest`, `RunPreview`, `RunResult`, `Decision`, `Event`, event-type constants (`models.py:25-227`) |
| `tools/run_service/providers.py` | Provider protocols + terminal/API adapters: `DecisionProvider`, `EventSink`, `ApprovalProvider`, `CancellationToken` (`providers.py:40-291`) |
| `tools/run_service/service.py` | `AssessmentService`: `prepare()` (preview, no side effects) + `execute()` (MCP session, agent loop, swarm, reports) (`service.py:280-879`) |
| `tools/api/__init__.py` | Package doc: v1 constraints (loopback-only, one active run, bearer auth) (`__init__.py:1-17`) |
| `tools/api/auth.py` | Bearer token, `assert_api_loopback`, WebSocket origin validation + auth handshake (`auth.py:30-151`) |
| `tools/api/errors.py` | `{error: {code, message, details, request_id}}` envelope, handlers, `sanitize()` redaction, request-id middleware (`errors.py:24-116`) |
| `tools/api/persistence.py` | `ApiPersistence`: SQLite (`reports/api_runtime.db`), runs + decisions tables, migrations, recovery (`persistence.py:87-374`) |
| `tools/api/decision_broker.py` | `DecisionBroker`: persists decisions, holds pending `asyncio.Future`s, resolves on answer/cancel (`decision_broker.py:19-74`) |
| `tools/api/event_broker.py` | `RunEventBroker`: JSONL append + in-memory ring + WS pub/sub; `EventBrokerRegistry` (`event_broker.py:21-169`) |
| `tools/api/run_manager.py` | `RunManager` + `RunHandle`: single-active-run owner, task lifecycle, MCP session handle, tool-call serialization (`run_manager.py:49-417`) |
| `tools/api/session_titler.py` | AI session titles via `gemma4:31b-cloud` (best-effort) (`session_titler.py:92-155`) |
| `tools/api/routes/__init__.py` | Route package marker |
| `tools/api/routes/system.py` | `/health`, `/capabilities`, `/config`, `/secrets`, `/models`, `/plugins`, `/skills`, `/goals`, `/diagnostics` (`system.py:49-529`) |
| `tools/api/routes/runs.py` | `POST/GET /runs`, get/cancel/resume/title/tools, artifacts, audit, swarm/campaign, logs, credentials, loot, delete (`runs.py:149-616`) |
| `tools/api/routes/decisions.py` | `GET/POST /runs/{id}/decisions[/{decision_id}]` (`decisions.py:55-92`) |
| `tools/api/routes/events.py` | `GET /runs/{id}/events`, SSE stream, `WS /ws/v1/runs/{id}` (`events.py:65-156`) |

---

## Run Lifecycle

`RunState` (`models.py:25-36`). The single-active-run invariant is enforced by
`RunManager._create_run_locked` — a second `POST /runs` while one is live
raises `409 conflict` (`run_manager.py:119-120`).

```
                    POST /runs (yes=false)
draft ───────────────────────────────▶ awaiting_confirmation
                                        │  POST /runs/{id}/decisions/{did}
                                        │  answer: "y"/"yes" or exact "ALLOW <ip>"
                                        ▼
                              ┌────── queued ──────┐
                              │     POST /runs      │
                              │   (yes=true)        │
                              ▼                     │
POST /runs/{id}/cancel ──▶ running ◀────────────────┘
                              │  ▲
   │  (cancelling)            │  │  decision answered,
   │                          │  └─ no decisions left pending
   ▼                          ▼
cancelling ──▶ cancelled   awaiting_input  ◀── tool_approval / goal_select created
                              │  run cancelled / daemon shutdown
                              ▼
                          interrupted
```

| State | Meaning | Set by |
|-------|---------|--------|
| `draft` | Row created, not yet confirmed | `persistence.create_run` (`run_manager.py:129`) |
| `awaiting_confirmation` | Preview ready, `start_confirm` decision pending | `_setup_handle_locked` (`run_manager.py:164`) |
| `queued` | Confirmed, waiting for execution slot | `confirm_and_start` (`run_manager.py:196`) or `yes=true` create (`run_manager.py:179`) |
| `running` | Execution in progress | `_execute_run` (`run_manager.py:218`) |
| `awaiting_input` | Blocked on a `tool_approval` / `goal_select` decision | `DecisionBroker.create` for non-`start_confirm` kinds (`decision_broker.py:41-44`) |
| `cancelling` | Cancel requested, tearing down | `cancel_run` (`run_manager.py:298`) |
| `completed` / `failed` | Terminal success / error | `_execute_run` result handling (`run_manager.py:231-237`) |
| `cancelled` | Cancelled by operator | `_execute_run` `CancelledError` branch (`run_manager.py:240`) or task-less cancel (`run_manager.py:308`) |
| `interrupted` | Daemon restarted while run was live | `recover_interrupted` at startup (`persistence.py:258-276`) |

**Terminal transitions:** `completed` when `result.error` is empty, `failed`
when the `RunResult` carries an `error` (`run_manager.py:231`). A
`BaseExceptionGroup` from MCP subprocess death is caught explicitly
(`run_manager.py:243-251`) — bare `except Exception` would miss it (see
`AGENTS.md` rule 1).

---

## RunManager Responsibilities

`RunManager` (`run_manager.py:70-417`) owns everything the routes delegate
to:

1. **Create** — `create_run` prepares the preview through `AssessmentService`,
   persists the row, builds the `DecisionBroker` + `RunEventBroker`, freezes a
   `config_snapshot` so the confirmed preview's permission/destructive/budgets
   stay valid even if `PATCH /config` happens mid-run (`run_manager.py:116-157`).
2. **Gate** — `_setup_handle_locked` creates the `start_confirm` decision
   (destructive runs get `required_text` = `"ALLOW <ip>"`) unless `yes=true`
   (`run_manager.py:159-182`).
3. **Start** — `confirm_and_start` validates the answer
   (exact-text match for destructive, `y`/`yes` otherwise) and spawns the
   `asyncio.Task` running `AssessmentService.execute` (`run_manager.py:184-200`).
4. **Execute** — `_execute_run` wires `ApiDecisionProvider`,
   `ApiEventSink`, `ApiApprovalProvider`, and a `session_attach` callback that
   records the live MCP `ClientSession` + tool schemas + `ExploitPolicy` into
   the handle so the tool-gateway route can use them (`run_manager.py:202-258`).
5. **Tool gateway** — `call_tool` serializes manual WebUI tool calls through
   `handle.tool_lock`, policy-checks via `exploit_policy.approve_action`, then
   `mcp_session.call_tool` (`run_manager.py:358-387`). Errors map to
   `no_session`/`no_policy`/`tool_not_found`/`tool_denied`/`tool_error`.
6. **Cancel** — `cancel_run` sets `CancellationToken`, resolves pending
   decision futures with `""`, cancels the task, waits up to
   `api.shutdown_timeout_seconds` (default 15); timeout → `504 cancel_timeout`
   (`run_manager.py:292-326`). MCP subprocess teardown happens in the
   service's `finally` blocks.
7. **Shutdown** — `shutdown` cancels the active run and closes all event
   brokers (`run_manager.py:405-411`).

---

## Persistence

`ApiPersistence` (`persistence.py:87-374`) — SQLite at
`reports/api_runtime.db`, separate from Flow B's `research.db`. Thread-safe
via a `threading.Lock` around every connection (`persistence.py:94`).
Schema version 2, migrated idempotently in `_init_db` (`persistence.py:107-134`).

### `runs`
| Column | Type | Notes |
|--------|------|-------|
| `id` | TEXT PK | `run-<12hex>` (`persistence.py:83-84`) |
| `created_at` / `updated_at` | TEXT | ISO UTC |
| `state` | TEXT | `RunState` value |
| `request_json` | TEXT | Serialized `RunRequest` |
| `preview_json` | TEXT | Serialized `RunPreview` |
| `result_json` | TEXT | Serialized `RunResult` |
| `resumed_from` | TEXT | Original run ID |
| `error` | TEXT | |
| `cancelled_at` | TEXT | Set when state → `cancelled` (`persistence.py:163-174`) |
| `title` | TEXT | v2; AI/manual session title (`persistence.py:180-195`) |

### `decisions`
| Column | Type | Notes |
|--------|------|-------|
| `id` | TEXT PK | `dec-<12hex>` |
| `run_id` | TEXT | FK → `runs(id)` ON DELETE CASCADE |
| `kind` | TEXT | `DecisionKind` value |
| `prompt_text` / `required_text` | TEXT | |
| `options_json` | TEXT | For `goal_select` |
| `status` | TEXT | `pending` \| `answered` \| `denied` \| `expired` |
| `answer` / `answered_at` | TEXT | |

Indexes: `idx_runs_state`, `idx_decisions_run_id` (`persistence.py:55-56`).
`recover_interrupted` (startup) marks live runs `interrupted` and expires
their pending decisions in one transaction (`persistence.py:258-276`).

**Events** are not stored in SQLite — the `RunEventBroker` appends them to
`reports/<run_id>/events.jsonl` (authoritative store) plus an in-memory ring
(`event_broker.py:52-55`). Run artifacts live under `reports/<run_id>/`
(summary, run.json, audit, workspace).

---

## Providers

### Decision / Event / Approval Providers

`tools/run_service/providers.py` defines the protocols the service calls and
the adapters each transport supplies. `_maybe_await` (`providers.py:21-33`)
handles `AttackUi` methods being a mix of sync and async.

| Protocol | Method | Terminal adapter | API adapter |
|----------|--------|------------------|-------------|
| `DecisionProvider` (`providers.py:40-54`) | `request(decision) -> str` | `TerminalDecisionProvider` → `AttackUi.ask_*` (`providers.py:57-119`) | `ApiDecisionProvider` → persist row + await future (`providers.py:122-150`) |
| `EventSink` (`providers.py:157-162`) | `emit(type, payload)` | `TerminalEventSink` no-op (UI prints directly) (`providers.py:165-175`) | `ApiEventSink` → `EventBroker.emit` (`providers.py:178-186`) |
| `ApprovalProvider` (`providers.py:193-209`) | `approve(action, command, detail, target) -> bool` | `TerminalApprovalProvider` wraps legacy `prompt_func` via `asyncio.to_thread` (`providers.py:212-241`) | `ApiApprovalProvider` → `tool_approval` decision (`providers.py:244-262`) |
| `CancellationToken` (`providers.py:269-291`) | `cancel()` / `cancelled` / `wait()` | shared | shared |

`ApiDecisionProvider.request` (`providers.py:137-150`) is the bridge to the
WebUI: it creates the decision row, emits a `state: awaiting_input` event and
an `approval` event, then blocks on `broker.await_answer(decision.id)`.

### Model / LLM Providers

Model selection is not part of `providers.py`; it is routed through
`tools/model_router.py` (`build_router` / `get_client`), wired by
`AssessmentService.prepare` (`service.py:344-359`) and `execute`
(`service.py:545-558`). The LLM backend is Ollama (cloud by default):

- `ollama.host` (default `https://api.ollama.com`) — chat/generate; the
  ollama client auto-attaches `Authorization: Bearer $OLLAMA_API_KEY`.
- `ollama.embed_host` (default `http://localhost:11434`) — local embeddings
  (`nomic-embed-text`); falls back to `ollama.host` when absent.
- `models.registry` maps aliases → model IDs; `models.default_alias`
  (default `glm`) picks the run model; `models.info` carries labels/context
  windows (`config.yaml:15-44`).
- `RunRequest.model_alias` overrides the default per run
  (`models.py:82`; resolved at `service.py:349`).
- Session titling uses a separate cheap model `gemma4:31b-cloud`
  (`session_titler.py:26`), same host/API-key wiring.

The service also builds `ExploitSettings` via `build_cli_exploit_settings`
(`service.py:403-417`) — budgets (`commands`/`rounds`/`duration_minutes`)
surface in the preview (`service.py:452-456`).

---

## Event Broker & WebSocket Transport

`RunEventBroker` (`event_broker.py:21-107`) is per-run:

1. `emit(type, payload)` assigns a monotonically increasing `sequence`,
   sanitizes the payload with `sanitize()` (secret-key redaction,
   `errors.py:62-71`), appends to `reports/<run_id>/events.jsonl`, pushes to
   the ring buffer (`deque(maxlen=event_buffer_size)`), and fans out to
   subscriber queues (`event_broker.py:39-62`).
2. `replay(after)` returns events with `sequence > after` — from the ring if
   the cursor is inside it, else a JSONL scan (`event_broker.py:64-87`).
3. `subscribe(after)` yields replay events first, then live ones; on 30s of
   idle it emits a `heartbeat` to keep the socket alive
   (`event_broker.py:89-141`). `EventSubscription.__anext__` returns
   `{"type": "heartbeat", "run_id": ...}` on timeout (`event_broker.py:134-137`).

`EventBrokerRegistry` (`event_broker.py:149-169`) holds one broker per run;
`close_all` runs on daemon shutdown.

**WS endpoint** — `WS /ws/v1/runs/{run_id}` (`events.py:125-156`):
1. `authenticate_websocket` checks the Origin (loopback or
   `api.allowed_origins`; fail → close `4403`), accepts, then requires a
   first JSON message `{"auth": "<token>", "after": <int>}` within 5s
   (fail → close `4401`; bad cursor → close `4400`) (`auth.py:121-151`).
2. Run existence check → close `4404` if missing (`events.py:138-140`).
3. `broker.subscribe(after)` replays then streams; a browser disconnect does
   **not** cancel the run — reconnect with the last seen `sequence` as
   `after` (ring + JSONL cover the gap).

**SSE fallback** — `GET /runs/{run_id}/events/stream` (`events.py:76-122`)
is the same subscription over `text/event-stream` with `?token=` auth
(EventSource can't set headers). The WebUI falls back to SSE after 3 WS
failures (`ws.ts:168-173`).

**Event types** — constants at `models.py:212-227`: `state`, `boot`,
`progress`, `phase`, `goal_suggestions`, `recon_assessment`, `assistant`,
`tool_request`, `tool_start`, `tool_result`, `approval`, `swarm`,
`artifact`, `completion`, `error`, plus transport-level `heartbeat`.

---

## Decision Broker & Approval Flow

`DecisionBroker` (`decision_broker.py:19-74`) holds `_pending: dict[str,
Future[str]]` per run. `create` persists the row and registers the future;
`await_answer` blocks on it; `resolve` marks the row answered and sets the
future; `cancel_all` expires rows and resolves every future with `""` so the
blocked service call unblocks cleanly.

**Approval flow for a `tool_approval` decision** (the `approve_only` policy
path; `full_access` auto-approves at `policy.py:408-415`):

```
exploit agent loop
  └─ ExploitPolicy.approve_action(...)              policy.py:368
       └─ await ApiApprovalProvider.approve(...)    providers.py:252
            └─ request(Decision TOOL_APPROVAL)      ApiDecisionProvider
                 ├─ DecisionBroker.create()         persist row + future   decision_broker.py:27
                 ├─ emit state: awaiting_input                              providers.py:140
                 ├─ emit approval {decision_id, kind, prompt_text,
                 │                required_text, options}                   providers.py:142
                 └─ await broker.await_answer(id)   blocks the agent loop   decision_broker.py:47
                                                        │
  WebUI sees approval event over WS ── POST /runs/{id}/decisions/{did}
    {"answer": "ALLOW <target>"}                       │
    └─ RunManager.answer_decision                   run_manager.py:328
         ├─ resolve() marks row answered, sets future ──┘ (agent unblocks)
         └─ emit approval {status: answered, answer}   run_manager.py:342
         └─ no pending decisions left → emit state: running  run_manager.py:345-350
```

Answer validation for `start_confirm` happens in
`confirm_and_start` (`run_manager.py:190-195`); goal/tool answers are
validated by the caller (`Decision` `required_text` match for `tool_approval`
at `providers.py:262`, chosen goal name for `goal_select`).

---

## Session Titling

`session_titler.py` generates a ≤60-char human title per run:

- **Model:** `gemma4:31b-cloud` (`session_titler.py:26`) — deliberately not
  the main attack model so titling never competes for its context window.
- **Prompt:** compact summary of target/mode/goal/actions/outcome/error/skills
  capped at 1500 chars (`_build_prompt`, `session_titler.py:37-69`);
  `_clean_title` strips prefixes, quotes, markdown, trailing punctuation
  (`session_titler.py:72-89`).
- **Trigger:** `RunManager._maybe_title_run` fires after the terminal state
  is persisted, best-effort with every failure swallowed
  (`run_manager.py:260-290`); skips runs that already have a title (resumed
  runs keep the parent's). `POST /runs/{id}/title` supports manual titles or
  on-demand regen via the sync variant (`runs.py:262-293`).

---

## Auth & Error Shape

### Auth (token gate)

- **Bearer token** on every route except `GET /health`. `BearerAuth`
  (`auth.py:65-86`) compares with `hmac.compare_digest`; missing/invalid →
  `401`.
- **Token source** (`load_or_create_token`, `auth.py:39-62`):
  `NETATTACKAI_API_TOKEN` env → `api.token_file` (default `.webui_secret_key`)
  → generate `secrets.token_urlsafe(32)` with `0o600` best-effort. Never
  logged or returned.
- **Loopback bind:** `assert_api_loopback` (`auth.py:30-36`) refuses any
  host outside `{127.0.0.1, localhost, ::1}`.
- **WebSocket:** origin check (`is_loopback_origin`, `auth.py:89-118`) +
  auth message handshake (`auth.py:121-151`). Close codes: `4403` origin,
  `4401` auth, `4400` cursor, `4404` run not found, `1011` unconfigured.

### Error shape

Every error is `{error: {code, message, details, request_id}}`
(`errors.py:42-59`); `request_id` is injected per request and echoed in the
`X-Request-ID` header (`errors.py:108-116`). Handlers registered by
`install_error_handlers` (`errors.py:74-105`): `HTTPException` →
`http_error`, `RequestValidationError` → `validation_error` (422),
`APIError` → its own code/status, `ValueError` → `value_error` (400),
anything else → `internal_error` (500, generic message). `sanitize()` redacts
secret-pattern keys everywhere events/config/errors are emitted
(`errors.py:19-21, 62-71`).

Common `APIError` codes (raised in `run_manager.py`): `conflict` (409),
`not_found` (404), `invalid_confirmation` (400), `decision_not_found` (404),
`no_decisions` (400), `no_session`/`no_policy` (409), `tool_not_found`
(404), `tool_denied` (403), `tool_error` (500), `cancel_timeout` (504).

---

## Connection to the Exploit Agent

The run service sits on top of the Flow A exploit stack (see `CLAUDE.md` and
`docs/architecture.md`):

1. `AssessmentService.execute` → `_run_session` (`service.py:1044-1094`)
   calls `run_exploit_session` (`tools/exploit_session.py`), which:
   - opens the MCP exploit session via `open_exploit_mcp_session` (HTTP
     transport, `mcp.http_port` default 8001) (`exploit_session.py:186-196`),
   - attaches the swarm bridge if enabled (`exploit_session.py:202-206`),
   - runs the agent loop `run_exploit_agent` (`tools/exploit_agent/runner/_impl.py (run_exploit_agent)`)
     with the model client, goal, exploit settings, and the `event_sink`.
2. The loop emits `assistant` / `tool_request` / `tool_start` / `tool_result`
   / `phase` events through `event_sink.emit` (`loop.py:68-73, 943, 1050,
   1206, 1555, 1916`) — the API's `ApiEventSink` forwards them to the broker.
3. `ExploitPolicy.approve_action` (`policy.py:368-439`) gates each action:
   `read_only` proposes-only, `full_access` auto-approves (the real lock is
   the target-IP allowlist at the MCP tool layer), `approve_only` delegates to
   the `ApprovalProvider` — the API path routes this through a `tool_approval`
   decision to the WebUI.
4. The live MCP `ClientSession`, tool schemas, and policy reach
   `RunManager` via the `session_attach` callback (`run_manager.py:227-229`,
   `set_mcp_session` at `run_manager.py:395-403`), enabling the manual tool
   gateway and `GET /runs/{id}/tools`.
5. Swarm mode runs an `AgentLoop` campaign as a sibling task, bridged through
   `SwarmMcpBridge`; progress is polled from `swarm_state.json`
   (`service.py:989-1042, 1096-1149`).
6. Outputs: `session_summary.md`, `run.json`, audit trail, and a derived
   `campaign_result` → `EnhancedReportGenerator` writes
   `reports/<run_id>/enhanced/enhanced_report.json` for the WebUI attack
   graph (`service.py:781-845`).

Recon-first mode (`_recon_first`, `service.py:903-987`) opens a soft-fail MCP
session, runs `run_recon_assessment`, emits `recon_assessment` +
`goal_suggestions`, and asks a `goal_select` decision before proceeding.

---

## How the WebUI Consumes It

The SPA (`webui/`, Vite + React + TypeScript) talks only to the API:

- **REST client** — `webui/src/api/client.ts` wraps `fetch` under
  `/api/v1`, attaches `Authorization: Bearer <token>` from
  `sessionStorage` (`client.ts:8-27, 69-123`), and normalizes the error
  envelope into `ApiError` with `isAuth`/`isConflict`/`isNotFound` helpers
  (`client.ts:29-57, 125-159`).
- **Token storage** — `netattackai.apiToken.v1` in `sessionStorage`
  (`client.ts:6`); cleared on WS `4401` auth rejection (`ws.ts:149-153`).
- **Live events** — `webui/src/api/ws.ts` `useRunEvents(runId, {after})`
  opens `WS /api/v1/ws/v1/runs/{id}` and sends `{auth, after: lastSeq}`
  (`ws.ts:101-130`); dedupes by `sequence` (`ws.ts:40-55`); reconnects with
  exponential backoff; after 3 WS failures switches to the SSE stream
  (`ws.ts:168-173`); falls back on close codes `4400` (reset cursor) and
  `4404` (run gone) (`ws.ts:160-167`).
- **Typed contract** — `webui/src/api/types.ts` mirrors the API: `RunState`
  union + `ACTIVE_RUN_STATES` / `TERMINAL_RUN_STATES` helpers
  (`types.ts:1, 610-637`), `RunEvent` (`types.ts:560-566`),
  `ApiErrorEnvelope` (`types.ts:592-599`), decision/run/preview shapes.
- **Workflow** — create run → answer `start_confirm` → stream `state`
  events → answer `tool_approval`/`goal_select` → poll
  `GET /runs/{id}` for the result → `POST /runs/{id}/cancel` to stop. Full
  end-to-end walkthrough: `docs/api.md` §End-to-End Flow.

---

## Config Keys

Keys consumed by the run service / API layer (`config.yaml`, see
`docs/api.md` §Config Reference for the `api` block):

| Key | Default | Used by |
|-----|---------|---------|
| `ollama.host` | `https://api.ollama.com` | Model chat/generate routing (`service.py:336, 546`) + titler host (`run_manager.py:275-278`) |
| `ollama.embed_host` | `http://localhost:11434` | Local embeddings (skills/memory); falls back to `ollama.host` |
| `ollama.api_key_env` | `OLLAMA_API_KEY` | Cloud auth (auto-attached bearer) |
| `models.registry` / `models.default_alias` / `models.info` | `glm` | Model alias resolution + `/models` (`system.py:188-196`) |
| `mcp.http_port` | `8001` | MCP exploit session transport port (`service.py:446, 918, 1054`) |
| `exploit.permission` | `read_only` | Preview `permission` + `destructive` verdict (`service.py:435-450`); `full_access` auto-approves |
| `exploit.max_rounds` / `max_commands` / `max_duration_minutes` | n/a | Preview `budgets` (`service.py:452-456`) |
| `api.host` / `api.port` | `127.0.0.1` / `8765` | Bind (loopback-enforced, `auth.py:30-36`) |
| `api.token_file` | `.webui_secret_key` | Bearer token persistence (`auth.py:39-62`) |
| `api.allowed_origins` | `[]` | Extra loopback origins for CORS/WS (`auth.py:89-118`) |
| `api.event_buffer_size` | `256` | In-memory ring per run (`event_broker.py:29-37`) |
| `api.shutdown_timeout_seconds` | `15` | Cancel wait before `504 cancel_timeout` (`run_manager.py:319-324`) |
| `api.serve_webui` | `false` | Mount `webui/dist/` at `/` (`--web` sets in-memory) |
| `long_session.request_timeout_seconds` | n/a | Model request timeout when `long_session` active (`service.py:337-343`) |

**Env overrides:** `NETATTACKAI_API_TOKEN` (token, precedes token_file),
`NETATTACKAI_API_KEY_FILE` (API key file for `/secrets`),
`OLLAMA_API_KEY` (cloud auth).

---

> Source: `tools/run_service/` (contracts + engine), `tools/api/` (daemon
> services + routes), `app.py` (ASGI factory). HTTP reference: `docs/api.md`.
