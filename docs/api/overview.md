---
title: WebUI API Overview — Lifecycle, Auth, Persistence, Brokers, Run Manager, Models
sources:
  - app.py
  - tools/api/__init__.py
  - tools/api/auth.py
  - tools/api/errors.py
  - tools/api/persistence.py
  - tools/api/event_broker.py
  - tools/api/decision_broker.py
  - tools/api/run_manager.py
  - tools/api/session_titler.py
  - tools/api/graph_builder.py
  - tools/api/graph_service.py
  - tools/run_service/models.py
  - tools/run_service/service.py
  - tools/run_service/providers.py
  - docs/api.md
  - docs/run-service.md
tests:
  - tests/test_api_auth.py
  - tests/test_api_runs.py
  - tests/test_api_events.py
  - tests/test_api_persistence.py
  - tests/test_api_frontend.py
  - tests/test_api_campaign_checkpoint.py
subsystem: api
status: maintained
---

# WebUI API Overview

Loopback-only REST + WebSocket daemon (`tools/api/`) that lets the bundled Vite/React WebUI (or any third-party client) drive `AssessmentService` through the same `RunRequest` / `RunPreview` / `RunResult` contracts the CLI uses.

> Canonical HTTP reference is `docs/api.md`. This file is the engineering orientation (how the pieces fit).

## Factory & Lifecycle

`app.py:create_app` (`app.py:42`) is the ASGI factory called by `main._run_daemon` (`--daemon` (legacy alias: `--demon`) / `--web`).

```
main._run_daemon  -->  app.create_app(config_path, config, callables)
                        | load_config OR in-memory config override (--web)
                        | assert_api_loopback(host)                          app.py:70
                        | load_or_create_token(token_file, env)              app.py:73
                        | ApiPersistence(reports_dir)                        app.py:81
                        | EventBrokerRegistry(reports_dir, buffer_size)      app.py:88
                        | RunManager(persistence, registry, config, ...)     app.py:91
                        | CORSMiddleware (loopback-only) + error handlers    app.py:120
                        | configure(route modules)                           app.py:133
                        | optionally mount webui/dist/ SPA at /              app.py:162
                        --> FastAPI(lifespan=recover_interrupted/shutdown)
```

Lifespan (`app.py:100`):

- Startup: `persistence.recover_interrupted()` marks every run in `draft` / `awaiting_confirmation` / `running` / `awaiting_input` / `queued` / `cancelling` as `interrupted` and expires its `pending` decisions (`tools/api/persistence.py:353`).
- Shutdown: `run_manager.shutdown()` cancels all active handles and closes all brokers (`tools/api/run_manager.py:534`).

Mount order matters: `/api/v1`, `/docs`, `/openapi.json` are matched before the SPA catch-all `/{full_path:path}` (`app.py:204`). `app.openapi` is patched to hide webui-only routes so schema generation stays valid (`app.py:214`).

## Auth

Summary — detail in `docs/api/auth.md`.

- Bind: `assert_api_loopback` (`tools/api/auth.py:38`) rejects any host not in `{127.0.0.1, localhost, ::1}`. v1 has no public-bind override.
- HTTP: `BearerAuth` (`tools/api/auth.py:72`) as a FastAPI dependency on every route except `GET /api/v1/health`. Constant-time `hmac.compare_digest`. Token source: `BREACHPILOT_API_TOKEN` env → `api.token_file` (default `.webui_secret_key`, `0o600` where supported) → generate `secrets.token_urlsafe(32)` (`tools/api/auth.py:46`).
- CORS: `CORSMiddleware` allowlist = `api.allowed_origins` + loopback defaults; entries must pass `is_loopback_origin` or factory raises (`app.py:115`).
- WebSocket: `authenticate_websocket` (`tools/api/auth.py:128`) checks `Origin` (→ `4403`), accepts, then requires first JSON `{"auth": "<token>", "after": <int>}` within 5 s (→ `4401` auth, `4400` cursor).
- Multi-operator passwords (when `api.multi_operator`): `hash_password` / `verify_password` PBKDF2-HMAC-SHA256, 200 k iterations, 16-byte salt (`tools/api/auth.py:164`).

## Error Shape & Middleware

`tools/api/errors.py:42` — every error is `{error: {code, message, details, request_id}}`.

- Handlers (`tools/api/errors.py:71`): `HTTPException` → `http_error`, `RequestValidationError` → `validation_error` (422), `APIError` → its own code, `ValueError` → `value_error` (400), catch-all → `internal_error` (500, generic message).
- Middleware (`tools/api/errors.py:106`): injects `request_id` UUID per request, echoes `X-Request-ID`.
- Redaction (`tools/api/errors.py:62`): `sanitize()` recursively replaces values whose keys match `password|passwd|secret|token|api[_-]?key|auth|bearer|credential|private[_-]?key` with `"[REDACTED]"`. Applied to config responses, event payloads, secret reads.

## Persistence

`tools/api/persistence.py:131` `ApiPersistence` — SQLite at `reports/api_runtime.db` (separate from Flow B `research.db`). Thread-safe via `threading.Lock` (`tools/api/persistence.py:138`).

- Tables: `runs`, `decisions`, `users`, `annotations`, `_migrations` (`tools/api/persistence.py:21`). Schema version 3, idempotent migrations (`tools/api/persistence.py:90`).
- Runs: `create_run` / `update_run_state` / `update_run_title` / `get_run` / `list_runs` (filter `q` + `state`, sort `created_desc|created_asc|title_asc|title_desc|state_asc|state_desc`) / `count_runs` / `get_active_run` / `recover_interrupted` / `delete_run` / `reset_all` (keeps file, deletes rows, users kept).
- Decisions: `create_decision` / `answer_decision` / `get_decision` / `list_decisions` / `expire_pending_decisions`.
- Users/annotations (D4, only when `api.multi_operator`): `create_user` / `get_user_by_username` / `get_user` / `list_users` / `touch_user_login`; `add_annotation` / `list_annotations` / `delete_annotation`.
- Events are **not** in SQLite — JSONL + ring (`tools/api/event_broker.py:52`).

Detail in `docs/api/persistence.md`.

## Brokers

### Event broker

`tools/api/event_broker.py:21` `RunEventBroker` — per-run JSONL (`reports/<run_id>/events.jsonl`) + bounded `deque(maxlen=buffer_size)` ring + `asyncio.Queue` pub/sub via `EventSubscription` (`tools/api/event_broker.py:183`).

- `emit(type, payload)`: assign monotonic `sequence`, `sanitize`, append JSONL, push ring, fan-out to subscribers (`tools/api/event_broker.py:39`). Fires plugin outbound subscribers best-effort after persistence (`tools/api/event_broker.py:66`, `tools/plugins.py`).
- `replay(after)`: ring fast-path else JSONL scan (`tools/api/event_broker.py:69`).
- `replay_page(after, tail, before, limit)`: paged cursor with `oldest_sequence` / `latest_sequence` (full history) + `first/last_returned_sequence`, `omitted_before`, `next_before`, `has_more_before=omitted_before>0` (`tools/api/event_broker.py:112`).
- `subscribe(after)`: replays then live, 30 s heartbeat `{"type":"heartbeat"}` (`tools/api/event_broker.py:159`, `tools/api/event_broker.py:204`).
- `EventBrokerRegistry` (`tools/api/event_broker.py:220`): `OrderedDict` of ≤`max_brokers` (10) per-run brokers, LRU eviction, `get_or_create` / `get` / `close_all`.

Detail in `docs/api/event-broker.md`.

### Decision broker

`tools/api/decision_broker.py:19` `DecisionBroker` — per-run `_pending: dict[str, Future[str]]`.

- `create(decision)`: persist row (`tools/api/persistence.py:375`), assign `decision.id`, set `run state → awaiting_input` unless `start_confirm`, register future (`tools/api/decision_broker.py:27`).
- `await_answer(id)`: blocks until resolved or cancelled (`tools/api/decision_broker.py:50`).
- `resolve(id, answer)`: mark row `answered`, `future.set_result` (`tools/api/decision_broker.py:60`).
- `cancel_all()`: expire rows, resolve all futures with `""` (`tools/api/decision_broker.py:71`).

The mid-run operator checkpoint (`campaign_next_step`) is also a decision — see `tools/run_service/service.py:964` `checkpoint_hook`.

## Run Manager

`tools/api/run_manager.py:119` `RunManager` — owns active handles, concurrency, MCP session handles, tool-call serialization.

- `RunHandle` (`tools/api/run_manager.py:68`): `run_id`, `task`, `cancellation`, `decision_broker`, `event_broker`, `mcp_session`, `exploit_policy`, `tool_schemas`, `tool_lock`, `preview`, `request`, `config_snapshot` (frozen at `prepare`), `allowlist` (frozen `exploit.allowed_targets ∪ target`).
- Concurrency: `max_concurrent_runs` reads `api.max_concurrent_runs` (default 1 legacy → `409` on second; lab default 3) (`tools/api/run_manager.py:150`). `_snapshot_allowlist` (`tools/api/run_manager.py:97`) plus `EXPLOIT_TARGET` per-subprocess env give per-run isolation.
- `create_run` (`tools/api/run_manager.py:187`): `AssessmentService.prepare` → persist row → `EventBrokerRegistry.get_or_create` → `RunHandle` → `_setup_handle_locked` (creates `start_confirm` decision unless `yes` → `queued`).
- `confirm_and_start` (`tools/api/run_manager.py:286`): validates answer (exact `ALLOW <ip>` for destructive, `y`/`yes` otherwise) → `decision_broker.resolve` → `asyncio.create_task(_execute_run)`.
- `_execute_run` (`tools/api/run_manager.py:304`): wires `ApiDecisionProvider` / `ApiEventSink` / `ApiApprovalProvider` / `session_attach`, runs `AssessmentService.execute`, maps `cancelled`/`error`/`completed`, calls `_maybe_title_run` (`tools/api/session_titler.py` via `gemma4:31b-cloud`, best-effort).
- `cancel_run` (`tools/api/run_manager.py:420`): `state→cancelling`, `cancellation.cancel()`, `decision_broker.cancel_all()`, `task.cancel()`, wait `api.shutdown_timeout_seconds` or `504 cancel_timeout`.
- `call_tool` (`tools/api/run_manager.py:486`): requires `mcp_session` + `exploit_policy`, validates `tool_name` in `tool_schemas`, `tool_lock`, `approve_action("Manual WebUI tool call")` → `mcp_session.call_tool` → extract `content[].text`.
- `shutdown` (`tools/api/run_manager.py:534`): cancel all active ids best-effort + `events.close_all()`.

Detail in `docs/api/run-manager.md`.

## Models & Providers

`tools/run_service/models.py` (`docs/api/models.md`):

- Enums: `RunState` (`draft|awaiting_confirmation|queued|running|awaiting_input|cancelling|completed|failed|cancelled|interrupted`), `RunKind` (`agent`), `DecisionKind` (`start_confirm|goal_select|tool_approval|campaign_next_step`), `DecisionStatus` (`pending|answered|denied|expired`).
- Dataclasses: `RunRequest`, `RunPreview`, `RunResult`, `Decision`, `Event`.
- Constants: `EVENT_STATE|BOOT|PROGRESS|...|ERROR|HEARTBEAT` and helpers `is_agent_attack_mode` / `is_fast_mode`.

`tools/run_service/providers.py`:

- Protocols: `DecisionProvider` / `EventSink` / `ApprovalProvider` + `CancellationToken`.
- Adapters: `Terminal*` (CLI) vs `Api*` (daemon). `ApiDecisionProvider.request` persists + awaits future; `ApiEventSink.emit` forwards to broker; `ApiApprovalProvider.approve` routes through `tool_approval` decision.

`tools/run_service/service.py` `AssessmentService` — `prepare()` (pure, worker-thread) builds `RunPreview`; `execute()` opens MCP session, runs agent loop / swarm, writes `session_summary.md` / `run.json` / `enhanced_report.json`, derives `campaign_result` for the graph.

## Endpoint Families

| Family | Module | Prefix | Auth |
|--------|--------|--------|------|
| System | `tools/api/routes/system.py` | `/api/v1` | bearer (except `GET /health`) |
| Runs | `tools/api/routes/runs.py` | `/api/v1` | bearer |
| Decisions | `tools/api/routes/decisions.py` | `/api/v1` | bearer |
| Events (REST + SSE + WS) | `tools/api/routes/events.py` | `/api/v1` + `WS /ws/v1` | bearer (REST/SSE) / first-message auth (WS) |
| Graph (legacy DAG) | `tools/api/routes/graph.py` | `/api/v1` | bearer, gated `api.graph_route` |
| Graph explorer | `tools/api/routes/graph_explorer.py` | `/api/v1/graph` | bearer, gated `api.graph_route` |
| Users/annotations | `tools/api/routes/users.py` | `/api/v1` | bearer, only when `api.multi_operator` |

Full method/handler inventory: `docs/api/endpoint-matrix.md`. Per-family pages: `docs/api/endpoints/*.md`. WebSocket detail: `docs/api/websocket.md`.

## Related

- `docs/run-service.md` — deeper run-service architecture
- `docs/components/root/app.md` — factory/middleware/SPA detail
- `docs/webui/api-integration.md` — how the SPA consumes the API
