---
title: Run Manager — Active Runs, Concurrency, MCP Session, Tool Gateway
sources:
  - tools/api/run_manager.py
  - tools/api/persistence.py
  - tools/api/event_broker.py
  - tools/api/decision_broker.py
  - tools/api/session_titler.py
  - tools/run_service/service.py
  - tools/run_service/models.py
  - tools/run_service/providers.py
  - tools/api/routes/runs.py
tests:
  - tests/test_api_runs.py
  - tests/test_api_campaign_checkpoint.py
subsystem: api
status: maintained
---

# Run Manager

`tools/api/run_manager.py:119` `RunManager` + `tools/api/run_manager.py:68` `RunHandle` — owns every active run's task, MCP session handle, allowlist snapshot, decision/event brokers, and tool-call serialization. Enforces `api.max_concurrent_runs` (default 1 legacy → `409`) and per-run target isolation.

## RunHandle

`tools/api/run_manager.py:68`:

| Field | Type | Purpose |
|-------|------|---------|
| `run_id` | `str` | `RunPreview.run_id` (`%Y%m%d_%H%M%S_%f`) |
| `task` | `asyncio.Task|None` | `AssessmentService.execute` task; `None` until `confirm_and_start` |
| `cancellation` | `CancellationToken` | `tools/run_service/providers.py:346` flag checked in `service.py` |
| `decision_broker` | `DecisionBroker|None` | per-run |
| `event_broker` | `RunEventBroker|None` | per-run JSONL+ring |
| `mcp_session` | `Any|None` | `ClientSession` after `session_attach` |
| `exploit_policy` | `Any|None` | `ExploitPolicy` after `session_attach` |
| `tool_schemas` | `list[dict]` | OpenAI-function-call schemas, set in `set_mcp_session` |
| `tool_lock` | `asyncio.Lock` | serializes `call_tool` per run |
| `preview` / `request` | `RunPreview|None` / `RunRequest|None` | frozen at `create_run` |
| `config_snapshot` | `dict|None` | `copy.deepcopy(config)` at `prepare` so `PATCH /config` cannot retroactively change the confirmed preview |
| `allowlist` | `list[str]` | frozen `exploit.allowed_targets ∪ (original_target|target_ip)` at `prepare` (`tools/api/run_manager.py:232`) |

`_snapshot_allowlist(config, target)` (`tools/api/run_manager.py:97`) builds `exploit.allowed_targets` ∪ target (strip, dedupe). Domain re-resolution is intentionally skipped — the MCP subprocess `env["EXPLOIT_TARGET"]` (set in `tools/mcp_session.open_exploit_mcp_session`) is the authoritative lock; the snapshot is the handle-level mirror for the WebUI.

## Construction & Concurrency Cap

`RunManager(persistence, event_registry, config, config_path, callables)` (`tools/api/run_manager.py:129`):

- `_active: dict[str, RunHandle]` — keyed by `run_id`, O(1) `has_active`/`active`/`active_for`.
- `_lifecycle_lock = asyncio.Lock()` serializes `create_run`/`confirm_and_start`/`cancel_run` vs `_execute_run` cleanup.

`max_concurrent_runs` (`tools/api/run_manager.py:150`): `int(api.max_concurrent_runs or 1)` clamped `≥1`. `app.py` passes `config` live so patching `api.max_concurrent_runs` takes effect for the next create.

`has_active` (`tools/api/run_manager.py:157`) `bool(_active)`. `active` (`tools/api/run_manager.py:170`) is the first handle (legacy compat when N=1). `active_for(run_id)` (`tools/api/run_manager.py:179`) and `active_run_ids`.

## Create — `create_run` / `_create_run_locked` / `_setup_handle_locked`

`create_run(request)` (`tools/api/run_manager.py:187`) → `_lifecycle_lock` → `_create_run_locked`.

`_create_run_locked` (`tools/api/run_manager.py:196`):

1. If `len(_active) >= max_concurrent_runs` → `APIError("conflict", 409)` (`tools/api/run_manager.py:201`).
2. Set `request.config_path/reports_dir` to manager's values (`tools/api/run_manager.py:208`).
3. `service = AssessmentService(config, callables)`; `preview = await service.prepare(request)` (which validates/resolves target, picks model, computes `destructive`, `required_confirmation_text="ALLOW <ip>"` when `permission==full_access && attack_mode`).
4. `persistence.create_run(run_id, _request_to_dict(req), _preview_to_dict(prev))` (`tools/api/run_manager.py:216`).
5. `event_broker = events.get_or_create(preview.run_id)`; `handle = RunHandle(preview.run_id)`; freeze `config_snapshot`, `allowlist`; attach brokers; `self._active[preview.run_id]=handle`.
6. `await _setup_handle_locked(handle, request, preview)` — on exception, `cancel_all`+`close` brokers, pop handle, mark `FAILED`.

`_setup_handle_locked` (`tools/api/run_manager.py:253`):

- If `not request.yes` → `state=awaiting_confirmation` + `emit("state")` + `Decision(kind=START_CONFIRM, prompt="Proceed?" or "DESTRUCTIVE — confirm", required_text=preview.required_confirmation_text)` → `broker.create` → `emit("approval" {decision_id,kind,...})`; return `decision`.
- Else `yes` → `state=queued` + `emit("state")` → `handle.task = create_task(_execute_run(handle))`; no decision.

Return value (`tools/api/routes/runs.py:210`) is `(run_id, preview, decision|None)`; the route maps to `state="awaiting_confirmation"` when decision exists else `"queued"`.

## Start — `confirm_and_start`

`confirm_and_start(run_id, decision_id, answer)` (`tools/api/run_manager.py:286`):

- Hold `_lifecycle_lock`; `handle = require_active(run_id)`; if `handle.task is not None` → `409 conflict` (already started).
- Validate: destructive → `answer == preview.required_confirmation_text` else `answer.strip().lower() in {y, yes}` (`tools/api/run_manager.py:292`); fail → `400 invalid_confirmation`.
- `state=queued` + emit, then `decision_broker.resolve(decision_id, answer)` → `404` if missing/already answered.
- `handle.task = create_task(_execute_run(handle))`.

Called from two paths: `POST /runs/{id}/decisions/{decision_id}` when `kind==start_confirm` via `answer_decision` (`tools/api/run_manager.py:462`), and the `resume` route creates a new run through the same `create_run` gate.

## Execute — `_execute_run`

`_execute_run(handle)` (`tools/api/run_manager.py:304`) — background `asyncio.Task`:

1. `service = AssessmentService(config=handle.config_snapshot, callables)` — uses frozen snapshot.
2. Wire `ApiDecisionProvider(handle.run_id, handle.decision_broker, handle.event_broker.emit)` (`tools/run_service/providers.py:195`), `ApiEventSink`, `ApiApprovalProvider(handle.run_id, decision_provider, handle.preview.target_ip)` (`tools/run_service/providers.py:319`).
3. `state=running` + emit.
4. `await service.execute(request, preview, decision_provider, event_sink, cancellation, config, approval_provider, session_attach=lambda s,sch,pol: set_mcp_session(handle.run_id, s, sch, pol))` (`tools/api/run_manager.py:327`).
5. On `result.cancelled` (operator `cancel` at checkpoint) → `state=cancelled`; else `result.error` → `failed` else `completed`; `result_dict=_result_to_dict(r)` → `update_run_state(state, error, result)` + `emit("state" {state, result})` + `_maybe_title_run`.
6. Except `asyncio.CancelledError` (from `cancel_run` `task.cancel`) → `state=cancelled` + emit (`tools/api/run_manager.py:362`).
7. Except `BaseExceptionGroup` (MCP subprocess death is NOT an `Exception`) (`tools/api/run_manager.py:366`) → `state=failed` + `emit("error")`, `_is_exception_group` + `_log_nested_exceptions` (`tools/exceptions.py`), title with error.
8. Finally (`tools/api/run_manager.py:375`): `decision_broker.cancel_all()`, `event_broker.close()`, pop from `_active` under lock.

### Session attachment

`set_mcp_session(run_id, session, schemas, policy)` (`tools/api/run_manager.py:520`) records the live `ClientSession` + tool schemas + `ExploitPolicy` into the handle so `get_tool_schemas` and `call_tool` can find them. Called by `service.py:1090` `session_attach` callback both for the main MCP session and by `SwarmMcpBridge.attach` for swarm.

### Titling

`_maybe_title_run(handle, result_dict)` (`tools/api/run_manager.py:383`): best-effort. Skip if run already has `title` (resumed keeps parent's). `host = config["ollama"]["host"] or https://api.ollama.com`; `await generate_session_title(result, _request_to_dict(req), host, config)` (`tools/api/session_titler.py:129`) — uses `gemma4:31b-cloud` (Ollama) or `chatgpt.default_model` when ChatGPT provider. On success → `persistence.update_run_title` + `emit("title")`. Any exception → `logger.debug` swallowed.

## Decisions — `answer_decision` / `list_decisions`

`answer_decision(run_id, decision_id, answer)` (`tools/api/run_manager.py:454`):

- Fetch handle, require `decision_broker`.
- `persistence.get_decision(decision_id)` must exist, matching `run_id`, `status=="pending"` else `404 decision_not_found`.
- If `kind=="start_confirm"` → delegate to `confirm_and_start` (so start_confirm answers kick off execution).
- Else `decision_broker.resolve(decision_id, answer)` → `404` if broker lost the future; `emit("approval" {decision_id,status:"answered",answer})`; if no rows remain `pending`, `state=running` + emit.

`list_decisions(run_id)` (`tools/api/run_manager.py:481`) raises `404` if run missing, else `persistence.list_decisions`.

## Tool Gateway — `call_tool` / `get_tool_schemas`

`get_tool_schemas(run_id)` (`tools/api/run_manager.py:514`) returns `handle.tool_schemas` or `[]`.

`call_tool(run_id, tool_name, arguments)` (`tools/api/run_manager.py:486`):

1. Require active handle; `mcp_session None → 409 no_session`; `exploit_policy None → 409 no_policy`.
2. Validate `tool_name` in `tool_schemas[].function.name` → `404 tool_not_found`.
3. `async with handle.tool_lock`: `approved = await exploit_policy.approve_action(tool_name, json.dumps(arguments, sort_keys), "Manual WebUI tool call")` → `403 tool_denied` if false.
4. `await mcp_session.call_tool(tool_name, arguments)` — `BaseExceptionGroup` caught via `_EXC_GROUP_CATCH` + `_log_nested_exceptions` (`tools/api/run_manager.py:504`).
5. Extract text via `_extract_text(result)` (`tools/api/run_manager.py:552`): gather `content[].text` joined with `\n`.

## Cancel & Shutdown

`cancel_run(run_id)` (`tools/api/run_manager.py:420`):

- Under `_lifecycle_lock`: `state=cancelling` + emit (capture any emit error to re-raise after cleanup), `cancellation.cancel()`, `decision_broker.cancel_all()`, `task = handle.task`.
- If `task is None` (run never started — still `awaiting_confirmation`): `state=cancelled` + emit, `close`, pop, re-raise captured emit error if any.
- Else `task.cancel()` then **outside** lock `await asyncio.wait({task}, timeout=max(0, api.shutdown_timeout_seconds))`; `pending` → `504 cancel_timeout`; re-raise captured emit error.

`shutdown()` (`tools/api/run_manager.py:534`): best-effort cancel each `run_id in list(_active)` (swallow) then `events.close_all()`.

## Serialization Helpers

`_request_to_dict`, `_preview_to_dict`, `_result_to_dict` (`tools/api/run_manager.py:569`) produce the dicts persisted in `request_json`/`preview_json`/`result_json`.

## Related

- `docs/api/persistence.md` — rows consumed/created here
- `docs/api/event-broker.md` — brokers owned here
- `tools/run_service/service.py` — the engine this manager drives
