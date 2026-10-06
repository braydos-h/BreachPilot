---
title: Runs Endpoints — Create, List, Get, Cancel, Resume, Title, Tools, Artifacts, Workspace, Audit, Swarm, Logs, Credentials, Loot
sources:
  - tools/api/routes/runs.py
  - tools/api/run_manager.py
  - tools/api/persistence.py
  - tools/api/event_broker.py
  - tools/run_service/models.py
tests:
  - tests/test_api_runs.py
  - tests/test_api_frontend.py
subsystem: api
---

# Runs Endpoints

`tools/api/routes/runs.py:1` — `APIRouter(prefix="/api/v1", tags=["runs"])`. Configured by `runs_routes.configure(auth, persistence, run_manager)` (`app.py:135`). Every route below requires bearer (`_require_auth` `tools/api/routes/runs.py:37`); unknown `run_id` is `404`.

Shared guards: `_run_dir(run_id)` (`tools/api/routes/runs.py:55`) resolve `reports/<run_id>/` with escape check; `_safe_child` (`tools/api/routes/runs.py:98`) and `_safe_workspace_path` (`tools/api/routes/runs.py:121`) refuse `..`/absolute traversal. Whitelists: `_ARTIFACT_WHITELIST`, `_LOG_WHITELIST`, `_CONTENT_TYPES` (`tools/api/routes/runs.py:64`).

Request model: `RunCreateRequest` (`tools/api/routes/runs.py:243`) and `TitleRequest`, `ToolCallRequest`, `HitlDecideRequest` (`tools/api/routes/runs.py:269-282`).

## `POST /api/v1/runs` — `create_run` — 201

`tools/api/routes/runs.py:471` — persist the run request and begin preparation.

Body `RunCreateRequest`:

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `target` | `str` | required | IP or domain |
| `mode` | `recon|attack|fast` | `attack` | `fast` = parallel recon preset |
| `goal` | `str` | `""` | preset name |
| `custom_goal` | `str` | `""` | free text |
| `recon_first` | `bool|null` | `null` | null auto |
| `model` | `str|null` | `null` | alias override |
| `swarm` / `parallel_swarm` / `critic` / `reflection` / `adaptive_exploits` / `long_session` / `multi_model_consult` / `ultrathink` | `bool` variants | `false`/`null` | power-ups |
| `observer_mode` | `str` | `hybrid` | |
| `skills` | `str|null` | `null` | `on/off/hints/lookup` |
| `skills_include` / `skills_exclude` | `str[]` | `[]` | |
| `resume` | `str` | `""` | source `run_id` |
| `kind` | `agent` | `agent` | only `agent` is presently supported |
| `yes` | `bool` | `false` | skip `start_confirm` |

The handler builds `RunRequest(kind=RunKind(body.kind), ...)` and calls `run_manager.create_run`. Preparation may continue in the background after this request returns. The common response is `201` with `preview: null` and `state: "preparing"`:

```json
{
  "run_id": "20260809_...",
  "preview": null,
  "state": "preparing"
}
```

Poll `GET /runs/{run_id}` and subscribe to `GET /runs/{run_id}/events` while preparation completes. The prepared preview and start-confirm decision are persisted and exposed by the run and decision endpoints. If preparation completes before the create response is assembled, `preview` may already be present; the state is `awaiting_confirmation` when a decision is pending or `queued` when execution can start. `yes=true` skips the start-confirm decision after preparation. `409 conflict` is returned when the active-run limit prevents creation.

## `POST /api/v1/runs/demo/restore` — `restore_demo`

Idempotently restores the built-in demo record and artifacts and clears its deletion tombstone. Returns `200 {run_id, restored:true}`.

## `GET /api/v1/runs` — `list_runs`

`tools/api/routes/runs.py:539` — paginated, sortable, searchable history. Query: `limit 1..200 default 50`, `offset≥0`, `sort` enum `created_desc|created_asc|title_asc|title_desc|state_asc|state_desc`, `q` filter `≤200`, and `state` exact filter `≤32`. Calls persistence asynchronously. Each row includes `{id, state, created_at, target, mode, goal_name, target_ip, model_alias, title}`. Response `{runs:[...], sort, total}`.

## `GET /api/v1/runs/{run_id}` — `get_run`

`tools/api/routes/runs.py:583` — full detail: `{id, state, created_at, updated_at, request, preview, result, error, title, cancelled_at, resumed_from, is_demo, decisions:[{id,kind,status,answer}]}`. `404` if missing.

## `POST /api/v1/runs/{run_id}/cancel` — `cancel_run`

`tools/api/routes/runs.py:290` — delegates to `run_manager.cancel_run` (`tools/api/run_manager.py:420`): `cancelling` → `cancellation.cancel()` + `decision_broker.cancel_all()` + `task.cancel()` + wait `api.shutdown_timeout_seconds` else `504 cancel_timeout`. Response `{run_id, state:"cancelled"}`. Pending decisions resolved with `""` so `service.execute` unblocks.

## `POST /api/v1/runs/{run_id}/resume` — `resume_run`

`tools/api/routes/runs.py:622` — copy original request fields supported by `RunRequest`, set `resume_source=run_id`, preserve the kind, and require the normal confirmation flow. Response `{run_id: new, resumed_from: old}`; preparation and preview follow the ordinary background run lifecycle. `404` if original missing; the active-run cap may reject creation.

## `POST /api/v1/runs/{run_id}/title` — `set_run_title`

`tools/api/routes/runs.py:319` — `TitleRequest {title?:str|null, regen:bool}`. `404` if missing. If `title` non-empty `[:200]` and changed → `persistence.update_run_title`. Else if `!title && regen` → off-thread `generate_session_title_sync(result_json, request_json, host=ollama.host, config)` (`tools/api/session_titler.py:148`) best-effort; if non-empty and changed, persist. Else return current. Response `{run_id, title, regenerated: bool}`; titler failure returns current with `200`.

## `GET /api/v1/runs/{run_id}/tools` — `get_tools`

`tools/api/routes/runs.py:358` — live MCP schemas from `run_manager.get_tool_schemas(run_id)` (`tools/api/run_manager.py:514`) (plugin-contributed included after attach). Returns `{tools: [...]}`; `[]` when run inactive or no session.

## `POST /api/v1/runs/{run_id}/tools/{tool_name}/calls` — `call_tool`

`tools/api/routes/runs.py:365` — `ToolCallRequest {arguments:dict}`. Delegates to `run_manager.call_tool` (`tools/api/run_manager.py:486`): require `mcp_session` (`409 no_session`), `exploit_policy` (`409 no_policy`), `tool_name` in `tool_schemas` (`404 tool_not_found`), `tool_lock`, `exploit_policy.approve_action(tool, json.dumps(args, sort_keys), "Manual WebUI tool call")` → `403 tool_denied`, `mcp_session.call_tool` → `500 tool_error` on `BaseExceptionGroup`, extract text blocks → `{tool, result}`.

## Artifacts (B2–B3)

### `GET /api/v1/runs/{run_id}/artifacts` — `list_artifacts` — `tools/api/routes/runs.py:376`

Lists present files under `reports/<run_id>/`. Whitelisted top-level `_ARTIFACT_WHITELIST` + every file under `enhanced/` when the dir exists. Returns `{artifacts:[{name, bytes, exists:true}]}`.

### `GET /api/v1/runs/{run_id}/artifacts/{name:path}` — `get_artifact` — `tools/api/routes/runs.py:401`

Whitelist-bound + traversal-safe via `_safe_child`. `enhanced/` prefix checked against `enhanced.iterdir()` listing (missing dir → `404` not `500`). Returns raw `Response` with `content_type` from `_CONTENT_TYPES` by suffix, `404` when not whitelisted/exists.

## Workspace (C10)

### `GET /api/v1/runs/{run_id}/workspace` — `list_workspace` — `tools/api/routes/runs.py:432`

Lists `exploit_workspace/` under the run dir recursively via `rglob`, `{files:[{path: relative POSIX, bytes}]}`. Empty `[]` when no workspace.

### `GET /api/v1/runs/{run_id}/workspace/{path:path}` — `get_workspace_file` — `tools/api/routes/runs.py:447`

Reads one file under `exploit_workspace/` via `_safe_workspace_path` (arbitrary depth, but no `..`). `404` if not found. Returns raw `Response` with `_CONTENT_TYPES`.

## Audit (C6)

### `GET /api/v1/runs/{run_id}/audit` — `get_audit` — `tools/api/routes/runs.py:465`

Reads the host-owned `reports/<run_id>/exploit_audit.jsonl`; older runs may fall back to `exploit_workspace/exploit_audit.jsonl`. Current runs create the canonical report-side file before worker startup, so a worker-writable legacy copy is not selected. Parsing tolerates malformed JSONL rows; `tools.exploit_agent.policy.verify_audit_chain(path)` checks the chain. Returns `{records:[...], chain_valid:bool, chain_reason:str}`.

## Errors, sandbox, and human review

- `GET /api/v1/runs/{run_id}/errors?kind=&tail=200` returns `{run_id, records, total_records, kinds}` from `errors.jsonl`; `tail` is bounded to 1–2000. An assessment with no deep-error records returns an empty list.
- `GET /api/v1/runs/{run_id}/sandbox` returns a read-only summary derived from the run's audit and event artifacts. It does not control a live worker.
- `GET /api/v1/runs/{run_id}/proposed` returns findings awaiting operator review, each with its read-only proof capsule.
- `POST /api/v1/runs/{run_id}/decide` accepts `{finding_id, decision, note}` and persists a human decision. The server sets the actor to `human`; clients cannot self-assert an agent decision as human review. It returns `{run_id, finding_id, finding}`.

## Swarm / Campaign / Witness

- `GET /api/v1/runs/{run_id}/witness` — `get_witness_flags` (`tools/api/routes/runs.py:513`) reads process-global `witness.log_path` (`reports/witness.jsonl` default, via `config["witness"]`), `404` when absent, else `{flags:[...]}` parsed JSONL.
- `GET /api/v1/runs/{run_id}/swarm` — `get_swarm_state` (`tools/api/routes/runs.py:544`) reads `swarm_workspace/swarm_state.json` via `_read_state_json` `404` if missing.
- `GET /api/v1/runs/{run_id}/campaign` — `get_campaign_state` (`tools/api/routes/runs.py:551`) reads `swarm_workspace/autonomous/attack_states.json`.
- Helper `_read_state_json(run_id, filename, subdir)` (`tools/api/routes/runs.py:499`) — traverses `_run_dir/run_id/swarm_workspace/[subdir]/filename`.

## `GET /api/v1/runs/{run_id}/logs/{name}` — `get_log` — `tools/api/routes/runs.py:563`

Whitelist `_LOG_WHITELIST ∪ {terminal.log, python_run.log, msf_output.log, run_active_check.ps1}`. `tail 1..2000 default 200`. Per-attempt logs require `attempt_id` + `target_ip` (resolved under `exploit_workspace/<ip>/<id>/name`). Candidates include workspace copy for `mcp_exploit_server.log`. Returns `{name, lines:[...], total_lines_returned, total_lines_in_file}`. `404` for unknown log, `400` when per-attempt params missing.

## Credentials + Loot (C3–C5)

- Helpers `_exploit_workspace`, `_credential_access_log`, `_find_credential_stores` (`tools/api/routes/runs.py:612`): finds `credentials/<target>/credentials.jsonl` per target + legacy `credentials.jsonl`.
- `GET /api/v1/runs/{run_id}/credentials` — `list_credentials` (`tools/api/routes/runs.py:640`) iterates `CredentialStore(parent)` per store, maps `rec.to_json()` with `password:"[REDACTED]"` + synthetic `index`.
- `POST /api/v1/runs/{run_id}/credentials/{index}/reveal` — `reveal_credential` (`tools/api/routes/runs.py:667`) global index across stores, audits `credential_access.jsonl`, returns `{index, username, target_host, password}` plaintext (auth required to call).
- `POST /api/v1/runs/{run_id}/credentials/{index}/confirm` — authenticated operator action; marks `confirmed` after the operator reviews successful reuse evidence, audits with `action:"confirm"`, and returns `{index, username, target_host, confirmed}`. Agent-facing MCP confirmation is disabled.
- `GET /api/v1/runs/{run_id}/loot` — `list_loot` (`tools/api/routes/runs.py:770`) candidates `exploit_workspace/loot/loot.jsonl` (modern per `LootStore(workspace/"loot")`) else `exploit_workspace/loot.jsonl` (legacy); returns `{loot: [item.to_json()]}`.
- Errors `500` on credential/loot read failures.

## `DELETE /api/v1/runs/{run_id}` — `delete_run` — `tools/api/routes/runs.py:796` — D1

Refuses `404` missing; refuses active run `409 conflict` when `has_active && active.run_id==run_id`. Optional `?purge=true` `shutil.rmtree(reports/<run_id>/)`. Then `persistence.delete_run(run_id)` (cascade). Response `{run_id, deleted:true, purged:bool}`.
