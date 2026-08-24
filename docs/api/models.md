---
title: API Models — RunRequest, RunPreview, RunResult, Decision, Event, Decisions
sources:
  - tools/run_service/models.py
  - tools/run_service/providers.py
  - tools/run_service/service.py
  - tools/api/persistence.py
  - tools/api/routes/runs.py
  - tools/api/routes/decisions.py
  - tools/api/routes/events.py
tests:
  - tests/test_api_persistence.py
  - tests/test_api_runs.py
subsystem: api
status: maintained
---

# Models

`tools/run_service/models.py:1` — transport-neutral dataclasses + enums shared between CLI (`main.async_main` via `AssessmentService.prepare/execute`) and the API daemon (`RunManager` + route handlers). The API returns many of these shapes serialized (also via `_request_to_dict`/`_preview_to_dict`/`_result_to_dict` in `tools/api/run_manager.py:569`). Events are `tools/run_service/models.py:230`; decisions are `tools/run_service/models.py:210`.

## Enums

| Enum | Values | Notes |
|------|--------|-------|
| `RunState` (`tools/run_service/models.py:26`) | `draft, awaiting_confirmation, queued, running, awaiting_input, cancelling, completed, failed, cancelled, interrupted` | terminal: `completed|failed|cancelled|interrupted`; `interrupted` set by `recover_interrupted` (`tools/api/persistence.py:353`) |
| `RunKind` (`tools/run_service/models.py:41`) | `agent` | `manual` removed — agent + MCP gateway only (drive manual calls via `POST /runs/{id}/tools/*/calls`) |
| `DecisionKind` (`tools/run_service/models.py:52`) | `start_confirm, goal_select, tool_approval, campaign_next_step` | `campaign_next_step` is the mid-run checkpoint (`service.py:964`) |
| `DecisionStatus` (`tools/run_service/models.py:59`) | `pending, answered, denied, expired` | `expired` = run cancelled/failed before answer (`decision_broker.cancel_all`) |

Helpers: `is_agent_attack_mode(mode: str)` (`tools/run_service/models.py:73`) → `mode in {attack, fast}`; `is_fast_mode` (`tools/run_service/models.py:84`) → `mode=="fast"`.

## `RunRequest`

`tools/run_service/models.py:88` — what operator wants to run. Built from `POST /api/v1/runs` `RunCreateRequest` (`tools/api/routes/runs.py:142`).

| Field | Type | Default | Setter |
|-------|------|---------|--------|
| `target` | `str` | required | `POST /runs.target` |
| `mode` | `RunMode("recon"|"attack"|"fast")` | `attack` | same |
| `goal_name` | `str` | `""` | `goal` |
| `custom_goal` | `str` | `""` | |
| `recon_first` | `bool|None` | `null` | null=auto (recon-first when no goal; skipped on resume `service.py:776`) |
| `model_alias` | `str` | `""` | `POST model` else `config models.default_alias` / `chatgpt.default_model` |
| `config_path` / `reports_dir` | `Path` | `config.yaml` / `reports` | overwritten to manager's values (`tools/api/run_manager.py:208`) |
| `swarm` / `parallel_swarm` / `critic` / `reflection` / `adaptive_exploits` / `long_session` | `bool` | `false` | power-ups |
| `multi_model_consult` | `bool|None` | none | `config multi_model.enabled` if none |
| `observer_mode` | `str` | `hybrid` | |
| `ultrathink` / `debug` / `plain` / `json_output` / `yes` | `bool` | `false` | `yes` skips `start_confirm` |
| `skills_mode` | `str|None` | none | `on/off/hints/lookup` (`tools/skills_cli.py`) |
| `skills_include` / `skills_exclude` | `str[]` | `[]` | |
| `skills_no_reselect` | `bool` | `false` | |
| `resume_source` | `str` | `""` | `resume` / set by resume route |
| `kind` | `RunKind` | `agent` | |
| `interactive` | `bool` | `false` | API-only target-via-menu flag |

`_request_to_dict` (`tools/api/run_manager.py:569`) serializes to `request_json`.

## `RunPreview`

`tools/run_service/models.py:132` — returned from `AssessmentService.prepare` before any side effects (`tools/run_service/service.py:498`). Serialized by `_preview_to_dict` (`tools/api/run_manager.py:598`).

| Field | Type | Notes |
|-------|------|-------|
| `run_id` | `str` | `strftime %Y%m%d_%H%M%S_%f` UTC (`service.py:618`) |
| `reports_dir` / `config_path` | `Path` | |
| `target_ip` | `str` | normalized (`_resolve_target`, validation `validate_target`) |
| `original_target` | `str` | operator input |
| `resolved_ip` / `resolved_domain` | `str|None` | for domains |
| `mode` / `goal_name` / `goal_description` | `str` | `GoalEngine` preset/ custom |
| `model_alias` / `model_label` | `str` | resolved via `models.registry`/`info` + `format_model_choice` |
| `transport_summary` | `str` | `f"http on port {http_port}"` |
| `permission` | `str` | `read_only|approve_only|full_access` |
| `attack_mode` | `bool` | `is_agent_attack_mode(mode)` |
| `swarm` / `parallel_swarm` / `multi_model` | `bool` | effective flags |
| `destructive` | `bool` | `permission==full_access && attack_mode` |
| `required_confirmation_text` | `str` | `""` non-destructive else `ALLOW <ip>` (`service.py:641`) |
| `budgets` | `dict` | `{commands, rounds, duration_minutes}` from `ExploitSettings` |
| `skill_activations` / `skill_errors` | `list[dict]` / `list[str]` | runtime skill selection |
| `resumed_from` | `str` | |

Shown to operator at the `start_confirm` gate. Frozen `config_snapshot` & `allowlist` at `create_run` so PATCH between confirm and start cannot retroactively change it.

## `RunResult`

`tools/run_service/models.py:170` — sanitized serializable outcome (keys in `_result_to_dict` `tools/api/run_manager.py:625`).

| Field | Type | Notes |
|-------|------|-------|
| `run_id` / `target_ip` / `mode` / `goal_name` / `goal_description` | `str` | |
| `total_actions` | `int` | executed actions |
| `workspace` / `audit_path` / `reports_dir` / `summary_path` / `run_json_path` | `str` | paths under `reports/<run_id>/` |
| `records` | `list[dict]` | audit records |
| `messages` | `list[dict]` | conversation |
| `error` | `str` | empty on success |
| `swarm_result` | `dict|None` | when swarm enabled |
| `active_skills` | `list[dict]` | |
| `outcome_summary` | `str` | verified-compromise + timeline summary |
| `telemetry` | `dict|None` | from `llm_usage.jsonl` snapshot |
| `safety_review` | `dict|None` | recon mode `safe_to_proceed` etc. |
| `cancelled` | `bool` | mid-run `cancel` at checkpoint (`service.py:1090`) |
| `objective_transitions` | `list[dict]` | `{from, to, at_checkpoint}` (`service.py:1060`) |

Persists in `result_json`.

## `Decision`

`tools/run_service/models.py:210`:

| Field | Type | Notes |
|-------|------|-------|
| `id` | `str` | assigned by broker `dec-<12hex>` (`decision_broker.py:34`) |
| `run_id` | `str` | |
| `kind` | `DecisionKind` | |
| `prompt_text` | `str` | |
| `required_text` | `str` | exact match needed for `start_confirm`/`tool_approval` |
| `options` | `list[dict]` | `goal_select` presets, `campaign_next_step` actions (+ nested goals) |
| `status` | `DecisionStatus` | (`pending` default) |
| `answer` | `str` | |
| `created_at` / `answered_at` | `str` | ISO UTC |

HTTP mapping `DecisionOut` is `tools/api/routes/decisions.py:41` (adds `options` field mapping from `options_json`).

## `Event`

`tools/run_service/models.py:230`:

| Field | Type | Notes |
|-------|------|-------|
| `sequence` | `int` | monotonic per broker (`event_broker.py:44`) |
| `timestamp` | `str` | `datetime.now(timezone.utc).isoformat()` |
| `run_id` | `str` | |
| `type` | `str` | `EVENT_*` constants (`models.py:248`) + runtime `heartbeat\|title\|approval` |
| `payload` | `dict` | `sanitize`'d |

Constants (`tools/run_service/models.py:248`): `EVENT_STATE`, `EVENT_BOOT`, `EVENT_PROGRESS`, `EVENT_PHASE`, `EVENT_GOAL_SUGGESTIONS`, `EVENT_RECON`, `EVENT_ASSISTANT`, `EVENT_TOOL_REQUEST`, `EVENT_TOOL_START`, `EVENT_TOOL_RESULT`, `EVENT_APPROVAL`, `EVENT_SWARM`, `EVENT_ARTIFACT`, `EVENT_COMPLETION`, `EVENT_ERROR`, plus Fast: `EVENT_FAST_RECON_STARTED` etc., `EVENT_AI_TAKEOVER_STARTED`.

Wire shape: HTTP `GET /events?after` and WS `send_json(event)` both use this shape. SSE wraps `data: {json}\n\n`.

## Pydantic route models

| Model | File | Fields |
|-------|------|--------|
| `RunCreateRequest` | `tools/api/routes/runs.py:142` | `target, mode, goal, custom_goal, recon_first, model, swarm, parallel_swarm, critic, reflection, adaptive_exploits, long_session, multi_model_consult, observer_mode, ultrathink, skills, skills_include, skills_exclude, resume, kind, yes` |
| `TitleRequest` | `tools/api/routes/runs.py:170` | `title?:str, regen:bool` |
| `ToolCallRequest` | `tools/api/routes/runs.py:177` | `arguments:dict` |
| `DecisionAnswer/Out` | `tools/api/routes/decisions.py:37` | `answer:str` / full row |
| `UserRequest/Response`, `AnnotationRequest/Response` | `tools/api/routes/users.py:61` | user/ann shapes when `multi_operator` |
| `EventOut` | `tools/api/routes/events.py:56` | typed event for OpenAPI |

## Provider protocols

`tools/run_service/providers.py:40` `DecisionProvider(request)->str`, `EventSink(emit)`, `ApprovalProvider(approve)` (`providers.py:193`), `CancellationToken` (`providers.py:346`). `Api*` vs `Terminal*` adapters wire CLI vs daemon; `ApiApprovalProvider` routes to `tool_approval` decision with `ALLOW <target>` required text (`providers.py:327`).
