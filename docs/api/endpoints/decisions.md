---
title: Decisions Endpoints — List, Get, Answer (start_confirm, goal_select, tool_approval, campaign_next_step)
sources:
  - tools/api/routes/decisions.py
  - tools/api/run_manager.py
  - tools/api/persistence.py
  - tools/api/decision_broker.py
  - tools/run_service/models.py
  - tools/run_service/providers.py
tests:
  - tests/test_api_frontend.py
  - tests/test_api_campaign_checkpoint.py
subsystem: api
---

# Decisions Endpoints

`tools/api/routes/decisions.py:1` — `APIRouter(prefix="/api/v1", tags=["decisions"])`. Wired by `decisions_routes.configure(auth, run_manager)` (`app.py:136`) and mounted `app.py:150`. All routes require bearer (`_require_auth` `tools/api/routes/decisions.py:25`). Persistence accessed through `run_manager._persistence`.

## Model

`DecisionOut` (`tools/api/routes/decisions.py:41`):

| Field | Type | Notes |
|-------|------|-------|
| `id` | `str` | `dec-<12hex>` |
| `run_id` | `str` | |
| `kind` | `str` | `DecisionKind` (`start_confirm|goal_select|tool_approval|campaign_next_step`) |
| `prompt_text` | `str` | human readable question / evidence summary |
| `required_text` | `str` | exact text to match for `start_confirm`/`tool_approval` |
| `options` | `list[dict]` | for `goal_select`: `{name, description, ...}`; for `campaign_next_step`: `{action, label, goals?}` |
| `status` | `str` | `pending|answered|denied|expired` |
| `answer` | `str` | filled when answered |
| `created_at` / `answered_at` | `str` | ISO UTC |

Stored rows are `tools/api/persistence.py:41` `decisions` with `options_json`.

## `GET /api/v1/runs/{run_id}/decisions` — `list_decisions`

`tools/api/routes/decisions.py:56` — `await run_manager.list_decisions(run_id)` (`tools/api/run_manager.py:481`) which raises `404 not_found` if run missing else returns `persistence.list_decisions` ordered `created_at`. Response `{decisions:[...raw rows with options_json/status/...]}`.

## `GET /api/v1/runs/{run_id}/decisions/{decision_id}` — `get_decision`

`tools/api/routes/decisions.py:63` — reads `persistence.get_decision(decision_id)` via `run_manager._persistence`; `404` if none or `row.run_id != run_id`. Returns typed `DecisionOut` mapping `options_json` → `options`.

Typical consumer: WebUI after seeing `approval` event `decision_id` to render prompt/required text.

## `POST /api/v1/runs/{run_id}/decisions/{decision_id}` — `answer_decision`

`tools/api/routes/decisions.py:91` — `Body DecisionAnswer {answer: str}` (`tools/api/routes/decisions.py:37`). Delegates to `run_manager.answer_decision(run_id, decision_id, body.answer)` (`tools/api/run_manager.py:454`):

1. Require active handle + `decision_broker`.
2. Load persisted row, verify `run_id` match and `status=="pending"` else `404 decision_not_found`.
3. If `kind==start_confirm` → `confirm_and_start(run_id, decision_id, answer)` validates `ALLOW <ip>` vs `y/yes` (`tools/api/run_manager.py:292`) and kicks off `_execute_run`; `400 invalid_confirmation`, `409 conflict` if already started.
4. Else `decision_broker.resolve(decision_id, answer)` (fails → `404`); emit `approval {decision_id,status:"answered",answer}`; if no `pending` rows remain, set `state=running` + emit.

Response `200 {decision_id, status:"answered"}`. The `await_answer` future unblock (`tools/api/decision_broker.py:60`) resumes `AssessmentService.execute` (goal selection, tool approval, or `checkpoint_hook` for `campaign_next_step` `tools/run_service/service.py:964`).

### Answer encoding

| Kind | Expected `answer` |
|------|-------------------|
| `start_confirm` (non-destructive) | `y` / `yes` (case-insensitive) |
| `start_confirm` (destructive) | exact `required_confirmation_text` e.g. `ALLOW 10.0.0.50` |
| `goal_select` | chosen goal name or custom text (`custom` branch in `tools/run_service/service.py:837`) |
| `tool_approval` | `ALLOW <target>` to approve, anything else deny (`tools/run_service/providers.py:262`) |
| `campaign_next_step` | `<action>` or `<action>:<goal>` or `<action>:custom:<text>` (`tools/run_service/service.py:1040`) |

Mid-run `campaign_next_step` actions (from `checkpoint_hook` `tools/run_service/service.py:987`):
- `access` checkpoint: `privesc|another_goal|finish|cancel`
- `no_path` checkpoint: `continue|change_goal|finish|cancel`

Fallback on empty answer / `EOFError`/`KeyboardInterrupt` is `finish` (terminal flow) and the service maps `cancelled_by_operator` to `RunState.cancelled` (`tools/api/run_manager.py:347`).

## Tests

`tests/test_api_frontend.py:534` `test_get_single_decision`; `tests/test_api_campaign_checkpoint.py` covers `campaign_next_step` persist + transition and `cancel` at checkpoint.
