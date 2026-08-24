---
title: API Persistence — SQLite (api_runtime.db), Migrations, Runs, Decisions, Users, Annotations
sources:
  - tools/api/persistence.py
  - app.py
tests:
  - tests/test_api_persistence.py
  - tests/test_api_runs.py
subsystem: api
status: maintained
---

# Persistence

`tools/api/persistence.py:131` `ApiPersistence` — thread-safe SQLite at `reports/api_runtime.db`. Separate from Flow B `research.db`; DB file lives inside `reports_dir` and is held open by the live instance (never deleted on reset — rows are deleted instead).

## Schema

DDL (`tools/api/persistence.py:21`):

```sql
CREATE TABLE _migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);

CREATE TABLE runs(
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'draft',
  request_json TEXT NOT NULL DEFAULT '{}',
  preview_json TEXT NOT NULL DEFAULT '{}',
  result_json TEXT NOT NULL DEFAULT '{}',
  resumed_from TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  cancelled_at TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL DEFAULT ''          -- v2
);
CREATE TABLE decisions(
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL,
  kind TEXT NOT NULL, prompt_text TEXT NOT NULL DEFAULT '',
  required_text TEXT NOT NULL DEFAULT '', options_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'pending', answer TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL, answered_at TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
);
CREATE TABLE users(                       -- D4
  id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, password_salt TEXT NOT NULL,
  created_at TEXT NOT NULL, last_login TEXT NOT NULL DEFAULT ''
);
CREATE TABLE annotations(                  -- D4
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, user_id TEXT NOT NULL,
  username TEXT NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '',
  finding_ref TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
  FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
);
CREATE INDEX idx_decisions_run_id ON decisions(run_id);
CREATE INDEX idx_runs_state ON runs(state);
CREATE INDEX idx_annotations_run_id ON annotations(run_id);
```

Version (`tools/api/persistence.py:18`) `3`. Migrations applied idempotently in `_init_db` (`tools/api/persistence.py:151`):

- v2 (`tools/api/persistence.py:90`): `ALTER TABLE runs ADD COLUMN title TEXT NOT NULL DEFAULT ''` when column missing.
- v3 (`tools/api/persistence.py:97`): create `users` + `annotations` idempotently (new DBs get them via DDL).
- Always `INSERT OR IGNORE (_SCHEMA_VERSION, now)`.

Thread safety: `self._lock = threading.Lock()` (`tools/api/persistence.py:138`) around every `_connect()` (`tools/api/persistence.py:145`, `check_same_thread=False`, `PRAGMA foreign_keys=ON`, `row_factory=sqlite3.Row`).

## Construction & Lifecycle

`ApiPersistence(reports_dir: Path)` (`tools/api/persistence.py:133`): `reports_dir.mkdir(parents=True)`, `self._path = reports_dir / "api_runtime.db"`, `_init_db()`.

`app.py:81` creates it; `app.py:100` lifespan calls `recover_interrupted()` on startup.

## Runs

| Method | Signature | Notes |
|--------|-----------|-------|
| `create_run` | `(run_id, request, preview)` | `state='draft'`, `request_json`/`preview_json`/`resumed_from` from `request.resume_source` (`tools/api/persistence.py:186`) |
| `update_run_state` | `(run_id, state, error="", result=None)` | sets `updated_at=now`, `result_json` if provided, `cancelled_at` when `state=='cancelled'` (`tools/api/persistence.py:207`) |
| `update_run_title` | `(run_id, title) -> bool` | strip, `false` if empty, cap `[:200]`, `rowcount>0` (`tools/api/persistence.py:237`) |
| `get_run` | `(run_id) -> dict|None` | `SELECT *`, json-parse `request_json`/`preview_json`/`result_json` (`tools/api/persistence.py:254`) |
| `list_runs` | `(limit=50, offset=0, sort="created_desc", q="", state="") -> list[dict]` | `order_by` from `_SORT_CLAUSES` (`tools/api/persistence.py:113`), `WHERE state=?` + `(title LIKE ? OR request_json LIKE ?)` case-insensitive; query `request_json`/`preview_json` for summary (`tools/api/persistence.py:268`) |
| `count_runs` | `(q="", state="") -> int` | same filters as `list_runs` (`tools/api/persistence.py:316`) |
| `get_active_run` | `() -> dict|None` | `WHERE state IN ('draft','awaiting_confirmation','running','awaiting_input','queued','cancelling') ORDER BY created_at DESC LIMIT 1` (`tools/api/persistence.py:339`) |
| `recover_interrupted` | `() -> int` | `UPDATE runs SET state='interrupted' WHERE state IN (live states)` + `UPDATE decisions SET status='expired' WHERE pending AND run interrupted` (`tools/api/persistence.py:353`) |
| `delete_run` | `(run_id) -> bool` | `DELETE FROM runs` (decisions/annotations cascade) (`tools/api/persistence.py:463`) |
| `reset_all` | `() -> int` | `DELETE FROM runs` keep file/schema (live instance stays valid); users kept (`tools/api/persistence.py:474`) |

Sort clauses (`tools/api/persistence.py:113`):

| `sort` | `ORDER BY` |
|--------|-----------|
| `created_desc` (default) | `created_at DESC` |
| `created_asc` | `created_at ASC` |
| `title_asc` | `title COLLATE NOCASE ASC, created_at DESC` |
| `title_desc` | `title COLLATE NOCASE DESC, created_at DESC` |
| `state_asc` | `state ASC, created_at DESC` |
| `state_desc` | `state DESC, created_at DESC` |

ID shape: `_new_id(prefix)` (`tools/api/persistence.py:127`) → `"{prefix}-{uuid4 hex[:12]}"` (`usr-`, `ann-`, `dec-`, `run-` via preview).

## Decisions

| Method | Signature | Notes |
|--------|-----------|-------|
| `create_decision` | `(decision dict) -> str` | id from `decision["id"] or _new_id("dec")`, `INSERT ... status='pending', created_at=now` (`tools/api/persistence.py:375`) |
| `answer_decision` | `(decision_id, answer) -> dict|None` | none if missing; returns row unchanged if already answered; else `UPDATE status='answered', answer, answered_at=now` (`tools/api/persistence.py:398`) |
| `get_decision` | `(decision_id) -> dict|None` | json-parse `options_json` (`tools/api/persistence.py:421`) |
| `list_decisions` | `(run_id) -> list[dict]` | `ORDER BY created_at` (`tools/api/persistence.py:434`) |
| `expire_pending_decisions` | `(run_id)` | `status='expired' WHERE pending` (`tools/api/persistence.py:451`) |

## Users (D4)

Only wired when `api.multi_operator` → `users_routes` mounted (`app.py:144`). `PBKDF2` hashing lives in `tools/api/auth.py`, not here.

| Method | Signature | Notes |
|--------|-----------|-------|
| `create_user` | `(username, hash, salt) -> str` | `id=_new_id("usr")`, raise `ValueError("already exists")` on `IntegrityError` (`tools/api/persistence.py:492`) |
| `get_user_by_username` | `(username) -> dict|None` | (`tools/api/persistence.py:509`) |
| `get_user` | `(user_id) -> dict|None` | (`tools/api/persistence.py:518`) |
| `list_users` | `() -> list[dict]` | `SELECT id, username, created_at, last_login ORDER BY created_at` (never hashes) (`tools/api/persistence.py:527`) |
| `touch_user_login` | `(user_id)` | `UPDATE last_login=now` (`tools/api/persistence.py:538`) |

## Annotations (D4)

Operator comments on findings, per `run_id` so the WebUI can render inline with the timeline.

| Method | Signature | Notes |
|--------|-----------|-------|
| `add_annotation` | `(run_id, user_id, username, body, finding_ref="") -> str` | `id=_new_id("ann")` (`tools/api/persistence.py:552`) |
| `list_annotations` | `(run_id) -> list[dict]` | `ORDER BY created_at` (`tools/api/persistence.py:575`) |
| `delete_annotation` | `(annotation_id) -> bool` | (`tools/api/persistence.py:588`) |

## Events

Events are **not** rows — `RunEventBroker` writes `reports/<run_id>/events.jsonl` + in-memory ring. Persistence only creates the `reports/<run_id>/` directory and owns the `reports_dir` path (`tools/api/persistence.py:142` `reports_dir` property) used by brokers and `list_runs` artifact overlays.

## Reset Semantics

`POST /api/v1/system/reset` (`tools/api/routes/system.py:526`) refuses when `run_manager.has_active`, else `reset_all()` (rows) + `shutil.rmtree(reports_dir)` etc., then `mkdir` + `_init_db()` so the live `ApiPersistence` keeps working. `research_workspace/research.db` tables are wiped in-place (file held open).

## Tests

`tests/test_api_persistence.py` exercises `create_run`/`list_runs`/`get_run`/`update_run_state`/`recover_interrupted`/decisions CRUD; `tests/test_api_runs.py` exercises run lifecycle via the HTTP layer.
