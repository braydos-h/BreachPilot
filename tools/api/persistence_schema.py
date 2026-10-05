"""Versioned schema and incremental migrations for the API runtime database.

This database is isolated from Flow B's ``research.db``. Keep the schema
version and migration statements together so startup can apply each change
idempotently before serving API requests.
"""

from __future__ import annotations

_SCHEMA_VERSION = 5
_API_DB_NAME = "api_runtime.db"

_DDL = """
CREATE TABLE IF NOT EXISTS _migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'draft',
    request_json TEXT NOT NULL DEFAULT '{}',
    preview_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT NOT NULL DEFAULT '{}',
    resumed_from TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    cancelled_at TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    is_demo INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS decisions (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    prompt_text TEXT NOT NULL DEFAULT '',
    required_text TEXT NOT NULL DEFAULT '',
    options_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    answer TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    answered_at TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_decisions_run_id ON decisions(run_id);
CREATE INDEX IF NOT EXISTS idx_runs_state ON runs(state);

-- Phase 6.3 (D4): multi-operator user accounts + per-run annotations.
-- Users: password-hash auth (stdlib hashlib.pbkdf2_hmac + secrets). No roles
--   (AGENTS.md §E rejects a permissions system). The loopback bind is the
--   trust boundary; user accounts add attribution + pair-testing annotations.
-- Annotations: operator comments attached to a run's findings. Stored per
--   run_id so the WebUI can render them inline with the run timeline.
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_login TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS annotations (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    finding_ref TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_annotations_run_id ON annotations(run_id);

CREATE TABLE IF NOT EXISTS custom_goals (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE,
    objective TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(name)
);
CREATE INDEX IF NOT EXISTS idx_custom_goals_name ON custom_goals(name COLLATE NOCASE);
"""

# v2: add ``title`` column to runs for AI-generated session titles.
# Existing v1 DBs lack the column; ALTER it in idempotently. New DBs get it
# via _DDL above so this migration is a no-op there (PRAGMA table_info check).
_MIGRATION_V2 = [
    "ALTER TABLE runs ADD COLUMN title TEXT NOT NULL DEFAULT ''",
]

# v3 (D4): add multi-operator user accounts + per-run annotations tables.
# New DBs get them via _DDL; existing v2 DBs get them created idempotently
# (CREATE TABLE IF NOT EXISTS is safe to re-run).
_MIGRATION_V3 = [
    "CREATE TABLE IF NOT EXISTS users ("
    "id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, "
    "password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, "
    "created_at TEXT NOT NULL, last_login TEXT NOT NULL DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS annotations ("
    "id TEXT PRIMARY KEY, run_id TEXT NOT NULL, user_id TEXT NOT NULL, "
    "username TEXT NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '', "
    "finding_ref TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, "
    "FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE)",
    "CREATE INDEX IF NOT EXISTS idx_annotations_run_id ON annotations(run_id)",
]

# v4: demo session support — is_demo flag + tombstone app_state table.
_MIGRATION_V4 = [
    "ALTER TABLE runs ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0",
    "CREATE TABLE IF NOT EXISTS app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')",
]

# v5: persistent user-created custom goals (Goals tab + RunWizard).
_MIGRATION_V5 = [
    "CREATE TABLE IF NOT EXISTS custom_goals ("
    "id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE, "
    "objective TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
    "UNIQUE(name))",
    "CREATE INDEX IF NOT EXISTS idx_custom_goals_name ON custom_goals(name COLLATE NOCASE)",
]
