"""Versioned SQLite persistence for API run metadata and decisions.

Separate from Flow B's ``research.db`` — this DB owns only API-run state.
On daemon restart, any run in a live state (running/awaiting_input/queued/
cancelling) is marked ``interrupted`` and pending decisions are ``expired``.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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

# Sort clauses for list_runs. Keys map to the public ``sort`` query param.
# All use index-backed columns or the small runs table's natural size; no
# extra indexes needed at this scale.
_SORT_CLAUSES = {
    "created_desc": "created_at DESC",
    "created_asc": "created_at ASC",
    "title_asc": "title COLLATE NOCASE ASC, created_at DESC",
    "title_desc": "title COLLATE NOCASE DESC, created_at DESC",
    "state_asc": "state ASC, created_at DESC",
    "state_desc": "state DESC, created_at DESC",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class ApiPersistence:
    """Thread-safe SQLite access for API runs + decisions."""

    def __init__(self, reports_dir: Path) -> None:
        self._reports_dir = reports_dir
        self._path = reports_dir / _API_DB_NAME
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    @property
    def reports_dir(self) -> Path:
        return self._reports_dir

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(_DDL)
                # Apply incremental migrations for DBs created at an older
                # schema version. Each migration is gated on its column/idx
                # not already existing so re-runs are safe.
                applied = {row["version"] for row in conn.execute("SELECT version FROM _migrations").fetchall()}
                if 2 not in applied and "title" not in {
                    r["name"] for r in conn.execute("PRAGMA table_info(runs)").fetchall()
                }:
                    for stmt in _MIGRATION_V2:
                        conn.execute(stmt)
                    conn.execute(
                        "INSERT OR IGNORE INTO _migrations (version, applied_at) VALUES (?, ?)",
                        (2, _now_iso()),
                    )
                if 3 not in applied:
                    for stmt in _MIGRATION_V3:
                        conn.execute(stmt)
                    conn.execute(
                        "INSERT OR IGNORE INTO _migrations (version, applied_at) VALUES (?, ?)",
                        (3, _now_iso()),
                    )
                # v4: is_demo column + app_state table
                cols = {r["name"] for r in conn.execute("PRAGMA table_info(runs)").fetchall()}
                has_is_demo = "is_demo" in cols
                has_app_state = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='app_state'"
                ).fetchone()
                if not has_is_demo or not has_app_state:
                    for stmt in _MIGRATION_V4:
                        try:
                            conn.execute(stmt)
                        except sqlite3.OperationalError as exc:
                            # duplicate column/table on re-run is safe
                            if "duplicate column" not in str(exc).lower() and "already exists" not in str(exc).lower():
                                raise
                    if 4 not in applied:
                        conn.execute(
                            "INSERT OR IGNORE INTO _migrations (version, applied_at) VALUES (?, ?)",
                            (4, _now_iso()),
                        )
                elif 4 not in applied:
                    conn.execute(
                        "INSERT OR IGNORE INTO _migrations (version, applied_at) VALUES (?, ?)",
                        (4, _now_iso()),
                    )
                # v5: custom_goals table for persistent user-created goals
                has_custom_goals = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='custom_goals'"
                ).fetchone()
                if not has_custom_goals:
                    for stmt in _MIGRATION_V5:
                        try:
                            conn.execute(stmt)
                        except sqlite3.OperationalError as exc:
                            if "already exists" not in str(exc).lower():
                                raise
                    if 5 not in applied:
                        conn.execute(
                            "INSERT OR IGNORE INTO _migrations (version, applied_at) VALUES (?, ?)",
                            (5, _now_iso()),
                        )
                elif 5 not in applied:
                    conn.execute(
                        "INSERT OR IGNORE INTO _migrations (version, applied_at) VALUES (?, ?)",
                        (5, _now_iso()),
                    )
                conn.execute(
                    "INSERT OR IGNORE INTO _migrations (version, applied_at) VALUES (?, ?)",
                    (_SCHEMA_VERSION, _now_iso()),
                )
                conn.commit()
            finally:
                conn.close()

    # ── Runs ──────────────────────────────────────────────────────────────

    def create_run(
        self,
        *,
        run_id: str,
        request: dict[str, Any],
        preview: dict[str, Any],
        state: str = "draft",
        title: str = "",
        is_demo: bool = False,
        created_at: str | None = None,
    ) -> None:
        now = created_at or _now_iso()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO runs "
                    "(id, created_at, updated_at, state, request_json, preview_json, resumed_from, title, is_demo) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        run_id,
                        now,
                        now,
                        state,
                        json.dumps(request, default=str),
                        json.dumps(preview, default=str),
                        str(request.get("resume_source", "")),
                        title,
                        1 if is_demo else 0,
                    ),
                )
                if is_demo:
                    # Mark that demo has been seeded at least once (for tombstone logic).
                    conn.execute(
                        "INSERT OR IGNORE INTO app_state (key, value) VALUES (?, ?)",
                        ("demo_seed_version", "1"),
                    )
                conn.commit()
            finally:
                conn.close()

    def update_run_preview(self, run_id: str, preview: dict[str, Any]) -> None:
        """Persist the prepared preview (target/mode/goal/model/...) after background preparation."""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE runs SET preview_json=?, updated_at=? WHERE id=?",
                    (json.dumps(preview, default=str), _now_iso(), run_id),
                )
                conn.commit()
            finally:
                conn.close()

    def update_run_state(
        self, run_id: str, state: str, *, error: str = "", result: dict[str, Any] | None = None
    ) -> None:
        with self._lock:
            conn = self._connect()
            try:
                if result is not None:
                    conn.execute(
                        "UPDATE runs SET state=?, updated_at=?, error=?, result_json=?, "
                        "cancelled_at=CASE WHEN ?='cancelled' THEN ? ELSE cancelled_at END WHERE id=?",
                        (
                            state,
                            _now_iso(),
                            error,
                            json.dumps(result, default=str),
                            state,
                            _now_iso(),
                            run_id,
                        ),
                    )
                else:
                    conn.execute(
                        "UPDATE runs SET state=?, updated_at=?, error=?, "
                        "cancelled_at=CASE WHEN ?='cancelled' THEN ? ELSE cancelled_at END WHERE id=?",
                        (state, _now_iso(), error, state, _now_iso(), run_id),
                    )
                conn.commit()
            finally:
                conn.close()

    def update_run_title(self, run_id: str, title: str) -> bool:
        """Persist an AI-generated (or manual) title for a run. Returns True if updated."""
        title = (title or "").strip()
        if not title:
            return False
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "UPDATE runs SET title=?, updated_at=? WHERE id=?",
                    (title[:200], _now_iso(), run_id),
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
                if row is None:
                    return None
                d = dict(row)
                for key in ("request_json", "preview_json", "result_json"):
                    d[key] = json.loads(d.get(key, "{}"))
                return d
            finally:
                conn.close()

    def list_runs(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        sort: str = "created_desc",
        q: str = "",
        state: str = "",
    ) -> list[dict[str, Any]]:
        """List runs with target/mode/goal/model summary (no N+1 queries).

        ``sort`` is one of: created_desc (default, newest first), created_asc
        (oldest first), title_asc, title_desc, state_asc, state_desc. Unknown
        values fall back to the default. Sorting on title treats empty titles
        as the empty string (so they cluster together, not at either extreme).

        ``q`` filters on title + request_json (target/mode/goal) via a
        case-insensitive substring match; ``state`` filters on the exact state.
        """
        order_by = _SORT_CLAUSES.get(sort, _SORT_CLAUSES["created_desc"])
        where: list[str] = []
        params: list[Any] = []
        if state:
            where.append("state = ?")
            params.append(state)
        if q:
            where.append("(title LIKE ? OR request_json LIKE ?)")
            like = f"%{q}%"
            params.extend([like, like])
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        with self._lock:
            conn = self._connect()
            try:
                # ``is_demo`` may be absent on a pre-migrated DB before _init_db
                # ran; SELECT * would hide that, but the explicit column tolerates
                # the migration race via a fallback query.
                try:
                    rows = conn.execute(
                        f"SELECT id, created_at, state, request_json, preview_json, title, is_demo "
                        f"FROM runs {where_sql} ORDER BY {order_by} LIMIT ? OFFSET ?",
                        (*params, limit, offset),
                    ).fetchall()
                except sqlite3.OperationalError as exc:
                    if "no such column: is_demo" in str(exc):
                        rows = conn.execute(
                            f"SELECT id, created_at, state, request_json, preview_json, title "
                            f"FROM runs {where_sql} ORDER BY {order_by} LIMIT ? OFFSET ?",
                            (*params, limit, offset),
                        ).fetchall()
                        # Backfill missing key so callers can rely on it.
                        rows = [dict(r) | {"is_demo": 0} for r in rows]
                        result = []
                        for row in rows:
                            d = dict(row)
                            d["request_json"] = json.loads(d.get("request_json", "{}"))
                            d["preview_json"] = json.loads(d.get("preview_json", "{}"))
                            result.append(d)
                        return result
                    raise
                result = []
                for row in rows:
                    d = dict(row)
                    d["request_json"] = json.loads(d.get("request_json", "{}"))
                    d["preview_json"] = json.loads(d.get("preview_json", "{}"))
                    result.append(d)
                return result
            finally:
                conn.close()

    def count_runs(self, *, q: str = "", state: str = "") -> int:
        """Count runs matching the same filters as ``list_runs`` (for pagination)."""
        where: list[str] = []
        params: list[Any] = []
        if state:
            where.append("state = ?")
            params.append(state)
        if q:
            where.append("(title LIKE ? OR request_json LIKE ?)")
            like = f"%{q}%"
            params.extend([like, like])
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    f"SELECT COUNT(*) AS n FROM runs {where_sql}",
                    params,
                ).fetchone()
                return int(row["n"]) if row else 0
            finally:
                conn.close()

    def get_active_run(self) -> dict[str, Any] | None:
        """Return the one live run (preparing/running/awaiting_input/queued/cancelling/...) if any."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM runs WHERE state IN "
                    "('draft', 'preparing', 'awaiting_confirmation', 'running', 'awaiting_input', 'queued', 'cancelling') "
                    "ORDER BY created_at DESC LIMIT 1"
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def recover_interrupted(self) -> int:
        """Mark live runs as interrupted on startup; expire pending decisions."""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE runs SET state='interrupted', updated_at=? "
                    "WHERE state IN "
                    "('draft', 'preparing', 'awaiting_confirmation', 'running', 'awaiting_input', 'queued', 'cancelling')",
                    (_now_iso(),),
                )
                conn.execute(
                    "UPDATE decisions SET status='expired' WHERE status='pending' "
                    "AND run_id IN (SELECT id FROM runs WHERE state='interrupted')"
                )
                conn.commit()
                return conn.total_changes
            finally:
                conn.close()

    # ── Decisions ─────────────────────────────────────────────────────────

    def create_decision(self, decision: dict[str, Any]) -> str:
        did = decision.get("id") or _new_id("dec")
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO decisions (id, run_id, kind, prompt_text, required_text, options_json, status, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)",
                    (
                        did,
                        decision.get("run_id", ""),
                        decision.get("kind", ""),
                        decision.get("prompt_text", ""),
                        decision.get("required_text", ""),
                        json.dumps(decision.get("options", []), default=str),
                        _now_iso(),
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        return did

    def answer_decision(self, decision_id: str, answer: str) -> dict[str, Any] | None:
        """Mark a decision as answered; returns the decision row or None if not found."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
                if row is None:
                    return None
                d = dict(row)
                if d["status"] != "pending":
                    return d
                conn.execute(
                    "UPDATE decisions SET status='answered', answer=?, answered_at=? WHERE id=?",
                    (answer, _now_iso(), decision_id),
                )
                conn.commit()
                d["status"] = "answered"
                d["answer"] = answer
                d["answered_at"] = _now_iso()
                return d
            finally:
                conn.close()

    def get_decision(self, decision_id: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
                if row is None:
                    return None
                d = dict(row)
                d["options_json"] = json.loads(d.get("options_json", "[]"))
                return d
            finally:
                conn.close()

    def list_decisions(self, run_id: str) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM decisions WHERE run_id=? ORDER BY created_at",
                    (run_id,),
                ).fetchall()
                result = []
                for row in rows:
                    d = dict(row)
                    d["options_json"] = json.loads(d.get("options_json", "[]"))
                    result.append(d)
                return result
            finally:
                conn.close()

    def expire_pending_decisions(self, run_id: str) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE decisions SET status='expired' WHERE run_id=? AND status='pending'",
                    (run_id,),
                )
                conn.commit()
            finally:
                conn.close()

    def delete_run(self, run_id: str) -> bool:
        """Delete a run and its decisions (cascade). Returns True if a row was removed.

        When the deleted run is the demo (is_demo=1) the durable tombstone
        ``demo_deleted=1`` is set in ``app_state`` so the demo is NOT recreated
        on the next restart/seed. Centralized here so every deletion path (UI,
        API, direct) respects the tombstone without scattering checks.
        """
        with self._lock:
            conn = self._connect()
            try:
                # Detect demo before deleting so the tombstone survives the FK cascade.
                is_demo_row = None
                try:
                    is_demo_row = conn.execute("SELECT is_demo FROM runs WHERE id=?", (run_id,)).fetchone()
                except sqlite3.OperationalError:
                    pass
                is_demo = bool(is_demo_row and is_demo_row["is_demo"])
                cur = conn.execute("DELETE FROM runs WHERE id=?", (run_id,))
                if is_demo and cur.rowcount > 0:
                    conn.execute(
                        "INSERT OR REPLACE INTO app_state (key, value) VALUES (?, ?)",
                        ("demo_deleted", "1"),
                    )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def is_demo_tombstoned(self) -> bool:
        """Return True when the demo was intentionally deleted (do not recreate)."""
        with self._lock:
            conn = self._connect()
            try:
                try:
                    row = conn.execute("SELECT value FROM app_state WHERE key='demo_deleted'").fetchone()
                except sqlite3.OperationalError:
                    return False
                return bool(row and row["value"] == "1")
            finally:
                conn.close()

    def set_demo_tombstone(self, deleted: bool) -> None:
        """Explicitly set/clear the demo tombstone (for testing + restore path)."""
        with self._lock:
            conn = self._connect()
            try:
                # Ensure app_state exists (old DBs migrated lazily).
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')"
                )
                if deleted:
                    conn.execute(
                        "INSERT OR REPLACE INTO app_state (key, value) VALUES (?, ?)",
                        ("demo_deleted", "1"),
                    )
                else:
                    conn.execute("DELETE FROM app_state WHERE key='demo_deleted'")
                conn.commit()
            finally:
                conn.close()

    def get_demo_tombstone(self) -> bool:
        return self.is_demo_tombstoned()

    def clear_demo_tombstone(self) -> None:
        self.set_demo_tombstone(False)

    def get_app_state(self, key: str) -> str | None:
        with self._lock:
            conn = self._connect()
            try:
                try:
                    row = conn.execute("SELECT value FROM app_state WHERE key=?", (key,)).fetchone()
                except sqlite3.OperationalError:
                    return None
                return str(row["value"]) if row else None
            finally:
                conn.close()

    def set_app_state(self, key: str, value: str) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')"
                )
                conn.execute("INSERT OR REPLACE INTO app_state (key, value) VALUES (?, ?)", (key, value))
                conn.commit()
            finally:
                conn.close()

    def reset_all(self) -> int:
        """Delete all runs, decisions, and annotations (users are kept).

        Decisions and annotations cascade via the runs FK. The DB file and
        schema stay intact so the app's live persistence instance keeps
        working after a reset.
        """
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM runs")
                conn.commit()
                return cur.rowcount
            finally:
                conn.close()

    # ── Users (D4: multi-operator accounts) ────────────────────────────────

    def create_user(self, username: str, password_hash: str, password_salt: str) -> str:
        """Insert a user row. Returns the user id. Raises on duplicate username."""
        uid = _new_id("usr")
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO users (id, username, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?)",
                    (uid, username, password_hash, password_salt, _now_iso()),
                )
                conn.commit()
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"username {username!r} already exists") from exc
            finally:
                conn.close()
        return uid

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def list_users(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT id, username, created_at, last_login FROM users ORDER BY created_at"
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def touch_user_login(self, user_id: str) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE users SET last_login=? WHERE id=?",
                    (_now_iso(), user_id),
                )
                conn.commit()
            finally:
                conn.close()

    # ── Annotations (D4: operator comments on findings) ───────────────────

    def add_annotation(
        self,
        run_id: str,
        user_id: str,
        username: str,
        body: str,
        finding_ref: str = "",
    ) -> str:
        """Attach an operator comment to a run. Returns the annotation id."""
        aid = _new_id("ann")
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO annotations (id, run_id, user_id, username, body, finding_ref, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (aid, run_id, user_id, username, body, finding_ref, _now_iso()),
                )
                conn.commit()
            finally:
                conn.close()
        return aid

    def list_annotations(self, run_id: str) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT id, run_id, user_id, username, body, finding_ref, created_at "
                    "FROM annotations WHERE run_id=? ORDER BY created_at",
                    (run_id,),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def delete_annotation(self, annotation_id: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM annotations WHERE id=?", (annotation_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    # ── Custom goals (persistent user-created goals) ──────────────────────

    def list_custom_goals(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT id, name, objective, created_at, updated_at FROM custom_goals ORDER BY created_at"
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_custom_goal(self, goal_id: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT id, name, objective, created_at, updated_at FROM custom_goals WHERE id=?",
                    (goal_id,),
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def get_custom_goal_by_name(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT id, name, objective, created_at, updated_at FROM custom_goals WHERE name=? COLLATE NOCASE",
                    (name,),
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def create_custom_goal(self, name: str, objective: str) -> dict[str, Any]:
        gid = _new_id("goal")
        now = _now_iso()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO custom_goals (id, name, objective, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (gid, name, objective, now, now),
                )
                conn.commit()
            except sqlite3.IntegrityError as exc:
                # UNIQUE violation (case-insensitive) -> duplicate name
                if "UNIQUE" in str(exc) or "unique" in str(exc).lower():
                    raise ValueError(f"custom goal name {name!r} already exists") from exc
                raise
            finally:
                conn.close()
        return {"id": gid, "name": name, "objective": objective, "created_at": now, "updated_at": now}

    def update_custom_goal(self, goal_id: str, name: str, objective: str) -> dict[str, Any] | None:
        now = _now_iso()
        with self._lock:
            conn = self._connect()
            try:
                # Verify existence first
                row = conn.execute("SELECT id FROM custom_goals WHERE id=?", (goal_id,)).fetchone()
                if row is None:
                    return None
                try:
                    cur = conn.execute(
                        "UPDATE custom_goals SET name=?, objective=?, updated_at=? WHERE id=?",
                        (name, objective, now, goal_id),
                    )
                    conn.commit()
                    if cur.rowcount == 0:
                        return None
                except sqlite3.IntegrityError as exc:
                    if "UNIQUE" in str(exc) or "unique" in str(exc).lower():
                        raise ValueError(f"custom goal name {name!r} already exists") from exc
                    raise
                updated = conn.execute(
                    "SELECT id, name, objective, created_at, updated_at FROM custom_goals WHERE id=?",
                    (goal_id,),
                ).fetchone()
                return dict(updated) if updated else None
            finally:
                conn.close()

    def delete_custom_goal(self, goal_id: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM custom_goals WHERE id=?", (goal_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()
