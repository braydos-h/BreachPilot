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

_SCHEMA_VERSION = 3
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
    title TEXT NOT NULL DEFAULT ''
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
                applied = {
                    row["version"]
                    for row in conn.execute("SELECT version FROM _migrations").fetchall()
                }
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
                conn.execute(
                    "INSERT OR IGNORE INTO _migrations (version, applied_at) VALUES (?, ?)",
                    (_SCHEMA_VERSION, _now_iso()),
                )
                conn.commit()
            finally:
                conn.close()

    # ── Runs ──────────────────────────────────────────────────────────────

    def create_run(self, *, run_id: str, request: dict[str, Any], preview: dict[str, Any]) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO runs "
                    "(id, created_at, updated_at, state, request_json, preview_json, resumed_from) "
                    "VALUES (?, ?, ?, 'draft', ?, ?, ?)",
                    (
                        run_id, _now_iso(), _now_iso(),
                        json.dumps(request, default=str),
                        json.dumps(preview, default=str),
                        str(request.get("resume_source", "")),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def update_run_state(self, run_id: str, state: str, *, error: str = "", result: dict[str, Any] | None = None) -> None:
        with self._lock:
            conn = self._connect()
            try:
                if result is not None:
                    conn.execute(
                    "UPDATE runs SET state=?, updated_at=?, error=?, result_json=?, "
                    "cancelled_at=CASE WHEN ?='cancelled' THEN ? ELSE cancelled_at END WHERE id=?",
                    (
                        state, _now_iso(), error, json.dumps(result, default=str),
                        state, _now_iso(), run_id,
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
                rows = conn.execute(
                    f"SELECT id, created_at, state, request_json, preview_json, title "
                    f"FROM runs {where_sql} ORDER BY {order_by} LIMIT ? OFFSET ?",
                    (*params, limit, offset),
                ).fetchall()
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
                    f"SELECT COUNT(*) AS n FROM runs {where_sql}", params,
                ).fetchone()
                return int(row["n"]) if row else 0
            finally:
                conn.close()

    def get_active_run(self) -> dict[str, Any] | None:
        """Return the one live run (running/awaiting_input/queued/cancelling) if any."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM runs WHERE state IN "
                    "('draft', 'awaiting_confirmation', 'running', 'awaiting_input', 'queued', 'cancelling') "
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
                    "('draft', 'awaiting_confirmation', 'running', 'awaiting_input', 'queued', 'cancelling')",
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
                        did, decision.get("run_id", ""), decision.get("kind", ""),
                        decision.get("prompt_text", ""), decision.get("required_text", ""),
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
        """Delete a run and its decisions (cascade). Returns True if a row was removed."""
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM runs WHERE id=?", (run_id,))
                conn.commit()
                return cur.rowcount > 0
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
                    "INSERT INTO users (id, username, password_hash, password_salt, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
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
                row = conn.execute(
                    "SELECT * FROM users WHERE username=?", (username,)
                ).fetchone()
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
                    "UPDATE users SET last_login=? WHERE id=?", (_now_iso(), user_id),
                )
                conn.commit()
            finally:
                conn.close()

    # ── Annotations (D4: operator comments on findings) ───────────────────

    def add_annotation(
        self, run_id: str, user_id: str, username: str, body: str, finding_ref: str = "",
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
