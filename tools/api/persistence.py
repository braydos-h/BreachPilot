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

_SCHEMA_VERSION = 1
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
    cancelled_at TEXT NOT NULL DEFAULT ''
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
"""


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

    def list_runs(self, *, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM runs ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
                result = []
                for row in rows:
                    d = dict(row)
                    d["request_json"] = json.loads(d.get("request_json", "{}"))
                    d["preview_json"] = json.loads(d.get("preview_json", "{}"))
                    d["result_json"] = json.loads(d.get("result_json", "{}"))
                    result.append(d)
                return result
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
