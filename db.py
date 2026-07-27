"""Persistent SQLite database for the authorized bug bounty research agent.

Schema: missions, scope_rules, tasks, hypotheses, outcome assessments,
observations, graph_nodes, graph_edges, evidence, findings, audit logs, memories.

All IDs use a consistent format: {prefix}-{sequence}. Timestamps are ISO8601 UTC.
JSON fields are stored as TEXT and deserialized on read.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

_SCHEMA_VERSION = 4
_MIGRATIONS_TABLE = "_migrations"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    short = uuid.uuid4().hex[:8].upper()
    seq = int(time.time() * 1000) % 100000
    return f"{prefix}-{seq:05d}-{short}"


# ── SQL DDL ────────────────────────────────────────────────────────────────

DDL = f"""
CREATE TABLE IF NOT EXISTS {_MIGRATIONS_TABLE} (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS missions (
    id TEXT PRIMARY KEY,
    program_name TEXT NOT NULL DEFAULT '',
    objective TEXT NOT NULL DEFAULT 'Find valid, in-scope, non-destructive, reproducible vulnerabilities with evidence.',
    risk_profile TEXT NOT NULL DEFAULT 'low_noise_non_destructive',
    testing_modes_json TEXT NOT NULL DEFAULT '[]',
    target_assets_json TEXT NOT NULL DEFAULT '[]',
    allowed_assets_json TEXT NOT NULL DEFAULT '[]',
    disallowed_assets_json TEXT NOT NULL DEFAULT '[]',
    forbidden_actions_json TEXT NOT NULL DEFAULT '[]',
    rate_limits_json TEXT NOT NULL DEFAULT '{{}}',
    accounts_json TEXT NOT NULL DEFAULT '[]',
    notes TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_rules (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    rule_type TEXT NOT NULL CHECK(rule_type IN ('allow', 'deny')),
    target_type TEXT NOT NULL CHECK(target_type IN ('domain', 'ip', 'cidr', 'wildcard_domain', 'url_prefix', 'action')),
    pattern TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('recon', 'analysis', 'test', 'validate', 'exploit', 'post_exploit', 'report')),
    target TEXT NOT NULL DEFAULT '',
    asset_type TEXT NOT NULL DEFAULT '',
    objective TEXT NOT NULL DEFAULT '',
    hypothesis TEXT NOT NULL DEFAULT '',
    preconditions_json TEXT NOT NULL DEFAULT '[]',
    allowed_tools_json TEXT NOT NULL DEFAULT '[]',
    risk_level TEXT NOT NULL DEFAULT 'low' CHECK(risk_level IN ('low', 'medium', 'high')),
    priority INTEGER NOT NULL DEFAULT 0,
    required_human_approval INTEGER NOT NULL DEFAULT 0,
    success_criteria_json TEXT NOT NULL DEFAULT '[]',
    stop_conditions_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN (
        'pending','running','blocked','complete','failed','needs_approval'
    )),
    result_summary TEXT NOT NULL DEFAULT '',
    block_reason TEXT NOT NULL DEFAULT '',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    hypothesis_id TEXT NOT NULL DEFAULT '',
    check_fingerprint TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    hypothesis_key TEXT NOT NULL,
    statement TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN (
        'open','confirmed','refuted','inconclusive','exhausted'
    )),
    confidence REAL NOT NULL DEFAULT 0.5,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    independent_check_count INTEGER NOT NULL DEFAULT 0,
    check_history_json TEXT NOT NULL DEFAULT '[]',
    candidate_checks_json TEXT NOT NULL DEFAULT '[]',
    last_information_value REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_assessed_at TEXT NOT NULL DEFAULT '',
    UNIQUE(mission_id, hypothesis_key),
    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS outcome_assessments (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    task_id TEXT NOT NULL UNIQUE,
    hypothesis_id TEXT NOT NULL,
    execution_outcome TEXT NOT NULL CHECK(execution_outcome IN (
        'succeeded','failed','blocked'
    )),
    hypothesis_status TEXT NOT NULL CHECK(hypothesis_status IN (
        'open','confirmed','refuted','inconclusive','exhausted'
    )),
    confidence REAL NOT NULL DEFAULT 0.5,
    satisfied_criteria_json TEXT NOT NULL DEFAULT '[]',
    unsatisfied_criteria_json TEXT NOT NULL DEFAULT '[]',
    triggered_stop_conditions_json TEXT NOT NULL DEFAULT '[]',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    reasoning TEXT NOT NULL DEFAULT '',
    information_value REAL NOT NULL DEFAULT 0.0,
    another_investigation_justified INTEGER NOT NULL DEFAULT 0,
    check_fingerprint TEXT NOT NULL DEFAULT '',
    independent_check INTEGER NOT NULL DEFAULT 0,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    tool_name TEXT NOT NULL DEFAULT '',
    input_summary TEXT NOT NULL DEFAULT '',
    output_summary TEXT NOT NULL DEFAULT '',
    raw_output_ref TEXT NOT NULL DEFAULT '',
    facts_json TEXT NOT NULL DEFAULT '[]',
    new_assets_json TEXT NOT NULL DEFAULT '[]',
    new_endpoints_json TEXT NOT NULL DEFAULT '[]',
    new_parameters_json TEXT NOT NULL DEFAULT '[]',
    new_technologies_json TEXT NOT NULL DEFAULT '[]',
    new_identities_json TEXT NOT NULL DEFAULT '[]',
    new_objects_json TEXT NOT NULL DEFAULT '[]',
    interesting_signals_json TEXT NOT NULL DEFAULT '[]',
    possible_findings_json TEXT NOT NULL DEFAULT '[]',
    dead_ends_json TEXT NOT NULL DEFAULT '[]',
    recommended_followup_tasks_json TEXT NOT NULL DEFAULT '[]',
    memory_updates_json TEXT NOT NULL DEFAULT '[]',
    graph_updates_json TEXT NOT NULL DEFAULT '[]',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    hypothesis_evidence_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL DEFAULT 0.0,
    usefulness INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS graph_nodes (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{{}}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS graph_edges (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    from_node_id TEXT NOT NULL,
    to_node_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{{}}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE,
    FOREIGN KEY (from_node_id) REFERENCES graph_nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (to_node_id) REFERENCES graph_nodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    task_id TEXT,
    finding_id TEXT,
    type TEXT NOT NULL CHECK(type IN (
        'raw_output','http_response','screenshot','note','diff','file','http_request','structured_json'
    )),
    path TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    hash TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{{}}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    vuln_class TEXT NOT NULL DEFAULT '',
    affected_asset TEXT NOT NULL DEFAULT '',
    affected_endpoint TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    impact TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.0,
    impact_score INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'candidate' CHECK(status IN (
        'candidate','needs_validation','rejected','duplicate_suspected','validated','report_ready'
    )),
    rejection_reason TEXT NOT NULL DEFAULT '',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    reproduction_steps_json TEXT NOT NULL DEFAULT '[]',
    missing_validation_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    task_id TEXT,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{{}}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS memories (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    memory_type TEXT NOT NULL CHECK(memory_type IN ('working','episodic','semantic','target','hypothesis','dead_end','finding_note')),
    target TEXT NOT NULL DEFAULT '',
    fact TEXT NOT NULL DEFAULT '',
    tags_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL DEFAULT 0.0,
    metadata_json TEXT NOT NULL DEFAULT '{{}}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS embeddings (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL DEFAULT '',
    source_table TEXT NOT NULL DEFAULT '',
    source_id TEXT NOT NULL DEFAULT '',
    embedding_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lessons (
    id TEXT PRIMARY KEY,
    pattern_hash TEXT NOT NULL DEFAULT '',
    target_signature TEXT NOT NULL DEFAULT '',
    action_type TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL DEFAULT '' CHECK(outcome IN ('success','failure','partial','unknown')),
    confidence REAL NOT NULL DEFAULT 0.0,
    embedding_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{{}}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scope_rules_mission ON scope_rules(mission_id);
CREATE INDEX IF NOT EXISTS idx_tasks_mission ON tasks(mission_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, priority);
CREATE INDEX IF NOT EXISTS idx_tasks_target ON tasks(target, status);
CREATE INDEX IF NOT EXISTS idx_hypotheses_mission ON hypotheses(mission_id, status);
CREATE INDEX IF NOT EXISTS idx_hypotheses_target ON hypotheses(mission_id, target, status);
CREATE INDEX IF NOT EXISTS idx_outcome_assessments_hypothesis
    ON outcome_assessments(hypothesis_id, created_at);
CREATE INDEX IF NOT EXISTS idx_observations_task ON observations(task_id);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_mission ON graph_nodes(mission_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_mission ON graph_edges(mission_id);
CREATE INDEX IF NOT EXISTS idx_evidence_mission ON evidence(mission_id);
CREATE INDEX IF NOT EXISTS idx_evidence_task ON evidence(task_id);
CREATE INDEX IF NOT EXISTS idx_findings_mission ON findings(mission_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_audit_mission ON audit_logs(mission_id);
CREATE INDEX IF NOT EXISTS idx_memories_mission ON memories(mission_id);
CREATE INDEX IF NOT EXISTS idx_memories_target ON memories(target, memory_type);
CREATE INDEX IF NOT EXISTS idx_embeddings_source ON embeddings(source_table, source_id);
CREATE INDEX IF NOT EXISTS idx_lessons_signature ON lessons(target_signature, action_type);
CREATE INDEX IF NOT EXISTS idx_lessons_outcome ON lessons(outcome, confidence);
"""


# ── Database manager ───────────────────────────────────────────────────────

class DatabaseManager:
    """Thread-safe SQLite wrapper for the research agent.

    Usage::

        db = DatabaseManager(Path("workspace/research.db"))
        with db.connection() as conn:
            db.ensure_schema(conn)
    """

    def __init__(self, path: Path, *, wal: bool = True, foreign_keys: bool = True):
        self._path = path.resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()  # ponytail: reentrant so nested connection(write=True) won't deadlock
        self._wal = wal
        self._foreign_keys = foreign_keys
        # ponytail: thread-local connection cache — one read + one write conn per
        # thread avoids sqlite3.connect() + 3 pragmas on every call. WAL mode
        # makes long-lived connections safe for concurrent reads.
        self._local = threading.local()

    # ------------------------------------------------------------------
    def _get_conn(self, write: bool = False) -> sqlite3.Connection:
        """Get or create a cached thread-local connection."""
        attr = "_write_conn" if write else "_read_conn"
        conn = getattr(self._local, attr, None)
        if conn is None:
            conn = sqlite3.connect(
                str(self._path),
                isolation_level=None if write else "DEFERRED",
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL" if self._wal else "PRAGMA journal_mode=DELETE")
            if self._foreign_keys:
                conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            setattr(self._local, attr, conn)
        return conn

    @contextmanager
    def connection(self, *, write: bool = False) -> Generator[sqlite3.Connection, None, None]:
        """Yield a cached thread-local connection. Writer connections block all other writers."""
        conn = self._get_conn(write=write)
        if write:
            acquired = self._lock.acquire(timeout=30)
            if not acquired:
                raise TimeoutError("Could not acquire DB write lock within 30s.")
            try:
                yield conn
            finally:
                self._lock.release()
        else:
            try:
                yield conn
            finally:
                pass

    # ------------------------------------------------------------------
    def ensure_schema(self, conn: sqlite3.Connection) -> None:
        """Create tables and run pending migrations. Idempotent."""
        conn.executescript(DDL)

        cur = conn.execute(
            f"SELECT version FROM {_MIGRATIONS_TABLE} ORDER BY version DESC LIMIT 1"
        )
        installed = cur.fetchone()
        current = installed["version"] if installed else 0

        for ver in range(current + 1, _SCHEMA_VERSION + 1):
            self._run_migration(conn, ver)
        conn.commit()

    # ------------------------------------------------------------------
    def _run_migration(self, conn: sqlite3.Connection, version: int) -> None:
        if version == 2:
            self._migrate_v2_task_phases(conn)
        if version == 3:
            self._migrate_v3_indexes(conn)
        if version == 4:
            self._migrate_v4_outcome_judgment(conn)
        conn.execute(
            f"INSERT INTO {_MIGRATIONS_TABLE}(version, applied_at) VALUES(?,?)",
            (version, _now_iso()),
        )

    # ------------------------------------------------------------------
    def _migrate_v2_task_phases(self, conn: sqlite3.Connection) -> None:
        """Allow swarm-created exploit/post_exploit tasks in existing DBs."""
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='tasks'"
        ).fetchone()
        table_sql = row["sql"] if row else ""
        if "post_exploit" in table_sql and "'exploit'" in table_sql:
            return

        previous_foreign_keys = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        conn.execute("PRAGMA foreign_keys=OFF")
        try:
            conn.execute("BEGIN")
            conn.execute(
                """CREATE TABLE tasks_new (
                    id TEXT PRIMARY KEY,
                    mission_id TEXT NOT NULL,
                    phase TEXT NOT NULL CHECK(phase IN ('recon', 'analysis', 'test', 'validate', 'exploit', 'post_exploit', 'report')),
                    target TEXT NOT NULL DEFAULT '',
                    asset_type TEXT NOT NULL DEFAULT '',
                    objective TEXT NOT NULL DEFAULT '',
                    hypothesis TEXT NOT NULL DEFAULT '',
                    preconditions_json TEXT NOT NULL DEFAULT '[]',
                    allowed_tools_json TEXT NOT NULL DEFAULT '[]',
                    risk_level TEXT NOT NULL DEFAULT 'low' CHECK(risk_level IN ('low', 'medium', 'high')),
                    priority INTEGER NOT NULL DEFAULT 0,
                    required_human_approval INTEGER NOT NULL DEFAULT 0,
                    success_criteria_json TEXT NOT NULL DEFAULT '[]',
                    stop_conditions_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN (
                        'pending','running','blocked','complete','failed','needs_approval'
                    )),
                    result_summary TEXT NOT NULL DEFAULT '',
                    block_reason TEXT NOT NULL DEFAULT '',
                    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE
                )"""
            )
            conn.execute(
                """INSERT INTO tasks_new(
                    id, mission_id, phase, target, asset_type, objective, hypothesis,
                    preconditions_json, allowed_tools_json, risk_level, priority,
                    required_human_approval, success_criteria_json, stop_conditions_json,
                    status, result_summary, block_reason, evidence_refs_json,
                    created_at, updated_at)
                SELECT
                    id, mission_id,
                    CASE
                        WHEN phase IN ('recon', 'analysis', 'test', 'validate', 'exploit', 'post_exploit', 'report') THEN phase
                        WHEN phase = 'validation' THEN 'validate'
                        WHEN phase = 'exploitation' THEN 'exploit'
                        WHEN phase IN ('post-exploit', 'post_exploitation', 'postexploitation') THEN 'post_exploit'
                        WHEN phase IN ('service_enumeration', 'vulnerability_research', 'web_enumeration') THEN 'analysis'
                        WHEN phase = 'credential_testing' THEN 'test'
                        WHEN phase = 'reporting' THEN 'report'
                        ELSE 'test'
                    END,
                    target, asset_type, objective, hypothesis,
                    preconditions_json, allowed_tools_json, risk_level, priority,
                    required_human_approval, success_criteria_json, stop_conditions_json,
                    status, result_summary, block_reason, evidence_refs_json,
                    created_at, updated_at
                FROM tasks"""
            )
            conn.execute("DROP TABLE tasks")
            conn.execute("ALTER TABLE tasks_new RENAME TO tasks")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            if previous_foreign_keys:
                conn.execute("PRAGMA foreign_keys=ON")

        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_tasks_mission ON tasks(mission_id);
            CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, priority);
            CREATE INDEX IF NOT EXISTS idx_tasks_target ON tasks(target, status);
            """
        )

    # ------------------------------------------------------------------
    def _migrate_v3_indexes(self, conn: sqlite3.Connection) -> None:
        """Add missing created_at indexes for high-volume tables."""
        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_observations_created
                ON observations(created_at);
            CREATE INDEX IF NOT EXISTS idx_evidence_created
                ON evidence(created_at);
            CREATE INDEX IF NOT EXISTS idx_findings_created
                ON findings(created_at);
            CREATE INDEX IF NOT EXISTS idx_audit_created
                ON audit_logs(created_at);
            CREATE INDEX IF NOT EXISTS idx_memories_created
                ON memories(created_at);
            CREATE INDEX IF NOT EXISTS idx_tasks_phase
                ON tasks(phase);
            CREATE INDEX IF NOT EXISTS idx_graph_nodes_type
                ON graph_nodes(type);
            """
        )

    # ------------------------------------------------------------------
    def _migrate_v4_outcome_judgment(self, conn: sqlite3.Connection) -> None:
        """Add hypothesis state, assessment persistence, and task check identity."""
        task_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(tasks)").fetchall()
        }
        if "hypothesis_id" not in task_columns:
            conn.execute(
                "ALTER TABLE tasks ADD COLUMN hypothesis_id TEXT NOT NULL DEFAULT ''"
            )
        if "check_fingerprint" not in task_columns:
            conn.execute(
                "ALTER TABLE tasks ADD COLUMN check_fingerprint TEXT NOT NULL DEFAULT ''"
            )

        observation_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(observations)").fetchall()
        }
        if "hypothesis_evidence_json" not in observation_columns:
            conn.execute(
                "ALTER TABLE observations ADD COLUMN "
                "hypothesis_evidence_json TEXT NOT NULL DEFAULT '[]'"
            )

        # DDL creates these tables before migrations run. Repeating the
        # definitions here makes this migration independently idempotent for
        # databases assembled from a partial historical schema.
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS hypotheses (
                id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                hypothesis_key TEXT NOT NULL,
                statement TEXT NOT NULL DEFAULT '',
                target TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open' CHECK(status IN (
                    'open','confirmed','refuted','inconclusive','exhausted'
                )),
                confidence REAL NOT NULL DEFAULT 0.5,
                evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                attempt_count INTEGER NOT NULL DEFAULT 0,
                independent_check_count INTEGER NOT NULL DEFAULT 0,
                check_history_json TEXT NOT NULL DEFAULT '[]',
                candidate_checks_json TEXT NOT NULL DEFAULT '[]',
                last_information_value REAL NOT NULL DEFAULT 0.0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_assessed_at TEXT NOT NULL DEFAULT '',
                UNIQUE(mission_id, hypothesis_key),
                FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS outcome_assessments (
                id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                task_id TEXT NOT NULL UNIQUE,
                hypothesis_id TEXT NOT NULL,
                execution_outcome TEXT NOT NULL CHECK(execution_outcome IN (
                    'succeeded','failed','blocked'
                )),
                hypothesis_status TEXT NOT NULL CHECK(hypothesis_status IN (
                    'open','confirmed','refuted','inconclusive','exhausted'
                )),
                confidence REAL NOT NULL DEFAULT 0.5,
                satisfied_criteria_json TEXT NOT NULL DEFAULT '[]',
                unsatisfied_criteria_json TEXT NOT NULL DEFAULT '[]',
                triggered_stop_conditions_json TEXT NOT NULL DEFAULT '[]',
                evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                reasoning TEXT NOT NULL DEFAULT '',
                information_value REAL NOT NULL DEFAULT 0.0,
                another_investigation_justified INTEGER NOT NULL DEFAULT 0,
                check_fingerprint TEXT NOT NULL DEFAULT '',
                independent_check INTEGER NOT NULL DEFAULT 0,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE,
                FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE CASCADE
            );
            """
        )
        assessment_columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(outcome_assessments)"
            ).fetchall()
        }
        if "attempt_count" not in assessment_columns:
            conn.execute(
                "ALTER TABLE outcome_assessments "
                "ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0"
            )

        # Backfill identity for historical tasks without inferring evidential
        # success from their execution status.
        from outcome_judge import build_check_fingerprint, build_hypothesis_key

        rows = conn.execute(
            """SELECT id, mission_id, target, phase, objective, hypothesis,
                      allowed_tools_json, success_criteria_json
               FROM tasks WHERE hypothesis<>''"""
        ).fetchall()
        now = _now_iso()
        for row in rows:
            task = dict(row)
            try:
                allowed_tools = json.loads(task.get("allowed_tools_json") or "[]")
            except (json.JSONDecodeError, TypeError):
                allowed_tools = []
            try:
                criteria = json.loads(task.get("success_criteria_json") or "[]")
            except (json.JSONDecodeError, TypeError):
                criteria = []
            task_data = {
                "phase": task.get("phase", ""),
                "objective": task.get("objective", ""),
                "hypothesis": task.get("hypothesis", ""),
                "target": task.get("target", ""),
                "allowed_tools": allowed_tools,
                "success_criteria": criteria,
            }
            key = build_hypothesis_key(
                str(task.get("hypothesis", "")),
                str(task.get("target", "")),
            )
            existing = conn.execute(
                "SELECT id, candidate_checks_json FROM hypotheses "
                "WHERE mission_id=? AND hypothesis_key=?",
                (task["mission_id"], key),
            ).fetchone()
            if existing is None:
                hypothesis_id = _new_id("HYP")
                conn.execute(
                    """INSERT INTO hypotheses(
                        id, mission_id, hypothesis_key, statement, target, status,
                        confidence, evidence_refs_json, attempt_count,
                        independent_check_count, check_history_json,
                        candidate_checks_json, last_information_value,
                        created_at, updated_at, last_assessed_at)
                       VALUES(?,?,?,?,?,'open',0.5,'[]',0,0,'[]',?,0.0,?,?,?)""",
                    (
                        hypothesis_id,
                        task["mission_id"],
                        key,
                        task["hypothesis"],
                        task["target"],
                        json.dumps(allowed_tools),
                        now,
                        now,
                        "",
                    ),
                )
            else:
                hypothesis_id = existing["id"]
                try:
                    candidates = json.loads(existing["candidate_checks_json"] or "[]")
                except (json.JSONDecodeError, TypeError):
                    candidates = []
                for tool in allowed_tools:
                    if tool not in candidates:
                        candidates.append(tool)
                conn.execute(
                    "UPDATE hypotheses SET candidate_checks_json=?, updated_at=? WHERE id=?",
                    (json.dumps(candidates), now, hypothesis_id),
                )
            conn.execute(
                "UPDATE tasks SET hypothesis_id=?, check_fingerprint=? WHERE id=?",
                (hypothesis_id, build_check_fingerprint(task_data), task["id"]),
            )

        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_tasks_hypothesis
                ON tasks(mission_id, hypothesis_id, check_fingerprint);
            CREATE INDEX IF NOT EXISTS idx_hypotheses_mission
                ON hypotheses(mission_id, status);
            CREATE INDEX IF NOT EXISTS idx_hypotheses_target
                ON hypotheses(mission_id, target, status);
            CREATE INDEX IF NOT EXISTS idx_outcome_assessments_hypothesis
                ON outcome_assessments(hypothesis_id, created_at);
            """
        )

    # ------------------------------------------------------------------
    # High-level helpers used across modules
    # ------------------------------------------------------------------

    def create_mission(self, conn: sqlite3.Connection, **fields: Any) -> dict[str, Any]:
        mid = fields.get("id") or _new_id("M")
        now = _now_iso()
        conn.execute(
            """INSERT INTO missions(
                id, program_name, objective, risk_profile,
                testing_modes_json, target_assets_json,
                allowed_assets_json, disallowed_assets_json,
                forbidden_actions_json, rate_limits_json,
                accounts_json, notes, status, created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                mid,
                fields.get("program_name", ""),
                fields.get("objective", "Find valid, in-scope, non-destructive, reproducible vulnerabilities with evidence."),
                fields.get("risk_profile", "low_noise_non_destructive"),
                json.dumps(fields.get("testing_modes", [])),
                json.dumps(fields.get("target_assets", [])),
                json.dumps(fields.get("allowed_assets", [])),
                json.dumps(fields.get("disallowed_assets", [])),
                json.dumps(fields.get("forbidden_actions", [])),
                json.dumps(fields.get("rate_limits", {})),
                json.dumps(fields.get("accounts", [])),
                fields.get("notes", ""),
                "active",
                now,
                now,
            ),
        )
        return {"id": mid, "created_at": now}

    def add_scope_rule(
        self,
        conn: sqlite3.Connection,
        mission_id: str,
        rule_type: str,
        target_type: str,
        pattern: str,
        notes: str = "",
    ) -> str:
        sid = _new_id("S")
        conn.execute(
            "INSERT INTO scope_rules(id, mission_id, rule_type, target_type, pattern, notes, created_at) VALUES(?,?,?,?,?,?,?)",
            (sid, mission_id, rule_type, target_type, pattern, notes, _now_iso()),
        )
        return sid

    def get_scope_rules(
        self, conn: sqlite3.Connection, mission_id: str
    ) -> list[dict[str, Any]]:
        cur = conn.execute(
            "SELECT * FROM scope_rules WHERE mission_id=? ORDER BY created_at",
            (mission_id,),
        )
        return [dict(r) for r in cur.fetchall()]

    def log_audit(
        self,
        conn: sqlite3.Connection,
        mission_id: str,
        event_type: str,
        message: str = "",
        task_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        aid = _new_id("A")
        conn.execute(
            "INSERT INTO audit_logs(id, mission_id, task_id, event_type, message, metadata_json, created_at) VALUES(?,?,?,?,?,?,?)",
            (aid, mission_id, task_id or None, event_type, message, json.dumps(metadata or {}), _now_iso()),
        )
        return aid

    def close(self) -> None:
        """Close any cached thread-local connections."""
        for attr in ("_read_conn", "_write_conn"):
            conn = getattr(self._local, attr, None)
            if conn is not None:
                conn.close()
                delattr(self._local, attr)


# ── Global singleton (optional convenience) ─────────────────────────────────

_default_db: DatabaseManager | None = None


def get_default_db() -> DatabaseManager:
    global _default_db
    if _default_db is None:
        workspace = Path(os.environ.get("RESEARCH_WORKSPACE", "research_workspace"))
        _default_db = DatabaseManager(workspace / "research.db")
    return _default_db


def set_default_path(path: Path) -> DatabaseManager:
    global _default_db
    _default_db = DatabaseManager(path)
    return _default_db


def reset_default() -> None:
    global _default_db
    _default_db = None
