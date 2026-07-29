"""Persistent task queue with priority scoring.

Tasks are grouped by phase: recon → analysis → test → validate → report.

Priority formula:
    priority = asset_value + auth_boundary_score + object_reference_score
             + sensitive_data_score + novelty_score + confidence_score
             - duplicate_penalty - scope_risk_penalty - noise_penalty

Backed by SQLite tasks table via DatabaseManager.
"""

from __future__ import annotations

import json
from typing import Any

from db import DatabaseManager, _new_id, _now_iso
from outcome_judge import HypothesisRepository

VALID_TASK_PHASES = frozenset({
    "recon",
    "analysis",
    "test",
    "validate",
    "exploit",
    "post_exploit",
    "report",
})

_TASK_PHASE_ALIASES = {
    "validation": "validate",
    "vulnerability_research": "analysis",
    "service_enumeration": "analysis",
    "web_enumeration": "analysis",
    "credential_testing": "test",
    "exploitation": "exploit",
    "post-exploit": "post_exploit",
    "postexploitation": "post_exploit",
    "post_exploitation": "post_exploit",
    "reporting": "report",
}


class TaskQueue:
    """Persistent priority queue for research tasks."""

    def __init__(self, db: DatabaseManager, mission_id: str) -> None:
        self._db = db
        self._mission_id = mission_id
        self._hypotheses = HypothesisRepository(db, mission_id)

    # ── CRUD ────────────────────────────────────────────────────────────

    def create_task(self, task_data: dict[str, Any]) -> str:
        """Insert a new task. Returns the task_id."""
        hypothesis_state, check_fingerprint = self._hypotheses.prepare_task(task_data)
        hypothesis_id = hypothesis_state.hypothesis_id if hypothesis_state else ""
        if "task_id" in task_data:
            tid = task_data["task_id"]
        elif "id" in task_data:
            tid = task_data["id"]
        else:
            tid = _new_id("T")

        phase = _normalize_task_phase(task_data.get("phase", "recon"))
        risk_level_str = task_data.get("risk_level", "low")
        if risk_level_str not in ("low", "medium", "high"):
            risk_level_str = "low"

        status = task_data.get("status", "pending")
        allowed_statuses = {"pending", "running", "blocked", "complete", "failed", "needs_approval"}
        if status not in allowed_statuses:
            status = "pending"

        # Calculate priority if not provided
        priority = task_data.get("priority", 0)
        if not priority:
            priority = self._score_priority(task_data)

        requires_approval = 1 if task_data.get("requires_human_approval") else 0

        with self._db.connection(write=True) as conn:
            conn.execute(
                """INSERT INTO tasks(
                    id, mission_id, phase, target, asset_type, objective,
                    hypothesis, preconditions_json, allowed_tools_json,
                    risk_level, priority, required_human_approval,
                    success_criteria_json, stop_conditions_json,
                    status, result_summary, evidence_refs_json,
                    hypothesis_id, check_fingerprint, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    tid,
                    self._mission_id,
                    phase,
                    task_data.get("target", ""),
                    task_data.get("asset_type", ""),
                    task_data.get("objective", ""),
                    task_data.get("hypothesis", ""),
                    json.dumps(task_data.get("preconditions", [])),
                    json.dumps(task_data.get("allowed_tools", [])),
                    risk_level_str,
                    priority,
                    requires_approval,
                    json.dumps(task_data.get("success_criteria", [])),
                    json.dumps(task_data.get("stop_conditions", [])),
                    status,
                    task_data.get("result_summary", ""),
                    json.dumps(task_data.get("evidence_refs", [])),
                    hypothesis_id,
                    check_fingerprint,
                    _now_iso(),
                    _now_iso(),
                ),
            )
        return tid

    def get_next_task(self, target: str = "") -> dict[str, Any] | None:
        """Return the highest-priority pending task with a non-terminal hypothesis."""
        query = """SELECT t.* FROM tasks t
                   LEFT JOIN hypotheses h ON h.id=t.hypothesis_id
                   WHERE t.mission_id=? AND t.status='pending'
                     AND (h.id IS NULL OR h.status IN ('open','inconclusive'))"""

        params: list[Any] = [self._mission_id]
        if target:
            query += " AND t.target=?"
            params.append(target)

        query += " ORDER BY t.priority DESC, t.created_at ASC LIMIT 1"

        with self._db.connection() as conn:
            cur = conn.execute(query, params)
            row = cur.fetchone()
            if row:
                row = dict(row)
                return _row_to_task(row)
        return None

    def update_task_status(
        self,
        task_id: str,
        status: str,
        result_summary: str = "",
        evidence_refs: list[str] | None = None,
    ) -> None:
        """Update task status. Valid statuses: pending, running, blocked, complete, failed."""
        valid = {"pending", "running", "blocked", "complete", "failed", "needs_approval"}
        if status not in valid:
            raise ValueError(f"Invalid status '{status}'. Must be one of {valid}.")
        with self._db.connection(write=True) as conn:
            conn.execute(
                """UPDATE tasks SET status=?, result_summary=COALESCE(NULLIF(?, ''), result_summary),
                   evidence_refs_json=COALESCE(?, evidence_refs_json), updated_at=? WHERE id=? AND mission_id=?""",
                (
                    status,
                    result_summary,
                    json.dumps(evidence_refs) if evidence_refs is not None else None,
                    _now_iso(),
                    task_id,
                    self._mission_id,
                ),
            )

    def complete_task(
        self,
        task_id: str,
        result_summary: str = "",
        evidence_refs: list[str] | None = None,
    ) -> None:
        self.update_task_status(task_id, "complete", result_summary, evidence_refs)

    def block_task(self, task_id: str, reason: str) -> None:
        with self._db.connection(write=True) as conn:
            conn.execute(
                "UPDATE tasks SET status='blocked', block_reason=?, updated_at=? WHERE id=? AND mission_id=?",
                (reason, _now_iso(), task_id, self._mission_id),
            )

    def reset_stale_running(self) -> int:
        """Re-queue every task left in 'running' status back to 'pending'.

        A crashed/killed run can leave tasks marked 'running' that never
        completed. On resume those MUST be re-queued as 'pending' (so they're
        re-attempted from a clean start) -- NOT skipped (which would silently
        drop them) and NOT re-run as 'running' (which would let the planner
        believe they're in-flight and never pick them up via get_next_task,
        which only selects status='pending'). Returns the count reset.

        Tier 1.3: this is the safety-critical resume primitive -- without it a
        botched resume would silently lose the in-flight work of the prior
        run, or worse, leave offensive tasks half-executed and untracked.
        """
        with self._db.connection(write=True) as conn:
            cur = conn.execute(
                "UPDATE tasks SET status='pending', updated_at=? "
                "WHERE mission_id=? AND status='running'",
                (_now_iso(), self._mission_id),
            )
            return cur.rowcount

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT * FROM tasks WHERE id=? AND mission_id=?",
                (task_id, self._mission_id),
            )
            row = cur.fetchone()
            if row:
                return _row_to_task(dict(row))
        return None

    # ── List operations ─────────────────────────────────────────────────

    def list_open_tasks(
        self,
        target: str = "",
        status: str = "",
        phase: str = "",
        search: str = "",
    ) -> list[dict[str, Any]]:
        # When a status filter is supplied it *replaces* the default open-set
        # predicate (pending/running) so callers can request, for example, only
        # 'blocked' or only 'complete'. Empty status keeps the open-set default.
        params: list[Any] = []
        if status:
            query = "SELECT * FROM tasks WHERE mission_id=? AND status=?"
            params = [self._mission_id, status]
        else:
            query = "SELECT * FROM tasks WHERE mission_id=? AND status IN ('pending','running')"
            params = [self._mission_id]
        if target:
            query += " AND target=?"
            params.append(target)
        if phase:
            query += " AND phase=?"
            params.append(phase)
        if search:
            query += " AND (objective LIKE ? OR target LIKE ? OR id LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        query += " ORDER BY priority DESC"
        with self._db.connection() as conn:
            cur = conn.execute(query, params)
            return [_row_to_task(dict(r)) for r in cur.fetchall()]

    def list_blocked_tasks(self, target: str = "") -> list[dict[str, Any]]:
        query = "SELECT * FROM tasks WHERE mission_id=? AND status='blocked'"
        params: list[Any] = [self._mission_id]
        if target:
            query += " AND target=?"
            params.append(target)
        with self._db.connection() as conn:
            cur = conn.execute(query, params)
            return [_row_to_task(dict(r)) for r in cur.fetchall()]

    def list_completed_tasks(self, target: str = "") -> list[dict[str, Any]]:
        query = "SELECT * FROM tasks WHERE mission_id=? AND status='complete'"
        params: list[Any] = [self._mission_id]
        if target:
            query += " AND target=?"
            params.append(target)
        with self._db.connection() as conn:
            cur = conn.execute(query, params)
            return [_row_to_task(dict(r)) for r in cur.fetchall()]

    # ── Dedup ───────────────────────────────────────────────────────────

    def deduplicate(self) -> int:
        """Remove duplicate tasks with same (target, objective, phase). Returns count removed."""
        with self._db.connection(write=True) as conn:
            cur = conn.execute(
                """DELETE FROM tasks WHERE id IN (
                    SELECT id FROM tasks t1 WHERE EXISTS (
                        SELECT 1 FROM tasks t2 WHERE t2.target = t1.target
                        AND t2.objective = t1.objective AND t2.phase = t1.phase
                        AND t2.id < t1.id AND t1.status = 'pending' AND t2.status = 'pending'
                        AND t1.mission_id = t2.mission_id
                    )
                ) AND mission_id=? AND status='pending'""",
                (self._mission_id,),
            )
            return cur.rowcount

    def reprioritize(self) -> None:
        """Re-score all pending tasks."""
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT * FROM tasks WHERE mission_id=? AND status='pending'",
                (self._mission_id,),
            )
            tasks = [_row_to_task(dict(r)) for r in cur.fetchall()]

        with self._db.connection(write=True) as conn:
            for t in tasks:
                new_priority = self._score_priority(t)
                conn.execute(
                    "UPDATE tasks SET priority=?, updated_at=? WHERE id=?",
                    (new_priority, _now_iso(), t.get("task_id", "")),
                )

    # ── Priority scoring ────────────────────────────────────────────────

    @staticmethod
    def _score_priority(task: dict[str, Any]) -> int:
        """Compute priority score (0-100) for a task based on heuristics."""
        score = 0
        phase = task.get("phase", "")
        objective = task.get("objective", "").lower()
        hypothesis = task.get("hypothesis", "").lower()
        obj_text = f"{objective} {hypothesis}"

        # Phase bonus (test and validate are higher value)
        phase_bonus = {
            "recon": 5,
            "analysis": 10,
            "test": 20,
            "validate": 25,
            "exploit": 30,
            "post_exploit": 20,
            "report": 5,
        }
        score += phase_bonus.get(phase, 0)

        # Auth boundary bonus
        for kw in ("auth", "bypass", "privilege", "escalation", "role", "admin", "access control"):
            if kw in obj_text:
                score += 10
                break

        # Object reference bonus
        for kw in ("idor", "object", "id", "uuid", "reference", "direct"):
            if kw in obj_text:
                score += 10

        # Sensitive data bonus
        for kw in ("sensitive", "data", "exposure", "leak", "disclosure", "pii", "secret"):
            if kw in obj_text:
                score += 10

        # Novelty bonus (tasks with hypotheses are more directed)
        if task.get("hypothesis", "").strip():
            score += 5

        # Confidence bonus (pre-scored tasks)
        confidence = task.get("confidence", 0.0)
        if isinstance(confidence, (int, float)):
            score += int(float(confidence) * 10)

        # Evidence-directed hypotheses favor high-value, discriminating checks
        # while steadily reducing priority for paths that already consumed
        # several independent attempts.
        information_value = task.get("expected_information_value", 0.0)
        if isinstance(information_value, (int, float)):
            score += int(max(0.0, min(float(information_value), 1.0)) * 20)
        attempts = task.get("hypothesis_attempt_count", 0)
        if isinstance(attempts, int) and not isinstance(attempts, bool):
            score -= min(attempts, 5) * 5
        estimated_cost = task.get("estimated_cost", 0.0)
        if isinstance(estimated_cost, (int, float)):
            score -= int(max(0.0, min(float(estimated_cost), 1.0)) * 10)

        # Duplicate penalty (slightly reduce lower-ID tasks in same group)
        # Handled during dedup; base penalty applied to generic tasks
        if "scan" in obj_text and "all" in obj_text:
            score -= 5  # "scan all ports" type tasks get penalized

        # Scope risk penalty
        risk_level_str = task.get("risk_level", "low")
        if risk_level_str == "high":
            score -= 10
        elif risk_level_str == "medium":
            score -= 3

        # Noise penalty — tasks with vague objectives
        vague_words = {"discover", "enumerate", "scan", "check all", "try everything"}
        if any(v in objective.lower() for v in vague_words) and not task.get("hypothesis"):
            score -= 5

        return max(0, min(score, 100))

    # ── Counts ──────────────────────────────────────────────────────────

    def count_by_status(self) -> dict[str, int]:
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM tasks WHERE mission_id=? GROUP BY status",
                (self._mission_id,),
            )
            return {row["status"]: row["cnt"] for row in cur.fetchall()}

    def count_total(self) -> int:
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM tasks WHERE mission_id=?",
                (self._mission_id,),
            ).fetchone()
        return int(row["cnt"]) if row else 0


# ── Helpers ─────────────────────────────────────────────────────────────────


def _row_to_task(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": data.get("id", ""),
        "mission_id": data.get("mission_id", ""),
        "phase": data.get("phase", "recon"),
        "target": data.get("target", ""),
        "asset_type": data.get("asset_type", ""),
        "objective": data.get("objective", ""),
        "hypothesis": data.get("hypothesis", ""),
        "preconditions": _json_load(data.get("preconditions_json", "[]"), []),
        "allowed_tools": _json_load(data.get("allowed_tools_json", "[]"), []),
        "risk_level": data.get("risk_level", "low"),
        "priority": int(data.get("priority", 0)),
        "requires_human_approval": bool(data.get("required_human_approval", 0)),
        "success_criteria": _json_load(data.get("success_criteria_json", "[]"), []),
        "stop_conditions": _json_load(data.get("stop_conditions_json", "[]"), []),
        "status": data.get("status", "pending"),
        "result_summary": data.get("result_summary", ""),
        "block_reason": data.get("block_reason", ""),
        "evidence_refs": _json_load(data.get("evidence_refs_json", "[]"), []),
        "hypothesis_id": data.get("hypothesis_id", ""),
        "check_fingerprint": data.get("check_fingerprint", ""),
        "created_at": data.get("created_at", ""),
        "updated_at": data.get("updated_at", ""),
    }


def _normalize_task_phase(phase: Any) -> str:
    value = str(phase or "recon").strip().lower()
    if value in VALID_TASK_PHASES:
        return value
    return _TASK_PHASE_ALIASES.get(value, "test")


def _json_load(raw: Any, default: Any = None) -> Any:
    if isinstance(raw, (list, dict)):
        return raw
    if isinstance(raw, str) and raw:
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            pass
    if default is None:
        return {}
    return default
