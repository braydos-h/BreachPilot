"""Deterministic, evidence-grounded hypothesis outcome judgment.

The judge deliberately separates whether a tool ran from whether the resulting
evidence resolved a task hypothesis.  It consumes only structured observation
fields for evidential decisions; raw-output words such as ``success`` are not a
confirmation signal.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Iterable, Mapping

from db import DatabaseManager, _new_id, _now_iso


class ExecutionOutcome(str, Enum):
    """Operational result of the attempted check."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"


class HypothesisStatus(str, Enum):
    """Current evidential state of a hypothesis."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    EXHAUSTED = "exhausted"


TERMINAL_HYPOTHESIS_STATUSES = frozenset(
    {
        HypothesisStatus.CONFIRMED,
        HypothesisStatus.REFUTED,
        HypothesisStatus.EXHAUSTED,
    }
)


@dataclass
class HypothesisState:
    """Persisted state for one mission, target, and hypothesis statement."""

    hypothesis_id: str
    mission_id: str
    statement: str
    target: str
    status: HypothesisStatus = HypothesisStatus.OPEN
    confidence: float = 0.5
    evidence_refs: list[str] = field(default_factory=list)
    attempt_count: int = 0
    independent_check_count: int = 0
    check_history: list[dict[str, Any]] = field(default_factory=list)
    candidate_checks: list[str] = field(default_factory=list)
    last_information_value: float = 0.0
    created_at: str = ""
    updated_at: str = ""
    last_assessed_at: str = ""

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_HYPOTHESIS_STATUSES

    @property
    def check_fingerprints(self) -> set[str]:
        return {str(item.get("fingerprint", "")) for item in self.check_history if item.get("fingerprint")}

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "mission_id": self.mission_id,
            "statement": self.statement,
            "hypothesis": self.statement,
            "target": self.target,
            "status": self.status.value,
            "confidence": self.confidence,
            "evidence_refs": list(self.evidence_refs),
            "attempt_count": self.attempt_count,
            "independent_check_count": self.independent_check_count,
            "check_history": list(self.check_history),
            "check_fingerprints": sorted(self.check_fingerprints),
            "candidate_checks": list(self.candidate_checks),
            "last_information_value": self.last_information_value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_assessed_at": self.last_assessed_at,
        }


@dataclass
class OutcomeAssessment:
    """The complete judgment for one executed investigation task."""

    task_id: str
    hypothesis_id: str
    execution_outcome: ExecutionOutcome
    hypothesis_status: HypothesisStatus
    confidence: float
    satisfied_criteria: list[Any] = field(default_factory=list)
    unsatisfied_criteria: list[Any] = field(default_factory=list)
    triggered_stop_conditions: list[Any] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    reasoning: str = ""
    information_value: float = 0.0
    another_investigation_justified: bool = False
    check_fingerprint: str = ""
    independent_check: bool = True
    attempt_count: int = 0
    assessment_id: str = ""
    created_at: str = ""

    @property
    def evidential_outcome(self) -> str | None:
        """Map only supported terminal judgments to a learning outcome."""
        if self.hypothesis_status is HypothesisStatus.CONFIRMED:
            return "success"
        if self.hypothesis_status is HypothesisStatus.REFUTED:
            return "failure"
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "task_id": self.task_id,
            "hypothesis_id": self.hypothesis_id,
            "execution_outcome": self.execution_outcome.value,
            "hypothesis_status": self.hypothesis_status.value,
            "confidence": self.confidence,
            "satisfied_criteria": self.satisfied_criteria,
            "unsatisfied_criteria": self.unsatisfied_criteria,
            "triggered_stop_conditions": self.triggered_stop_conditions,
            "evidence_refs": self.evidence_refs,
            "reasoning": self.reasoning,
            "information_value": self.information_value,
            "another_investigation_justified": self.another_investigation_justified,
            "check_fingerprint": self.check_fingerprint,
            "independent_check": self.independent_check,
            "attempt_count": self.attempt_count,
            "created_at": self.created_at,
        }


class DuplicateInvestigationError(ValueError):
    """Raised when a task repeats a check already queued or attempted."""


class ClosedHypothesisError(ValueError):
    """Raised when a task targets a terminal hypothesis."""


class OutcomeJudge:
    """Pure deterministic judge over a task, execution, and observation."""

    def __init__(
        self,
        *,
        max_inconclusive_attempts: int = 3,
        confirmation_threshold: float = 0.75,
        refutation_threshold: float = 0.75,
        min_evidence_references: int = 1,
    ) -> None:
        if isinstance(max_inconclusive_attempts, bool) or max_inconclusive_attempts < 2:
            raise ValueError("max_inconclusive_attempts must be an integer >= 2")
        for name, value in (
            ("confirmation_threshold", confirmation_threshold),
            ("refutation_threshold", refutation_threshold),
        ):
            if isinstance(value, bool) or not 0.5 <= float(value) <= 1.0:
                raise ValueError(f"{name} must be between 0.5 and 1.0")
        if isinstance(min_evidence_references, bool) or min_evidence_references < 1:
            raise ValueError("min_evidence_references must be an integer >= 1")

        self.max_inconclusive_attempts = int(max_inconclusive_attempts)
        self.confirmation_threshold = float(confirmation_threshold)
        self.refutation_threshold = float(refutation_threshold)
        self.min_evidence_references = int(min_evidence_references)

    def judge(
        self,
        task: Mapping[str, Any],
        execution_result: Any,
        observation: Any,
        evidence_refs: Iterable[str] | None = None,
        *,
        prior_hypothesis: HypothesisState | Mapping[str, Any] | None = None,
    ) -> OutcomeAssessment:
        """Return an evidence assessment without mutating persistence."""
        task_data = dict(task)
        obs = _as_mapping(observation)
        prior = _coerce_state(prior_hypothesis)
        execution = _execution_outcome(execution_result)
        refs = _merge_refs(
            evidence_refs or (),
            _get(execution_result, "evidence_refs", []),
            obs.get("evidence_refs", []),
            task_data.get("evidence_refs", []),
        )
        check_fingerprint = build_check_fingerprint(task_data)
        prior_checks = prior.check_fingerprints if prior else set()
        independent_check = check_fingerprint not in prior_checks
        attempted = execution is not ExecutionOutcome.BLOCKED
        attempt_count = (prior.attempt_count if prior else 0) + (1 if attempted else 0)
        independent_count = (prior.independent_check_count if prior else 0) + (
            1 if attempted and independent_check else 0
        )

        success_criteria = _criterion_list(task_data.get("success_criteria", []))
        stop_conditions = _criterion_list(task_data.get("stop_conditions", []))
        satisfied = [criterion for criterion in success_criteria if _criterion_met(criterion, obs)]
        unsatisfied = [criterion for criterion in success_criteria if criterion not in satisfied]
        triggered_stops = [condition for condition in stop_conditions if _criterion_met(condition, obs)]

        explicit_support, explicit_refutation = _explicit_evidence_scores(obs)
        criteria_ratio = len(satisfied) / len(success_criteria) if success_criteria else 0.0
        criteria_support = criteria_ratio if success_criteria and not unsatisfied else 0.0
        contradiction = _contradiction_score(task_data, obs)
        has_terminal_evidence = len(refs) >= self.min_evidence_references
        actual_tool_error = bool(_get(execution_result, "error", "")) and execution is ExecutionOutcome.FAILED

        support_score = max(explicit_support, criteria_support)
        refutation_score = max(explicit_refutation, contradiction)
        if actual_tool_error and explicit_support == 0.0:
            support_score = 0.0
        if actual_tool_error and explicit_refutation == 0.0:
            refutation_score = 0.0

        prior_confidence = prior.confidence if prior else _clamp(task_data.get("hypothesis_confidence", 0.5))
        status = HypothesisStatus.INCONCLUSIVE if attempted else HypothesisStatus.OPEN
        confidence = prior_confidence
        reason_bits: list[str] = []

        if prior and prior.is_terminal:
            status = prior.status
            confidence = prior.confidence
            reason_bits.append(f"Hypothesis was already terminal ({prior.status.value}); no new path is justified.")
        elif has_terminal_evidence and refutation_score >= self.refutation_threshold:
            status = HypothesisStatus.REFUTED
            confidence = _clamp(0.7 + 0.3 * refutation_score)
            reason_bits.append("Structured evidence directly contradicts the hypothesis.")
        elif has_terminal_evidence and support_score >= self.confirmation_threshold:
            status = HypothesisStatus.CONFIRMED
            confidence = _clamp(0.7 + 0.3 * support_score)
            reason_bits.append("Structured evidence satisfies the required success criteria.")
        elif attempted and independent_count >= self.max_inconclusive_attempts:
            status = HypothesisStatus.EXHAUSTED
            confidence = prior_confidence
            reason_bits.append(
                f"{independent_count} materially different checks remained inconclusive, "
                f"reaching the configured limit of {self.max_inconclusive_attempts}."
            )
        else:
            if execution is ExecutionOutcome.SUCCEEDED:
                reason_bits.append("The check executed successfully but did not resolve the hypothesis.")
            elif execution is ExecutionOutcome.FAILED:
                reason_bits.append("The check failed operationally; an execution error does not refute the hypothesis.")
            else:
                reason_bits.append("The check was blocked before execution and produced no hypothesis attempt.")
            if satisfied and unsatisfied:
                reason_bits.append("Only some success criteria were satisfied.")
            elif unsatisfied:
                reason_bits.append("Required success criteria remain unsatisfied.")
            if triggered_stops:
                reason_bits.append(
                    "A stop condition was observed, but it did not by itself prove or disprove the claim."
                )
            if not has_terminal_evidence:
                reason_bits.append("There are not enough persisted evidence references for a terminal judgment.")

        information_value = _information_value(
            obs,
            refs,
            satisfied_count=len(satisfied),
            triggered_count=len(triggered_stops),
            terminal=status in {HypothesisStatus.CONFIRMED, HypothesisStatus.REFUTED},
        )
        another = (
            status in {HypothesisStatus.OPEN, HypothesisStatus.INCONCLUSIVE}
            and independent_count < self.max_inconclusive_attempts
        )

        return OutcomeAssessment(
            task_id=str(task_data.get("task_id", task_data.get("id", ""))),
            hypothesis_id=str(task_data.get("hypothesis_id", prior.hypothesis_id if prior else "")),
            execution_outcome=execution,
            hypothesis_status=status,
            confidence=round(_clamp(confidence), 4),
            satisfied_criteria=satisfied,
            unsatisfied_criteria=unsatisfied,
            triggered_stop_conditions=triggered_stops,
            evidence_refs=refs,
            reasoning=" ".join(reason_bits)[:1000],
            information_value=round(information_value, 4),
            another_investigation_justified=another,
            check_fingerprint=check_fingerprint,
            independent_check=independent_check,
            attempt_count=attempt_count,
        )


class HypothesisRepository:
    """Persistence and queue guards for hypothesis state and assessments."""

    def __init__(self, db: DatabaseManager, mission_id: str) -> None:
        self._db = db
        self._mission_id = mission_id

    def ensure_for_task(self, task: Mapping[str, Any]) -> HypothesisState | None:
        statement = str(task.get("hypothesis", "")).strip()
        if not statement:
            return None
        target = str(task.get("target", "")).strip()
        key = build_hypothesis_key(statement, target)
        candidate_checks = _candidate_checks(task)
        now = _now_iso()

        with self._db.connection(write=True) as conn:
            row = conn.execute(
                "SELECT * FROM hypotheses WHERE mission_id=? AND hypothesis_key=?",
                (self._mission_id, key),
            ).fetchone()
            if row is None:
                hypothesis_id = str(task.get("hypothesis_id", "")) or _new_id("HYP")
                conn.execute(
                    """INSERT INTO hypotheses(
                        id, mission_id, hypothesis_key, statement, target, status,
                        confidence, evidence_refs_json, attempt_count,
                        independent_check_count, check_history_json,
                        candidate_checks_json, last_information_value,
                        created_at, updated_at, last_assessed_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        hypothesis_id,
                        self._mission_id,
                        key,
                        statement,
                        target,
                        HypothesisStatus.OPEN.value,
                        _clamp(task.get("hypothesis_confidence", 0.5)),
                        "[]",
                        0,
                        0,
                        "[]",
                        json.dumps(candidate_checks),
                        0.0,
                        now,
                        now,
                        "",
                    ),
                )
                row = conn.execute("SELECT * FROM hypotheses WHERE id=?", (hypothesis_id,)).fetchone()
            elif candidate_checks:
                state = _row_to_hypothesis(dict(row))
                merged = _merge_refs(state.candidate_checks, candidate_checks)
                if merged != state.candidate_checks:
                    conn.execute(
                        "UPDATE hypotheses SET candidate_checks_json=?, updated_at=? WHERE id=?",
                        (json.dumps(merged), now, state.hypothesis_id),
                    )
                    row = conn.execute("SELECT * FROM hypotheses WHERE id=?", (state.hypothesis_id,)).fetchone()
        return _row_to_hypothesis(dict(row)) if row is not None else None

    def prepare_task(self, task: Mapping[str, Any]) -> tuple[HypothesisState | None, str]:
        """Resolve identity and reject terminal or repeated investigations."""
        state = self.ensure_for_task(task)
        fingerprint = build_check_fingerprint(task)
        if state is None:
            return None, fingerprint
        if state.is_terminal:
            raise ClosedHypothesisError(
                f"Hypothesis {state.hypothesis_id} is {state.status.value} and cannot be replanned."
            )
        if fingerprint in state.check_fingerprints:
            raise DuplicateInvestigationError(
                f"Check {fingerprint} has already been attempted for hypothesis {state.hypothesis_id}."
            )
        with self._db.connection() as conn:
            duplicate = conn.execute(
                """SELECT id FROM tasks
                   WHERE mission_id=? AND hypothesis_id=? AND check_fingerprint=?
                   LIMIT 1""",
                (self._mission_id, state.hypothesis_id, fingerprint),
            ).fetchone()
        if duplicate is not None:
            raise DuplicateInvestigationError(
                f"Check {fingerprint} is already queued for hypothesis {state.hypothesis_id}."
            )
        return state, fingerprint

    def get(self, hypothesis_id: str) -> HypothesisState | None:
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM hypotheses WHERE id=? AND mission_id=?",
                (hypothesis_id, self._mission_id),
            ).fetchone()
        return _row_to_hypothesis(dict(row)) if row else None

    def get_for_task(self, task: Mapping[str, Any]) -> HypothesisState | None:
        hypothesis_id = str(task.get("hypothesis_id", ""))
        if hypothesis_id:
            state = self.get(hypothesis_id)
            if state is not None:
                return state
        return self.ensure_for_task(task)

    def list_all(self) -> list[HypothesisState]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM hypotheses WHERE mission_id=? ORDER BY updated_at DESC",
                (self._mission_id,),
            ).fetchall()
        return [_row_to_hypothesis(dict(row)) for row in rows]

    def list_unresolved(self) -> list[HypothesisState]:
        return [state for state in self.list_all() if not state.is_terminal]

    def persist_assessment(
        self,
        task: Mapping[str, Any],
        assessment: OutcomeAssessment,
    ) -> tuple[OutcomeAssessment, HypothesisState | None]:
        """Atomically persist one assessment and update its hypothesis state."""
        state = self.get_for_task(task)
        now = _now_iso()
        assessment_id = assessment.assessment_id or _new_id("JDG")
        if state is None:
            return replace(assessment, assessment_id=assessment_id, created_at=now), None

        with self._db.connection(write=True) as conn:
            existing = conn.execute(
                "SELECT * FROM outcome_assessments WHERE task_id=?",
                (assessment.task_id,),
            ).fetchone()
            if existing is not None:
                persisted = _row_to_assessment(dict(existing))
                current = conn.execute("SELECT * FROM hypotheses WHERE id=?", (state.hypothesis_id,)).fetchone()
                return persisted, _row_to_hypothesis(dict(current)) if current else state

            history = list(state.check_history)
            if assessment.independent_check and assessment.execution_outcome is not ExecutionOutcome.BLOCKED:
                history.append(
                    {
                        "fingerprint": assessment.check_fingerprint,
                        "task_id": assessment.task_id,
                        "tool": _selected_tool(task),
                        "objective": str(task.get("objective", ""))[:300],
                        "phase": str(task.get("phase", "")),
                        "risk_level": str(task.get("risk_level", "low")),
                        "estimated_cost": task.get("estimated_cost", 0.1),
                        "success_criteria": _criterion_list(task.get("success_criteria", [])),
                        "stop_conditions": _criterion_list(task.get("stop_conditions", [])),
                        "execution_outcome": assessment.execution_outcome.value,
                        "hypothesis_status": assessment.hypothesis_status.value,
                        "evidence_refs": assessment.evidence_refs,
                        "created_at": now,
                    }
                )
            merged_refs = _merge_refs(state.evidence_refs, assessment.evidence_refs)
            independent_count = len({item.get("fingerprint") for item in history if item.get("fingerprint")})
            persisted = replace(
                assessment,
                assessment_id=assessment_id,
                hypothesis_id=state.hypothesis_id,
                attempt_count=max(state.attempt_count, assessment.attempt_count),
                created_at=now,
            )
            conn.execute(
                """INSERT INTO outcome_assessments(
                    id, mission_id, task_id, hypothesis_id, execution_outcome,
                    hypothesis_status, confidence, satisfied_criteria_json,
                    unsatisfied_criteria_json, triggered_stop_conditions_json,
                    evidence_refs_json, reasoning, information_value,
                    another_investigation_justified, check_fingerprint,
                    independent_check, attempt_count, created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    assessment_id,
                    self._mission_id,
                    assessment.task_id,
                    state.hypothesis_id,
                    assessment.execution_outcome.value,
                    assessment.hypothesis_status.value,
                    assessment.confidence,
                    json.dumps(assessment.satisfied_criteria),
                    json.dumps(assessment.unsatisfied_criteria),
                    json.dumps(assessment.triggered_stop_conditions),
                    json.dumps(assessment.evidence_refs),
                    assessment.reasoning,
                    assessment.information_value,
                    int(assessment.another_investigation_justified),
                    assessment.check_fingerprint,
                    int(assessment.independent_check),
                    persisted.attempt_count,
                    now,
                ),
            )
            conn.execute(
                """UPDATE hypotheses SET
                    status=?, confidence=?, evidence_refs_json=?, attempt_count=?,
                    independent_check_count=?, check_history_json=?,
                    last_information_value=?, updated_at=?, last_assessed_at=?
                   WHERE id=? AND mission_id=?""",
                (
                    assessment.hypothesis_status.value,
                    assessment.confidence,
                    json.dumps(merged_refs),
                    persisted.attempt_count,
                    independent_count,
                    json.dumps(history),
                    assessment.information_value,
                    now,
                    now,
                    state.hypothesis_id,
                    self._mission_id,
                ),
            )
            if assessment.hypothesis_status in TERMINAL_HYPOTHESIS_STATUSES:
                conn.execute(
                    """UPDATE tasks SET status='blocked', block_reason=?, updated_at=?
                       WHERE mission_id=? AND hypothesis_id=? AND status='pending'
                         AND id<>?""",
                    (
                        f"Hypothesis is {assessment.hypothesis_status.value}.",
                        now,
                        self._mission_id,
                        state.hypothesis_id,
                        assessment.task_id,
                    ),
                )
            self._db.log_audit(
                conn,
                self._mission_id,
                "outcome_judgment",
                (
                    f"Hypothesis {state.hypothesis_id} -> "
                    f"{assessment.hypothesis_status.value} "
                    f"(confidence {assessment.confidence:.2f})."
                ),
                task_id=assessment.task_id,
                metadata=persisted.to_dict(),
            )
            row = conn.execute("SELECT * FROM hypotheses WHERE id=?", (state.hypothesis_id,)).fetchone()
        return persisted, _row_to_hypothesis(dict(row)) if row else state

    def get_assessment_for_task(self, task_id: str) -> OutcomeAssessment | None:
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM outcome_assessments WHERE task_id=?",
                (task_id,),
            ).fetchone()
        return _row_to_assessment(dict(row)) if row else None


def build_hypothesis_key(statement: str, target: str) -> str:
    normalized = f"{_normalize_text(target)}\n{_normalize_text(statement)}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def build_check_fingerprint(task: Mapping[str, Any]) -> str:
    """Fingerprint the material investigation method, not cosmetic retry text."""
    explicit_method = str(task.get("investigation_method", task.get("check", ""))).strip()
    tool = _selected_tool(task)
    tool_args = task.get("tool_args", {})
    if not isinstance(tool_args, Mapping):
        tool_args = {}
    payload: dict[str, Any] = {
        "tool": tool.strip().lower(),
        "tool_args": dict(tool_args),
    }
    if not tool:
        payload["method"] = _normalize_text(explicit_method)
        if not explicit_method:
            payload["objective"] = _normalize_retry_objective(str(task.get("objective", "")))
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _selected_tool(task: Mapping[str, Any]) -> str:
    selected = str(task.get("selected_tool", "")).strip()
    if selected:
        return selected
    tools = task.get("allowed_tools", [])
    if isinstance(tools, (list, tuple)) and tools:
        return str(tools[0])
    return ""


def _candidate_checks(task: Mapping[str, Any]) -> list[str]:
    tools = task.get("allowed_tools", [])
    if not isinstance(tools, (list, tuple)):
        return []
    return [str(tool).strip() for tool in tools if str(tool).strip()]


def _execution_outcome(result: Any) -> ExecutionOutcome:
    if bool(_get(result, "success", False)):
        return ExecutionOutcome.SUCCEEDED
    error = str(_get(result, "error", "")).lower()
    gate_passed = bool(_get(result, "scope_gate_passed", False)) or bool(_get(result, "risk_gate_passed", False))
    blocked_markers = ("out of scope", "blocked", "approval", "not authorized", "scope gate")
    if not gate_passed and any(marker in error for marker in blocked_markers):
        return ExecutionOutcome.BLOCKED
    return ExecutionOutcome.FAILED


def _as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        data = to_dict()
        return dict(data) if isinstance(data, Mapping) else {}
    return {
        key: getattr(value, key)
        for key in (
            "facts",
            "new_assets",
            "new_endpoints",
            "new_parameters",
            "new_technologies",
            "new_identities",
            "new_objects",
            "interesting_signals",
            "possible_findings",
            "dead_ends",
            "evidence_refs",
            "hypothesis_evidence",
            "confidence",
            "usefulness",
        )
        if hasattr(value, key)
    }


def _get(value: Any, key: str, default: Any) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _criterion_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _criterion_met(criterion: Any, observation: Mapping[str, Any]) -> bool:
    if isinstance(criterion, Mapping):
        return _structured_criterion_met(criterion, observation)
    text = str(criterion).strip()
    if not text:
        return False
    clauses = [clause.strip() for clause in text.split(";") if clause.strip()]
    return bool(clauses) and all(_text_criterion_met(clause, observation) for clause in clauses)


def _structured_criterion_met(
    criterion: Mapping[str, Any],
    observation: Mapping[str, Any],
) -> bool:
    field_name = str(criterion.get("field", criterion.get("path", ""))).strip()
    operator = str(criterion.get("operator", "contains")).strip().lower()
    expected = criterion.get("value", criterion.get("expected"))
    actual = _resolve_field(observation, field_name)

    if operator in {"exists", "nonempty"}:
        return bool(actual)
    if operator in {"count_gte", "length_gte"}:
        try:
            return len(actual or []) >= int(expected)
        except (TypeError, ValueError):
            return False
    if operator in {"gte", ">="}:
        try:
            return float(actual) >= float(expected)
        except (TypeError, ValueError):
            return False
    if operator in {"equals", "eq", "=="}:
        return _normalize_text(str(actual)) == _normalize_text(str(expected))
    if operator in {"not_equals", "ne", "!="}:
        return _normalize_text(str(actual)) != _normalize_text(str(expected))
    flattened = _flatten_text(actual)
    expected_text = _normalize_text(str(expected))
    if operator in {"contains", "includes", ""} and not _meaningful_tokens(expected_text):
        # Generic operational words such as "success" or "completed" are not
        # evidence that a hypothesis is true.
        return False
    contains = any(expected_text and expected_text in _normalize_text(item) for item in flattened)
    if operator in {"not_contains", "excludes"}:
        return not contains
    return contains


def _resolve_field(observation: Mapping[str, Any], field_name: str) -> Any:
    current: Any = observation
    for part in field_name.split("."):
        if not part:
            continue
        if isinstance(current, Mapping):
            current = current.get(part)
        else:
            return None
    return current


def _text_criterion_met(criterion: str, observation: Mapping[str, Any]) -> bool:
    criterion_norm = _normalize_text(criterion)
    facts = _flatten_text(observation.get("facts", []))
    endpoints = _flatten_text(observation.get("new_endpoints", []))
    technologies = _flatten_text(observation.get("new_technologies", []))
    assets = _flatten_text(observation.get("new_assets", []))
    signals = _flatten_text(observation.get("interesting_signals", []))
    evidence_items = _flatten_text(observation.get("hypothesis_evidence", []))
    dead_ends = _flatten_text(observation.get("dead_ends", []))
    structured = facts + endpoints + technologies + assets + signals + evidence_items + dead_ends

    if "endpoints" in criterion_norm and "technologies" in criterion_norm:
        return bool(endpoints) and bool(technologies)
    if "at least one service" in criterion_norm and "version" in criterion_norm:
        versioned = technologies + facts
        return any(re.search(r"\b\d+(?:\.\d+)+\b", item) for item in versioned)
    if "reachable" in criterion_norm:
        return bool(assets) or any(
            any(marker in _normalize_text(item) for marker in ("reachable", "host is up", "responded"))
            for item in facts
        )
    if "web response" in criterion_norm or "http response" in criterion_norm:
        return bool(endpoints) or any("http " in _normalize_text(item) for item in facts)
    if "endpoints" in criterion_norm and ("noted" in criterion_norm or "identified" in criterion_norm):
        return bool(endpoints)
    if "technologies" in criterion_norm and ("noted" in criterion_norm or "identified" in criterion_norm):
        return bool(technologies)
    if "scope confirmed" in criterion_norm:
        return any("scope confirmed" in _normalize_text(item) for item in facts) and not observation.get("dead_ends")
    if "hypothesis confirmed or refuted" in criterion_norm:
        support, refute = _explicit_evidence_scores(observation)
        return max(support, refute) >= 0.75

    expected_tokens = _meaningful_tokens(criterion_norm)
    if not expected_tokens:
        return False
    for item in structured:
        actual_norm = _normalize_text(item)
        actual_tokens = _meaningful_tokens(actual_norm)
        if criterion_norm in actual_norm:
            return True
        overlap = expected_tokens & actual_tokens
        required = 1 if len(expected_tokens) == 1 else max(2, int(len(expected_tokens) * 0.6 + 0.5))
        if len(overlap) >= required:
            return True
    return False


def _explicit_evidence_scores(observation: Mapping[str, Any]) -> tuple[float, float]:
    support = 0.0
    refute = 0.0
    entries = observation.get("hypothesis_evidence", [])
    if isinstance(entries, Mapping):
        entries = [entries]
    for entry in entries if isinstance(entries, (list, tuple)) else []:
        if isinstance(entry, Mapping):
            polarity = str(entry.get("polarity", entry.get("status", entry.get("hypothesis_status", "")))).lower()
            confidence = _clamp(entry.get("confidence", 1.0))
        else:
            polarity = str(entry).lower()
            confidence = 1.0
        if polarity in {"supports", "support", "confirmed", "confirm", "positive"}:
            support = max(support, confidence)
        if polarity in {"contradicts", "contradiction", "refuted", "refute", "negative"}:
            refute = max(refute, confidence)

    for fact in _flatten_text(observation.get("facts", [])):
        normalized = _normalize_text(fact)
        if normalized.startswith(("confirms ", "confirmed ", "evidence supports ")):
            support = max(support, 0.9)
        if normalized.startswith(("refutes ", "refuted ", "evidence contradicts ")):
            refute = max(refute, 0.9)
    return support, refute


def _contradiction_score(task: Mapping[str, Any], observation: Mapping[str, Any]) -> float:
    actual_items = _flatten_text(observation.get("facts", [])) + _flatten_text(
        observation.get("hypothesis_evidence", [])
    )
    expected_items = [str(task.get("hypothesis", ""))] + [
        str(item) for item in _criterion_list(task.get("success_criteria", [])) if not isinstance(item, Mapping)
    ]
    for expected in expected_items:
        for actual in actual_items:
            if _texts_contradict(expected, actual):
                return 0.9
    return 0.0


def _texts_contradict(expected: str, actual: str) -> bool:
    expected_norm = _normalize_text(expected)
    actual_norm = _normalize_text(actual)
    pairs = (
        (
            {"open", "reachable", "present", "enabled", "allowed", "responds", "exposes"},
            {"closed", "unreachable", "absent", "disabled", "denied", "down", "filtered"},
        ),
        (
            {"closed", "unreachable", "absent", "disabled", "denied", "down"},
            {"open", "reachable", "present", "enabled", "allowed", "up"},
        ),
    )
    expected_tokens = _meaningful_tokens(expected_norm)
    actual_tokens = _meaningful_tokens(actual_norm)
    anchor_expected = expected_tokens - _POLARITY_TOKENS
    anchor_actual = actual_tokens - _POLARITY_TOKENS
    anchors_match = bool(anchor_expected & anchor_actual)
    if not anchors_match:
        expected_numbers = set(re.findall(r"\b\d+\b", expected_norm))
        actual_numbers = set(re.findall(r"\b\d+\b", actual_norm))
        anchors_match = bool(expected_numbers & actual_numbers)
    if not anchors_match:
        return False
    if any((expected_tokens & positive) and (actual_tokens & negative) for positive, negative in pairs):
        return True
    if re.search(r"\b(no|not|never|without)\b", actual_norm):
        positive_expected = expected_tokens & _POLARITY_TOKENS
        return bool(positive_expected)
    return False


def _information_value(
    observation: Mapping[str, Any],
    evidence_refs: list[str],
    *,
    satisfied_count: int,
    triggered_count: int,
    terminal: bool,
) -> float:
    usefulness = _clamp(float(observation.get("usefulness", 0) or 0) / 100.0)
    populated = sum(
        bool(observation.get(field))
        for field in (
            "facts",
            "new_assets",
            "new_endpoints",
            "new_parameters",
            "new_technologies",
            "new_identities",
            "new_objects",
            "interesting_signals",
            "possible_findings",
            "hypothesis_evidence",
        )
    )
    structural = min(1.0, populated / 5.0)
    evidence = min(1.0, len(evidence_refs) / 2.0)
    resolution = min(1.0, (satisfied_count + triggered_count) / 2.0)
    score = 0.35 * usefulness + 0.25 * structural + 0.2 * evidence + 0.2 * resolution
    if terminal:
        score = max(score, 0.85)
    return _clamp(score)


def _flatten_text(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [json.dumps(value, sort_keys=True, default=str)]
    if isinstance(value, (list, tuple, set)):
        items: list[str] = []
        for entry in value:
            items.extend(_flatten_text(entry))
        return items
    return [str(value)]


def _merge_refs(*groups: Iterable[Any]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for value in group or ():
            item = str(value).strip()
            if item and item not in seen:
                seen.add(item)
                merged.append(item)
    return merged


_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "been",
    "by",
    "confirmed",
    "complete",
    "completed",
    "for",
    "from",
    "has",
    "have",
    "in",
    "is",
    "it",
    "no",
    "not",
    "of",
    "on",
    "or",
    "success",
    "successful",
    "that",
    "the",
    "this",
    "to",
    "was",
    "were",
    "with",
}
_POLARITY_TOKENS = {
    "absent",
    "allowed",
    "closed",
    "denied",
    "disabled",
    "down",
    "enabled",
    "exposes",
    "filtered",
    "open",
    "present",
    "reachable",
    "responds",
    "unreachable",
    "up",
}


def _meaningful_tokens(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9_.:/-]+", text.lower())
        if token not in _STOPWORDS and (len(token) > 2 or token.isdigit())
    }


def _normalize_text(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9_.:/-]+", str(value).lower()))


def _normalize_retry_objective(value: str) -> str:
    normalized = re.sub(r"^\s*\[retry\s+\d+\]\s*", "", value, flags=re.IGNORECASE)
    normalized = re.sub(
        r"\s*\((?:extended timeout|connection retry|rate limit backoff)\)\s*$",
        "",
        normalized,
        flags=re.IGNORECASE,
    )
    return _normalize_text(normalized)


def _clamp(value: Any) -> float:
    try:
        return max(0.0, min(float(value), 1.0))
    except (TypeError, ValueError):
        return 0.5


def _coerce_state(value: HypothesisState | Mapping[str, Any] | None) -> HypothesisState | None:
    if value is None or isinstance(value, HypothesisState):
        return value
    status_raw = str(value.get("status", HypothesisStatus.OPEN.value))
    try:
        status = HypothesisStatus(status_raw)
    except ValueError:
        status = HypothesisStatus.OPEN
    history = value.get("check_history", [])
    if not history and value.get("check_fingerprints"):
        history = [{"fingerprint": item} for item in value.get("check_fingerprints", [])]
    return HypothesisState(
        hypothesis_id=str(value.get("hypothesis_id", value.get("id", ""))),
        mission_id=str(value.get("mission_id", "")),
        statement=str(value.get("statement", value.get("hypothesis", ""))),
        target=str(value.get("target", "")),
        status=status,
        confidence=_clamp(value.get("confidence", 0.5)),
        evidence_refs=list(value.get("evidence_refs", [])),
        attempt_count=int(value.get("attempt_count", 0) or 0),
        independent_check_count=int(value.get("independent_check_count", len(history)) or 0),
        check_history=list(history),
        candidate_checks=list(value.get("candidate_checks", [])),
        last_information_value=_clamp(value.get("last_information_value", 0.0)),
        created_at=str(value.get("created_at", "")),
        updated_at=str(value.get("updated_at", "")),
        last_assessed_at=str(value.get("last_assessed_at", "")),
    )


def _row_to_hypothesis(data: Mapping[str, Any]) -> HypothesisState:
    status_raw = str(data.get("status", HypothesisStatus.OPEN.value))
    try:
        status = HypothesisStatus(status_raw)
    except ValueError:
        status = HypothesisStatus.OPEN
    return HypothesisState(
        hypothesis_id=str(data.get("id", "")),
        mission_id=str(data.get("mission_id", "")),
        statement=str(data.get("statement", "")),
        target=str(data.get("target", "")),
        status=status,
        confidence=_clamp(data.get("confidence", 0.5)),
        evidence_refs=_json_list(data.get("evidence_refs_json", "[]")),
        attempt_count=int(data.get("attempt_count", 0) or 0),
        independent_check_count=int(data.get("independent_check_count", 0) or 0),
        check_history=_json_list(data.get("check_history_json", "[]")),
        candidate_checks=_json_list(data.get("candidate_checks_json", "[]")),
        last_information_value=_clamp(data.get("last_information_value", 0.0)),
        created_at=str(data.get("created_at", "")),
        updated_at=str(data.get("updated_at", "")),
        last_assessed_at=str(data.get("last_assessed_at", "")),
    )


def _row_to_assessment(data: Mapping[str, Any]) -> OutcomeAssessment:
    return OutcomeAssessment(
        assessment_id=str(data.get("id", "")),
        task_id=str(data.get("task_id", "")),
        hypothesis_id=str(data.get("hypothesis_id", "")),
        execution_outcome=ExecutionOutcome(str(data.get("execution_outcome", "failed"))),
        hypothesis_status=HypothesisStatus(str(data.get("hypothesis_status", "inconclusive"))),
        confidence=_clamp(data.get("confidence", 0.5)),
        satisfied_criteria=_json_list(data.get("satisfied_criteria_json", "[]")),
        unsatisfied_criteria=_json_list(data.get("unsatisfied_criteria_json", "[]")),
        triggered_stop_conditions=_json_list(data.get("triggered_stop_conditions_json", "[]")),
        evidence_refs=_json_list(data.get("evidence_refs_json", "[]")),
        reasoning=str(data.get("reasoning", "")),
        information_value=_clamp(data.get("information_value", 0.0)),
        another_investigation_justified=bool(data.get("another_investigation_justified", 0)),
        check_fingerprint=str(data.get("check_fingerprint", "")),
        independent_check=bool(data.get("independent_check", 0)),
        attempt_count=int(data.get("attempt_count", 0) or 0),
        created_at=str(data.get("created_at", "")),
    )


def _json_list(raw: Any) -> list[Any]:
    if isinstance(raw, list):
        return raw
    try:
        value = json.loads(raw or "[]")
    except (json.JSONDecodeError, TypeError):
        return []
    return value if isinstance(value, list) else []


__all__ = [
    "ClosedHypothesisError",
    "DuplicateInvestigationError",
    "ExecutionOutcome",
    "HypothesisRepository",
    "HypothesisState",
    "HypothesisStatus",
    "OutcomeAssessment",
    "OutcomeJudge",
    "TERMINAL_HYPOTHESIS_STATUSES",
    "build_check_fingerprint",
    "build_hypothesis_key",
]
