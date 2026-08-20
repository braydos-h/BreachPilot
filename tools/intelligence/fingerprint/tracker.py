"""In-memory attempt tracker: dedup, repetition checks, retry justification.

Thread-safe via one ``threading.Lock`` around the whole store (fine for
single-process use; shard per-fingerprint only if contention ever matters).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .attempt import Attempt, AttemptStatus, RetryJustification, RetryJustifier

__all__ = [
    "PERMANENT_FAILURE_MARKERS",
    "AttemptTracker",
    "is_permanent_failure",
]

# Single consolidated vocabulary of terminal (non-retryable) failures.
# This replaces the 3+ duplicated permanent-error lists in the repo:
#   planner.py:140-144, autonomous_orchestrator.py:421-430, attack_memory.py:433-448.
PERMANENT_FAILURE_MARKERS: tuple[str, ...] = (
    "out of scope",
    "permission denied",
    "not authorized",
    "blocked by scope",
    "target unreachable",
    "connection refused",
    "tool not found",
    "not installed",
    "command not found",
)


def is_permanent_failure(output: str) -> bool:
    """True if ``output`` mentions any permanent-failure marker (case-insensitive)."""
    if not output:
        return False
    lowered = output.lower()
    return any(marker in lowered for marker in PERMANENT_FAILURE_MARKERS)


@dataclass
class _Record:
    key: str
    status: AttemptStatus
    detail: str
    evidence: dict
    timestamp: str
    repeat_count: int = 0
    history: list[tuple[str, str, str]] = field(default_factory=list)


class AttemptTracker:
    """In-memory store of attempt fingerprints.

    * ``record`` dedups: a second record of the same fingerprint while the
      existing status is ATTEMPTED/FAILED returns the existing key and bumps
      the repeat counter instead of overwriting.
    * BLOCKED is deliberately *not* terminal: a blocked attempt may be
      transient, so a later retry without new evidence is not flagged as an
      unjustified repetition (see :meth:`is_repetition`).
    * REFUTED and FAILED *are* terminal: retrying after one of those requires
      new evidence, or the retry is reported as ``NONE``.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, _Record] = {}

    def record(
        self,
        attempt: Attempt,
        status: AttemptStatus,
        detail: str = "",
        evidence_snapshot: dict | None = None,
        timestamp: str = "",
    ) -> str:
        """Record an attempt; dedup on fingerprint. Returns the attempt key."""
        key = attempt.fingerprint()
        with self._lock:
            existing = self._records.get(key)
            if existing is not None and existing.status in (
                AttemptStatus.ATTEMPTED,
                AttemptStatus.FAILED,
            ):
                existing.repeat_count += 1
                existing.history.append((timestamp, "repeat", detail or "duplicate attempt"))
                return existing.key
            if existing is None:
                self._records[key] = _Record(
                    key=key,
                    status=status,
                    detail=detail,
                    evidence=evidence_snapshot or {},
                    timestamp=timestamp,
                )
                self._records[key].history.append((timestamp, status.value, detail))
            else:
                existing.status = status
                existing.detail = detail
                existing.evidence = evidence_snapshot or {}
                existing.timestamp = timestamp
                existing.history.append((timestamp, status.value, detail))
            return key

    def has_attempted(self, fingerprint: str) -> bool:
        """True if any attempt with this fingerprint has been recorded."""
        with self._lock:
            return fingerprint in self._records

    def status_of(self, fingerprint: str) -> AttemptStatus | None:
        """Current status of the fingerprint, or None if never recorded."""
        with self._lock:
            rec = self._records.get(fingerprint)
            return rec.status if rec else None

    def is_repetition(
        self, fingerprint: str, current_evidence: dict | None = None
    ) -> tuple[bool, RetryJustification, str]:
        """Decide whether acting again on this fingerprint is a repetition.

        * No prior record -> ``(False, NONE, "no prior attempt")``.
        * Prior terminal status (FAILED/REFUTED) with *no material evidence
          change* -> ``(True, NONE, ...)`` — retry not justified.
        * Prior terminal status with a material evidence change ->
          ``(True, justification, detail)`` — retry justified.
        * Prior BLOCKED/ATTEMPTED/INCONCLUSIVE/CONFIRMED -> ``(False, ...)`` —
          BLOCKED may be transient; the others are not failures to retry.
        """
        with self._lock:
            rec = self._records.get(fingerprint)
            if rec is None:
                return False, RetryJustification.NONE, "no prior attempt"
            if rec.status in (AttemptStatus.ATTEMPTED, AttemptStatus.INCONCLUSIVE, AttemptStatus.CONFIRMED):
                return False, RetryJustification.NONE, f"prior status {rec.status.value} is not terminal"
            if rec.status is AttemptStatus.BLOCKED:
                return False, RetryJustification.NONE, "prior status blocked is not terminal (may be transient)"
            snapshot = {k: v for k, v in (current_evidence or {}).items() if k != "previous_evidence"}
            reason, detail = RetryJustifier().evaluate(Attempt("", ""), {**snapshot, "previous_evidence": rec.evidence})
            return True, reason, detail

    def all_fingerprints(self) -> list[str]:
        """All recorded fingerprints (insertion order)."""
        with self._lock:
            return list(self._records.keys())

    def clear(self) -> None:
        """Drop all records."""
        with self._lock:
            self._records.clear()

    def summary(self) -> dict[str, int]:
        """Counts of recorded attempts by status value."""
        with self._lock:
            counts = {s.value: 0 for s in AttemptStatus}
            for rec in self._records.values():
                counts[rec.status.value] += 1
            return counts

    def retry_history(self, fingerprint: str) -> list[tuple[str, str, str]]:
        """[(timestamp, status_or_repeat, detail)] in record order, for diagnostics."""
        with self._lock:
            rec = self._records.get(fingerprint)
            return list(rec.history) if rec else []

    def register_evidence_change(self, fingerprint: str, reason: str) -> None:
        """Telemetry hook: note that the environment changed for a fingerprint."""
        with self._lock:
            rec = self._records.get(fingerprint)
            if rec is not None:
                rec.history.append(("", "evidence_change", reason))
