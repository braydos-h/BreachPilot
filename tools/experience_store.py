"""Experience Store — tracks exploit outcomes with Bayesian confidence updates.

Provides per-(service, version, os, module) success rates so agents can
select high-confidence tools and avoid repeatedly failing approaches.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from typing import Any

from db import DatabaseManager, _new_id, _now_iso


class ExperienceStore:
    """Tracks action outcomes and maintains Bayesian confidence scores.

    Confidence is the mean of a Beta posterior, updated per recorded outcome.
    Two soundness gates (Tier 1.1) keep the "principled action selector" honest:

    - **min_samples**: when fewer than ``min_samples`` outcomes have been
      recorded for a (target_signature, action_type) pair, ``get_confidence``
      returns a neutral ``0.5`` instead of a confident-looking ratio built on
      thin data (one success used to read as 0.67 — "high confidence").
    - **time_decay_days**: outcomes are weighted by an exponential time decay
      (half-life ``time_decay_days``) so an ancient outcome counts less than a
      recent one; the default half-life of 90 days means a 90-day-old result
      weighs half as much as one recorded today. Set ``time_decay_days <= 0``
      to disable decay (weight 1.0 for every row, the pre-1.1 behavior).
    """

    def __init__(
        self,
        db: DatabaseManager,
        *,
        min_samples: int = 3,
        time_decay_days: float = 90.0,
    ) -> None:
        self._db = db
        self._min_samples = max(1, int(min_samples))
        self._time_decay_days = (
            float(time_decay_days) if time_decay_days and time_decay_days > 0 else 0.0
        )

    def _decay_weight(self, created_at: str) -> float:
        """Exponential decay weight in [0, 1] for a row's ``created_at``.

        1.0 at age 0, 0.5 at age ``time_decay_days``, decaying toward 0. Returns
        1.0 (no decay) when ``time_decay_days`` <= 0 or the timestamp is
        unparseable — never raises on a bad row.
        """
        if self._time_decay_days <= 0.0:
            return 1.0
        try:
            created = datetime.fromisoformat(created_at)
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = max(
                0.0,
                (datetime.now(timezone.utc) - created).total_seconds() / 86400.0,
            )
            return float(math.exp(-age_days / self._time_decay_days))
        except Exception:
            return 1.0

    # ── Recording outcomes ──────────────────────────────────────────────

    def record_outcome(
        self,
        target_signature: str,
        action_type: str,
        outcome: str,  # 'success', 'failure', 'partial'
        metadata: dict[str, Any] | None = None,
        *,
        action_suffix: str = "",
    ) -> str:
        """Record an outcome observation. Returns the record ID.

        ``action_suffix`` is an optional free-form tag (e.g. ``"shell"``,
        ``"creds"``, ``"partial"``) appended to ``action_type`` as
        ``f"{action_type}:{action_suffix}"`` for storage and querying. This
        lets the Bayesian posterior condition on the distinct outcome class —
        a shell compromise (``"module:strategy:shell"``) is scored
        independently from a credential dump (``"module:strategy:creds"``)
        or a bare operational outcome (``"module:strategy"``), instead of all
        three collapsing into one Beta distribution. Empty / falsy
        ``action_suffix`` preserves the original behavior (callers that pass
        a bare ``action_type`` are byte-identical to pre-1.1 runs).
        """
        stored_action = f"{action_type}:{action_suffix}" if action_suffix else action_type
        rid = _new_id("EXP")
        with self._db.connection(write=True) as conn:
            conn.execute(
                """INSERT INTO lessons(id, pattern_hash, target_signature, action_type, outcome, confidence, embedding_json, metadata_json, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    rid,
                    f"{target_signature}:{stored_action}",
                    target_signature,
                    stored_action,
                    outcome,
                    0.5,  # initial confidence
                    "[]",
                    json.dumps(metadata or {}),
                    _now_iso(),
                ),
            )
        return rid

    def record_evidential_outcome(
        self,
        target_signature: str,
        action_type: str,
        hypothesis_status: str,
        *,
        confidence: float,
        evidence_refs: list[str],
        metadata: dict[str, Any] | None = None,
    ) -> str | None:
        """Record learning only for evidence-supported confirmation/refutation.

        Operational success/failure is intentionally not accepted here.
        Inconclusive, open, and exhausted hypotheses return ``None`` so they
        cannot reinforce a tool or strategy.
        """
        normalized_status = str(hypothesis_status).strip().lower()
        outcome_by_status = {
            "confirmed": "success",
            "refuted": "failure",
        }
        outcome = outcome_by_status.get(normalized_status)
        if outcome is None:
            return None
        try:
            calibrated_confidence = max(0.0, min(float(confidence), 1.0))
        except (TypeError, ValueError):
            calibrated_confidence = 0.5
        if not evidence_refs:
            return None
        evidence_metadata = dict(metadata or {})
        evidence_metadata.update(
            {
                "hypothesis_status": normalized_status,
                "judgment_confidence": calibrated_confidence,
                "evidence_refs": list(dict.fromkeys(str(ref) for ref in evidence_refs if ref)),
                "evidence_grounded": True,
            }
        )
        return self.record_outcome(
            target_signature,
            action_type,
            outcome,
            evidence_metadata,
        )

    # ── Bayesian confidence query ───────────────────────────────────────

    def get_confidence(
        self,
        target_signature: str,
        action_type: str,
    ) -> float:
        """Return the Bayesian confidence for a (target_signature, action_type) pair.

        Uses the decay-weighted Beta(1+successes, 1+failures) mean as the
        confidence score. Returns a neutral ``0.5`` when fewer than
        ``min_samples`` outcomes have been recorded so thin data does not
        masquerade as a confident ratio.
        """
        successes = 0.0
        failures = 0.0
        partials = 0.0
        n = 0

        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT outcome, created_at FROM lessons "
                "WHERE target_signature = ? AND action_type = ? "
                "AND embedding_json = '[]'",
                (target_signature, action_type),
            )
            for row in cur.fetchall():
                n += 1
                w = self._decay_weight(row["created_at"])
                outcome = row["outcome"]
                if outcome == "success":
                    successes += w
                elif outcome == "failure":
                    failures += w
                elif outcome == "partial":
                    partials += 0.5 * w

        if n < self._min_samples:
            return 0.5

        # Beta prior: Beta(1,1) = uniform. Posterior mean = alpha / (alpha+beta)
        alpha = 1.0 + successes + partials
        beta = 1.0 + failures + partials
        return alpha / (alpha + beta)

    def observation_count(
        self,
        target_signature: str,
        action_type: str,
    ) -> int:
        """Return the total number of recorded outcomes for a pair.

        Unlike ``get_confidence`` (which gates on ``min_samples`` and returns a
        posterior), this is the raw row count used by callers that need their
        own sample-size gate -- e.g. the runtime-skill feedback loop applies a
        separate ``feedback_min_observations`` threshold before trusting a
        ``skill_prior``. Counts every row regardless of outcome value.
        """
        try:
            with self._db.connection() as conn:
                cur = conn.execute(
                    "SELECT COUNT(*) AS n FROM lessons "
                    "WHERE target_signature = ? AND action_type = ? "
                    "AND embedding_json = '[]'",
                    (target_signature, action_type),
                )
                row = cur.fetchone()
                return int(row["n"]) if row is not None else 0
        except Exception:
            return 0

    def get_best_action(
        self,
        target_signature: str,
        candidates: list[str],
    ) -> tuple[str, float] | None:
        """Return the candidate action with the highest confidence for the target."""
        best_action: str | None = None
        best_conf = -1.0
        for action in candidates:
            conf = self.get_confidence(target_signature, action)
            if conf > best_conf:
                best_conf = conf
                best_action = action
        if best_action is None:
            return None
        return best_action, best_conf

    def get_all_confidences(
        self,
        target_signature: str,
    ) -> dict[str, float]:
        """Return confidence scores for all known actions against a target signature.

        Each action's score is the decay-weighted Beta mean, gated on
        ``min_samples`` (actions with too few observations read as a neutral
        0.5 rather than a confident-looking thin-data ratio).
        """
        results: dict[str, float] = {}
        # action -> {success: weight_sum, failure: weight_sum, partial: weight_sum, n: int}
        agg: dict[str, dict[str, float]] = {}
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT action_type, outcome, created_at FROM lessons "
                "WHERE target_signature = ? AND embedding_json = '[]'",
                (target_signature,),
            )
            for row in cur.fetchall():
                action = row["action_type"]
                bucket = agg.setdefault(
                    action, {"success": 0.0, "failure": 0.0, "partial": 0.0, "n": 0.0}
                )
                bucket["n"] += 1
                w = self._decay_weight(row["created_at"])
                outcome = row["outcome"]
                if outcome == "success":
                    bucket["success"] += w
                elif outcome == "failure":
                    bucket["failure"] += w
                elif outcome == "partial":
                    bucket["partial"] += 0.5 * w

        for action, b in agg.items():
            if b["n"] < self._min_samples:
                results[action] = 0.5
                continue
            alpha = 1.0 + b["success"] + b["partial"]
            beta = 1.0 + b["failure"] + b["partial"]
            results[action] = alpha / (alpha + beta)

        return results

    # ── Feedback loop ───────────────────────────────────────────────────

    def update_from_result(
        self,
        target_signature: str,
        action_type: str,
        success: bool,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Convenience wrapper to record a binary success/failure outcome."""
        outcome = "success" if success else "failure"
        self.record_outcome(target_signature, action_type, outcome, metadata)

    def record_module_outcome(
        self,
        target_signature: str,
        module_name: str,
        status_str: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Phase 1: map an AttackModule's run() status string to a Bayesian
        outcome and record it. ``info`` → ``partial`` (neutral 0.5 weight --
        the module ran but produced no compromise signal, so it should not
        inflate or deflate confidence); ``success``/``exploited``/
        ``script_generated`` → ``success``; ``failed``/``blocked`` →
        ``failure``. This feeds the orchestrator's module runs into the
        same ExperienceStore the exploit-agent loop writes to, so
        ``find_modules`` on the next campaign reflects orchestrator history.
        """
        s = str(status_str or "").lower()
        if s in ("success", "exploited", "script_generated"):
            outcome = "success"
        elif s in ("failed", "blocked", "error"):
            outcome = "failure"
        else:
            outcome = "partial"
        self.record_outcome(
            target_signature=target_signature,
            action_type=module_name,
            outcome=outcome,
            metadata=metadata,
        )

    def update_from_exploit_result(
        self,
        service_name: str,
        version: str,
        os_hint: str,
        module_name: str,
        mutation_strategy: str,
        success: bool,
    ) -> None:
        """Record an exploit outcome with full context for adaptive generation."""
        target_signature = f"{service_name}:{version}:{os_hint}"
        action_type = f"{module_name}:{mutation_strategy}"
        self.update_from_result(
            target_signature=target_signature,
            action_type=action_type,
            success=success,
            metadata={
                "service_name": service_name,
                "version": version,
                "os_hint": os_hint,
                "module_name": module_name,
                "mutation_strategy": mutation_strategy,
            },
        )
