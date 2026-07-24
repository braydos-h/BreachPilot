"""Finding Verifier — ensures findings are real, in-scope, reproducible, impactful.

Finding states:
  candidate → needs_validation → validated → report_ready
  candidate → rejected
  candidate → duplicate_suspected

Verifier checklist:
1. Is the asset in scope?
2. Is the behavior reproducible?
3. Is there clear security impact?
4. Is there evidence?
5. Is there a benign explanation?
6. Is auth/ownership/permission context understood?
7. Is the issue likely accepted by a bug bounty triager?
8. Are there safe reproduction steps?
9. Is the report free of overclaiming?
10. Is more validation needed?

Backed by SQLite findings table via DatabaseManager.
"""

from __future__ import annotations

import json
from typing import Any

from db import DatabaseManager, _new_id, _now_iso


# ── Finding states ─────────────────────────────────────────────────────────

VALID_STATUS_TRANSITIONS = {
    "candidate": {"needs_validation", "rejected", "duplicate_suspected"},
    "needs_validation": {"validated", "rejected", "duplicate_suspected"},
    "duplicate_suspected": {"rejected", "validated", "needs_validation"},
    "validated": {"report_ready", "rejected"},
    "report_ready": {"rejected"},
    "rejected": set(),  # terminal
}

# ── Vulnerability classes ──────────────────────────────────────────────────

VULN_CLASSES = [
    "IDOR",
    "Broken Access Control",
    "Sensitive Data Exposure",
    "Security Misconfiguration",
    "Missing Authentication",
    "Information Disclosure",
    "CSRF",
    "SSRF",
    "XSS",
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "File Upload",
    "Authentication Bypass",
    "Authorization Bypass",
    "Privilege Escalation",
    "Known CVE",
    "Open Redirect",
    "Rate Limiting Missing",
    "Other",
]

# ── Impact scoring (0-100) ─────────────────────────────────────────────────

_IMPACT_CATEGORIES = {
    "high": 80,
    "medium": 50,
    "low": 20,
    "none": 0,
}


class FindingVerifier:
    """Manages the finding lifecycle from candidate → validation → report_ready."""

    def __init__(self, db: DatabaseManager, mission_id: str) -> None:
        self._db = db
        self._mission_id = mission_id

    # ── Creation ────────────────────────────────────────────────────────

    def create_candidate(
        self,
        title: str,
        affected_asset: str,
        summary: str,
        vuln_class: str = "",
        affected_endpoint: str = "",
        impact: str = "",
        confidence: float = 0.3,
        evidence_refs: list[str] | None = None,
    ) -> str:
        """Create a new finding in 'candidate' status. Returns finding_id."""
        fid = _new_id("F")
        with self._db.connection(write=True) as conn:
            conn.execute(
                """INSERT INTO findings(
                    id, mission_id, title, vuln_class, affected_asset, affected_endpoint,
                    summary, impact, confidence, impact_score, status,
                    evidence_refs_json, reproduction_steps_json, missing_validation_json,
                    created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    fid,
                    self._mission_id,
                    title,
                    vuln_class,
                    affected_asset,
                    affected_endpoint,
                    summary,
                    impact,
                    confidence,
                    self._score_impact(vuln_class, impact),
                    "candidate",
                    json.dumps(evidence_refs or []),
                    json.dumps([]),
                    json.dumps([]),
                    _now_iso(),
                    _now_iso(),
                ),
            )
        return fid

    # ── Status transitions ──────────────────────────────────────────────

    def validate(self, finding_id: str) -> str:
        """Move finding to 'validated' if valid transition."""
        finding = self._get(finding_id)
        if not finding:
            return f"Finding {finding_id} not found."

        if not self._can_transition(finding["status"], "validated"):
            return f"Finding {finding_id} is '{finding['status']}' — cannot move to 'validated'."

        # Check if evidence exists
        evidence = finding.get("evidence_refs", [])
        if not evidence:
            return f"Finding {finding_id} has no evidence attached. Validation requires evidence."

        return self._update_status(finding_id, "validated")

    def validate_finding(
        self,
        finding_id: str,
        *,
        scope_gate=None,
        evidence_store=None,
    ) -> dict[str, Any]:
        """Comprehensive validation check. Returns {valid: bool, reason: str, missing: [...], checks: {...}}."""
        finding = self._get(finding_id)
        if not finding:
            return {"valid": False, "reason": f"Finding {finding_id} not found."}

        result = {
            "valid": True,
            "reason": "",
            "missing": [],
            "checks": {},
        }

        # Check 1: In scope?
        if scope_gate:
            asset = finding.get("affected_asset", "")
            scope = scope_gate.check_scope(asset, "validate", "finding_verifier", "low")
            result["checks"]["in_scope"] = scope.allowed
            if not scope.allowed:
                result["valid"] = False
                result["reason"] = f"Asset '{asset}' is not in authorized scope."
                result["missing"].append("scope_confirmation")
                return result

        # Check 2: Evidence?
        evidence = finding.get("evidence_refs", [])
        result["checks"]["has_evidence"] = len(evidence) > 0
        if not evidence:
            result["missing"].append("evidence")
        elif evidence_store:
            # Verify each evidence reference actually exists on disk
            missing_evidence = []
            for ref in evidence:
                ev = evidence_store.get(ref)
                if ev is None:
                    missing_evidence.append(ref)
            if missing_evidence:
                result["checks"]["evidence_on_disk"] = False
                result["missing"].extend(f"missing_evidence:{r}" for r in missing_evidence)
                result["valid"] = False
                result["reason"] = f"Evidence references not found on disk: {missing_evidence}"

        # Check 3: Summary quality?
        summary = finding.get("summary", "")
        result["checks"]["has_summary"] = len(summary) > 20
        if len(summary) < 20:
            result["missing"].append("adequate_summary")

        # Check 4: Impact defined?
        impact = finding.get("impact", "")
        result["checks"]["has_impact"] = len(impact) > 10

        # Check 5: Vuln class?
        vuln_class = finding.get("vuln_class", "")
        result["checks"]["has_vuln_class"] = len(vuln_class) > 0
        if not vuln_class:
            result["missing"].append("vulnerability_classification")

        # Check 6: Reproduction steps?
        repro = finding.get("reproduction_steps", [])
        result["checks"]["has_reproduction_steps"] = len(repro) > 0
        if not repro:
            result["missing"].append("reproduction_steps")

        # Overall
        if len(result["missing"]) > 0:
            result["valid"] = False
            result["reason"] = f"Missing: {', '.join(result['missing'])}"
        else:
            result["reason"] = "All checks passed."
            # Auto-transition to validated if all checks pass
            if finding["status"] in ("candidate", "needs_validation"):
                self._update_status(finding_id, "validated")

        return result

    def reject(self, finding_id: str, reason: str = "") -> str:
        finding = self._get(finding_id)
        if not finding:
            return f"Finding {finding_id} not found."

        if not self._can_transition(finding["status"], "rejected"):
            return f"Finding {finding_id} (status: {finding['status']}) can only be rejected from: candidate, needs_validation, duplicate_suspected, validated, report_ready."

        return self._update_status(finding_id, "rejected", rejection_reason=reason)

    def mark_report_ready(self, finding_id: str) -> str:
        finding = self._get(finding_id)
        if not finding:
            return f"Finding {finding_id} not found."

        if finding["status"] != "validated":
            return f"Finding {finding_id} must be 'validated' before marking report_ready (current: {finding['status']})."

        return self._update_status(finding_id, "report_ready")

    def mark_needs_validation(self, finding_id: str, missing_items: list[str]) -> str:
        finding = self._get(finding_id)
        if not finding:
            return f"Finding {finding_id} not found."

        if not self._can_transition(finding["status"], "needs_validation"):
            return f"Cannot move to 'needs_validation' from '{finding['status']}'."

        with self._db.connection(write=True) as conn:
            conn.execute(
                """UPDATE findings SET status=?, missing_validation_json=?, updated_at=? WHERE id=? AND mission_id=?""",
                ("needs_validation", json.dumps(missing_items), _now_iso(), finding_id, self._mission_id),
            )
        return f"Finding {finding_id} → needs_validation: {', '.join(missing_items)}"

    # ── Queries ─────────────────────────────────────────────────────────

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        return self._get(finding_id)

    def list_candidates(self) -> list[dict[str, Any]]:
        return self._list_by_status("candidate")

    def list_needs_validation(self) -> list[dict[str, Any]]:
        return self._list_by_status("needs_validation")

    def list_validated(self) -> list[dict[str, Any]]:
        return self._list_by_status("validated")

    def list_report_ready(self) -> list[dict[str, Any]]:
        return self._list_by_status("report_ready")

    def list_rejected(self) -> list[dict[str, Any]]:
        return self._list_by_status("rejected")

    def list_all(self, status: str = "") -> list[dict[str, Any]]:
        with self._db.connection() as conn:
            if status:
                cur = conn.execute(
                    "SELECT * FROM findings WHERE mission_id=? AND status=? "
                    "ORDER BY updated_at DESC",
                    (self._mission_id, status),
                )
            else:
                cur = conn.execute(
                    "SELECT * FROM findings WHERE mission_id=? ORDER BY updated_at DESC",
                    (self._mission_id,),
                )
            return [_row_to_finding(dict(r)) for r in cur.fetchall()]

    def list_missing_evidence(self, finding_id: str) -> list[str]:
        finding = self._get(finding_id)
        if not finding:
            return []
        return finding.get("missing_validation", [])

    # ── Impact scoring ──────────────────────────────────────────────────

    @staticmethod
    def _score_impact(vuln_class: str, impact_text: str) -> int:
        score = 20  # base

        vuln_lower = vuln_class.lower()
        impact_lower = impact_text.lower()

        # Vuln class bonuses
        if any(c in vuln_lower for c in ("idor", "access control", "authorization")):
            score += 30
        if any(c in vuln_lower for c in ("injection", "rce", "command")):
            score += 40
        if any(c in vuln_lower for c in ("exposure", "disclosure")):
            score += 20
        if "cve" in vuln_lower:
            score += 25

        # Impact text bonuses
        for kw, bonus in [("sensitive", 20), ("critical", 30), ("admin", 25), ("bypass", 20), ("remote", 25)]:
            if kw in impact_lower:
                score += bonus
                break

        return min(score, 100)

    def score_impact(self, finding_id: str) -> int:
        finding = self._get(finding_id)
        if not finding:
            return 0
        return self._score_impact(
            finding.get("vuln_class", ""),
            finding.get("impact", ""),
        )

    def generate_validation_tasks(self, finding_id: str) -> list[dict[str, Any]]:
        """Create task dicts that would validate this finding."""
        finding = self._get(finding_id)
        if not finding:
            return []

        tasks: list[dict[str, Any]] = []
        missing = finding.get("missing_validation", [])

        if "evidence" in missing:
            tasks.append({
                "phase": "validate",
                "target": finding.get("affected_asset", ""),
                "asset_type": "endpoint",
                "objective": f"Capture evidence for finding: {finding.get('title', '')}",
                "hypothesis": "Evidence can be captured to support this finding.",
                "allowed_tools": ["raw_output"],
                "risk_level": "low",
                "priority": 75,
                "success_criteria": ["Evidence captured and stored."],
                "stop_conditions": ["Unable to reproduce after 3 attempts."],
            })

        if "reproduction_steps" in missing:
            tasks.append({
                "phase": "validate",
                "target": finding.get("affected_asset", ""),
                "asset_type": "endpoint",
                "objective": f"Document reproduction steps for: {finding.get('title', '')}",
                "hypothesis": "This finding can be reproduced with reliable steps.",
                "allowed_tools": [],
                "risk_level": "low",
                "priority": 70,
                "success_criteria": ["Reproduction steps documented."],
                "stop_conditions": [],
            })

        return tasks

    # ── Private helpers ─────────────────────────────────────────────────

    def _get(self, finding_id: str) -> dict[str, Any] | None:
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT * FROM findings WHERE id=? AND mission_id=?",
                (finding_id, self._mission_id),
            )
            row = cur.fetchone()
            if row:
                return _row_to_finding(dict(row))
        return None

    def _list_by_status(self, status: str) -> list[dict[str, Any]]:
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT * FROM findings WHERE mission_id=? AND status=? ORDER BY impact_score DESC",
                (self._mission_id, status),
            )
            return [_row_to_finding(dict(r)) for r in cur.fetchall()]

    def _update_status(
        self,
        finding_id: str,
        status: str,
        rejection_reason: str = "",
    ) -> str:
        with self._db.connection(write=True) as conn:
            conn.execute(
                "UPDATE findings SET status=?, rejection_reason=?, updated_at=? WHERE id=? AND mission_id=?",
                (status, rejection_reason, _now_iso(), finding_id, self._mission_id),
            )
        return f"Finding {finding_id} → {status}"

    @staticmethod
    def _can_transition(current: str, target: str) -> bool:
        return target in VALID_STATUS_TRANSITIONS.get(current, set())


# ── Row helpers ────────────────────────────────────────────────────────────


def _row_to_finding(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": data.get("id", ""),
        "mission_id": data.get("mission_id", ""),
        "title": data.get("title", ""),
        "vuln_class": data.get("vuln_class", ""),
        "affected_asset": data.get("affected_asset", ""),
        "affected_endpoint": data.get("affected_endpoint", ""),
        "summary": data.get("summary", ""),
        "impact": data.get("impact", ""),
        "confidence": float(data.get("confidence", 0.0)),
        "impact_score": int(data.get("impact_score", 0)),
        "status": data.get("status", "candidate"),
        "rejection_reason": data.get("rejection_reason", ""),
        "evidence_refs": _json_load(data.get("evidence_refs_json", "[]"), []),
        "reproduction_steps": _json_load(data.get("reproduction_steps_json", "[]"), []),
        "missing_validation": _json_load(data.get("missing_validation_json", "[]"), []),
        "created_at": data.get("created_at", ""),
        "updated_at": data.get("updated_at", ""),
    }


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
