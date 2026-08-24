"""Tests for the report generator module.

Covers:
- Report generation for report_ready findings
- Export to JSON
- Summary report generation
- Error on non-report_ready status
"""

from __future__ import annotations

import json

import pytest

from db import DatabaseManager, _new_id
from report_generator import ReportGenerator, _severity_label

# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def temp_db(tmp_path):
    path = tmp_path / "test_reporter.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
        mid = _new_id("M")
        conn.execute(
            """INSERT INTO missions(id, program_name, objective, risk_profile, created_at, updated_at)
            VALUES(?,?,?,?,datetime('now'),datetime('now'))""",
            (mid, "Reporter Test", "Find vulns.", "standard_authorized"),
        )
        db._mid = mid
    return db


@pytest.fixture
def reporter(temp_db, tmp_path):
    ws = tmp_path / "report_ws"
    ws.mkdir(parents=True, exist_ok=True)
    return ReportGenerator(temp_db, getattr(temp_db, "_mid", "M-TEST"), ws)


def _create_report_ready_finding(reporter):
    """Insert a finding directly into the DB with report_ready status."""
    fid = _new_id("F")
    db = reporter._db
    with db.connection(write=True) as conn:
        conn.execute(
            """INSERT INTO findings(
                id, mission_id, title, vuln_class, affected_asset, affected_endpoint,
                summary, impact, confidence, impact_score, status,
                evidence_refs_json, reproduction_steps_json, missing_validation_json,
                created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))""",
            (
                fid,
                getattr(db, "_mid", reporter._mission_id),
                "Test IDOR on /api/users/42",
                "IDOR",
                "example.com",
                "/api/users/42",
                "User can access other users' data by modifying the user ID parameter.",
                "An attacker can enumerate and access all user profiles, exposing PII.",
                0.8,
                85,
                "report_ready",
                json.dumps(["E-00001", "E-00002"]),
                json.dumps(
                    [
                        "1. Login as user_A",
                        "2. Request GET /api/users/42",
                        "3. Observe response contains user_B's profile data",
                    ]
                ),
                json.dumps([]),
            ),
        )
    return fid


# ── Severity labels ───────────────────────────────────────────────────────


def test_severity_critical():
    assert _severity_label(90) == "Critical"


def test_severity_high():
    assert _severity_label(65) == "High"


def test_severity_medium():
    assert _severity_label(45) == "Medium"


def test_severity_low():
    assert _severity_label(20) == "Low"


def test_severity_informational():
    assert _severity_label(5) == "Informational"


# ── Report generation ─────────────────────────────────────────────────────


def test_generate_report(reporter):
    fid = _create_report_ready_finding(reporter)
    report = reporter.generate_report(fid)

    assert "# Test IDOR" in report or "Test IDOR" in report
    assert "example.com" in report
    assert "IDOR" in report
    assert "Critical" in report
    assert "E-00001" in report
    assert "Login as user_A" in report


def test_generate_report_creates_file(reporter):
    fid = _create_report_ready_finding(reporter)
    _ = reporter.generate_report(fid)

    report_path = reporter._reports_dir / f"{fid}.md"
    assert report_path.exists()
    content = report_path.read_text()
    assert "Test IDOR" in content


def test_reject_non_report_ready(reporter):
    # Insert a finding with candidate status
    db = reporter._db
    fid = _new_id("F")
    with db.connection(write=True) as conn:
        conn.execute(
            """INSERT INTO findings(
                id, mission_id, title, vuln_class, affected_asset, summary, status,
                created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,datetime('now'),datetime('now'))""",
            (
                fid,
                getattr(db, "_mid", reporter._mission_id),
                "Not ready",
                "Other",
                "test.com",
                "Summary",
                "candidate",
            ),
        )

    with pytest.raises(ValueError) as exc:
        reporter.generate_report(fid)
    assert "report_ready" in str(exc.value).lower()


# ── Export ────────────────────────────────────────────────────────────────


def test_export_report(reporter):
    fid = _create_report_ready_finding(reporter)
    exported = reporter.export_report(fid)

    assert exported["finding_id"] == fid
    assert exported["title"] == "Test IDOR on /api/users/42"
    assert exported["severity"] == "Critical"
    assert exported["vuln_class"] == "IDOR"
    assert isinstance(exported, dict)


# ── Summary report ────────────────────────────────────────────────────────


def test_generate_summary_report(reporter):
    fid = _create_report_ready_finding(reporter)
    summary = reporter.generate_summary_report()

    assert "Bug Bounty Research Summary" in summary
    assert "Report-Ready Findings" in summary
    assert fid in summary

    report_path = reporter._reports_dir / "summary_report.md"
    assert report_path.exists()


def test_summary_report_empty(reporter):
    summary = reporter.generate_summary_report()
    assert "Bug Bounty Research Summary" in summary
    assert "0" in summary  # should have counts
