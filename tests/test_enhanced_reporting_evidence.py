"""Tests for evidence-grounded enhanced reporting (Phase 1.4).

Covers:
- ``_build_report_data`` back-fills ``TechnicalFinding.evidence_refs`` and
  ``reproduction_steps`` from a promoted exploit-audit EvidenceStore.
- Finding confidence reflects the OutcomeJudge verdict (CONFIRMED/REFUTED/
  INCONCLUSIVE/none) instead of the legacy hardcoded 0.9.
- Exploitation-chain entry timestamps are filled from audit records / timeline.
- ``_estimate_cvss`` consumes the previously-unused ``services`` arg for the
  service-aware fallback and vulnerable-version bump.
- ``generate_full_report`` writes a self-contained HTML report that contains
  finding titles, evidence refs, reproduction steps, and escaped content.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from db import DatabaseManager, _new_id
from evidence import EvidenceStore, promote_exploit_audit
from tools.enhanced_reporting import (
    EnhancedReportGenerator,
    _bump_cia,
    _confidence_from_verdict,
    _cvss_profile_from_services,
    _resolve_verdict,
    _service_indicates_vulnerable_version,
    _sev_class,
)

# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def temp_db(tmp_path):
    path = tmp_path / "test_reporting.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
        mid = _new_id("M")
        conn.execute(
            """INSERT INTO missions(id, program_name, objective, risk_profile, created_at, updated_at)
            VALUES(?,?,?,?,datetime('now'),datetime('now'))""",
            (mid, "Reporting Test", "Find vulns.", "standard_authorized"),
        )
        db._mid = mid
    return db


@pytest.fixture
def evidence_store(temp_db, tmp_path):
    ws = tmp_path / "evidence_ws"
    ws.mkdir(parents=True, exist_ok=True)
    return EvidenceStore(temp_db, getattr(temp_db, "_mid", "M-TEST"), ws)


@pytest.fixture
def generator(tmp_path):
    return EnhancedReportGenerator(db=None, mission_id="M-1", workspace=tmp_path / "reports")


def _write_audit(audit_path: Path, rows: list[dict[str, Any]]) -> Path:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, default=str) + "\n")
    return audit_path


def _campaign(target: str = "10.0.0.5", exploit: str = "eternalblue") -> dict[str, Any]:
    return {
        "states": {
            target: {
                "successful_exploits": [exploit],
                "recon_result": {
                    "services": [
                        {"port": 445, "product": "Microsoft Windows SMB", "version": "v1"},
                    ],
                },
                "privilege_level": "root",
                "access_achieved": True,
                "timeline": [
                    {
                        "timestamp": "2026-07-28T10:00:00+00:00",
                        "event_type": "exploit_success",
                        "description": "Compromised host",
                        "metadata": {"module": exploit},
                    },
                ],
            },
        },
    }


# ── Evidence back-fill ────────────────────────────────────────────────────


def test_evidence_refs_and_reproduction_steps_populated(generator, evidence_store, tmp_path):
    audit = tmp_path / "exploit_workspace" / "10.0.0.5" / "exploit_audit.jsonl"
    _write_audit(
        audit,
        [
            {
                "timestamp": "2026-07-28T10:00:00+00:00",
                "target_ip": "10.0.0.5",
                "action": "run_exploit_terminal",
                "approved": True,
                "status": "completed",
                "exit_code": 0,
                "command": "nmap -sV 10.0.0.5",
                "detail": "scan ok",
                "attempt_id": "ATT-1",
                "full_args": {"command": "nmap -sV 10.0.0.5"},
                "code_sha256": "abc123",
                "prev_hash": "prev0",
                "hash": "hash_flow_a_1",
            },
        ],
    )
    promote_exploit_audit(evidence_store, audit, "M-1", "10.0.0.5")

    data = generator._build_report_data(
        _campaign(),
        evidence_store=evidence_store,
        outcome_assessments=None,
    )
    finding = data["technical_findings"][0]
    assert finding["evidence_refs"], "evidence_refs should be back-filled from the store"
    assert finding["reproduction_steps"], "reproduction_steps should be derived from evidence"
    # Each reproduction step is labeled with the originating tool action.
    assert any("run_exploit_terminal" in step.lower() for step in finding["reproduction_steps"])
    # The evidence id is one of the promoted structured_json rows.
    promoted = evidence_store.list_for_mission(limit=50, evidence_type="structured_json")
    promoted_ids = {item["evidence_id"] for item in promoted}
    assert set(finding["evidence_refs"]).issubset(promoted_ids)


def test_no_evidence_store_leaves_refs_empty_but_repro_has_fallback(generator):
    data = generator._build_report_data(_campaign(), evidence_store=None)
    finding = data["technical_findings"][0]
    assert finding["evidence_refs"] == []
    # Fallback reproduction step is synthesized.
    assert finding["reproduction_steps"]
    assert "eternalblue" in finding["reproduction_steps"][0]


def test_explicit_state_evidence_refs_take_precedence(generator, evidence_store):
    campaign = _campaign()
    campaign["states"]["10.0.0.5"]["evidence_refs"] = ["E-PRE-1", "E-PRE-2"]
    data = generator._build_report_data(campaign, evidence_store=evidence_store)
    finding = data["technical_findings"][0]
    assert finding["evidence_refs"] == ["E-PRE-1", "E-PRE-2"]


# ── Confidence from OutcomeJudge verdict ──────────────────────────────────


@pytest.mark.parametrize(
    "verdict, expected",
    [
        ("confirmed", 0.95),
        ("refuted", 0.2),
        ("inconclusive", 0.5),
        ("open", 0.5),
        ("exhausted", 0.5),
        (None, 0.5),
    ],
)
def test_confidence_reflects_verdict(generator, verdict, expected):
    assessments = {"10.0.0.5": {"hypothesis_status": verdict}} if verdict else None
    data = generator._build_report_data(
        _campaign(),
        outcome_assessments=assessments,
    )
    finding = data["technical_findings"][0]
    assert finding["confidence"] == pytest.approx(expected)


def test_confidence_from_outcome_assessment_object(generator):
    """Duck-typed OutcomeAssessment (object with .hypothesis_status enum)."""

    class _Status:
        def __init__(self, value: str) -> None:
            self.value = value

    class _Assessment:
        def __init__(self, status: str) -> None:
            self.hypothesis_status = _Status(status)

    data = generator._build_report_data(
        _campaign(),
        outcome_assessments={"10.0.0.5": _Assessment("confirmed")},
    )
    assert data["technical_findings"][0]["confidence"] == pytest.approx(0.95)


def test_resolve_verdict_helpers():
    assert _resolve_verdict({"t": {"hypothesis_status": "confirmed"}}, "t") == "confirmed"
    assert _resolve_verdict({"t": {"hypothesis_status": "REFUTED"}}, "t") == "refuted"
    assert _resolve_verdict({"t": {"hypothesis_status": "open"}}, "t") == "open"
    assert _resolve_verdict({"t": {"hypothesis_status": "inconclusive"}}, "t") == "inconclusive"
    assert _resolve_verdict({"t": {"hypothesis_status": "exhausted"}}, "t") == "exhausted"
    assert _resolve_verdict(None, "t") is None
    assert _resolve_verdict({"t": None}, "t") is None
    assert _resolve_verdict({"t": {}}, "t") is None
    assert _confidence_from_verdict("confirmed") == 0.95
    assert _confidence_from_verdict("refuted") == 0.2
    assert _confidence_from_verdict("inconclusive") == 0.5
    assert _confidence_from_verdict(None) == 0.5
    assert _confidence_from_verdict("exhausted") == 0.5
    assert _confidence_from_verdict("open") == 0.5


# ── Chain timestamps ──────────────────────────────────────────────────────


def test_chain_timestamp_from_exploit_records(generator):
    campaign = _campaign()
    campaign["states"]["10.0.0.5"]["exploit_records"] = [
        {
            "timestamp": "2026-07-28T09:30:00+00:00",
            "action": "run_exploit_terminal eternalblue",
            "full_args": {"command": "msfconsole -x eternalblue"},
            "hash": "h1",
        }
    ]
    data = generator._build_report_data(campaign)
    entry = data["exploitation_chains"][0]["entries"][0]
    assert entry["timestamp"] == "2026-07-28T09:30:00+00:00"


def test_chain_timestamp_falls_back_to_timeline(generator):
    data = generator._build_report_data(_campaign())
    entry = data["exploitation_chains"][0]["entries"][0]
    assert entry["timestamp"] == "2026-07-28T10:00:00+00:00"


def test_chain_timestamp_empty_when_no_match(generator):
    campaign = _campaign(exploit="unknown_exploit")
    campaign["states"]["10.0.0.5"]["exploit_records"] = []
    # Remove the timeline event so neither audit records nor timeline match.
    campaign["states"]["10.0.0.5"]["timeline"] = []
    data = generator._build_report_data(campaign)
    entry = data["exploitation_chains"][0]["entries"][0]
    assert entry["timestamp"] == ""


# ── _estimate_cvss consumes services ──────────────────────────────────────


def test_cvss_service_fallback_smb():
    g = EnhancedReportGenerator(db=None, mission_id="M", workspace=Path("reports"))
    # No exploit-name match -> service fallback for SMB (port 445) -> scope C.
    cvss = g._estimate_cvss("generic_probe", [{"port": 445, "product": "Microsoft Windows SMB"}])
    assert cvss.base_score > 0
    # SMB profile uses scope=C.
    assert "/S:C/" in cvss.vector_string


def test_cvss_service_fallback_http():
    g = EnhancedReportGenerator(db=None, mission_id="M", workspace=Path("reports"))
    cvss = g._estimate_cvss("generic_probe", [{"port": 80, "product": "http"}])
    # HTTP profile -> C=L, I=L, A=N.
    assert "/C:L/I:L/A:N" in cvss.vector_string


def test_cvss_service_fallback_default_when_no_services():
    g = EnhancedReportGenerator(db=None, mission_id="M", workspace=Path("reports"))
    cvss = g._estimate_cvss("generic_probe", [])
    # Default profile -> High C/I/A.
    assert "/C:H/I:H/A:H" in cvss.vector_string


def test_cvss_exploit_name_branch_takes_precedence_over_services():
    g = EnhancedReportGenerator(db=None, mission_id="M", workspace=Path("reports"))
    # 'xss' branch sets C=L/I=L/A=N + UI=R; should win even with SMB services.
    cvss = g._estimate_cvss("xss_reflected", [{"port": 445, "product": "SMB"}])
    assert "/C:L/I:L/A:N" in cvss.vector_string
    assert "/UI:R" in cvss.vector_string


def test_cvss_vulnerable_version_bumps_impact():
    g = EnhancedReportGenerator(db=None, mission_id="M", workspace=Path("reports"))
    # HTTP profile normally C=L/I=L/A=N, but a vulnerable Apache banner bumps.
    services = [{"port": 80, "product": "Apache httpd", "version": "2.4.49"}]
    cvss = g._estimate_cvss("generic_probe", services)
    assert "/C:H" in cvss.vector_string
    # I and A bumped from L/N toward H.
    assert "/I:H" in cvss.vector_string


def test_cvss_helpers():
    assert _cvss_profile_from_services([{"port": 445}]) == ("N", "L", "N", "N", "H", "H", "H", "C")
    assert _cvss_profile_from_services([{"port": 80, "product": "http"}]) == ("N", "L", "N", "N", "L", "L", "N", "U")
    assert _cvss_profile_from_services([]) == ("N", "L", "N", "N", "H", "H", "H", "U")
    assert _service_indicates_vulnerable_version([{"product": "OpenSSH", "version": "7.9"}]) is True
    assert _service_indicates_vulnerable_version([{"product": "nginx", "version": "1.25"}]) is False
    assert _bump_cia("N") == "L"
    assert _bump_cia("L") == "H"
    assert _bump_cia("H") == "H"
    assert _sev_class("Critical") == "critical"
    assert _sev_class("low") == "low"
    assert _sev_class("") == "none"


# ── HTML report generation ────────────────────────────────────────────────


def test_html_report_written_and_contains_findings(generator, evidence_store, tmp_path):
    audit = tmp_path / "exploit_workspace" / "10.0.0.5" / "exploit_audit.jsonl"
    _write_audit(
        audit,
        [
            {
                "timestamp": "2026-07-28T10:00:00+00:00",
                "target_ip": "10.0.0.5",
                "action": "run_exploit_terminal",
                "approved": True,
                "status": "completed",
                "exit_code": 0,
                "command": "whoami",
                "detail": "root",
                "attempt_id": "ATT-1",
                "full_args": {"command": "whoami"},
                "hash": "hash_whoami",
            },
        ],
    )
    promote_exploit_audit(evidence_store, audit, "M-1", "10.0.0.5")

    paths = generator.generate_full_report(
        _campaign(),
        output_format="all",
        evidence_store=evidence_store,
        outcome_assessments={"10.0.0.5": {"hypothesis_status": "confirmed"}},
    )
    assert "html" in paths
    html_text = paths["html"].read_text(encoding="utf-8")
    # Finding title is present and escaped-content-safe.
    assert "eternalblue" in html_text
    assert "10.0.0.5" in html_text
    # Confidence rendered as 95%.
    assert "95%" in html_text
    # Evidence refs appear in the HTML.
    eid = evidence_store.list_for_mission(limit=50, evidence_type="structured_json")[0]["evidence_id"]
    assert eid in html_text
    # Reproduction steps section present.
    assert "Reproduction Steps" in html_text
    # Self-contained: inline CSS, no external stylesheet link.
    assert "<style>" in html_text
    assert "<link" not in html_text


def test_html_escates_user_content(generator):
    campaign = _campaign(target="10.0.0.5<script>", exploit="xss</script><b>")
    # Normalize the successful_exploits list to a safe-ish entry for the chain id.
    campaign["states"]["10.0.0.5<script>"]["successful_exploits"] = ["xss</script>"]
    paths = generator.generate_full_report(campaign, output_format="html")
    html_text = paths["html"].read_text(encoding="utf-8")
    # Raw angle brackets from user content must be escaped.
    assert "<script>" not in html_text.replace("<!DOCTYPE html>", "").replace("<html", "").replace("<head>", "")
    assert "&lt;script&gt;" in html_text


def test_html_omits_empty_sections(generator):
    campaign = {"states": {}}
    paths = generator.generate_full_report(campaign, output_format="html")
    html_text = paths["html"].read_text(encoding="utf-8")
    # No findings / chains / timeline sections when empty.
    assert "Technical Findings" not in html_text
    assert "Exploitation Chains" not in html_text
    assert "Attack Timeline" not in html_text


def test_output_format_all_produces_three_formats(generator):
    paths = generator.generate_full_report(_campaign(), output_format="all")
    assert set(paths.keys()) == {"json", "markdown", "html"}


def test_output_format_both_stays_json_and_markdown_only(generator):
    paths = generator.generate_full_report(_campaign(), output_format="both")
    assert set(paths.keys()) == {"json", "markdown"}
    assert "html" not in paths


def test_output_format_html_only(generator):
    paths = generator.generate_full_report(_campaign(), output_format="html")
    assert set(paths.keys()) == {"html"}
