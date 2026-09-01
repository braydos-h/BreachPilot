"""Built-in demo session seeding — realistic synthetic BreachPilot run.

Creates a deterministic demo run ``demo-session-v1`` in the normal
persistence/artifact layout so it flows through the existing:

* ``GET /api/v1/runs`` / ``GET /api/v1/runs/{id}``
* ``GET /api/v1/runs/{id}/graph`` (legacy DAG) and ``/api/v1/graph/runs/{id}``
* artifact endpoints (recon_assessment.json, enhanced/enhanced_report.json)
* event replay / WebSocket

No network, no MCP, no LLM, no shell — pure fixture.

The demo is seeded at API startup (``app.create_app`` lifespan) and is
idempotent. Once the user deletes it the tombstone ``demo_deleted=1`` in
``app_state`` prevents recreation until explicitly restored via
``POST /api/v1/runs/demo/restore``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DEMO_RUN_ID = "demo-session-v1"
DEMO_SEED_VERSION = 1
DEMO_TITLE = "Demo Attack — Meridian Finance Lab"
DEMO_TARGET = "portal.meridian-lab.example"
DEMO_RESOLVED_IP = "198.51.100.23"
DEMO_RESOLVED_DOMAIN = "portal.meridian-lab.example"

# Synthetic fleet (reserved/example addresses only).
FLEET: dict[str, str] = {
    "edge-web-01": "198.51.100.23",
    "app-01": "10.42.10.21",
    "api-01": "10.42.10.31",
    "files-01": "10.42.20.15",
    "workstation-07": "10.42.20.25",
    "identity-01": "10.42.30.10",
    "backup-01": "10.42.30.20",
    # Additional discovered assets for stats (11 total)
    "web-02": "10.42.10.22",
    "db-01": "10.42.20.16",
    "monitor-01": "10.42.30.30",
    "cache-01": "10.42.10.40",
}

# Reference start — persisted verbatim so timestamps never shift on restart.
DEMO_START: datetime = datetime(2026, 2, 14, 9, 0, 0, tzinfo=timezone.utc)
DEMO_DURATION_SECONDS = 702  # 11m42s
DEMO_CREATED = DEMO_START.isoformat()
DEMO_COMPLETED = (DEMO_START + timedelta(seconds=DEMO_DURATION_SECONDS)).isoformat()


def _iso(offset_seconds: int) -> str:
    return (DEMO_START + timedelta(seconds=offset_seconds)).isoformat()


# ── helpers ─────────────────────────────────────────────────────────────────


def is_demo_run(run: dict[str, Any] | None) -> bool:
    """Centralized demo check — no id-scattering in UI/backend."""
    if not run:
        return False
    # Prefer explicit is_demo flag; fall back to id for pre-migrated rows.
    if run.get("is_demo") == 1 or run.get("is_demo") is True:
        return True
    # preview/request may carry source/demo marker from older seeds
    for key in ("preview_json", "request_json", "preview", "request"):
        blob = run.get(key)
        if isinstance(blob, dict) and (blob.get("is_demo") is True or blob.get("source") == "demo"):
            return True
    return str(run.get("id", "")) == DEMO_RUN_ID


def _demo_request() -> dict[str, Any]:
    return {
        "target": DEMO_TARGET,
        "mode": "attack",
        "goal_name": "data_exfil",
        "custom_goal": "",
        "recon_first": False,
        "model_alias": "glm",
        "swarm": False,
        "parallel_swarm": False,
        "critic": False,
        "reflection": False,
        "adaptive_exploits": False,
        "long_session": False,
        "multi_model_consult": False,
        "observer_mode": "hybrid",
        "ultrathink": False,
        "skills_mode": None,
        "skills_include": [],
        "skills_exclude": [],
        "skills_no_reselect": False,
        "debug": False,
        "plain": False,
        "json_output": False,
        "resume_source": "",
        "kind": "agent",
        "is_demo": True,
        "source": "demo",
    }


def _demo_preview() -> dict[str, Any]:
    return {
        "run_id": DEMO_RUN_ID,
        "target_ip": DEMO_RESOLVED_IP,
        "original_target": DEMO_TARGET,
        "resolved_ip": DEMO_RESOLVED_IP,
        "resolved_domain": DEMO_RESOLVED_DOMAIN,
        "mode": "attack",
        "goal_name": "data_exfil",
        "goal_description": "Demonstrate access to sensitive-data repository in synthetic lab",
        "model_alias": "glm",
        "model_label": "GLM-5.2 (demo)",
        "transport_summary": "http on port 8001",
        "permission": "full_access",
        "attack_mode": True,
        "swarm": False,
        "parallel_swarm": False,
        "multi_model": False,
        "destructive": False,
        "required_confirmation_text": "",
        "budgets": {"commands": 150, "rounds": 50, "duration_minutes": 360},
        "skill_activations": [{"name": "demo-synthetic", "reason": "demo fixture"}],
        "skill_errors": [],
        "timings": {"config": 1.2, "plugins": 0.4, "router": 2.0, "total": 18.5},
        "resumed_from": "",
        "is_demo": True,
        "source": "demo",
    }


def _demo_result() -> dict[str, Any]:
    return {
        "run_id": DEMO_RUN_ID,
        "target_ip": DEMO_RESOLVED_IP,
        "mode": "attack",
        "goal_name": "data_exfil",
        "goal_description": "Demonstrate access to sensitive-data repository in synthetic lab",
        "total_actions": 27,
        "workspace": f"reports/{DEMO_RUN_ID}",
        "audit_path": f"reports/{DEMO_RUN_ID}/exploit_audit.jsonl",
        "records": [],
        "messages": [],
        "error": "",
        "swarm_result": None,
        "active_skills": [],
        "outcome_summary": "Compromise demonstrated — objective access confirmed on files-01 (synthetic). 6 assets reached; 3 viable attack paths (2 successful, 1 blocked). Risk score 93/100.",
        "telemetry": {
            "calls": 14,
            "total_tokens": 48210,
            "avg_ctx": 18.4,
            "max_ctx": 34.2,
            "context_window_tokens": 128000,
            "last_ctx_pct": 22.1,
            "last_estimated_context_tokens": 28300,
        },
        "safety_review": {"safe": True, "reasoning": "Synthetic demo — no real target touched."},
        "reports_dir": f"reports/{DEMO_RUN_ID}",
        "summary_path": f"reports/{DEMO_RUN_ID}/session_summary.md",
        "run_json_path": f"reports/{DEMO_RUN_ID}/run.json",
        "cancelled": False,
        "objective_transitions": [],
        "is_demo": True,
        "source": "demo",
    }


# ── recon assessment ───────────────────────────────────────────────────────


def _recon_assessment() -> dict[str, Any]:
    return {
        "target_ip": DEMO_RESOLVED_IP,
        "os_verdict": "Linux",
        "os_hints": ["Ubuntu 22.04 (Nginx banner)", "ttl=64"],
        "open_ports": [80, 443, 8080, 8443],
        "services": [
            {"name": "http", "port": 80, "banner": "nginx/1.18.0", "risk": 7.2},
            {"name": "https", "port": 443, "banner": "nginx/1.18.0 + TLS 1.2", "risk": 7.2},
            {"name": "http-proxy", "port": 8080, "banner": "Meridian Portal (Node.js/Express)", "risk": 8.1},
            {"name": "https-alt", "port": 8443, "banner": "Meridian API (api.meridian-lab.example)", "risk": 6.5},
        ],
        "cve_findings": [
            {
                "service": "http",
                "product": "nginx",
                "version": "1.18.0",
                "count": 2,
                "cves": ["CVE-2023-44487", "CVE-2021-23017"],
            },
            {
                "service": "http-proxy",
                "product": "express",
                "version": "4.18.2",
                "count": 1,
                "cves": ["CVE-2024-27298"],
            },
        ],
        "overall_risk_score": 93,
        "is_demo": True,
        "note": "Synthetic recon — no scans executed",
    }


# ── enhanced report ─────────────────────────────────────────────────────────


def _enhanced_report() -> dict[str, Any]:
    # 18 findings distribution: Critical 3, High 6, Medium 5, Low 4
    findings_spec: list[tuple[str, str, float, str, str]] = [
        # (title, severity, cvss, asset, vuln_class)
        (
            "Unauthenticated Template Injection → RCE on edge-web-01",
            "Critical",
            9.8,
            "edge-web-01 (198.51.100.23)",
            "Server-Side Template Injection",
        ),
        (
            "Insecure Deserialization in Meridian API (api-01)",
            "Critical",
            9.4,
            "api-01 (10.42.10.31)",
            "Insecure Deserialization",
        ),
        (
            "Domain Admin credential reuse via svc-web on identity-01",
            "Critical",
            9.1,
            "identity-01 (10.42.30.10)",
            "Credential Exposure",
        ),
        (
            "Stored XSS in Portal comment field → session hijack",
            "High",
            8.2,
            "edge-web-01 (198.51.100.23)",
            "Cross-Site Scripting",
        ),
        (
            "IDOR on /api/files/{id} exposes neighboring tenants",
            "High",
            7.9,
            "api-01 (10.42.10.31)",
            "Insecure Direct Object Reference",
        ),
        (
            "Service identity svc-web has excessive read on app-01",
            "High",
            7.6,
            "app-01 (10.42.10.21)",
            "Privilege Misconfiguration",
        ),
        ("Privilege escalation via SUID helper on app-01", "High", 7.8, "app-01 (10.42.10.21)", "Privilege Escalation"),
        (
            "Lateral movement app-01 → api-01 via cached service token",
            "High",
            7.5,
            "api-01 (10.42.10.31)",
            "Lateral Movement",
        ),
        (
            "SMB share readable on files-01 (anonymous read)",
            "High",
            7.3,
            "files-01 (10.42.20.15)",
            "Share Misconfiguration",
        ),
        (
            "Weak password policy on identity-01 (svc-backup)",
            "Medium",
            6.4,
            "identity-01 (10.42.30.10)",
            "Weak Credentials",
        ),
        (
            "Backup archive world-readable on backup-01",
            "Medium",
            6.1,
            "backup-01 (10.42.30.20)",
            "Information Disclosure",
        ),
        (
            "Exposed .git directory on edge-web-01",
            "Medium",
            5.8,
            "edge-web-01 (198.51.100.23)",
            "Information Disclosure",
        ),
        (
            "Missing security headers on portal (CSP, HSTS)",
            "Medium",
            5.3,
            "edge-web-01 (198.51.100.23)",
            "Security Misconfiguration",
        ),
        (
            "Verbose error messages leak stack traces on api-01",
            "Medium",
            5.0,
            "api-01 (10.42.10.31)",
            "Information Disclosure",
        ),
        (
            "Workstation-07 unpatched SMB (synthetic candidate)",
            "Low",
            3.9,
            "workstation-07 (10.42.20.25)",
            "Patch Management",
        ),
        ("Cache-01 Redis without AUTH (lab-only binding)", "Low", 3.7, "cache-01 (10.42.10.40)", "Misconfiguration"),
        (
            "Monitor-01 Grafana default creds present (lab)",
            "Low",
            3.5,
            "monitor-01 (10.42.30.30)",
            "Default Credentials",
        ),
        (
            "DB-01 verbose logging exposes query timing (lab)",
            "Low",
            2.8,
            "db-01 (10.42.20.16)",
            "Information Disclosure",
        ),
    ]

    findings: list[dict[str, Any]] = []
    for idx, (title, severity, cvss_score, asset, vuln_class) in enumerate(findings_spec, 1):
        is_confirmed = idx <= 12  # 12 confirmed, 6 suspected/inconclusive
        severity_lower = severity.lower()
        # Map severity to CVSS vector severity
        cvss_sev = severity if severity in ("Critical", "High", "Medium", "Low") else "Medium"
        fid = f"F-MERIDIAN-{idx:03d}"
        findings.append(
            {
                "finding_id": fid,
                "title": title,
                "affected_asset": asset,
                "vuln_class": vuln_class,
                "severity": severity,
                "cvss": {
                    "base_score": cvss_score,
                    "severity": cvss_sev,
                    "vector_string": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H ({severity})",
                },
                "confidence": 0.96 if is_confirmed else 0.58,
                "summary": f"Synthetic finding #{idx}: {title}. Demonstrates BreachPilot assessment depth in a lab environment.",
                "reproduction_steps": [
                    f"Identify {asset} via recon",
                    f"Validate {vuln_class} with safe synthetic check",
                    "Capture evidence (redacted lab data)",
                ],
                "evidence_refs": [f"ev:synthetic:{asset}:{fid}"],
                "exploitation_result": "Synthetic exploitation confirmed in lab" if is_confirmed else "",
                "persistence_achieved": is_confirmed and idx in (3, 7),
                "privilege_level_gained": "root" if idx == 7 else ("SYSTEM" if idx == 3 else ""),
                "attack_chain": {"chain_id": "CHAIN-MERIDIAN-PRIMARY"} if is_confirmed and idx <= 7 else None,
                "remediation": f"Remediate {vuln_class} on {asset} — synthetic guidance for demo.",
                "references": [f"https://example.com/advisory/{fid.lower()}"],
            }
        )

    # 3 exploitation chains: primary success, blocked branch, lateral success
    chains: list[dict[str, Any]] = [
        {
            "chain_id": "CHAIN-MERIDIAN-PRIMARY",
            "target": "files-01 (10.42.20.15)",
            "entries": [
                {"module": "http_ssti_probe", "timestamp": _iso(128), "result": "success"},
                {"module": "template_rce_synthetic", "timestamp": _iso(196), "result": "success"},
                {"module": "credential_harvest_svc-web", "timestamp": _iso(243), "result": "success"},
                {"module": "suid_privesc_app-01", "timestamp": _iso(311), "result": "success"},
                {"module": "lateral_api_token_reuse", "timestamp": _iso(495), "result": "success"},
                {"module": "objective_files_access", "timestamp": _iso(656), "result": "success"},
            ],
            "successful": True,
            "final_privilege": "root",
            "total_duration": 528.0,
        },
        {
            "chain_id": "CHAIN-MERIDIAN-BLOCKED",
            "target": "workstation-07 (10.42.20.25)",
            "entries": [
                {"module": "smb_enum_workstation-07", "timestamp": _iso(367), "result": "success"},
                {"module": "psexec_attempt_svc-web", "timestamp": _iso(402), "result": "failure"},
                {"module": "blocked_insufficient_privilege", "timestamp": _iso(410), "result": "blocked"},
            ],
            "successful": False,
            "final_privilege": "none",
            "total_duration": 43.0,
        },
        {
            "chain_id": "CHAIN-MERIDIAN-LATERAL-FILES",
            "target": "files-01 (10.42.20.15)",
            "entries": [
                {"module": "api_discovery_files-share", "timestamp": _iso(511), "result": "success"},
                {"module": "smb_anonymous_read_files-01", "timestamp": _iso(588), "result": "success"},
                {"module": "sensitive_repo_list", "timestamp": _iso(640), "result": "success"},
            ],
            "successful": True,
            "final_privilege": "user",
            "total_duration": 129.0,
        },
    ]

    # Attack timeline — spaced realistically through run
    timeline: list[dict[str, Any]] = [
        {
            "timestamp": _iso(0),
            "event_type": "run_started",
            "description": "Run started — target portal.meridian-lab.example (synthetic lab)",
            "target": "portal.meridian-lab.example",
            "module": "orchestrator",
            "result": "success",
        },
        {
            "timestamp": _iso(18),
            "event_type": "target_resolved",
            "description": "Target resolved to 198.51.100.23 (edge-web-01)",
            "target": "edge-web-01",
            "module": "dns",
            "result": "success",
        },
        {
            "timestamp": _iso(44),
            "event_type": "recon_completed",
            "description": "Reconnaissance completed — 4 open ports, 4 services, OS Linux",
            "target": "edge-web-01",
            "module": "recon",
            "result": "success",
        },
        {
            "timestamp": _iso(82),
            "event_type": "service_identified",
            "description": "Web service identified: Meridian Portal (Node.js/Express) on :8080",
            "target": "edge-web-01",
            "module": "service_enumeration",
            "result": "success",
        },
        {
            "timestamp": _iso(128),
            "event_type": "weakness_identified",
            "description": "Potential SSTI weakness identified on edge-web-01 (synthetic candidate)",
            "target": "edge-web-01",
            "module": "vuln_research",
            "result": "success",
        },
        {
            "timestamp": _iso(196),
            "event_type": "initial_access",
            "description": "Initial access hypothesis confirmed — application tier reached (app-01)",
            "target": "app-01",
            "module": "validation",
            "result": "success",
        },
        {
            "timestamp": _iso(243),
            "event_type": "credential_discovered",
            "description": "Service identity discovered: svc-web (app-01 → identity-01)",
            "target": "identity-01",
            "module": "credential_harvest",
            "result": "success",
        },
        {
            "timestamp": _iso(311),
            "event_type": "privilege_escalation",
            "description": "Privilege path identified — SUID helper on app-01 → root context (synthetic)",
            "target": "app-01",
            "module": "privesc",
            "result": "success",
        },
        {
            "timestamp": _iso(367),
            "event_type": "lateral_branch",
            "description": "First lateral branch attempted: app-01 → workstation-07",
            "target": "workstation-07",
            "module": "lateral",
            "result": "attempt",
        },
        {
            "timestamp": _iso(402),
            "event_type": "branch_blocked",
            "description": "Branch blocked — insufficient privilege for workstation-07 (expected demo branch failure)",
            "target": "workstation-07",
            "module": "lateral",
            "result": "failure",
        },
        {
            "timestamp": _iso(435),
            "event_type": "alternate_path",
            "description": "Alternate path selected: app-01 → api-01 via cached service token",
            "target": "api-01",
            "module": "lateral",
            "result": "success",
        },
        {
            "timestamp": _iso(511),
            "event_type": "internal_service",
            "description": "Internal service reached: api-01 → files share enumeration",
            "target": "api-01",
            "module": "enumeration",
            "result": "success",
        },
        {
            "timestamp": _iso(588),
            "event_type": "file_server_discovered",
            "description": "File server discovered: files-01 (SMB anonymous read, synthetic)",
            "target": "files-01",
            "module": "discovery",
            "result": "success",
        },
        {
            "timestamp": _iso(656),
            "event_type": "objective_confirmed",
            "description": "Objective access confirmed — synthetic sensitive-data repository on files-01 (no data extracted)",
            "target": "files-01",
            "module": "objective",
            "result": "success",
        },
        {
            "timestamp": _iso(702),
            "event_type": "assessment_completed",
            "description": "Assessment completed — 11 assets discovered, 7 reached, 18 findings, 93/100 risk",
            "target": "portal.meridian-lab.example",
            "module": "reporting",
            "result": "success",
        },
    ]

    # Failure analysis (mirrors blocked branch)
    failures: list[dict[str, Any]] = [
        {
            "operation": "psexec_attempt_svc-web",
            "failure_count": 1,
            "primary_error": "Insufficient privilege — svc-web cannot exec on workstation-07",
            "error_breakdown": {"insufficient_privilege": 1},
            "mitigation_suggestion": "Elevation to domain context required; blocked path demonstrates least-privilege enforcement (synthetic).",
            "recovery_actions": [],
        },
        {
            "operation": "smb_enum_workstation-07",
            "failure_count": 1,
            "primary_error": "Host filtered — synthetic lab segmentation",
            "error_breakdown": {"host_filtered": 1},
            "mitigation_suggestion": "Alternate path via api-01 succeeded — demonstrates branching.",
            "recovery_actions": [],
        },
    ]

    return {
        "report_metadata": {
            "generated_at": _iso(702),
            "mission_id": DEMO_RUN_ID,
            "generator_version": "2.0-demo",
            "total_targets": 1,
            "total_exploits": 9,
            "total_failures": 2,
            "is_demo": True,
            "source": "demo",
        },
        "executive_summary": (
            "# Executive Summary (Synthetic Demo — Meridian Finance Lab)\n\n"
            "This is a synthetic BreachPilot assessment against a fictional lab "
            "environment (portal.meridian-lab.example → 198.51.100.23). No real "
            "systems were contacted, no exploits were executed, and no data was "
            "extracted. The report demonstrates the depth, branching, and evidence "
            "model of a completed BreachPilot run.\n\n"
            "Primary path: edge-web-01 → app-01 → identity-01 → api-01 → files-01 "
            "(objective confirmed). Alternate branch to workstation-07 was blocked, "
            "demonstrating planning diversity."
        ),
        "attack_timeline": timeline,
        "exploitation_chains": chains,
        "failure_analysis": failures,
        "technical_findings": findings,
    }


# ── exploit audit ──────────────────────────────────────────────────────────


def _exploit_audit_records() -> list[dict[str, Any]]:
    """Synthetic audit trail — drives both DAG routes and the explorer store."""
    # Each record mimics the real exploit_audit.jsonl schema but carries no
    # commands, payloads, or credentials — only descriptive tool/target/status.
    base = [
        # Discovery phase
        ("nmap_scan", "198.51.100.23", "completed", 44, "edge-web discovery"),
        ("http_fingerprint", "198.51.100.23", "completed", 82, "portal banner grab"),
        ("vuln_research_ssti", "198.51.100.23", "completed", 128, "ssti candidate"),
        # Initial access
        ("template_rce_synthetic", "198.51.100.23", "completed", 196, "synthetic ssti → app tier"),
        ("app_enumeration", "10.42.10.21", "completed", 210, "app-01 enumeration"),
        # Credential / identity
        ("credential_harvest", "10.42.10.21", "completed", 243, "svc-web harvested"),
        ("identity_enum", "10.42.30.10", "completed", 260, "identity-01 enum"),
        # Privesc
        ("suid_privesc_check", "10.42.10.21", "completed", 311, "suid helper → root (synthetic)"),
        # Lateral — branch 1 (blocked)
        ("smb_enum", "10.42.20.25", "completed", 367, "workstation-07 smb enum"),
        ("psexec_svc-web", "10.42.20.25", "blocked", 402, "blocked: insufficient privilege"),
        # Lateral — branch 2 (success)
        ("token_reuse_api", "10.42.10.31", "completed", 435, "api-01 token reuse"),
        ("api_files_enum", "10.42.10.31", "completed", 511, "api → files share enum"),
        ("smb_anon_read", "10.42.20.15", "completed", 588, "files-01 anonymous read"),
        ("sensitive_repo_list", "10.42.20.15", "completed", 640, "repo listing (synthetic)"),
        ("objective_confirm", "10.42.20.15", "completed", 656, "objective confirmed"),
        # Additional discovery for stats breadth
        ("backup_enum", "10.42.30.20", "completed", 520, "backup-01 discovery"),
        ("monitor_enum", "10.42.30.30", "completed", 530, "monitor-01 discovery"),
        ("db_enum", "10.42.20.16", "completed", 540, "db-01 discovery"),
        ("cache_enum", "10.42.10.40", "completed", 550, "cache-01 discovery"),
    ]
    records: list[dict[str, Any]] = []
    for idx, (tool, target, status, offset, detail) in enumerate(base):
        ts = _iso(offset)
        # Deterministic attempt_id / hash — not a real execution
        attempt_id = hashlib.sha256(f"demo-{tool}-{target}-{idx}".encode()).hexdigest()[:12]
        code_hash = hashlib.sha256(f"{tool}-{detail}".encode()).hexdigest()[:16]
        records.append(
            {
                "timestamp": ts,
                "tool_name": tool,
                "target_ip": target,
                "status": status,
                "detail": f"[DEMO SYNTHETIC] {detail}",
                "attempt_id": f"demo-attempt-{attempt_id}",
                "code_sha256": code_hash,
                "exit_code": 0 if status == "completed" else 1,
                "is_demo": True,
                "source": "demo",
            }
        )
    # Add a synthetic blocked marker record for graph blocked path styling
    return records


# ── events.jsonl ───────────────────────────────────────────────────────────


def _events() -> list[dict[str, Any]]:
    """Deterministic events.jsonl — what EventViewer renders."""
    # Minimal but realistic event sequence using actual types.
    offsets_and_types: list[tuple[int, str, dict[str, Any]]] = [
        (0, "state", {"state": "running"}),
        (2, "boot", {"step": "mcp_start", "ok": True}),
        (5, "phase", {"phase": "recon"}),
        (18, "progress", {"phase": "recon", "round": 1, "actions": 2, "elapsed_seconds": 18}),
        (44, "recon_assessment", {"target_ip": DEMO_RESOLVED_IP, "os_verdict": "Linux", "overall_risk_score": 93}),
        (60, "phase", {"phase": "service_enumeration"}),
        (82, "progress", {"phase": "service_enumeration", "round": 2, "actions": 5}),
        (128, "phase", {"phase": "vulnerability_research"}),
        (150, "assistant", {"text": "Synthetic analysis: potential SSTI on edge-web-01 warrants validation."}),
        (
            196,
            "tool_request",
            {
                "name": "template_rce_synthetic",
                "action": 6,
                "phase": "validation",
                "arguments": {"target": DEMO_RESOLVED_IP},
            },
        ),
        (196, "tool_start", {"name": "template_rce_synthetic", "action": 6, "phase": "validation"}),
        (
            197,
            "tool_result",
            {"name": "template_rce_synthetic", "action": 6, "phase": "validation", "success": True, "exit_code": 0},
        ),
        (210, "phase", {"phase": "validation"}),
        (243, "progress", {"phase": "validation", "round": 3, "actions": 9}),
        (311, "assistant", {"text": "Synthetic: privesc path via SUID identified on app-01."}),
        (
            367,
            "tool_request",
            {"name": "psexec_svc-web", "action": 11, "phase": "validation", "arguments": {"target": "10.42.20.25"}},
        ),
        (
            402,
            "tool_result",
            {"name": "psexec_svc-web", "action": 11, "phase": "validation", "success": False, "exit_code": 1},
        ),
        (
            435,
            "tool_result",
            {"name": "token_reuse_api", "action": 12, "phase": "validation", "success": True, "exit_code": 0},
        ),
        (656, "progress", {"phase": "reporting", "round": 5, "actions": 27, "elapsed_seconds": DEMO_DURATION_SECONDS}),
        (702, "phase", {"phase": "reporting"}),
        (702, "artifact", {"name": "recon_assessment.json"}),
        (702, "artifact", {"name": "enhanced/enhanced_report.json"}),
        (
            702,
            "completion",
            {"state": "completed", "result": {"outcome_summary": "Compromise demonstrated (synthetic)"}},
        ),
        (702, "state", {"state": "completed"}),
    ]
    events: list[dict[str, Any]] = []
    for seq, (off, typ, payload) in enumerate(offsets_and_types, 1):
        # Ensure source/demo marker where relevant
        payload_with_meta = dict(payload)
        if typ in ("tool_request", "tool_start", "tool_result"):
            payload_with_meta.setdefault("is_demo", True)
        events.append(
            {
                "sequence": seq,
                "timestamp": _iso(off),
                "run_id": DEMO_RUN_ID,
                "type": typ,
                "payload": payload_with_meta,
            }
        )
    return events


# ── filesystem seeding ─────────────────────────────────────────────────────


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def create_demo_artifacts(reports_dir: Path) -> Path:
    """Write reports/demo-session-v1/ artifacts — idempotent overwrite."""
    run_dir = reports_dir / DEMO_RUN_ID
    run_dir.mkdir(parents=True, exist_ok=True)
    # recon
    _write_json(run_dir / "recon_assessment.json", _recon_assessment())
    # enhanced report
    _write_json(run_dir / "enhanced" / "enhanced_report.json", _enhanced_report())
    # audit
    _write_jsonl(run_dir / "exploit_audit.jsonl", _exploit_audit_records())
    # events (the source for WS replay + RunPage EventViewer)
    _write_jsonl(run_dir / "events.jsonl", _events())
    # Also mirror audit under workspace path for fallback readers
    _write_jsonl(run_dir / "exploit_workspace" / "exploit_audit.jsonl", _exploit_audit_records())
    # Minimal run.json for completeness
    _write_json(run_dir / "run.json", _demo_result())
    # session summary markdown stub
    (run_dir / "session_summary.md").write_text(
        f"# {DEMO_TITLE}\n\nSynthetic demo run — no real target was contacted.\n\n"
        f"Target: {DEMO_TARGET} ({DEMO_RESOLVED_IP})\nDuration: 11m42s\nResult: Compromise demonstrated\n",
        encoding="utf-8",
    )
    return run_dir


def ensure_demo_seed(persistence: Any, reports_dir: Path) -> bool:
    """Idempotently create the demo run and its artifacts.

    Returns True if a new demo was created, False if already present or
    tombstoned. Never touches the network or subprocesses.
    """
    # Tombstone check — user deleted the demo, never recreate automatically.
    try:
        if persistence.is_demo_tombstoned():
            return False
    except Exception:
        pass

    # Already exists?
    try:
        existing = persistence.get_run(DEMO_RUN_ID)
        if existing is not None:
            # Ensure artifacts exist (daemon restart after reports/ wiped but DB kept).
            run_dir = reports_dir / DEMO_RUN_ID
            if not (run_dir / "enhanced" / "enhanced_report.json").exists():
                create_demo_artifacts(reports_dir)
            return False
    except Exception:
        pass

    # Create DB row + artifacts atomically (lock inside persistence).
    request = _demo_request()
    preview = _demo_preview()
    result = _demo_result()
    try:
        persistence.create_run(
            run_id=DEMO_RUN_ID,
            request=request,
            preview=preview,
            state="completed",
            title=DEMO_TITLE,
            is_demo=True,
            created_at=DEMO_CREATED,
        )
        # Patch updated_at / result_json to completed timestamp
        try:
            persistence.update_run_state(DEMO_RUN_ID, "completed", result=result)
            # Overwrite timestamps to deterministic values (update_run_state uses now;
            # we correct via direct SQL for exact demo reproduciblity).

            conn = persistence._connect()  # type: ignore[attr-defined]
            try:
                conn.execute(
                    "UPDATE runs SET created_at=?, updated_at=? WHERE id=?",
                    (DEMO_CREATED, DEMO_COMPLETED, DEMO_RUN_ID),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass
    except Exception as exc:
        # Duplicate id race (concurrent startup) — treat as already seeded.
        if "UNIQUE constraint" in str(exc) or "already exists" in str(exc).lower():
            return False
        raise

    create_demo_artifacts(reports_dir)
    return True


def restore_demo(persistence: Any, reports_dir: Path) -> bool:
    """Explicit restore — clears tombstone and (re)creates the demo."""
    try:
        persistence.clear_demo_tombstone()
    except Exception:
        pass
    # If still exists, clear already done; else create.
    try:
        existing = persistence.get_run(DEMO_RUN_ID)
        if existing is not None:
            # Already there — just ensure artifacts.
            create_demo_artifacts(reports_dir)
            return True
    except Exception:
        pass
    return ensure_demo_seed(persistence, reports_dir)


__all__ = [
    "DEMO_RUN_ID",
    "DEMO_SEED_VERSION",
    "DEMO_TITLE",
    "DEMO_TARGET",
    "DEMO_RESOLVED_IP",
    "create_demo_artifacts",
    "ensure_demo_seed",
    "is_demo_run",
    "restore_demo",
]
