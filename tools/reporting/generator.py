"""Finding report orchestrator (split out of ``tools.enhanced_reporting``).

:class:`EnhancedReportGenerator` assembles report data and delegates
rendering to :mod:`tools.reporting.markdown` / :mod:`tools.reporting.html`,
scoring to :mod:`tools.reporting.cvss`, and models + the HITL gate to
:mod:`tools.reporting.models`. Same-named thin methods are kept so existing
call sites (``tools/mcp_tools/hitl.py``, ``verify.py``, ``web_scan.py``,
``tools/run_service/execute.py``) and test seams keep working.
Re-exported through :mod:`tools.enhanced_reporting`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from tools.logging_setup import get_logger
from tools.reporting import html as _html
from tools.reporting import markdown as _md
from tools.reporting.cvss import CVSSScore, estimate_cvss
from tools.reporting.models import (
    AttackTimelineEntry,
    ExploitationChain,
    FailureAnalysis,
    TechnicalFinding,
    _confidence_from_verdict,
    _resolve_verdict,
    apply_hitl_filter,
)

logger = get_logger()

__all__ = ["EnhancedReportGenerator"]


class EnhancedReportGenerator:
    """Professional red-team style report generator."""

    def __init__(
        self,
        db: Any | None = None,
        mission_id: str = "",
        workspace: Path | None = None,
    ) -> None:
        self._db = db
        self._mission_id = mission_id
        self._workspace = workspace or Path("reports")
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._reports_dir = self._workspace / "enhanced"
        self._reports_dir.mkdir(parents=True, exist_ok=True)

    # ── Main API ────────────────────────────────────────────────────────

    def generate_full_report(
        self,
        campaign_result: dict[str, Any],
        *,
        output_format: str = "both",  # json, markdown, both, html, all
        evidence_store: Any | None = None,
        outcome_assessments: Mapping[str, Any] | None = None,
    ) -> dict[str, Path]:
        """Generate a complete red-team style report from campaign results.

        This is the ONLY vetted-findings surface: ``technical_findings`` are
        filtered through :func:`apply_hitl_filter` before ANY write, so only
        findings whose lifecycle state is ``APPROVED`` / ``VERIFIED`` /
        ``STILL_OPEN`` reach JSON/Markdown/HTML. ``PROPOSED`` / ``REJECTED`` /
        undecided candidates never leak titles or details — only an
        ``N awaiting review`` banner with zero titles.

        Args:
            campaign_result: Output from AutonomousOrchestrator.run_autonomous_campaign()
            output_format: Output format(s). ``json``/``markdown``/``html``
                produce a single format; ``both`` (default) produces JSON +
                Markdown; ``all`` produces JSON + Markdown + HTML.
            evidence_store: Optional ``EvidenceStore``. When supplied, each
                technical finding is back-filled with evidence refs and
                reproduction steps drawn from the promoted exploit-audit rows
                tagged for that target (see ``evidence.promote_exploit_audit``).
            outcome_assessments: Optional mapping keyed by target IP to an
                ``OutcomeAssessment`` (or dict carrying ``hypothesis_status``).
                When supplied, finding confidence is derived from the verdict
                (CONFIRMED -> 0.95, REFUTED -> 0.2, INCONCLUSIVE -> 0.5);
                otherwise the existing 0.9 default is kept.

        Returns:
            Dict mapping format to file path
        """
        logger.info("Generating full red-team report")
        report_data = self._build_report_data(
            campaign_result,
            evidence_store=evidence_store,
            outcome_assessments=outcome_assessments,
        )
        # HITL gate: only human-APPROVED findings reach any output (JSON/MD/HTML).
        # The pending count is threaded explicitly into the renderers: they
        # re-filter defensively, and re-filtering this same (already filtered)
        # dict would yield 0 and drop the banner.
        pending = apply_hitl_filter(report_data)

        paths: dict[str, Path] = {}

        if output_format in ("json", "both", "all"):
            json_path = self._reports_dir / f"report_{self._mission_id}_{self._now()}.json"
            json_path.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")
            paths["json"] = json_path
            logger.info(f"JSON report saved to {json_path}")

        if output_format in ("markdown", "both", "all"):
            md_path = self._reports_dir / f"report_{self._mission_id}_{self._now()}.md"
            md_content = self._generate_markdown(report_data, pending_count=pending)
            md_path.write_text(md_content, encoding="utf-8")
            paths["markdown"] = md_path
            logger.info(f"Markdown report saved to {md_path}")

        if output_format in ("html", "all"):
            html_path = self._reports_dir / f"report_{self._mission_id}_{self._now()}.html"
            html_content = self._generate_html(report_data, pending_count=pending)
            html_path.write_text(html_content, encoding="utf-8")
            paths["html"] = html_path
            logger.info(f"HTML report saved to {html_path}")

        return paths

    def generate_executive_summary(
        self,
        campaign_result: dict[str, Any],
    ) -> str:
        """Generate executive summary markdown.

        HITL boundary: this renders aggregate campaign telemetry (counts,
        privilege levels, recon snapshots) — operational history, NOT vetted
        findings. It emits no finding titles and is safe to share
        pre-decision; the per-finding vetted surface is
        :meth:`generate_full_report`, which gates on the lifecycle state.
        """
        states = campaign_result.get("states", {})
        total_targets = len(states)
        successful_exploits = sum(len(s.get("successful_exploits", [])) for s in states.values())
        total_attempts = sum(
            len(s.get("successful_exploits", [])) + sum(len(v) for v in s.get("failed_attempts", {}).values())
            for s in states.values()
        )
        privilege_escalations = sum(
            1 for s in states.values() if s.get("privilege_level") in ("root", "system", "admin")
        )
        credentials_found = sum(len(s.get("credentials_found", [])) for s in states.values())

        critical_count = sum(
            1
            for s in states.values()
            for e in s.get("successful_exploits", [])
            if any(c in e for c in ["RCE", "CVE-2024-6387", "EternalBlue", "BlueKeep"])
        )

        lines = [
            "# Executive Summary",
            "",
            f"**Assessment Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Mission ID**: {self._mission_id}",
            f"**Total Targets Assessed**: {total_targets}",
            "",
            "---",
            "",
            "## Key Findings",
            "",
            f"- **Critical Vulnerabilities Exploited**: {critical_count}",
            f"- **Total Successful Exploits**: {successful_exploits}",
            f"- **Total Exploit Attempts**: {total_attempts}",
            f"- **Privilege Escalations Achieved**: {privilege_escalations}",
            f"- **Credentials Discovered**: {credentials_found}",
            f"- **Success Rate**: {(successful_exploits / total_attempts * 100):.1f}%"
            if total_attempts > 0
            else "- **Success Rate**: N/A",
            "",
            "## Risk Assessment",
            "",
        ]

        if critical_count > 0:
            lines.append(
                "🔴 **CRITICAL**: Immediate action required. Multiple critical vulnerabilities were successfully exploited."
            )
        elif successful_exploits > 0:
            lines.append("🟠 **HIGH**: Significant security weaknesses identified and exploited.")
        elif total_attempts > 0:
            lines.append("🟡 **MEDIUM**: Some attack vectors were identified but exploitation was limited.")
        else:
            lines.append("🟢 **LOW**: No successful exploits achieved during the assessment.")

        lines.extend(
            [
                "",
                "## Attack Surface Summary",
                "",
            ]
        )

        for target, state in states.items():
            recon = state.get("recon_result", {})
            lines.append(f"### {target}")
            lines.append(f"- **OS**: {recon.get('os_family', 'Unknown')}")
            lines.append(f"- **Open Ports**: {recon.get('total_open_ports', 0)}")
            lines.append(f"- **Services**: {recon.get('total_services', 0)}")
            lines.append(f"- **Access Achieved**: {'Yes' if state.get('access_achieved') else 'No'}")
            if state.get("privilege_level"):
                lines.append(f"- **Privilege Level**: {state.get('privilege_level')}")
            # Phase 3 Round 2 additive recon fields — tolerant of old runs
            # (recon_result snapshots that predate these keys).
            udp_ports = recon.get("udp_ports") or []
            if udp_ports:
                lines.append(f"- **UDP Ports**: {len(udp_ports)} - {udp_ports}")
            spider_results = recon.get("spider_results") or []
            if spider_results:
                lines.append(f"- **Web Spider**: {len(spider_results)} site(s) crawled")
            osint = recon.get("osint") or {}
            if isinstance(osint, dict) and osint:
                ipv6 = osint.get("ipv6_addresses") or []
                rev = osint.get("reverse_dns") or ""
                if ipv6 or rev:
                    bits = []
                    if ipv6:
                        bits.append(f"{len(ipv6)} IPv6 addr(s)")
                    if rev:
                        bits.append(f"rDNS={rev}")
                    lines.append(f"- **OSINT**: {', '.join(bits)}")
            ipv6_direct = recon.get("ipv6_addresses") or []
            if ipv6_direct:
                lines.append(f"- **IPv6 (passive)**: {ipv6_direct}")
            lines.append("")

        return "\n".join(lines)

    def generate_attack_timeline(
        self,
        campaign_result: dict[str, Any],
    ) -> str:
        """Generate attack timeline markdown."""
        states = campaign_result.get("states", {})

        lines = [
            "# Attack Timeline",
            "",
            "| Time | Target | Event Type | Module | Description | Result |",
            "|------|--------|------------|--------|-------------|--------|",
        ]

        all_events: list[tuple[str, str, dict]] = []
        for target, state in states.items():
            for event in state.get("timeline", []):
                all_events.append((event.get("timestamp", ""), target, event))

        all_events.sort(key=lambda x: x[0])

        for timestamp, target, event in all_events:
            time_str = timestamp.split("T")[1].split(".")[0] if "T" in timestamp else timestamp
            event_type = event.get("event_type", "")
            module = event.get("metadata", {}).get("module", "")
            description = event.get("description", "")[:60]
            result = (
                "✅" if "success" in event_type else "❌" if "fail" in event_type or "error" in event_type else "⏳"
            )
            lines.append(f"| {time_str} | {target} | {event_type} | {module} | {description} | {result} |")

        return "\n".join(lines)

    def generate_failure_analysis(
        self,
        campaign_result: dict[str, Any],
    ) -> str:
        """Generate failure analysis markdown."""
        states = campaign_result.get("states", {})

        lines = [
            "# Failure Analysis",
            "",
            "## Failed Exploit Attempts",
            "",
        ]

        all_failures: dict[str, list[str]] = {}
        for target, state in states.items():
            for module, errors in state.get("failed_attempts", {}).items():
                if module not in all_failures:
                    all_failures[module] = []
                all_failures[module].extend(errors)

        if not all_failures:
            lines.append("No failed attempts recorded.")
            return "\n".join(lines)

        for module, errors in sorted(all_failures.items(), key=lambda x: len(x[1]), reverse=True):
            lines.append(f"### {module}")
            lines.append(f"- **Total Failures**: {len(errors)}")

            # Analyze error types
            error_types: dict[str, int] = {}
            for error in errors:
                error_type = self._categorize_error(error)
                error_types[error_type] = error_types.get(error_type, 0) + 1

            lines.append("- **Error Breakdown**:")
            for error_type, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"  - {error_type}: {count}")

            # Suggest mitigation
            primary_error = max(error_types, key=error_types.get)
            mitigation = self._suggest_mitigation(primary_error)
            lines.append(f"- **Suggested Mitigation**: {mitigation}")
            lines.append("")

        return "\n".join(lines)

    def generate_exploitation_chains(
        self,
        campaign_result: dict[str, Any],
    ) -> str:
        """Generate exploitation chain analysis markdown.

        HITL boundary: chains record which exploit modules ran per target —
        operational history, NOT vetted findings. They carry module names
        only (no finding titles, summaries, or evidence) and are safe to
        share pre-decision; the vetted per-finding surface is
        :meth:`generate_full_report`.
        """
        states = campaign_result.get("states", {})

        lines = [
            "# Exploitation Chains",
            "",
        ]

        for target, state in states.items():
            exploits = state.get("successful_exploits", [])
            if not exploits:
                continue

            lines.append(f"## {target}")
            lines.append("")
            lines.append("### Chain of Successful Exploits")
            lines.append("")

            for i, exploit in enumerate(exploits, 1):
                lines.append(f"{i}. **{exploit}**")

            # Show privilege progression
            priv_level = state.get("privilege_level", "none")
            if priv_level != "none":
                lines.append("")
                lines.append(f"**Final Privilege Level**: {priv_level}")

            # Show credentials
            creds = state.get("credentials_found", [])
            if creds:
                lines.append("")
                lines.append("**Credentials Discovered**:")
                for cred in creds[:5]:  # Limit to 5
                    user = cred.get("user", "unknown")
                    lines.append(f"- {user}: ***")

            # Show pivot targets
            pivots = state.get("pivot_targets", [])
            if pivots:
                lines.append("")
                lines.append(f"**Lateral Movement Targets**: {', '.join(pivots[:5])}")

            lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def generate_technical_findings(
        self,
        campaign_result: dict[str, Any],
    ) -> str:
        """Generate technical findings with CVSS scoring.

        .. warning:: Pre-HITL provisional output. This renders *candidate*
            findings straight from campaign ``successful_exploits`` — every
            entry is an undecided proposal (no human decision, no oracle
            proof) and MUST NOT be treated as the vetted report. For
            operator-facing output use :meth:`generate_full_report`, which
            filters through the lifecycle gate (only ``APPROVED`` /
            ``VERIFIED`` / ``STILL_OPEN`` surface; ``PROPOSED`` / ``REJECTED``
            / undecided titles never leak).
        """
        states = campaign_result.get("states", {})

        lines = [
            "# Technical Findings",
            "",
        ]

        finding_count = 0
        for target, state in states.items():
            exploits = state.get("successful_exploits", [])
            recon = state.get("recon_result", {})
            services = recon.get("services", [])

            for exploit in exploits:
                finding_count += 1
                cvss = self._estimate_cvss(exploit, services)

                lines.append(f"## Finding {finding_count}: {exploit}")
                lines.append("")
                lines.append(f"**Affected Asset**: {target}")
                lines.append(f"**CVSS Score**: {cvss.base_score} ({cvss.severity})")
                lines.append(f"**Vector**: `{cvss.vector_string}`")
                lines.append("")
                lines.append("### Description")
                lines.append(f"Successfully exploited {exploit} on {target}.")
                lines.append("")
                lines.append("### Evidence")
                lines.append("- Attack timeline entries")
                lines.append("- Tool output logs")
                lines.append("")
                lines.append("### Remediation")
                lines.append(self._get_remediation(exploit))
                lines.append("")
                lines.append("---")
                lines.append("")

        if finding_count == 0:
            lines.append("No successful exploits were achieved during this assessment.")

        return "\n".join(lines)

    # ── Internal helpers ────────────────────────────────────────────────

    def _build_report_data(
        self,
        campaign_result: dict[str, Any],
        *,
        evidence_store: Any | None = None,
        outcome_assessments: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build structured report data dict.

        When ``evidence_store`` is supplied, technical findings are back-filled
        with evidence refs and reproduction steps drawn from the promoted
        exploit-audit rows for that target. When ``outcome_assessments`` is
        supplied (keyed by target IP), finding confidence reflects the verdict.

        HITL note: findings built here carry no lifecycle keys, so
        :func:`current_state` resolves them to ``PROPOSED`` and the
        final-report gate hides them until a human decides (see
        :func:`apply_hitl_filter`). Only ``generate_full_report`` (which
        applies the gate) is a vetted surface.
        """
        states = campaign_result.get("states", {})

        # Index promoted evidence by target once (best-effort; never fatal).
        evidence_by_target: dict[str, list[dict[str, Any]]] = {}
        if evidence_store is not None:
            try:
                mission_evidence = evidence_store.list_for_mission(limit=500)
            except Exception:
                mission_evidence = []
            for item in mission_evidence or []:
                meta = item.get("metadata", {}) or {}
                tgt = meta.get("target_ip", "") or item.get("target", "")
                if tgt:
                    evidence_by_target.setdefault(tgt, []).append(item)

        # Build attack timeline
        timeline: list[AttackTimelineEntry] = []
        for target, state in states.items():
            for event in state.get("timeline", []):
                timeline.append(
                    AttackTimelineEntry(
                        timestamp=event.get("timestamp", ""),
                        event_type=event.get("event_type", ""),
                        description=event.get("description", ""),
                        target=target,
                        module=event.get("metadata", {}).get("module", ""),
                        result="success" if "success" in event.get("event_type", "") else "failure",
                        metadata=event.get("metadata", {}),
                    )
                )

        # Build exploitation chains (timestamps back-filled from audit records /
        # timeline events when available).
        chains: list[ExploitationChain] = []
        for target, state in states.items():
            exploits = state.get("successful_exploits", [])
            if exploits:
                chain_entries = []
                for exploit in exploits:
                    ts = self._chain_entry_timestamp(exploit, target, state)
                    chain_entries.append(
                        {
                            "module": exploit,
                            "timestamp": ts,
                            "result": "success",
                        }
                    )
                chains.append(
                    ExploitationChain(
                        chain_id=f"CHAIN-{target.replace('.', '-')}",
                        target=target,
                        entries=chain_entries,
                        successful=True,
                        final_privilege=state.get("privilege_level", "none"),
                    )
                )

        # Build failure analysis
        failures: list[FailureAnalysis] = []
        all_failed: dict[str, list[str]] = {}
        for target, state in states.items():
            for module, errors in state.get("failed_attempts", {}).items():
                if module not in all_failed:
                    all_failed[module] = []
                all_failed[module].extend(errors)

        for module, errors in all_failed.items():
            error_types: dict[str, int] = {}
            for error in errors:
                et = self._categorize_error(error)
                error_types[et] = error_types.get(et, 0) + 1
            primary = max(error_types, key=error_types.get) if error_types else "Unknown"
            failures.append(
                FailureAnalysis(
                    operation=module,
                    failure_count=len(errors),
                    primary_error=primary,
                    error_breakdown=error_types,
                    mitigation_suggestion=self._suggest_mitigation(primary),
                )
            )

        # Build technical findings
        findings: list[TechnicalFinding] = []
        for target, state in states.items():
            recon = state.get("recon_result", {})
            services = recon.get("services", [])
            target_evidence = evidence_by_target.get(target, [])
            verdict = _resolve_verdict(outcome_assessments, target) if outcome_assessments else None
            for exploit in state.get("successful_exploits", []):
                cvss = self._estimate_cvss(exploit, services)
                refs, repro = self._evidence_for_finding(exploit, target, state, target_evidence)
                confidence = _confidence_from_verdict(verdict)
                summary = f"Successfully exploited {exploit}"
                if verdict is not None:
                    summary = f"{summary} (hypothesis {verdict})"
                # Closed-loop retest: carry the stored verification probe so
                # retest_finding can re-execute ONLY the original PoC command.
                raw_probe = (state.get("exploit_probes", {}) or {}).get(exploit, {})
                probe = dict(raw_probe) if isinstance(raw_probe, dict) else {}
                findings.append(
                    TechnicalFinding(
                        finding_id=f"F-{target.replace('.', '-')}-{exploit}",
                        title=f"{exploit} on {target}",
                        affected_asset=target,
                        vuln_class=self._classify_vulnerability(exploit),
                        severity=cvss.severity,
                        cvss=cvss,
                        confidence=confidence,
                        summary=summary,
                        reproduction_steps=repro,
                        evidence_refs=refs,
                        exploitation_result="Shell access achieved"
                        if state.get("access_achieved")
                        else "Exploit verified",
                        privilege_level_gained=state.get("privilege_level", ""),
                        remediation=self._get_remediation(exploit),
                        verification_probe=probe,
                    )
                )

        # T1.13: rank findings by CVSS base score (desc) so both render paths
        # (_generate_findings_md / _generate_findings_html, which iterate this
        # list in order) surface the highest-severity findings first. Guard
        # against None base scores (treat as 0).
        findings.sort(key=lambda f: f.cvss.base_score or 0, reverse=True)

        return {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "mission_id": self._mission_id,
                "generator_version": "2.0",
                "total_targets": len(states),
                "total_exploits": sum(len(s.get("successful_exploits", [])) for s in states.values()),
                "total_failures": sum(
                    sum(len(v) for v in s.get("failed_attempts", {}).values()) for s in states.values()
                ),
            },
            "executive_summary": self.generate_executive_summary(campaign_result),
            "attack_timeline": [t.to_dict() for t in timeline],
            "exploitation_chains": [c.to_dict() for c in chains],
            "failure_analysis": [f.to_dict() for f in failures],
            "technical_findings": [f.to_dict() for f in findings],
        }

    def _chain_entry_timestamp(
        self,
        exploit: str,
        target: str,
        state: dict[str, Any],
    ) -> str:
        """Best-effort timestamp for a chain step from audit records / timeline."""
        exploit_lower = (exploit or "").lower()
        # 1. ExploitRecord rows carried in campaign state.
        for rec in state.get("exploit_records", []) or state.get("audit_records", []):
            if not isinstance(rec, dict):
                continue
            hay = " ".join(
                str(v)
                for v in (
                    rec.get("action", ""),
                    rec.get("tool_name", ""),
                    (rec.get("full_args", {}) or {}).get("command", ""),
                    (rec.get("args", {}) or {}).get("command", ""),
                )
            ).lower()
            if exploit_lower and exploit_lower in hay:
                ts = rec.get("timestamp") or rec.get("created_at", "")
                if ts:
                    return str(ts)
        # 2. Timeline events whose module/event_type mentions the exploit.
        for event in state.get("timeline", []) or []:
            if not isinstance(event, dict):
                continue
            module = str(event.get("metadata", {}).get("module", "")).lower()
            etype = str(event.get("event_type", "")).lower()
            if exploit_lower and (exploit_lower in module or exploit_lower in etype):
                ts = event.get("timestamp", "")
                if ts:
                    return str(ts)
        return ""

    def _evidence_for_finding(
        self,
        exploit: str,
        target: str,
        state: dict[str, Any],
        target_evidence: list[dict[str, Any]],
    ) -> tuple[list[str], list[str]]:
        """Collect evidence ids + reproduction steps for a finding.

        Precedence:
        1. Explicit ``state["exploit_evidence"][exploit]`` list of evidence ids.
        2. ``state["evidence_refs"]`` list shared across the target's findings.
        3. Promoted audit evidence for this target (filtered by the exploit
           substring against the action/command when possible).
        """
        explicit = (state.get("exploit_evidence", {}) or {}).get(exploit)
        if isinstance(explicit, list) and explicit:
            refs = [str(r) for r in explicit if r]
            repro = self._reproduction_from_evidence(target_evidence, exploit, refs)
            return refs, repro

        shared = state.get("evidence_refs")
        if isinstance(shared, list) and shared:
            refs = [str(r) for r in shared if r]
            repro = self._reproduction_from_evidence(target_evidence, exploit, refs)
            return refs, repro

        if not target_evidence:
            # No promoted evidence for this target -- synthesize a single
            # fallback reproduction step so the report still documents the
            # exploit path even without an EvidenceStore.
            return [], [f"Execute {exploit} against the target and capture tool output."]

        exploit_lower = (exploit or "").lower()
        matched: list[dict[str, Any]] = []
        for item in target_evidence:
            meta = item.get("metadata", {}) or {}
            action = str(meta.get("action", "")).lower()
            cmd = str(meta.get("command", "")).lower()
            if exploit_lower and (exploit_lower in action or exploit_lower in cmd):
                matched.append(item)
        pool = matched if matched else target_evidence
        refs = [item.get("evidence_id", "") for item in pool if item.get("evidence_id")]
        repro = self._reproduction_from_evidence(pool, exploit, refs)
        return refs, repro

    def _reproduction_from_evidence(
        self,
        pool: list[dict[str, Any]],
        exploit: str,
        refs: list[str],
    ) -> list[str]:
        """Derive concise reproduction steps from evidence summaries."""
        ref_set = set(refs)
        steps: list[str] = []
        for item in pool:
            eid = item.get("evidence_id", "")
            if ref_set and eid not in ref_set:
                continue
            meta = item.get("metadata", {}) or {}
            action = str(meta.get("action", "") or meta.get("tool_name", "")).strip()
            summary = str(item.get("summary", "")).strip()
            if not summary:
                continue
            label = f"{action}: " if action else ""
            steps.append(f"{label}{summary[:120]}")
        if not steps:
            steps = [f"Execute {exploit} against the target and capture tool output."]
        return steps[:10]

    # ── Render delegates (bodies live in markdown.py / html.py) ──────────

    def _generate_markdown(self, report_data: dict[str, Any], *, pending_count: int | None = None) -> str:
        """Generate full markdown report from structured data (HITL-gated)."""
        return _md._generate_markdown(report_data, pending_count=pending_count)

    def _generate_html(self, report_data: dict[str, Any], *, pending_count: int | None = None) -> str:
        """Generate a self-contained HTML report (HITL-gated)."""
        return _html._generate_html(report_data, pending_count=pending_count)

    def _generate_timeline_html(self, timeline: list[dict]) -> str:
        return _html._generate_timeline_html(timeline)

    def _generate_chains_html(self, chains: list[dict]) -> str:
        return _html._generate_chains_html(chains)

    def _generate_findings_html(self, findings: list[dict], *, pending_count: int = 0) -> str:
        return _html._generate_findings_html(findings, pending_count=pending_count)

    def _generate_failures_html(self, failures: list[dict]) -> str:
        return _html._generate_failures_html(failures)

    def _generate_timeline_md(self, timeline: list[dict]) -> str:
        return _md._generate_timeline_md(timeline)

    def _generate_chains_md(self, chains: list[dict]) -> str:
        return _md._generate_chains_md(chains)

    def _generate_findings_md(self, findings: list[dict], *, pending_count: int = 0) -> str:
        return _md._generate_findings_md(findings, pending_count=pending_count)

    def _generate_failures_md(self, failures: list[dict]) -> str:
        return _md._generate_failures_md(failures)

    def _estimate_cvss(self, exploit_name: str, services: list[dict]) -> CVSSScore:
        """Estimate CVSS score based on exploit type and exposed services."""
        return estimate_cvss(exploit_name, services)

    def _classify_vulnerability(self, exploit_name: str) -> str:
        """Classify vulnerability type from exploit name."""
        exploit_lower = exploit_name.lower()
        classifications = {
            "brute": "Weak Credentials",
            "spray": "Weak Credentials",
            "cve": "Known CVE",
            "eternalblue": "Known CVE",
            "smbghost": "Known CVE",
            "bluekeep": "Known CVE",
            "regresshion": "Known CVE",
            "sql": "SQL Injection",
            "xss": "Cross-Site Scripting",
            "webshell": "File Upload",
            "upload": "File Upload",
            "privesc": "Privilege Escalation",
            "suid": "Privilege Escalation",
            "container": "Container Escape",
            "docker": "Container Escape",
            "ldap": "Information Disclosure",
            "anonymous": "Information Disclosure",
            "redis": "Unauthorized Access",
        }
        for key, value in classifications.items():
            if key in exploit_lower:
                return value
        return "Other"

    def _get_remediation(self, exploit_name: str) -> str:
        """Get remediation guidance for an exploit."""
        exploit_lower = exploit_name.lower()
        remediations = {
            "brute": "Implement account lockout policies and enforce strong password requirements. Enable MFA.",
            "spray": "Implement rate limiting and account lockout. Use MFA.",
            "cve-2024-6387": "Upgrade OpenSSH to version 9.8p1 or later. Apply vendor patches immediately.",
            "eternalblue": "Apply MS17-010 patch. Disable SMBv1. Enable SMB signing.",
            "smbghost": "Apply KB4551762 patch. Disable SMBv3 compression if not needed.",
            "bluekeep": "Apply CVE-2019-0708 patch. Enable Network Level Authentication (NLA).",
            "sql": "Use parameterized queries. Implement input validation and WAF rules.",
            "xss": "Implement Content Security Policy (CSP). Encode all output. Use modern frameworks.",
            "webshell": "Validate file uploads by type and content. Store uploads outside web root.",
            "upload": "Validate file uploads. Use allowlists for extensions. Scan uploaded files.",
            "privesc": "Apply principle of least privilege. Regularly patch systems. Audit SUID binaries.",
            "suid": "Remove unnecessary SUID permissions. Audit with tools like LinPEAS.",
            "container": "Run containers as non-root. Use read-only root filesystems. Apply seccomp profiles.",
            "docker": "Secure Docker daemon with TLS. Use user namespaces. Enable Docker Content Trust.",
            "ldap": "Disable anonymous binds. Implement LDAPS. Enforce strong authentication.",
            "redis": "Enable AUTH. Bind to localhost only. Use firewall rules. Enable TLS.",
        }
        for key, value in remediations.items():
            if key in exploit_lower:
                return value
        return "Review and apply vendor security advisories. Implement defense-in-depth measures."

    def _categorize_error(self, error: str) -> str:
        """Categorize an error message."""
        error_lower = error.lower()
        if "timeout" in error_lower:
            return "Timeout"
        elif "connection" in error_lower and "refused" in error_lower:
            return "Connection Refused"
        elif "connection" in error_lower:
            return "Connection Error"
        elif "permission" in error_lower or "denied" in error_lower:
            return "Permission Denied"
        elif "not found" in error_lower:
            return "Not Found"
        elif "scope" in error_lower or "out of scope" in error_lower:
            return "Scope Violation"
        elif "rate" in error_lower or "429" in error_lower:
            return "Rate Limited"
        elif "tool" in error_lower and ("not found" in error_lower or "not installed" in error_lower):
            return "Missing Tool"
        else:
            return "Other"

    def _suggest_mitigation(self, error_type: str) -> str:
        """Suggest mitigation for an error type."""
        mitigations = {
            "Timeout": "Increase timeout values or reduce scan scope. Check network latency.",
            "Connection Refused": "Target service may be down or firewall blocking. Verify target state.",
            "Permission Denied": "Verify credentials and permissions. Try with elevated privileges if authorized.",
            "Not Found": "Verify target exists and path is correct.",
            "Scope Violation": "Review scope configuration. Do not target out-of-scope assets.",
            "Rate Limited": "Reduce request rate. Implement delays between requests.",
            "Missing Tool": "Install required tools or use fallback alternatives.",
            "Other": "Review error details and adjust parameters accordingly.",
        }
        return mitigations.get(error_type, "Review error details and adjust parameters.")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
