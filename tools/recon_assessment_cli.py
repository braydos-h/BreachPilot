"""Recon-first assessment helpers for the CLI."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tools.attack_ui import AttackUi
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.goal_suggester import ReconAssessment, build_assessment_from_mcp_results

ui = AttackUi(plain=False)

async def run_recon_assessment(
    *,
    session: Any,
    target_ip: str,
    reports_dir: Path,
) -> ReconAssessment:
    """Run quick recon against target and build a structured assessment.

    Executes check_os, quick_scan, and search_cve_intel for each discovered
    service. Returns a ReconAssessment ready for goal suggestion.
    """
    ui.status("Running reconnaissance assessment...")
    ui.divider()

    # ── Step 1: OS detection ──
    with ui.spinner("Probing OS via TTL and port analysis...", soft_fail=True):
        try:
            os_raw = await session.call_tool("check_os", {"target_ip": target_ip})
            os_result = _extract_tool_text(os_raw)
        except _EXC_GROUP_CATCH as exc:
            # ``BaseExceptionGroup`` is *not* an ``Exception`` subclass — must be
            # listed explicitly or the spinner exits with a confusing [ERROR] line
            # and the user sees no underlying cause.
            os_result = (
                f"OS_CHECK_RESULTS:\nTARGET: {target_ip}\nOS_VERDICT: UNKNOWN\nHINTS: Error: {exc}"
            )
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)

    ui.result("OS Detection", os_result[:800])

    # ── Step 2: Quick port scan ──
    with ui.spinner("Scanning top 24 ports...", soft_fail=True):
        try:
            scan_raw = await session.call_tool("quick_scan", {
                "target_ip": target_ip,
                "ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,9000,27017,6379",
            })
            scan_result = _extract_tool_text(scan_raw)
        except _EXC_GROUP_CATCH as exc:
            scan_result = f"QUICK_SCAN_RESULTS: {target_ip}\nSUMMARY: 0/0 ports open\nNOTE: Scan error: {exc}"
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)

    ui.result("Port Scan", scan_result[:1200])

    # ── Step 3: CVE lookup per discovered service ──
    cve_results: list[dict[str, Any]] = []
    import re
    open_ports: list[tuple[str, str, str, str]] = []
    for line in scan_result.splitlines():
        port_match = re.match(
            r"\s*Port\s+(\d+)/(tcp|udp)\s+OPEN\s*\((\w*)\)\s*-\s*(.*)",
            line,
        )
        if port_match:
            open_ports.append(port_match.groups())

    if open_ports:
        ui.info(f"Looking up CVEs for {len(open_ports)} discovered service(s)...")
    for port, proto, service, banner in open_ports:
        banner = banner.strip()
        if banner == "(no banner)":
            banner = ""
        version = ""
        version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", banner)
        if version_match:
            version = version_match.group(1)
        query = f"{service} {version}".strip()
        with ui.spinner(f"Looking up CVEs for {service} on port {port}..."):
            try:
                cve_raw = await session.call_tool("search_cve_intel", {"query": query})
                cve_text = _extract_tool_text(cve_raw)
                cve_results.append({
                    "service": service,
                    "version": version,
                    "port": port,
                    "results": cve_text[:2000],
                })
                ui.result(f"CVEs for {service} {version}".strip(), cve_text[:600])
            except _EXC_GROUP_CATCH as exc:
                ui.info(f"CVE lookup skipped for {service}: {exc}")
                if _is_exception_group(exc):
                    _log_nested_exceptions(exc)

    # ── Build assessment ──
    assessment = build_assessment_from_mcp_results(
        target_ip=target_ip,
        os_result=os_result,
        scan_result=scan_result,
        cve_results=cve_results,
    )

    # ── Persist to reports dir ──
    assessment_path = reports_dir / "recon_assessment.json"
    assessment_path.write_text(
        json.dumps(assessment.to_dict(), indent=2), encoding="utf-8"
    )
    ui.info(f"Recon assessment saved to: {assessment_path}")

    return assessment


def _extract_tool_text(raw: Any) -> str:
    """Extract text content from an MCP tool call result."""
    if isinstance(raw, str):
        return raw
    if hasattr(raw, "content"):
        content = raw.content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if hasattr(item, "text"):
                    parts.append(item.text)
                elif isinstance(item, dict) and "text" in item:
                    parts.append(item["text"])
                elif isinstance(item, str):
                    parts.append(item)
            return "\n".join(parts)
        if isinstance(content, str):
            return content
    return str(raw)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
