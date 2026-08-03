"""Goal Suggestion Engine — scores preset goals against recon findings.

After reconnaissance completes, this engine:
1. Takes a ReconAssessment (OS, open ports, services, CVEs)
2. Scores each compatible AttackGoal against the findings
3. Returns ranked suggestions with exploit likelihood and success ratings

Scoring factors:
- Service risk scores (from ReconAgent _SERVICE_RISK_SCORES)
- CVE exploitability (CVSS severity + public exploit availability)
- OS match confidence
- Goal-to-service compatibility (from planner.py _SERVICE_ATTACK_MAP)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ── Service risk scores (mirrors ReconAgent._SERVICE_RISK_SCORES) ──────────

_SERVICE_RISK_SCORES: dict[str, int] = {
    "ssh": 70, "smb": 90, "microsoft-ds": 90, "rdp": 85, "ms-wbt-server": 85,
    "http": 60, "https": 60, "ftp": 65, "telnet": 95, "redis": 80,
    "elasticsearch": 75, "mongodb": 80, "mysql": 70, "postgresql": 70,
    "ldap": 75, "ldaps": 75, "docker": 85, "kubernetes": 85,
    "winrm": 80, "vnc": 70, "smtp": 50, "dns": 40, "snmp": 65,
    "unknown": 50,
}

# ── Goal-to-service compatibility mapping ──────────────────────────────────
# Maps goal names to service names that make the goal highly relevant.

_GOAL_SERVICE_AFFINITY: dict[str, list[str]] = {
    "recon_only": [],  # always relevant
    "identify_vulnerabilities": [],  # always relevant
    "service_mapping": [],  # always relevant
    "recon_and_document": [],  # always relevant
    "initial_access": ["ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server",
                       "http", "https", "ftp", "telnet", "redis", "winrm",
                       "mysql", "postgresql", "mongodb", "elasticsearch"],
    "verify_cves": ["ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server",
                    "http", "https", "ftp", "ldap", "ldaps", "docker"],
    "backdoor": ["ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server",
                 "http", "https", "winrm"],
    "privilege_escalation": ["ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server",
                             "docker", "kubernetes", "winrm"],
    "full_compromise": ["ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server",
                        "http", "https", "winrm", "docker"],
    "credential_dumping": ["ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server",
                           "winrm", "ldap", "ldaps", "mysql", "postgresql"],
    "pivot_and_discovery": ["ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server",
                            "winrm"],
    "lateral_movement": ["ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server",
                         "winrm"],
    "data_exfiltration": ["ssh", "smb", "microsoft-ds", "http", "https",
                          "ftp", "mysql", "postgresql", "elasticsearch"],
    "whatever_it_takes": ["ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server",
                          "http", "https", "ftp", "telnet", "redis", "winrm",
                          "docker", "kubernetes"],
}

# ── Goal risk requirements (mirrors goal_engine.py) ────────────────────────

_GOAL_RISK_REQUIREMENTS: dict[str, str] = {
    "recon_only": "safe",
    "identify_vulnerabilities": "safe",
    "service_mapping": "safe",
    "recon_and_document": "safe",
    "initial_access": "gated",
    "verify_cves": "gated",
    "backdoor": "high",
    "privilege_escalation": "high",
    "full_compromise": "high",
    "credential_dumping": "high",
    "pivot_and_discovery": "high",
    "lateral_movement": "high",
    "data_exfiltration": "high",
    "whatever_it_takes": "high",
}

_RISK_ORDER: dict[str, int] = {"safe": 0, "gated": 1, "high": 2}

_RISK_PROFILE_LEVEL: dict[str, str] = {
    "low_noise_non_destructive": "safe",
    "standard_authorized": "gated",
    "high_authorized_testing": "high",
}


# ── Data classes ───────────────────────────────────────────────────────────

@dataclass
class ReconAssessment:
    """Structured recon results used as input to goal suggestion."""
    target_ip: str
    os_verdict: str = "UNKNOWN"          # WINDOWS, LINUX, MIXED, UNKNOWN
    os_hints: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    cve_findings: list[dict[str, Any]] = field(default_factory=list)
    raw_scan_output: str = ""
    raw_os_output: str = ""
    overall_risk_score: int = 0          # 0-100 aggregate attack surface score

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "os_verdict": self.os_verdict,
            "os_hints": self.os_hints,
            "open_ports": self.open_ports,
            "services": self.services,
            "cve_findings": self.cve_findings,
            "overall_risk_score": self.overall_risk_score,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReconAssessment:
        return cls(
            target_ip=str(data.get("target_ip", "")),
            os_verdict=str(data.get("os_verdict", "UNKNOWN")),
            os_hints=data.get("os_hints", []),
            open_ports=data.get("open_ports", []),
            services=data.get("services", []),
            cve_findings=data.get("cve_findings", []),
            raw_scan_output=str(data.get("raw_scan_output", "")),
            raw_os_output=str(data.get("raw_os_output", "")),
            overall_risk_score=int(data.get("overall_risk_score", 0)),
        )


@dataclass
class SuggestedGoal:
    """A goal with its exploit rating and rationale."""
    name: str
    description: str
    exploit_likelihood: str          # Very Likely, Likely, Possible, Unlikely, Blocked
    success_rating: int              # 0-100
    rationale: str                   # Human-readable explanation
    compatible: bool = True
    blocked_reason: str = ""
    risk_requirement: str = "safe"
    is_ai_generated: bool = False    # True if this goal was auto-generated from recon

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "exploit_likelihood": self.exploit_likelihood,
            "success_rating": self.success_rating,
            "rationale": self.rationale,
            "compatible": self.compatible,
            "blocked_reason": self.blocked_reason,
            "risk_requirement": self.risk_requirement,
            "is_ai_generated": self.is_ai_generated,
        }


# ── Goal Suggester ─────────────────────────────────────────────────────────

class GoalSuggester:
    """Scores preset goals against recon findings and returns ranked suggestions."""

    def __init__(self) -> None:
        pass

    def suggest(
        self,
        assessment: ReconAssessment,
        risk_profile: str = "standard_authorized",
        goal_descriptions: dict[str, str] | None = None,
    ) -> list[SuggestedGoal]:
        """Score all preset goals against the recon assessment.

        Args:
            assessment: ReconAssessment with OS, services, CVEs
            risk_profile: Mission risk profile for compatibility filtering
            goal_descriptions: Optional dict of goal_name → description

        Returns:
            List of SuggestedGoal sorted by success_rating descending
        """
        if goal_descriptions is None:
            goal_descriptions = {}

        profile_level = _RISK_PROFILE_LEVEL.get(risk_profile, "safe")
        profile_order = _RISK_ORDER.get(profile_level, 0)

        suggestions: list[SuggestedGoal] = []

        for goal_name, goal_risk in _GOAL_RISK_REQUIREMENTS.items():
            goal_order = _RISK_ORDER.get(goal_risk, 0)

            # ── Risk compatibility check ──
            if goal_order > profile_order:
                suggestions.append(SuggestedGoal(
                    name=goal_name,
                    description=goal_descriptions.get(goal_name, ""),
                    exploit_likelihood="Blocked",
                    success_rating=0,
                    rationale=f"Requires '{goal_risk}' authorization. Current profile: '{risk_profile}'.",
                    compatible=False,
                    blocked_reason=(
                        f"Goal '{goal_name}' requires at least '{goal_risk}' authorization. "
                        f"Current risk profile is '{risk_profile}'."
                    ),
                    risk_requirement=goal_risk,
                ))
                continue

            # ── Score the goal ──
            rating, likelihood, rationale = self._score_goal(
                goal_name, assessment
            )

            suggestions.append(SuggestedGoal(
                name=goal_name,
                description=goal_descriptions.get(goal_name, ""),
                exploit_likelihood=likelihood,
                success_rating=rating,
                rationale=rationale,
                compatible=True,
                risk_requirement=goal_risk,
            ))

        # Sort: compatible first by rating desc, then blocked at bottom
        suggestions.sort(key=lambda g: (g.compatible, g.success_rating), reverse=True)

        # ── Generate AI custom goals from discovered services ──
        ai_goals = self._generate_ai_custom_goals(assessment, risk_profile)
        suggestions.extend(ai_goals)

        # Global rank by rating desc so the best goal is always #1, regardless
        # of whether it is preset or AI-generated. Compatible goals above
        # blocked ones; within each group, higher rating first.
        suggestions.sort(key=lambda g: (g.compatible, g.success_rating), reverse=True)
        return suggestions

    def _generate_ai_custom_goals(
        self, assessment: ReconAssessment, risk_profile: str
    ) -> list[SuggestedGoal]:
        """Create service-specific custom goals based on recon findings."""
        ai_goals: list[SuggestedGoal] = []
        services = assessment.services
        os_verdict = assessment.os_verdict
        cve_findings = assessment.cve_findings

        # Map services to AI-generated goal templates
        service_goal_map: dict[str, tuple[str, str, int, str]] = {
            "http": (
                "web_app_exploitation",
                "Exploit web application vulnerabilities on the discovered HTTP service. "
                "Target: SQL injection, RCE, path traversal, file upload, SSRF, Log4j, "
                "JWT tampering, and authentication bypass. Use write_python_file for custom "
                "web exploits and run_python_file to execute them.",
                85,
                "gated",
            ),
            "https": (
                "web_app_exploitation",
                "Exploit web application vulnerabilities on the discovered HTTPS service. "
                "Target: SQL injection, RCE, path traversal, file upload, SSRF, Log4j, "
                "JWT tampering, and authentication bypass. Use write_python_file for custom "
                "web exploits and run_python_file to execute them.",
                85,
                "gated",
            ),
            "ssh": (
                "ssh_compromise",
                "Compromise the SSH service via weak/default credentials or known CVEs. "
                "Use password_spray for common creds, hydra for brute force, and "
                "search_cve_intel for OpenSSH vulnerabilities. If access gained, use "
                "dump_credentials to harvest keys and lateral_exec for pivoting.",
                80,
                "gated",
            ),
            "smb": (
                "smb_domain_takeover",
                "Exploit SMB/Microsoft-DS for domain takeover. Target: null sessions, "
                "EternalBlue, SMBGhost, relay attacks, and credential dumping. Use "
                "lateral_exec (wmiexec/smbexec/psexec) with captured hashes, "
                "dump_credentials (secretsdump/mimikatz) for hash extraction, and "
                "kerberoast for TGS ticket extraction if domain-joined.",
                90,
                "high",
            ),
            "microsoft-ds": (
                "smb_domain_takeover",
                "Exploit SMB/Microsoft-DS for domain takeover. Target: null sessions, "
                "EternalBlue, SMBGhost, relay attacks, and credential dumping. Use "
                "lateral_exec (wmiexec/smbexec/psexec) with captured hashes, "
                "dump_credentials (secretsdump/mimikatz) for hash extraction, and "
                "kerberoast for TGS ticket extraction if domain-joined.",
                90,
                "high",
            ),
            "rdp": (
                "rdp_exploitation",
                "Exploit RDP for remote access. Target: BlueKeep, CredSSP, weak credentials. "
                "Use password_spray for common creds, search_cve_intel for RDP CVEs, "
                "and generate_payload to create a reverse shell stager if needed.",
                80,
                "gated",
            ),
            "ms-wbt-server": (
                "rdp_exploitation",
                "Exploit RDP for remote access. Target: BlueKeep, CredSSP, weak credentials. "
                "Use password_spray for common creds, search_cve_intel for RDP CVEs, "
                "and generate_payload to create a reverse shell stager if needed.",
                80,
                "gated",
            ),
            "mysql": (
                "database_takeover",
                "Compromise the MySQL database via SQL injection, default credentials, or "
                "known CVEs. Use search_cve_intel for MySQL vulnerabilities, password_spray "
                "for weak creds, and sqlmap or custom Python scripts for injection attacks. "
                "If access gained, dump_credentials to extract user tables.",
                75,
                "gated",
            ),
            "postgresql": (
                "database_takeover",
                "Compromise the PostgreSQL database via SQL injection, default credentials, or "
                "known CVEs. Use search_cve_intel for PostgreSQL vulnerabilities, password_spray "
                "for weak creds, and custom Python scripts for injection attacks. "
                "If access gained, dump_credentials to extract user tables.",
                75,
                "gated",
            ),
            "mongodb": (
                "database_takeover",
                "Compromise MongoDB via NoSQL injection, default credentials, or unauthenticated "
                "access. Use search_cve_intel for MongoDB CVEs and write_python_file for "
                "custom NoSQL injection exploits.",
                75,
                "gated",
            ),
            "redis": (
                "redis_exploitation",
                "Exploit Redis via unauthenticated access, command execution, or known CVEs. "
                "Use search_cve_intel for Redis vulnerabilities and write_python_file for "
                "custom exploits targeting Redis protocol.",
                75,
                "gated",
            ),
            "ldap": (
                "ad_credential_harvest",
                "Harvest Active Directory credentials via LDAP. Use dump_credentials with "
                "secretsdump for domain hash extraction, kerberoast for TGS tickets, and "
                "lateral_exec for pass-the-hash movement across domain-joined hosts.",
                85,
                "high",
            ),
            "ldaps": (
                "ad_credential_harvest",
                "Harvest Active Directory credentials via LDAPS. Use dump_credentials with "
                "secretsdump for domain hash extraction, kerberoast for TGS tickets, and "
                "lateral_exec for pass-the-hash movement across domain-joined hosts.",
                85,
                "high",
            ),
            "ftp": (
                "ftp_exploitation",
                "Exploit FTP via anonymous login, weak credentials, or known CVEs. "
                "Use password_spray for common creds, search_cve_intel for FTP daemon CVEs, "
                "and run_exploit_terminal for manual FTP enumeration.",
                65,
                "gated",
            ),
            "telnet": (
                "telnet_exploitation",
                "Exploit Telnet via weak credentials or known CVEs. Telnet is plaintext — "
                "sniffing and credential attacks are highly effective. Use password_spray "
                "and search_cve_intel for Telnet daemon vulnerabilities.",
                70,
                "gated",
            ),
            "winrm": (
                "winrm_lateral_movement",
                "Use WinRM for lateral movement and remote command execution. "
                "Use lateral_exec (wmiexec/atexec) with captured credentials, "
                "evil-winrm for interactive shells, and dump_credentials for hash extraction.",
                80,
                "high",
            ),
            "docker": (
                "container_escape",
                "Escape Docker containers and compromise the host. Target: exposed Docker API, "
                "privileged containers, kernel exploits. Use search_cve_intel for Docker CVEs "
                "and write_python_file for custom container escape exploits.",
                80,
                "high",
            ),
            "kubernetes": (
                "k8s_cluster_compromise",
                "Compromise the Kubernetes cluster via exposed API, weak RBAC, or pod escape. "
                "Use search_cve_intel for K8s CVEs and write_python_file for custom "
                "exploits targeting the Kubernetes API server.",
                85,
                "high",
            ),
            "elasticsearch": (
                "elasticsearch_rce",
                "Exploit Elasticsearch for remote code execution or data exfiltration. "
                "Target: unauthenticated access, script injection, known CVEs. Use "
                "search_cve_intel for Elasticsearch vulnerabilities and custom Python scripts.",
                75,
                "gated",
            ),
            "smtp": (
                "smtp_exploitation",
                "Exploit SMTP for email spoofing, relay abuse, or user enumeration. "
                "Use search_cve_intel for SMTP CVEs and custom Python scripts for "
                "SMTP-based attacks.",
                55,
                "gated",
            ),
            "snmp": (
                "snmp_enumeration",
                "Enumerate SNMP for system info, network topology, and potential misconfigurations. "
                "Use run_exploit_terminal with snmpwalk/snmpcheck and search_cve_intel for "
                "SNMP-related vulnerabilities.",
                60,
                "safe",
            ),
            "dns": (
                "dns_enumeration",
                "Enumerate DNS for zone transfers, subdomain discovery, and reconnaissance. "
                "Use run_exploit_terminal with dig/nslookup for zone transfer attempts and "
                "DNS enumeration.",
                50,
                "safe",
            ),
        }

        # Determine max allowed risk level
        profile_level = _RISK_PROFILE_LEVEL.get(risk_profile, "safe")
        profile_order = _RISK_ORDER.get(profile_level, 0)

        seen_names: set[str] = set()
        for s in services:
            svc_name = s.get("service", s.get("name", "unknown")).lower()
            if svc_name not in service_goal_map:
                continue

            goal_name, description, base_rating, risk_req = service_goal_map[svc_name]
            if goal_name in seen_names:
                continue
            seen_names.add(goal_name)

            goal_order = _RISK_ORDER.get(risk_req, 0)
            if goal_order > profile_order:
                continue  # Skip if risk level too high for profile

            # Adjust rating based on CVE findings for this service
            cve_boost = 0
            for cve_group in cve_findings:
                if cve_group.get("service", "").lower() == svc_name:
                    results = cve_group.get("results", "")
                    if isinstance(results, str):
                        if "Critical" in results or "CVSS:9" in results:
                            cve_boost += 10
                        if "exploit" in results.lower() or "PoC" in results:
                            cve_boost += 5

            # Adjust for known OS
            os_boost = 5 if os_verdict in ("WINDOWS", "LINUX") else 0

            rating = min(100, base_rating + cve_boost + os_boost)
            likelihood = (
                "Very Likely" if rating >= 80
                else "Likely" if rating >= 55
                else "Possible" if rating >= 30
                else "Unlikely"
            )

            ai_goals.append(SuggestedGoal(
                name=goal_name,
                description=description,
                exploit_likelihood=likelihood,
                success_rating=rating,
                rationale=f"AI-generated goal based on discovered {svc_name.upper()} service. "
                          f"Port: {s.get('port', '?')}, Version: {s.get('version', 'unknown')}. "
                          f"Tailored to exploit this specific service using the most effective tools.",
                compatible=True,
                risk_requirement=risk_req,
                is_ai_generated=True,
            ))

        # Sort by rating descending
        ai_goals.sort(key=lambda g: g.success_rating, reverse=True)
        return ai_goals

    def _score_goal(
        self, goal_name: str, assessment: ReconAssessment
    ) -> tuple[int, str, str]:
        """Score a single goal against recon findings.

        Returns: (success_rating 0-100, exploit_likelihood, rationale)
        """
        services = assessment.services
        open_ports = assessment.open_ports
        cve_findings = assessment.cve_findings
        os_verdict = assessment.os_verdict

        # ── Safe goals: always score well if recon produced data ──
        safe_goals = {"recon_only", "identify_vulnerabilities", "service_mapping", "recon_and_document"}
        if goal_name in safe_goals:
            if not services and not open_ports:
                return (30, "Unlikely", "No services or open ports discovered. Recon may be blocked.")
            if len(services) >= 3:
                return (90, "Very Likely", f"Strong recon position: {len(services)} services, {len(open_ports)} open ports discovered.")
            if services:
                return (75, "Likely", f"Recon complete: {len(services)} service(s) on {len(open_ports)} open port(s).")
            return (50, "Possible", "Limited recon data. Target may be firewalled or down.")

        # ── Attack goals: need services to exploit ──
        if not services and not open_ports:
            return (5, "Unlikely", "No open ports or services discovered. Cannot exploit.")

        # ── Compute service-driven score ──
        affinity_services = _GOAL_SERVICE_AFFINITY.get(goal_name, [])
        matching_services = [
            s for s in services
            if s.get("service", s.get("name", "")).lower() in affinity_services
        ]

        if not matching_services and affinity_services:
            return (10, "Unlikely",
                    f"No services matching this goal found. "
                    f"Goal targets: {', '.join(affinity_services[:5])}. "
                    f"Found: {', '.join(s.get('service', s.get('name', '?')) for s in services[:5])}.")

        # ── Base score from service risk ──
        max_service_risk = 0
        total_risk = 0
        for s in (matching_services or services):
            svc_name = s.get("service", s.get("name", "unknown")).lower()
            risk = _SERVICE_RISK_SCORES.get(svc_name, 50)
            total_risk += risk
            if risk > max_service_risk:
                max_service_risk = risk

        avg_risk = total_risk / max(len(matching_services or services), 1)
        base_score = int((max_service_risk * 0.6) + (avg_risk * 0.4))

        # ── CVE boost ──
        cve_boost = 0
        has_public_exploit = False
        has_critical_cve = False
        cve_count = 0

        for cve_group in cve_findings:
            results = cve_group.get("results", "")
            if isinstance(results, str):
                cve_count += results.count("CVE-")
                if "Critical" in results or "CVSS:9" in results or "CVSS: 9" in results:
                    has_critical_cve = True
                if "exploit" in results.lower() or "PoC" in results or "Metasploit" in results:
                    has_public_exploit = True
            elif isinstance(results, list):
                for entry in results:
                    if isinstance(entry, dict):
                        cvss = float(entry.get("cvss_score", entry.get("cvss", 0)) or 0)
                        if cvss >= 9.0:
                            has_critical_cve = True
                        if entry.get("exploit_available") or entry.get("has_exploit"):
                            has_public_exploit = True
                    cve_count += 1

        if has_critical_cve:
            cve_boost += 20
        if has_public_exploit:
            cve_boost += 15
        cve_boost += min(cve_count * 2, 10)  # up to +10 for volume

        # ── OS match boost ──
        os_boost = 0
        if os_verdict in ("WINDOWS", "LINUX"):
            os_boost = 5  # known OS helps targeting

        # ── Port count penalty/boost ──
        port_factor = 0
        if len(open_ports) >= 5:
            port_factor = 5  # large attack surface
        elif len(open_ports) == 0:
            port_factor = -20

        # ── Final score ──
        score = base_score + cve_boost + os_boost + port_factor
        score = max(0, min(100, score))

        # ── Likelihood label ──
        if score >= 80:
            likelihood = "Very Likely"
        elif score >= 55:
            likelihood = "Likely"
        elif score >= 30:
            likelihood = "Possible"
        else:
            likelihood = "Unlikely"

        # ── Rationale ──
        parts: list[str] = []
        if matching_services:
            svc_names = [s.get("service", s.get("name", "?")) for s in matching_services[:3]]
            parts.append(f"Matches {len(matching_services)} service(s): {', '.join(svc_names)}")
        else:
            svc_names = [s.get("service", s.get("name", "?")) for s in services[:3]]
            parts.append(f"No direct service match; {len(services)} service(s) present: {', '.join(svc_names)}")

        if has_critical_cve:
            parts.append("Critical CVEs detected")
        if has_public_exploit:
            parts.append("Public exploits available")
        if cve_count > 0:
            parts.append(f"{cve_count} CVE(s) identified")
        parts.append(f"OS: {os_verdict}")

        rationale = ". ".join(parts) + "."

        return score, likelihood, rationale


# ── Recon assessment builder ───────────────────────────────────────────────

def build_assessment_from_mcp_results(
    target_ip: str,
    os_result: str,
    scan_result: str,
    cve_results: list[dict[str, Any]],
) -> ReconAssessment:
    """Parse raw MCP tool outputs into a structured ReconAssessment.

    Args:
        target_ip: The target IP address
        os_result: Raw output from check_os MCP tool
        scan_result: Raw output from quick_scan MCP tool
        cve_results: List of {service, version, port, results} from search_cve_intel

    Returns:
        ReconAssessment ready for goal suggestion
    """
    import re

    # ── Parse OS ──
    os_verdict = "UNKNOWN"
    os_hints: list[str] = []

    os_match = re.search(r"OS_VERDICT:\s*(\S+)", os_result)
    if os_match:
        os_verdict = os_match.group(1).strip()

    hints_match = re.search(r"HINTS:\s*(.+)$", os_result, re.MULTILINE)
    if hints_match:
        os_hints = [h.strip() for h in hints_match.group(1).split(";") if h.strip()]

    # ── Parse services from scan ──
    services: list[dict[str, Any]] = []
    open_ports: list[int] = []

    for line in scan_result.splitlines():
        # Match: "Port 22/tcp OPEN (ssh) - banner text"
        port_match = re.match(
            r"\s*Port\s+(\d+)/(tcp|udp)\s+OPEN\s*\((\w*)\)\s*-\s*(.*)",
            line,
        )
        if port_match:
            port = int(port_match.group(1))
            protocol = port_match.group(2)
            service = port_match.group(3) or "unknown"
            banner = port_match.group(4).strip()
            if banner == "(no banner)":
                banner = ""

            open_ports.append(port)
            services.append({
                "port": port,
                "protocol": protocol,
                "service": service,
                "version": "",
                "banner": banner,
                "risk_score": _SERVICE_RISK_SCORES.get(service.lower(), 50),
            })

    # ── Compute overall risk score ──
    if services:
        overall_risk = sum(
            _SERVICE_RISK_SCORES.get(s.get("service", "unknown").lower(), 50)
            for s in services
        ) // len(services)
        # Boost for multiple high-risk services
        high_risk_count = sum(
            1 for s in services
            if _SERVICE_RISK_SCORES.get(s.get("service", "unknown").lower(), 50) >= 80
        )
        overall_risk = min(100, overall_risk + high_risk_count * 5)
    else:
        overall_risk = 0

    return ReconAssessment(
        target_ip=target_ip,
        os_verdict=os_verdict,
        os_hints=os_hints,
        open_ports=open_ports,
        services=services,
        cve_findings=cve_results,
        raw_scan_output=scan_result,
        raw_os_output=os_result,
        overall_risk_score=overall_risk,
    )
