"""Goal engine for AI-driven penetration testing.

Goals now carry a `risk_profile` requirement. Dangerous presets (exploitation,
pivoting, credential harvesting) require explicit mission opt-in via
risk_profile=high_authorized_testing.

Presets are categorized:
- Safe: always available regardless of risk profile
- Gated: require risk_profile ≥ standard_authorized
- High: require risk_profile = high_authorized_testing

The engine validates goal/risk_profile compatibility before use.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ── Risk requirement tags ──────────────────────────────────────────────────

SAFE = "safe"  # always allowed
GATED = "gated"  # needs standard_authorized or higher
HIGH = "high"  # needs high_authorized_testing


# ── Preset goals with risk categorization ──────────────────────────────────

PRESET_GOALS: dict[str, dict[str, Any]] = {
    # ── Safe presets (always available) ──
    "recon_only": {
        "description": (
            "Perform thorough reconnaissance of the target. "
            "Identify OS, open services, versions, banners, and potential attack surface. "
            "Do NOT exploit anything without explicit user confirmation."
        ),
        "risk_requirement": SAFE,
    },
    "identify_vulnerabilities": {
        "description": (
            "Identify potential vulnerabilities on the target based on service versions, "
            "banner information, and known CVEs. Document each finding with evidence but "
            "do not actively exploit or validate without explicit confirmation."
        ),
        "risk_requirement": SAFE,
    },
    "service_mapping": {
        "description": (
            "Map all exposed services on the target. "
            "Document ports, protocols, service versions, and banners. "
            "Identify the technology stack and potential attack surface."
        ),
        "risk_requirement": SAFE,
    },
    "recon_and_document": {
        "description": (
            "Perform comprehensive reconnaissance and document everything. "
            "Build a complete map of the target's attack surface including "
            "subdomains, endpoints, parameters, and technologies. No exploitation."
        ),
        "risk_requirement": SAFE,
    },
    # ── Gated presets (need standard_authorized or higher) ──
    "initial_access": {
        "description": (
            "Gain initial access to the target server by identifying and exploiting "
            "a vulnerability. This could be remote code execution, credential compromise, "
            "or service exploitation. Report the vulnerability exploited and the type of "
            "access obtained. Do NOT establish persistence or exfiltrate data."
        ),
        "risk_requirement": GATED,
    },
    "verify_cves": {
        "description": (
            "Verify whether identified CVEs are actually exploitable on the target. "
            "For each CVE found: (1) confirm version evidence, (2) attempt safe validation, "
            "(3) document whether it is exploitable, (4) do NOT cause damage or establish "
            "persistence. This is verification, not full exploitation."
        ),
        "risk_requirement": GATED,
    },
    # ── High presets (need high_authorized_testing) ──
    "backdoor": {
        "description": (
            "Establish a persistent backdoor on the target server. "
            "Gain a stable shell, maintain access, and report the method used. "
            "Prefer stealthy persistence methods (e.g., scheduled tasks, service installs, "
            "web shells). This requires explicit high-authorization testing mode."
        ),
        "risk_requirement": HIGH,
    },
    "privilege_escalation": {
        "description": (
            "Escalate privileges on an already compromised host. "
            "Move from standard user to SYSTEM/root. "
            "Report the privilege escalation vector and confirm elevated access."
        ),
        "risk_requirement": HIGH,
    },
    "full_compromise": {
        "description": (
            "Achieve complete compromise of the target. "
            "Gain root/SYSTEM access, establish persistence, and demonstrate full control. "
            "Report all access vectors and persistence mechanisms. "
            "This requires explicit high-authorization testing mode."
        ),
        "risk_requirement": HIGH,
    },
    "credential_dumping": {
        "description": (
            "Obtain credentials from the target system. "
            "Attempt to dump hashes, retrieve plaintext passwords, or extract key material. "
            "Report what credentials were recovered and from where."
        ),
        "risk_requirement": HIGH,
    },
    "pivot_and_discovery": {
        "description": (
            "Use the target as a pivot point to discover and map internal network segments. "
            "Scan nearby subnets, identify additional targets, and report network topology."
        ),
        "risk_requirement": HIGH,
    },
    "lateral_movement": {
        "description": (
            "Move laterally from the compromised target to other hosts on the network. "
            "Use stolen credentials, pass-the-hash, or trusted relationship abuse. "
            "Report new hosts accessed."
        ),
        "risk_requirement": HIGH,
    },
    "data_exfiltration": {
        "description": (
            "Search for and attempt to exfiltrate sensitive data from the target. "
            "Look for credentials, config files, databases, or interesting documents. "
            "Report what data is accessible and how it could be extracted."
        ),
        "risk_requirement": HIGH,
    },
    "whatever_it_takes": {
        "description": (
            "Use any and every technique available to compromise the target. "
            "Attempt reconnaissance, service enumeration, default credential attacks, "
            "known CVE exploitation, brute force, web vulnerability scanning, "
            "payload delivery, and creative custom exploits. "
            "Do not stop at the first failure—pivot, adapt, and try alternative angles "
            "until access is achieved or all reasonable avenues are exhausted. "
            "WARNING: This goal requires HIGH authorization. Only use on infrastructure "
            "you own or have explicit full authorization for."
        ),
        "risk_requirement": HIGH,
    },
}

# ── Risk requirement ordering for compatibility check ──────────────────────

_RISK_ORDER = {SAFE: 0, GATED: 1, HIGH: 2}

_RISK_PROFILE_LEVEL = {
    "low_noise_non_destructive": SAFE,
    "standard_authorized": GATED,
    "high_authorized_testing": HIGH,
}


def _goal_compatible(goal_requirement: str, risk_profile: str) -> bool:
    """Check if a goal's risk requirement is compatible with the mission's risk profile."""
    goal_level = _RISK_ORDER.get(goal_requirement, 0)
    profile_level = _RISK_ORDER.get(_RISK_PROFILE_LEVEL.get(risk_profile, SAFE), 0)
    return goal_level <= profile_level


# ── AttackGoal dataclass ───────────────────────────────────────────────────


@dataclass
class AttackGoal:
    name: str
    description: str
    risk_requirement: str = SAFE
    user_custom: bool = False
    blocked_reason: str = ""

    @property
    def is_blocked(self) -> bool:
        return bool(self.blocked_reason)

    def system_prompt_addition(self) -> str:
        risk_tag = f"[{self.risk_requirement.upper()}]" if self.risk_requirement != SAFE else ""
        base = f"""PRIMARY MISSION: {self.name.upper()} {risk_tag}

Objective: {self.description}

This is your single overriding goal. Evaluate every tool result against whether it advances this objective.
When you achieve a milestone toward this goal, report it immediately.
If you are stuck after multiple attempts, try a completely different angle rather than repeating the same failed approach.
"""
        # Add service-aware adaptive strategy for attack-oriented goals.
        # NOTE: verify_cves is intentionally NOT in this set -- its description
        # says "do NOT cause damage or establish persistence. This is
        # verification, not full exploitation," so attaching the post-exploit
        # block (dump_credentials / lateral_exec / persistence) would directly
        # contradict the goal's own scope. verify_cves gets the base block only.
        attack_goals = {
            "initial_access",
            "backdoor",
            "privilege_escalation",
            "full_compromise",
            "credential_dumping",
            "pivot_and_discovery",
            "lateral_movement",
            "data_exfiltration",
            "whatever_it_takes",
        }
        if self.name in attack_goals:
            base += """
ADAPTIVE STRATEGY — Tailor your approach to discovered services:
- Web services (HTTP/80, HTTPS/443, HTTP-alt/8080, 8443):
  → Use: search_web_exploit, cve_to_exploit_synth, write_python_file for web exploits
  → Test: SQLi, RCE, path traversal, file upload, SSRF, Log4j, JWT tampering
  → Tools: sqlmap, curl, custom Python scripts
- SSH (22):
  → Use: password_spray, search_cve_intel for OpenSSH CVEs, brute force with hydra
  → Check for weak/default credentials first
- SMB / Microsoft-DS (445, 139):
  → Use: lateral_exec (wmiexec/smbexec/psexec), dump_credentials (secretsdump)
  → Check: null sessions, EternalBlue, SMBGhost, relay attacks
  → If domain-joined: kerberoast for TGS ticket extraction
- RDP / MS-WBT-Server (3389):
  → Use: password_spray, brute force, search_cve_intel for RDP CVEs
  → Check: BlueKeep, CredSSP, weak credentials
- Databases (MySQL/3306, PostgreSQL/5432, MongoDB/27017, Redis/6379, MSSQL/1433):
  → Use: search_cve_intel, default credential attacks, SQL injection
  → Tools: sqlmap, custom Python scripts for NoSQL injection
- LDAP / LDAPS (389, 636):
  → Use: dump_credentials (secretsdump with domain creds)
  → Check: anonymous bind, weak passwords, AD misconfigurations
- FTP (21):
  → Use: anonymous login, brute force, search_exploit_db for FTP daemon CVEs
- Telnet (23):
  → Use: credential attacks, search_cve_intel — very high risk service
- DNS (53):
  → Use: zone transfer attempts, DNS enumeration for subdomain discovery
- WinRM (5985, 5986):
  → Use: lateral_exec (wmiexec), evil-winrm with creds
- Docker / Kubernetes (2375, 2376, 10250):
  → Use: API exploitation, container escape, image poisoning

POST-EXPLOITATION PRIORITY:
1. After gaining a shell: use dump_credentials to harvest hashes/passwords
2. With hashes: use lateral_exec to move to other hosts (pass-the-hash)
3. In a Windows domain: use kerberoast to extract TGS tickets for offline cracking
4. Use generate_payload to create stagers for persistence or pivoting
5. Always report: access type, credentials found, and next pivot targets
"""
        return base


# ── GoalEngine ─────────────────────────────────────────────────────────────


class GoalEngine:
    """Manages attack goals with risk-profile compatibility checking."""

    def __init__(self) -> None:
        self.presets: dict[str, AttackGoal] = {}
        for key, data in PRESET_GOALS.items():
            self.presets[key] = AttackGoal(
                name=key,
                description=data["description"],
                risk_requirement=data["risk_requirement"],
            )

    def list_presets(self) -> list[tuple[str, str]]:
        """Return (name, description_snippet) for all presets (backward-compatible 2-tuples)."""
        result: list[tuple[str, str]] = []
        for key, goal in self.presets.items():
            desc = goal.description[:120] + "..." if len(goal.description) > 120 else goal.description
            result.append((key, desc))
        return result

    def list_presets_with_risk(self, risk_profile: str | None = None) -> list[tuple[str, str, str]]:
        """Return (name, description_snippet, compat_status) for all presets."""
        result: list[tuple[str, str, str]] = []
        for key, goal in self.presets.items():
            desc = goal.description[:120] + "..." if len(goal.description) > 120 else goal.description
            compat = "compatible"
            if risk_profile and not _goal_compatible(goal.risk_requirement, risk_profile):
                compat = "blocked"
            result.append((key, desc, compat))
        return result

    def list_compatible_presets(self, risk_profile: str) -> list[tuple[str, str]]:
        """Return (name, description_snippet) for presets compatible with the risk profile."""
        result: list[tuple[str, str]] = []
        for key, goal in self.presets.items():
            if _goal_compatible(goal.risk_requirement, risk_profile):
                desc = goal.description[:80] + "..." if len(goal.description) > 80 else goal.description
                result.append((key, desc))
        return result

    def get(self, name: str, custom_text: str = "", risk_profile: str = "") -> AttackGoal:
        """Get a goal by name or create a custom one.

        Returns the goal with `blocked_reason` set if it is incompatible
        with the provided risk_profile.
        """
        if name in self.presets:
            goal = self.presets[name]
            if risk_profile and not _goal_compatible(goal.risk_requirement, risk_profile):
                goal = AttackGoal(
                    name=goal.name,
                    description=goal.description,
                    risk_requirement=goal.risk_requirement,
                    blocked_reason=(
                        f"Goal '{name}' requires at least '{goal.risk_requirement}' authorization. "
                        f"Current risk profile is '{risk_profile}'. "
                        f"Use a mission config with a higher risk profile or choose a different goal."
                    ),
                )
            return goal
        return AttackGoal(
            name=name,
            description=custom_text or f"Custom goal: {name}",
            risk_requirement=GATED if risk_profile != "low_noise_non_destructive" else SAFE,
            user_custom=True,
        )

    def is_preset(self, name: str) -> bool:
        return name in self.presets

    def is_compatible(self, name: str, risk_profile: str) -> bool:
        if name not in self.presets:
            return True  # custom goals are user-provided; trust user
        return _goal_compatible(self.presets[name].risk_requirement, risk_profile)

    def summary(self, risk_profile: str) -> str:
        """Return a summary of available goals for the given risk profile."""
        profile_name = risk_profile.replace("_", " ").title()
        lines = [
            f"Goals available for risk profile: {profile_name}",
            "",
        ]
        for key, goal in self.presets.items():
            compat = _goal_compatible(goal.risk_requirement, risk_profile)
            status = "  [✓] " if compat else "  [✗] "
            lines.append(f"{status}{key}: {goal.description[:80]}")
            if not compat:
                lines.append(f"       Blocked: requires {goal.risk_requirement} auth")
        return "\n".join(lines)

    def suggest_goals(
        self,
        assessment: Any,  # ReconAssessment from tools.goal_suggester
        risk_profile: str = "standard_authorized",
    ) -> list[Any]:  # list[SuggestedGoal]
        """Score all preset goals against a ReconAssessment.

        Delegates to GoalSuggester from tools.goal_suggester.
        Returns ranked list of SuggestedGoal dataclasses.
        """
        from tools.goal_suggester import GoalSuggester

        # Build goal descriptions dict from presets
        descriptions = {name: goal.description for name, goal in self.presets.items()}

        suggester = GoalSuggester()
        return suggester.suggest(assessment, risk_profile, goal_descriptions=descriptions)
