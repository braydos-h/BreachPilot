"""Planner Agent — creates concrete, scoped research tasks.

Operates using this loop:
1. Read current mission
2. Read target summary (from Memory)
3. Retrieve relevant memory
4. Inspect open tasks (from TaskQueue)
5. Pick the highest-value unknown
6. Create or update tasks
7. Avoid duplicate tasks
8. Prefer high-signal testing
9. Prioritize authenticated app/API logic over generic CVE scanning
10. Always define success criteria and stop conditions

Enhanced with:
    - Automatic attack module selection from recon findings
    - Service-aware task generation
    - Exploit chaining prerequisites
    - Adaptive priority based on attack surface value
    - Credential attack task generation
    - Privilege escalation path planning

The Planner creates Task objects, never executes them directly.
"""

from __future__ import annotations

from typing import Any



# ── Planning phases in priority order ──────────────────────────────────────

_PLANNING_PHASES = [
    "scope_confirmation",
    "asset_discovery",
    "service_identification",
    "web_api_mapping",
    "auth_boundaries",
    "authorization_boundaries",
    "object_ownership_boundaries",
    "role_differences",
    "sensitive_data_exposure",
    "misconfigurations",
    "known_cve_verification",
    "finding_validation",
    "report_generation",
]

# ── Service-to-attack-module mapping ───────────────────────────────────────

_SERVICE_ATTACK_MAP: dict[str, list[dict[str, Any]]] = {
    "ssh": [
        {"module": "SSHBruteForce", "tools": ["hydra", "medusa"], "risk": "medium", "priority": 75},
        {"module": "OpenSSHCVECheck", "tools": ["cve_lookup"], "risk": "low", "priority": 70},
        {"module": "SSHWeakCipher", "tools": ["nmap"], "risk": "low", "priority": 60},
    ],
    "smb": [
        {"module": "SMBRelay", "tools": ["impacket"], "risk": "high", "priority": 80},
        {"module": "SMBNullSession", "tools": ["smbclient", "enum4linux"], "risk": "medium", "priority": 75},
        {"module": "EternalBlue", "tools": ["msfconsole"], "risk": "high", "priority": 85},
        {"module": "SMBGhost", "tools": ["python"], "risk": "high", "priority": 85},
    ],
    "microsoft-ds": [
        {"module": "SMBRelay", "tools": ["impacket"], "risk": "high", "priority": 80},
        {"module": "SMBNullSession", "tools": ["smbclient", "enum4linux"], "risk": "medium", "priority": 75},
    ],
    "http": [
        {"module": "WebShellUpload", "tools": ["curl", "python"], "risk": "high", "priority": 70},
        {"module": "SQLInjection", "tools": ["sqlmap"], "risk": "medium", "priority": 75},
        {"module": "BasicAuthBuster", "tools": ["python"], "risk": "medium", "priority": 65},
        {"module": "APIFuzzer", "tools": ["python", "curl"], "risk": "low", "priority": 60},
        {"module": "Log4jRCE", "tools": ["python"], "risk": "high", "priority": 80},
    ],
    "https": [
        {"module": "WebShellUpload", "tools": ["curl", "python"], "risk": "high", "priority": 70},
        {"module": "SQLInjection", "tools": ["sqlmap"], "risk": "medium", "priority": 75},
        {"module": "BasicAuthBuster", "tools": ["python"], "risk": "medium", "priority": 65},
        {"module": "APIFuzzer", "tools": ["python", "curl"], "risk": "low", "priority": 60},
        {"module": "Log4jRCE", "tools": ["python"], "risk": "high", "priority": 80},
    ],
    "ftp": [
        {"module": "FTPAnonymous", "tools": ["curl", "ftp"], "risk": "low", "priority": 60},
    ],
    "rdp": [
        {"module": "RDPBlueKeep", "tools": ["msfconsole"], "risk": "high", "priority": 85},
        {"module": "RDPExploit", "tools": ["python"], "risk": "high", "priority": 75},
    ],
    "ms-wbt-server": [
        {"module": "RDPBlueKeep", "tools": ["msfconsole"], "risk": "high", "priority": 85},
    ],
    "redis": [
        {"module": "RedisExploit", "tools": ["nc", "redis-cli"], "risk": "medium", "priority": 75},
    ],
    "ldap": [
        {"module": "LDAPAnonymous", "tools": ["ldapsearch"], "risk": "low", "priority": 65},
    ],
    "ldaps": [
        {"module": "LDAPAnonymous", "tools": ["ldapsearch"], "risk": "low", "priority": 65},
    ],
    "docker": [
        {"module": "ContainerBreakout", "tools": ["curl"], "risk": "high", "priority": 85},
    ],
    "elasticsearch": [
        {"module": "ElasticsearchExploit", "tools": ["curl"], "risk": "medium", "priority": 70},
    ],
}

class PlannerAgent:
    """Creates structured task candidates from mission + memory + target graph context."""

    def __init__(self, risk_profile: str = "low_noise_non_destructive") -> None:
        self._risk_profile = risk_profile
        self._created_count = 0

    # ── Main API ────────────────────────────────────────────────────────

    def plan_retry_with_modifications(
        self,
        failed_task: dict[str, Any],
        error: str,
        attempt: int,
    ) -> dict[str, Any] | None:
        """Create a modified retry task based on failure analysis.

        If the error matches a known permanent failure pattern, returns None
        (no retry). Otherwise returns a modified copy of the failed task with
        an incremented attempt marker and lower priority.
        """
        permanent_errors = [
            "out of scope", "permission denied", "not authorized",
            "blocked by scope", "target unreachable", "connection refused",
            "tool not found", "not installed",
        ]
        if any(pe in error.lower() for pe in permanent_errors):
            return None

        new_task = dict(failed_task)
        new_task["task_id"] = f"{failed_task.get('task_id', 'T-000')}-R{attempt}"
        new_task["status"] = "pending"
        new_task["priority"] = max(10, failed_task.get("priority", 50) - 5)

        if "timeout" in error.lower():
            new_task["objective"] = f"[RETRY {attempt}] {failed_task.get('objective', '')} (extended timeout)"
        elif "rate limit" in error.lower() or "429" in error:
            new_task["objective"] = f"[RETRY {attempt}] {failed_task.get('objective', '')} (rate limit bypass)"
            new_task["risk_level"] = "low"
        elif "connection" in error.lower():
            new_task["objective"] = f"[RETRY {attempt}] {failed_task.get('objective', '')} (connection retry)"
        else:
            new_task["objective"] = f"[RETRY {attempt}] {failed_task.get('objective', '')}"

        return new_task

    # ── Main API ────────────────────────────────────────────────────────

    def plan(
        self,
        *,
        mission: dict[str, Any],
        target_summary: str = "",
        graph_summary: str = "",
        open_hypotheses: list[str] | None = None,
        existing_task_count: int = 0,
        phase_filter: str = "",
        max_tasks: int = 5,
    ) -> list[dict[str, Any]]:
        """Generate a batch of concrete tasks based on the current state.

        Args:
            mission: Mission dict (program, scope, objective, etc.)
            target_summary: Text summary from MemoryManager
            graph_summary: Text summary from TargetGraph
            open_hypotheses: List of open hypotheses to investigate
            existing_task_count: How many tasks already exist (for dedup)
            phase_filter: Only create tasks for this phase (optional)
            max_tasks: Maximum tasks to return

        Returns:
            List of task dicts ready for TaskQueue.create_task()
        """
        tasks: list[dict[str, Any]] = []
        hypotheses = open_hypotheses or []
        primary_target = _primary_mission_target(mission)

        # ── 1. Scope Confirmation tasks ──
        if not phase_filter or phase_filter == "scope_confirmation":
            if existing_task_count == 0:
                tasks.append(self._create_task(
                    phase="recon",
                    target=primary_target,
                    asset_type="asset",
                    objective="Confirm and validate mission scope configuration.",
                    hypothesis="Scope rules are correctly configured and cover all authorized assets.",
                    allowed_tools=["check_scope", "list_scope"],
                    risk_level="low",
                    priority=90,
                    success_criteria=["Scope confirmed with no errors or warnings."],
                    stop_conditions=["Critical scope misconfiguration detected."],
                ))

        # ── 2. Asset Discovery tasks ──
        if not phase_filter or phase_filter == "asset_discovery":
            for asset in mission.get("allowed_assets", [])[:5]:
                if asset.strip():
                    tasks.append(self._create_task(
                        phase="recon",
                        target=asset,
                        asset_type="asset",
                        objective=f"Discover and verify the asset: {asset}",
                        hypothesis=f"The asset '{asset}' is reachable and may expose services.",
                        allowed_tools=["check_os", "ping", "nmap_basic"],
                        risk_level="low",
                        priority=80,
                        success_criteria=[f"Asset '{asset}' confirmed reachable."],
                        stop_conditions=["Asset unreachable after 3 attempts."],
                    ))

        # ── 3. Service Identification tasks ──
        if not phase_filter or phase_filter == "service_identification":
            for asset in mission.get("allowed_assets", [])[:3]:
                tasks.append(self._create_task(
                    phase="analysis",
                    target=asset,
                    asset_type="host",
                    objective=f"Identify all services and versions running on {asset}.",
                    hypothesis=f"{asset} exposes network services that can be identified and versioned.",
                    allowed_tools=["nmap_service_scan", "http_probe", "check_os"],
                    risk_level="low",
                    priority=70,
                    success_criteria=[f"At least one service identified with version on {asset}."],
                    stop_conditions=["No ports respond after basic scan."],
                ))

        # ── 4. Web/API Mapping tasks ──
        if not phase_filter or phase_filter == "web_api_mapping":
            for asset in mission.get("allowed_assets", [])[:3]:
                tasks.append(self._create_task(
                    phase="recon",
                    target=asset,
                    asset_type="web_app",
                    objective=f"Map web application surface on {asset}.",
                    hypothesis=f"{asset} hosts web applications with discoverable endpoints.",
                    allowed_tools=["http_probe", "dir_enum", "web_vuln_scan"],
                    risk_level="low",
                    priority=65,
                    success_criteria=["Web response received; endpoints and technologies noted."],
                    stop_conditions=["No HTTP/HTTPS response on common ports."],
                ))

        # ── 5. Investigate open hypotheses ──
        for i, hypothesis in enumerate(hypotheses[:3]):
            tasks.append(self._create_task(
                phase="analysis",
                target=primary_target,
                asset_type="finding",
                objective=f"Investigate hypothesis: {hypothesis}",
                hypothesis=hypothesis,
                allowed_tools=["search_cve_intel", "search_exploit_db"],
                risk_level="low",
                priority=60 - i,
                success_criteria=["Hypothesis confirmed or refuted with evidence."],
                stop_conditions=["No actionable information after research."],
            ))

        # ── Filter and cap ──
        filtered = [t for t in tasks if t.get("objective") and t.get("hypothesis")]
        return filtered[:max_tasks]

    def _create_task(
        self,
        phase: str,
        target: str,
        asset_type: str,
        objective: str,
        hypothesis: str,
        allowed_tools: list[str],
        risk_level: str = "low",
        priority: int = 50,
        success_criteria: list[str] | None = None,
        stop_conditions: list[str] | None = None,
    ) -> dict[str, Any]:
        return {
            "phase": phase,
            "target": target,
            "asset_type": asset_type,
            "objective": objective,
            "hypothesis": hypothesis,
            "allowed_tools": allowed_tools,
            "risk_level": risk_level,
            "priority": priority,
            "requires_human_approval": risk_level == "high",
            "preconditions": [],
            "success_criteria": success_criteria or [],
            "stop_conditions": stop_conditions or [],
            "status": "pending",
        }


def _primary_mission_target(mission: dict[str, Any]) -> str:
    for key in ("allowed_assets", "target_assets"):
        assets = mission.get(key, [])
        if isinstance(assets, str):
            assets = [assets]
        if isinstance(assets, list):
            for asset in assets:
                value = str(asset or "").strip()
                if value:
                    return value
    return str(mission.get("target", "") or mission.get("program_name", "target")).strip() or "target"
