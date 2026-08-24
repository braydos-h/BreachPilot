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

from outcome_judge import (
    TERMINAL_HYPOTHESIS_STATUSES,
    HypothesisStatus,
    build_check_fingerprint,
    build_hypothesis_key,
)

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
        hypothesis_state: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Create a modified retry task based on failure analysis.

        If the error matches a known permanent failure pattern, returns None
        (no retry). Otherwise returns a modified copy of the failed task with
        an incremented attempt marker and lower priority.
        """
        state_status = str((hypothesis_state or {}).get("status", "open"))
        if state_status in {status.value for status in TERMINAL_HYPOTHESIS_STATUSES}:
            return None

        permanent_errors = [
            "out of scope",
            "permission denied",
            "not authorized",
            "blocked by scope",
            "target unreachable",
            "connection refused",
            "tool not found",
            "not installed",
        ]
        if any(pe in error.lower() for pe in permanent_errors):
            return None

        new_task = dict(failed_task)
        new_task["task_id"] = f"{failed_task.get('task_id', 'T-000')}-R{attempt}"
        new_task["status"] = "pending"
        new_task["priority"] = max(10, failed_task.get("priority", 50) - 5)
        allowed_tools = [str(tool) for tool in failed_task.get("allowed_tools", []) if str(tool).strip()]
        if len(allowed_tools) > 1:
            # Rotate to a genuinely different check rather than rewording the
            # same objective and calling it a retry.
            new_task["allowed_tools"] = allowed_tools[1:] + allowed_tools[:1]
            new_task["investigation_method"] = f"alternative-tool:{new_task['allowed_tools'][0]}"
        elif "timeout" in error.lower():
            old_args = failed_task.get("tool_args", {})
            new_args = dict(old_args) if isinstance(old_args, dict) else {}
            old_timeout = new_args.get("timeout_seconds", 30)
            try:
                new_args["timeout_seconds"] = min(max(int(old_timeout) * 2, 60), 600)
            except (TypeError, ValueError):
                new_args["timeout_seconds"] = 60
            new_task["tool_args"] = new_args
            new_task["investigation_method"] = "extended-timeout"
        else:
            return None

        if "timeout" in error.lower():
            new_task["objective"] = f"[RETRY {attempt}] {failed_task.get('objective', '')} (extended timeout)"
        elif "rate limit" in error.lower() or "429" in error:
            new_task["objective"] = f"[RETRY {attempt}] {failed_task.get('objective', '')} (rate limit backoff)"
            new_task["risk_level"] = "low"
        elif "connection" in error.lower():
            new_task["objective"] = f"[RETRY {attempt}] {failed_task.get('objective', '')} (connection retry)"
        else:
            new_task["objective"] = f"[RETRY {attempt}] {failed_task.get('objective', '')}"

        if build_check_fingerprint(new_task) == build_check_fingerprint(failed_task):
            return None
        return new_task

    # ── Main API ────────────────────────────────────────────────────────

    def plan(
        self,
        *,
        mission: dict[str, Any],
        target_summary: str = "",
        graph_summary: str = "",
        open_hypotheses: list[Any] | None = None,
        hypothesis_states: list[Any] | None = None,
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
        all_states = list(hypothesis_states or open_hypotheses or [])
        hypotheses = self.rank_unresolved_hypotheses(all_states)
        primary_target = _primary_mission_target(mission)

        # ── 1. Scope Confirmation tasks ──
        if not phase_filter or phase_filter == "scope_confirmation":
            if existing_task_count == 0:
                tasks.append(
                    self._create_task(
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
                    )
                )

        # ── 2. Asset Discovery tasks ──
        if not phase_filter or phase_filter == "asset_discovery":
            for asset in mission.get("allowed_assets", [])[:5]:
                if asset.strip():
                    tasks.append(
                        self._create_task(
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
                        )
                    )

        # ── 3. Service Identification tasks ──
        if not phase_filter or phase_filter == "service_identification":
            for asset in mission.get("allowed_assets", [])[:3]:
                tasks.append(
                    self._create_task(
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
                    )
                )

        # ── 4. Web/API Mapping tasks ──
        if not phase_filter or phase_filter == "web_api_mapping":
            for asset in mission.get("allowed_assets", [])[:3]:
                tasks.append(
                    self._create_task(
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
                    )
                )

        # ── 5. Investigate open hypotheses ──
        for i, hypothesis_state in enumerate(hypotheses[:3]):
            statement = str(hypothesis_state.get("statement", hypothesis_state.get("hypothesis", ""))).strip()
            if not statement:
                continue
            target = str(hypothesis_state.get("target", "")).strip() or primary_target
            candidate_checks = list(
                hypothesis_state.get("candidate_checks", [])
                or ["search_cve_intel", "search_exploit_db", "nmap_service_scan"]
            )
            prior_fingerprints = set(hypothesis_state.get("check_fingerprints", []))
            prior_fingerprints.update(
                item.get("fingerprint", "")
                for item in hypothesis_state.get("check_history", [])
                if isinstance(item, dict)
            )
            history = [item for item in hypothesis_state.get("check_history", []) if isinstance(item, dict)]
            template = history[-1] if history else {}
            success_criteria = list(
                template.get("success_criteria", []) or ["Hypothesis confirmed or refuted with evidence."]
            )
            stop_conditions = list(template.get("stop_conditions", []) or ["No actionable information after research."])
            task: dict[str, Any] | None = None
            for tool in candidate_checks:
                candidate = self._create_task(
                    phase=str(template.get("phase", "analysis")),
                    target=target,
                    asset_type="finding",
                    objective=f"Run an independent {tool} check for: {statement}",
                    hypothesis=statement,
                    allowed_tools=[str(tool)],
                    risk_level=str(template.get("risk_level", "low")),
                    priority=max(10, int(hypothesis_state.get("planning_score", 60)) - i),
                    success_criteria=success_criteria,
                    stop_conditions=stop_conditions,
                    planning_score=hypothesis_state.get("planning_score"),
                    expected_information_value=hypothesis_state.get("last_information_value"),
                )
                candidate["hypothesis_id"] = hypothesis_state.get("hypothesis_id", "")
                candidate["hypothesis_confidence"] = hypothesis_state.get("confidence", 0.5)
                candidate["hypothesis_attempt_count"] = hypothesis_state.get("attempt_count", 0)
                candidate["expected_information_value"] = hypothesis_state.get("expected_information_value", 0.5)
                candidate["estimated_cost"] = hypothesis_state.get(
                    "estimated_cost", template.get("estimated_cost", 0.1)
                )
                candidate["investigation_method"] = f"independent:{tool}"
                if build_check_fingerprint(candidate) not in prior_fingerprints:
                    task = candidate
                    break
            if task is not None:
                tasks.append(task)

        # ── Filter and cap ──
        states_by_key = {
            build_hypothesis_key(
                str(state.get("statement", state.get("hypothesis", ""))),
                str(state.get("target", "")),
            ): state
            for state in (_state_dict(item) for item in all_states)
            if state.get("statement", state.get("hypothesis", ""))
        }
        seen_checks: set[tuple[str, str]] = set()
        filtered: list[dict[str, Any]] = []
        for task in tasks:
            if not task.get("objective") or not task.get("hypothesis"):
                continue
            key = build_hypothesis_key(
                str(task.get("hypothesis", "")),
                str(task.get("target", "")),
            )
            fingerprint = build_check_fingerprint(task)
            state = states_by_key.get(key, {})
            status = str(state.get("status", "open"))
            prior_fingerprints = set(state.get("check_fingerprints", []))
            prior_fingerprints.update(
                item.get("fingerprint", "") for item in state.get("check_history", []) if isinstance(item, dict)
            )
            identity = (key, fingerprint)
            if status in {terminal.value for terminal in TERMINAL_HYPOTHESIS_STATUSES}:
                continue
            if fingerprint in prior_fingerprints or identity in seen_checks:
                continue
            seen_checks.add(identity)
            filtered.append(task)
        return filtered[:max_tasks]

    @staticmethod
    def rank_unresolved_hypotheses(hypotheses: list[Any]) -> list[dict[str, Any]]:
        """Rank unresolved hypotheses by uncertainty, value, attempts, risk, and cost."""
        ranked: list[dict[str, Any]] = []
        risk_penalty = {"low": 0.0, "medium": 10.0, "high": 25.0}
        for item in hypotheses:
            state = _state_dict(item)
            try:
                status = HypothesisStatus(str(state.get("status", "open")))
            except ValueError:
                status = HypothesisStatus.OPEN
            if status in TERMINAL_HYPOTHESIS_STATUSES:
                continue
            confidence = _unit_float(state.get("confidence", 0.5), 0.5)
            uncertainty = 1.0 - abs(confidence - 0.5) * 2.0
            information_value = _unit_float(
                state.get(
                    "expected_information_value",
                    max(0.5, state.get("last_information_value", 0.0)),
                ),
                0.5,
            )
            attempts = max(0, int(state.get("attempt_count", 0) or 0))
            cost = _unit_float(state.get("estimated_cost", 0.1), 0.1)
            risk = str(state.get("risk_level", "low")).lower()
            score = (
                45.0
                + 20.0 * uncertainty
                + 20.0 * information_value
                + 10.0 * confidence
                - 8.0 * attempts
                - risk_penalty.get(risk, 15.0)
                - 10.0 * cost
            )
            state["planning_score"] = max(0, min(int(round(score)), 100))
            state["expected_information_value"] = information_value
            ranked.append(state)
        return sorted(
            ranked,
            key=lambda state: (
                int(state.get("planning_score", 0)),
                -int(state.get("attempt_count", 0) or 0),
                str(state.get("updated_at", "")),
            ),
            reverse=True,
        )

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
        planning_score: int | None = None,
        expected_information_value: float | None = None,
    ) -> dict[str, Any]:
        task = {
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
        if planning_score is not None:
            task["confidence"] = round(max(0.0, min(float(planning_score) / 100.0, 1.0)), 3)
        if expected_information_value is not None:
            task["expected_information_value"] = expected_information_value
        return task


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


def _state_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        data = to_dict()
        return dict(data) if isinstance(data, dict) else {}
    if isinstance(value, str):
        return {
            "statement": value,
            "hypothesis": value,
            "status": HypothesisStatus.OPEN.value,
            "confidence": 0.5,
        }
    return {}


def _unit_float(value: Any, default: float) -> float:
    try:
        return max(0.0, min(float(value), 1.0))
    except (TypeError, ValueError):
        return default
