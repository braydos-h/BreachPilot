"""Service registry — wraps all backend modules for the TUI.

Provides:
- Lazy initialization of all service objects (shared DB connection)
- Aggregate queries for dashboard stats
- Empty-state handling
- Mission loading/switching
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from db import DatabaseManager
from mission import MissionController, Mission
from scope_gate import ScopeGate, ScopeCheckResult
from task_queue import TaskQueue
from memory import MemoryManager
from evidence import EvidenceStore
from finding_verifier import FindingVerifier
from report_generator import ReportGenerator
from target_graph import TargetGraph


@dataclass
class DashboardStats:
    mission_active: bool = False
    mission_name: str = ""
    mission_risk: str = ""
    mission_status: str = ""
    tasks_pending: int = 0
    tasks_running: int = 0
    tasks_blocked: int = 0
    tasks_completed: int = 0
    tasks_failed: int = 0
    findings_candidates: int = 0
    findings_needs_validation: int = 0
    findings_validated: int = 0
    findings_report_ready: int = 0
    evidence_count: int = 0
    scope_allows: int = 0
    scope_denies: int = 0
    swarm_active: bool = False
    swarm_agent_count: int = 0
    swarm_running_count: int = 0
    swarm_blocked_count: int = 0
    swarm_access_achieved: bool = False
    swarm_last_reflection: str = ""
    swarm_error: str = ""
    next_task: dict[str, Any] | None = None
    last_action: str = ""
    error: str = ""


@dataclass
class SwarmStateSnapshot:
    active: bool = False
    agent_rows: list[dict[str, Any]] = field(default_factory=list)
    blackboard: dict[str, Any] = field(default_factory=dict)
    battle_log_tail: list[dict[str, Any]] = field(default_factory=list)
    last_reflection: dict[str, Any] = field(default_factory=dict)
    strategy_shift: str = ""
    updated_at: float = 0.0
    error: str = ""


class ServiceRegistry:
    """Wraps all backend services in one lazy-loaded, cached object.

    Usage::

        svc = ServiceRegistry(Path("research_workspace"))
        if svc.has_active_mission:
            stats = svc.get_dashboard_stats()
            task = svc.tasks.get_next_task()
    """

    def __init__(self, workspace_root: Path | None = None) -> None:
        if workspace_root is None:
            ws_env = os.environ.get("RESEARCH_WORKSPACE", "")
            if ws_env:
                workspace_root = Path(ws_env)
            else:
                workspace_root = Path.cwd() / "research_workspace"

        self._workspace = workspace_root.resolve()
        self._workspace.mkdir(parents=True, exist_ok=True)

        self._db = DatabaseManager(self._workspace / "research.db")
        self._mission_id: str | None = None
        self._mission_data: dict[str, Any] | None = None

        # Lazy caches
        self._scope: ScopeGate | None = None
        self._tasks: TaskQueue | None = None
        self._memory: MemoryManager | None = None
        self._evidence: EvidenceStore | None = None
        self._verifier: FindingVerifier | None = None
        self._reporter: ReportGenerator | None = None
        self._graph: TargetGraph | None = None
        self._skills: SkillsService | None = None

        self._load_active_mission()

    # ── Private helpers ────────────────────────────────────────────────

    def _load_active_mission(self) -> None:
        with self._db.connection() as conn:
            self._db.ensure_schema(conn)
            cur = conn.execute(
                "SELECT * FROM missions WHERE status='active' ORDER BY created_at DESC LIMIT 1"
            )
            row = cur.fetchone()
            if row:
                data = dict(row)
                self._mission_id = data["id"]
                self._mission_data = data
                self._invalidate_caches()
            else:
                self._mission_id = None
                self._mission_data = None

    def _invalidate_caches(self) -> None:
        self._scope = None
        self._tasks = None
        self._memory = None
        self._evidence = None
        self._verifier = None
        self._reporter = None
        self._graph = None
        self._skills = None

    # ── Properties ─────────────────────────────────────────────────────

    @property
    def has_active_mission(self) -> bool:
        return self._mission_id is not None

    @property
    def mission_name(self) -> str:
        if self._mission_data:
            return self._mission_data.get("program_name", "")
        return ""

    @property
    def mission_risk_profile(self) -> str:
        if self._mission_data:
            return self._mission_data.get("risk_profile", "")
        return ""

    @property
    def mission_id(self) -> str | None:
        return self._mission_id

    @property
    def workspace_root(self) -> Path:
        return self._workspace

    @property
    def db(self) -> DatabaseManager:
        return self._db

    @property
    def scope(self) -> ScopeGate:
        if self._scope is None and self.has_active_mission:
            from mission import Mission
            m = Mission.from_dict(self._mission_data or {})
            self._scope = ScopeGate(
                self._db,
                self._mission_id or "",
                allowed_assets=m.allowed_assets,
                disallowed_assets=m.disallowed_assets,
                forbidden_actions=m.forbidden_actions,
                rate_limits=m.rate_limits,
                risk_profile=m.risk_profile,
            )
        return self._scope  # type: ignore

    @property
    def tasks(self) -> TaskQueue:
        if self._tasks is None and self.has_active_mission:
            self._tasks = TaskQueue(self._db, self._mission_id or "")
        return self._tasks  # type: ignore

    @property
    def memory(self) -> MemoryManager:
        if self._memory is None and self.has_active_mission:
            self._memory = MemoryManager(self._db, self._mission_id or "")
        return self._memory  # type: ignore

    @property
    def evidence(self) -> EvidenceStore:
        if self._evidence is None and self.has_active_mission:
            self._evidence = EvidenceStore(self._db, self._mission_id or "", self._workspace)
        return self._evidence  # type: ignore

    @property
    def verifier(self) -> FindingVerifier:
        if self._verifier is None and self.has_active_mission:
            self._verifier = FindingVerifier(self._db, self._mission_id or "")
        return self._verifier  # type: ignore

    @property
    def reporter(self) -> ReportGenerator:
        if self._reporter is None and self.has_active_mission:
            self._reporter = ReportGenerator(self._db, self._mission_id or "", self._workspace)
        return self._reporter  # type: ignore

    @property
    def swarm(self) -> SwarmStateSnapshot:
        return self.get_swarm_state()

    @property
    def graph(self) -> TargetGraph:
        if self._graph is None and self.has_active_mission:
            self._graph = TargetGraph(self._db, self._mission_id or "")
        return self._graph  # type: ignore

    @property
    def skills(self) -> "SkillsService":
        if self._skills is None:
            self._skills = SkillsService()
        return self._skills

    # ── Public API ─────────────────────────────────────────────────────

    def reload(self) -> None:
        """Re-query DB for active mission, invalidate caches."""
        self._load_active_mission()

    def load_mission(self, mission_id: str) -> bool:
        """Switch active mission. Returns True if loaded."""
        with self._db.connection() as conn:
            cur = conn.execute("SELECT * FROM missions WHERE id=?", (mission_id,))
            row = cur.fetchone()
            if not row:
                return False
            self._mission_data = dict(row)
            self._mission_id = mission_id
            self._invalidate_caches()
            return True

    def list_missions(self) -> list[dict[str, Any]]:
        """Return all missions for the mission switcher."""
        with self._db.connection() as conn:
            cur = conn.execute("SELECT id, program_name, risk_profile, status, created_at FROM missions ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]

    def create_mission(self, config: dict[str, Any]) -> Mission:
        """Create a new mission and set it as active. Returns the Mission object."""
        ctrl = MissionController(self._db, self._workspace)
        mission = ctrl.create_from_config(config)
        self._load_active_mission()
        return mission

    def check_scope(
        self, asset: str, action_type: str, tool_name: str = "", risk_level: str = "low"
    ) -> ScopeCheckResult | None:
        if not self.has_active_mission:
            return ScopeCheckResult(
                allowed=False,
                reason="No active mission. Create one first.",
            )
        return self.scope.check_scope(asset, action_type, tool_name, risk_level)

    def _find_swarm_state_file(self) -> Path | None:
        """Discover the most recent swarm_state.json next to the workspace."""
        candidates: list[Path] = [
            self._workspace.parent / "swarm_workspace" / "swarm_state.json",
            self._workspace / "swarm_state.json",
            self._workspace / ".." / "swarm_workspace" / "swarm_state.json",
        ]
        # Also look for any swarm_workspace sibling directory
        if self._workspace.parent.is_dir():
            for subdir in self._workspace.parent.iterdir():
                if subdir.is_dir() and "swarm" in subdir.name.lower():
                    candidates.append(subdir / "swarm_state.json")
                    candidates.append(subdir / "state" / "swarm_state.json")
        existing = [p.resolve() for p in candidates if p.exists()]
        if not existing:
            return None
        def _mtime(p: Path) -> float:
            try:
                return p.stat().st_mtime
            except OSError:
                return -1.0
        existing = [p for p in existing if _mtime(p) >= 0]
        return max(existing, key=_mtime) if existing else None

    def get_swarm_state(self) -> SwarmStateSnapshot:
        """Load the latest swarm state snapshot from disk."""
        snapshot = SwarmStateSnapshot()
        state_path = self._find_swarm_state_file()
        if state_path is None:
            snapshot.error = "No swarm state file found."
            return snapshot
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
            snapshot.active = True
            snapshot.agent_rows = list(data.get("agents", []))
            snapshot.blackboard = dict(data.get("blackboard", {}))
            snapshot.battle_log_tail = list(data.get("battle_log_tail", []))
            snapshot.last_reflection = dict(data.get("last_reflection", {}))
            snapshot.strategy_shift = str(data.get("strategy_shift", ""))
            snapshot.updated_at = float(data.get("updated_at", 0))
        except Exception as exc:
            snapshot.error = f"Failed to read swarm state: {exc}"
        return snapshot

    def get_dashboard_stats(self) -> DashboardStats:
        """Gather all dashboard card data in one aggregate query."""
        stats = DashboardStats()

        if not self.has_active_mission:
            stats.error = "No active mission."
            return stats

        try:
            md = self._mission_data or {}
            stats.mission_active = True
            stats.mission_name = md.get("program_name", "")
            stats.mission_risk = md.get("risk_profile", "")
            stats.mission_status = md.get("status", "")

            # Task counts
            task_counts = self.tasks.count_by_status()
            stats.tasks_pending = task_counts.get("pending", 0) + task_counts.get("needs_approval", 0)
            stats.tasks_running = task_counts.get("running", 0)
            stats.tasks_blocked = task_counts.get("blocked", 0)
            stats.tasks_completed = task_counts.get("complete", 0)
            stats.tasks_failed = task_counts.get("failed", 0)

            # Finding counts
            all_findings = self.verifier.list_all()
            for f in all_findings:
                s = f.get("status", "")
                if s == "candidate":
                    stats.findings_candidates += 1
                elif s == "needs_validation":
                    stats.findings_needs_validation += 1
                elif s == "validated":
                    stats.findings_validated += 1
                elif s == "report_ready":
                    stats.findings_report_ready += 1

            # Evidence count
            ev_list = self.evidence.list_for_mission(limit=1000)
            stats.evidence_count = len(ev_list)

            # Scope counts
            scope_data = self.scope.list_scope()
            stats.scope_allows = len(scope_data.get("allow", []))
            stats.scope_denies = len(scope_data.get("deny", []))

            # Swarm state
            try:
                swarm = self.swarm
                stats.swarm_active = swarm.active
                stats.swarm_agent_count = len(swarm.agent_rows)
                stats.swarm_running_count = sum(
                    1 for a in swarm.agent_rows if a.get("status") == "running"
                )
                stats.swarm_blocked_count = sum(
                    1 for a in swarm.agent_rows if a.get("status") == "blocked"
                )
                stats.swarm_access_achieved = bool(swarm.blackboard.get("access_achieved", False))
                stats.swarm_last_reflection = swarm.strategy_shift or (
                    swarm.last_reflection.get("recommended_strategy_shift", "")
                )
                stats.swarm_error = swarm.error
            except Exception as exc:
                stats.swarm_error = str(exc)

            # Next task
            stats.next_task = self.tasks.get_next_task()

            # Last action
            with self._db.connection() as conn:
                cur = conn.execute(
                    "SELECT message FROM audit_logs WHERE mission_id=? ORDER BY created_at DESC LIMIT 1",
                    (self._mission_id,),
                )
                row = cur.fetchone()
                stats.last_action = row["message"] if row else ""

        except Exception as exc:
            stats.error = str(exc)

        return stats


class SkillsService:
    """Read-only runtime-skills view for the TUI (Tier 3.2).

    Wraps the cached skill registry and the deterministic selector so the
    Skills screen can render the catalog and the current-run active
    selection. **Read-only by design**: no enable/disable toggle -- selection
    stays deterministic so a user cannot be coerced into pulling attack-only
    skills in recon mode. Advisory only; never changes permission/scope/audit.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}

    def _registry(self):
        from tools.skill_registry_cache import get_registry

        return get_registry(self._config or {"skills": {}}, base_dir=Path.cwd())

    def list_catalog(self, *, include_maybe: bool = False) -> list[dict[str, Any]]:
        """Return one dict per loaded skill: name, tags, description, maybe flag."""
        registry = self._registry()
        out: list[dict[str, Any]] = []
        for skill in registry.list_skills():
            if skill.metadata.maybe and not include_maybe:
                continue
            out.append({
                "name": skill.name,
                "tags": list(skill.metadata.tags),
                "description": skill.metadata.description,
                "maybe": bool(skill.metadata.maybe),
                "domain": skill.metadata.domain,
            })
        return out

    def active_selection(
        self,
        *,
        goal_name: str = "",
        goal_description: str = "",
        mode: str = "recon",
        services: list[str] | None = None,
        known_cves: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return the current-run active skill selection as payload dicts."""
        from tools.skill_pipeline import build_skill_selection_for_context, active_skill_payloads

        selection = build_skill_selection_for_context(
            self._config,
            goal_name=goal_name,
            goal_description=goal_description,
            mode=mode,
            services=services or [],
            known_cves=known_cves or [],
        )
        return active_skill_payloads(selection)

    @property
    def errors(self) -> list[str]:
        return list(self._registry().errors)
