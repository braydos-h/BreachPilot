"""Campaign state — AttackState, enums, task + retry engine."""

from __future__ import annotations

import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Iterator

from tools.logging_setup import get_logger
from tools.recon_pipeline import HostReconResult

logger = get_logger()

_AUTONOMOUS_PROGRESS: ContextVar[Callable[[dict[str, Any]], None] | None] = ContextVar(
    "autonomous_progress", default=None
)


@contextmanager
def observe_autonomous_progress(callback: Callable[[dict[str, Any]], None]) -> Iterator[None]:
    token = _AUTONOMOUS_PROGRESS.set(callback)
    try:
        yield
    finally:
        _AUTONOMOUS_PROGRESS.reset(token)


def _report_autonomous_progress(**payload: Any) -> None:
    cb = _AUTONOMOUS_PROGRESS.get()
    if cb is not None:
        try:
            cb(payload)
        except Exception:  # noqa: BLE001
            pass


class AggressionLevel(Enum):
    STEALTH = "stealth"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"
    MAXIMUM = "maximum"


class AttackPhase(Enum):
    RECONNAISSANCE = "recon"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploit"
    PRIVILEGE_ESCALATION = "privesc"
    LATERAL_MOVEMENT = "lateral"
    PERSISTENCE = "persistence"
    VALIDATION = "validation"
    REPORTING = "report"


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    BLOCKED = "blocked"
    CHAINED = "chained"


@dataclass
class AttackTask:
    task_id: str
    phase: AttackPhase
    module_name: str
    target: str
    parameters: dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    aggression: AggressionLevel = AggressionLevel.NORMAL
    priority: int = 50
    retry_count: int = 0
    max_retries: int = 3
    created_at: float = field(default_factory=time.monotonic)
    started_at: float | None = None
    completed_at: float | None = None
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    chain_parent: str | None = None
    chain_children: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    created_from: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "phase": self.phase.value,
            "module_name": self.module_name,
            "target": self.target,
            "parameters": self.parameters,
            "status": self.status.value,
            "aggression": self.aggression.value,
            "priority": self.priority,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result": self.result,
            "error": self.error,
            "evidence_refs": self.evidence_refs,
            "chain_parent": self.chain_parent,
            "chain_children": self.chain_children,
            "prerequisites": self.prerequisites,
            "created_from": self.created_from,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackTask":
        def _enum(enum_cls, value, default):
            try:
                return enum_cls(value)
            except (ValueError, KeyError, TypeError):
                return default

        return cls(
            task_id=str(data.get("task_id", "")),
            phase=_enum(AttackPhase, data.get("phase"), AttackPhase.RECONNAISSANCE),
            module_name=str(data.get("module_name", "")),
            target=str(data.get("target", "")),
            parameters=dict(data.get("parameters", {}) or {}),
            status=_enum(TaskStatus, data.get("status"), TaskStatus.PENDING),
            aggression=_enum(AggressionLevel, data.get("aggression"), AggressionLevel.NORMAL),
            priority=int(data.get("priority", 50) or 50),
            retry_count=int(data.get("retry_count", 0) or 0),
            max_retries=int(data.get("max_retries", 3) or 3),
            created_at=float(data.get("created_at", 0) or 0),
            started_at=float(data["started_at"]) if data.get("started_at") is not None else None,
            completed_at=float(data["completed_at"]) if data.get("completed_at") is not None else None,
            result=dict(data.get("result", {}) or {}),
            error=str(data.get("error", "") or ""),
            evidence_refs=list(data.get("evidence_refs", []) or []),
            chain_parent=data.get("chain_parent"),
            chain_children=list(data.get("chain_children", []) or []),
            prerequisites=list(data.get("prerequisites", []) or []),
            created_from=str(data.get("created_from", "") or ""),
        )


@dataclass
class AttackState:
    target: str
    current_phase: AttackPhase = AttackPhase.RECONNAISSANCE
    aggression: AggressionLevel = AggressionLevel.NORMAL
    privilege_level: str = "none"
    access_achieved: bool = False
    shell_type: str = ""
    successful_exploits: list[str] = field(default_factory=list)
    failed_attempts: dict[str, list[str]] = field(default_factory=dict)
    attack_paths: list[list[str]] = field(default_factory=list)
    credentials_found: list[dict[str, str]] = field(default_factory=list)
    loot: list[str] = field(default_factory=list)
    pivot_targets: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    recon_result: HostReconResult | None = None
    persistence_established: list[str] = field(default_factory=list)
    original_target: str = ""
    resolved_ip: str = ""
    discovered_subdomains: list[dict[str, str]] = field(default_factory=list)
    hard_target_rounds: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "current_phase": self.current_phase.value,
            "aggression": self.aggression.value,
            "privilege_level": self.privilege_level,
            "access_achieved": self.access_achieved,
            "shell_type": self.shell_type,
            "successful_exploits": self.successful_exploits,
            "failed_attempts": self.failed_attempts,
            "attack_paths": self.attack_paths,
            "credentials_found": self.credentials_found,
            "loot": self.loot,
            "pivot_targets": self.pivot_targets,
            "timeline": self.timeline,
            "recon_result": self.recon_result.to_dict() if self.recon_result else None,
            "persistence_established": self.persistence_established,
            "original_target": self.original_target,
            "resolved_ip": self.resolved_ip,
            "discovered_subdomains": list(self.discovered_subdomains),
            "hard_target_rounds": int(self.hard_target_rounds),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackState":
        def _enum(enum_cls, value, default):
            try:
                return enum_cls(value)
            except (ValueError, KeyError, TypeError):
                return default

        recon_data = data.get("recon_result")
        recon = HostReconResult.from_dict(recon_data) if isinstance(recon_data, dict) else None
        return cls(
            target=str(data.get("target", "")),
            current_phase=_enum(AttackPhase, data.get("current_phase"), AttackPhase.RECONNAISSANCE),
            aggression=_enum(AggressionLevel, data.get("aggression"), AggressionLevel.NORMAL),
            privilege_level=str(data.get("privilege_level", "none") or "none"),
            access_achieved=bool(data.get("access_achieved", False)),
            shell_type=str(data.get("shell_type", "") or ""),
            successful_exploits=list(data.get("successful_exploits", []) or []),
            failed_attempts=dict(data.get("failed_attempts", {}) or {}),
            attack_paths=[list(p) for p in (data.get("attack_paths", []) or []) if isinstance(p, list)],
            credentials_found=[dict(c) for c in (data.get("credentials_found", []) or []) if isinstance(c, dict)],
            loot=list(data.get("loot", []) or []),
            pivot_targets=list(data.get("pivot_targets", []) or []),
            timeline=list(data.get("timeline", []) or []),
            recon_result=recon,
            persistence_established=list(data.get("persistence_established", []) or []),
            original_target=str(data.get("original_target", "") or ""),
            resolved_ip=str(data.get("resolved_ip", "") or ""),
            discovered_subdomains=[
                dict(s) for s in (data.get("discovered_subdomains", []) or []) if isinstance(s, dict)
            ],
            hard_target_rounds=int(data.get("hard_target_rounds", 0) or 0),
        )

    def add_timeline_event(self, event_type: str, description: str, metadata: dict[str, Any] | None = None) -> None:
        self.timeline.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "description": description,
                "metadata": metadata or {},
            }
        )

    def record_failure(self, module_name: str, error: str) -> None:
        self.failed_attempts.setdefault(module_name, []).append(error)

    def record_success(self, module_name: str, result: dict[str, Any]) -> None:
        from tools.attack_ui import get_ui

        self.successful_exploits.append(module_name)
        if result.get("shell_type"):
            self.shell_type = result["shell_type"]
            self.access_achieved = True
            get_ui().compromise(
                action_num=len(self.successful_exploits),
                shell_type=result.get("shell_type", ""),
                privilege_level=result.get("privilege_level", ""),
            )
        if result.get("privilege_level"):
            self.privilege_level = result["privilege_level"]
        if result.get("credentials"):
            self.credentials_found.extend(result["credentials"])
            get_ui().cred_dump(action_num=len(self.successful_exploits))
        if result.get("loot"):
            self.loot.extend(result["loot"])
        if result.get("pivot_targets"):
            self.pivot_targets.extend(result["pivot_targets"])

    def escalate_aggression(self) -> None:
        from tools.attack_ui import get_ui

        levels = [AggressionLevel.STEALTH, AggressionLevel.NORMAL, AggressionLevel.AGGRESSIVE, AggressionLevel.MAXIMUM]
        idx = levels.index(self.aggression)
        if idx < len(levels) - 1:
            self.aggression = levels[idx + 1]
            logger.info(f"Aggression escalated to {self.aggression.value} for {self.target}")
            get_ui().warning(f"Aggression escalated to {self.aggression.value} — retrying failed modules")

    def should_continue(self) -> bool:
        if not self.access_achieved:
            return True
        if self.privilege_level not in ("system", "root", "admin"):
            return True
        if self.pivot_targets:
            return True
        return False


class RetryEngine:
    RETRY_STRATEGIES: dict[str, list[dict[str, Any]]] = {
        "SSHBruteForce": [
            {"timeout": 10, "threads": 4},
            {"timeout": 15, "threads": 8, "wordlist": "medium"},
            {"timeout": 20, "threads": 16, "wordlist": "large", "aggressive": True},
        ],
        "SMBRelay": [
            {"timeout": 30},
            {"timeout": 60, "null_session": True},
            {"timeout": 90, "relay": True, "signing_check": False},
        ],
        "WebShellUpload": [
            {"extensions": [".php", ".phtml", ".php5"]},
            {"extensions": [".jsp", ".jspx", ".war"], "bypass": "double_extension"},
            {"extensions": [".aspx", ".ashx", ".asmx"], "bypass": "null_byte", "encoding": "utf-16"},
        ],
        "SQLInjection": [
            {"technique": "union", "level": 1},
            {"technique": "error", "level": 2},
            {"technique": "time", "level": 3, "tamper": "space2comment"},
            {"technique": "stacked", "level": 5, "tamper": "charencode"},
        ],
        "default": [{"timeout": 30}, {"timeout": 60, "retries": 2}, {"timeout": 120, "retries": 3, "aggressive": True}],
    }

    @classmethod
    def get_retry_parameters(cls, module_name: str, attempt: int) -> dict[str, Any]:
        strategies = cls.RETRY_STRATEGIES.get(module_name, cls.RETRY_STRATEGIES["default"])
        if attempt < len(strategies):
            return strategies[attempt]
        params = dict(strategies[-1])
        params["aggressive"] = True
        params["timeout"] = params.get("timeout", 60) * 4
        return params

    @classmethod
    def should_retry(cls, module_name: str, error: str, attempt: int, max_attempts: int) -> bool:
        if attempt >= max_attempts:
            return False
        try:
            from tools.failure_taxonomy import classify_failure, is_permanent

            fc = classify_failure(error)
            if is_permanent(fc):
                return False
        except Exception:  # noqa: BLE001
            pass
        permanent_errors = [
            "out of scope",
            "permission denied",
            "not authorized",
            "blocked by scope",
            "target unreachable",
            "connection refused",
        ]
        error_lower = error.lower()
        if any(pe in error_lower for pe in permanent_errors):
            return False
        if "not found" in error_lower or "not installed" in error_lower:
            return False
        return True
