"""Campaign state — enums, task/state dataclasses, retry engine.

Canonical source for AttackTask / AttackState / AggressionLevel / AttackPhase /
TaskStatus / RetryEngine and the autonomous progress ContextVar helpers.
Moved from tools.autonomous_orchestrator (2743 LOC) to break the god file.
See tools/campaign/__init__.py and tools/autonomous_orchestrator.py shim.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Iterator

from tools.attack_ui import get_ui
from tools.kernel.orchestration import MAX_MODULE_FAILURES, safe_emit
from tools.logging_setup import get_logger
from tools.recon_pipeline import HostReconResult

logger = get_logger()
ui = get_ui()

_AUTONOMOUS_PROGRESS: ContextVar[Callable[[dict[str, Any]], None] | None] = ContextVar(
    "autonomous_progress",
    default=None,
)


@contextmanager
def observe_autonomous_progress(
    callback: Callable[[dict[str, Any]], None],
) -> Iterator[None]:
    """Route this task's autonomous phase/action updates to ``callback``."""
    token = _AUTONOMOUS_PROGRESS.set(callback)
    try:
        yield
    finally:
        _AUTONOMOUS_PROGRESS.reset(token)


def _report_autonomous_progress(**payload: Any) -> None:
    safe_emit(_AUTONOMOUS_PROGRESS.get(), payload)


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
    CHAINED = "chained"  # Waiting for prerequisite


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
    max_retries: int = MAX_MODULE_FAILURES
    created_at: float = field(default_factory=time.monotonic)
    started_at: float | None = None
    completed_at: float | None = None
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    chain_parent: str | None = None  # Task ID that must complete first
    chain_children: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    # Capability-upgrade: provenance tag. The dynamic-composition path sets
    # this to "recovery:prerequisite" when it schedules a producer module to
    # satisfy a missing artifact for a failed sibling. Empty for normal
    # planner-created tasks. Additive; serialized for resume/debugging only.
    created_from: str = ""
    # FSM/planner-executor split: classified failure of the last attempt
    # (tools/failure_taxonomy.FailureClass value, "" = unclassified/success).
    # Additive with default; old state dicts load unchanged.
    failure_class: str = ""
    # p2-09: last error text of the most recent attempt. Kept in sync with
    # ``error`` by the executor/batch retry path so resume and the timeline
    # can report what the latest failure was without re-reading the result.
    last_error: str = ""

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
            "failure_class": self.failure_class,
            "last_error": self.last_error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackTask":
        """Reconstruct an AttackTask from its serialized form (Tier 1.3 resume).

        Tolerant of unknown enum strings: an unrecognized phase/aggression/
        status falls back to the defaults rather than raising, so a state file
        written by a newer/older version never breaks resume. ``created_at``
        and the started/completed timestamps are preserved verbatim so retry
        accounting and timeline ordering survive the round-trip.
        """

        def _enum(enum_cls, value, default):
            try:
                return enum_cls(value)
            except (ValueError, KeyError, TypeError):
                return default

        # ponytail: resume demotion — a persisted RUNNING/RETRYING task was
        # mid-flight at crash; re-queue as PENDING so the next run retries it
        # instead of wedging on a stale in-flight status.
        _status = _enum(TaskStatus, data.get("status"), TaskStatus.PENDING)
        if _status in (TaskStatus.RUNNING, TaskStatus.RETRYING):
            _status = TaskStatus.PENDING

        return cls(
            task_id=str(data.get("task_id", "")),
            phase=_enum(AttackPhase, data.get("phase"), AttackPhase.RECONNAISSANCE),
            module_name=str(data.get("module_name", "")),
            target=str(data.get("target", "")),
            parameters=dict(data.get("parameters", {}) or {}),
            status=_status,
            aggression=_enum(AggressionLevel, data.get("aggression"), AggressionLevel.NORMAL),
            priority=int(data.get("priority", 50) or 50),
            retry_count=int(data.get("retry_count", 0) or 0),
            max_retries=int(data.get("max_retries", MAX_MODULE_FAILURES) or MAX_MODULE_FAILURES),
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
            failure_class=str(data.get("failure_class", "") or ""),
            last_error=str(data.get("last_error", "") or data.get("error", "") or ""),
        )


@dataclass
class AttackState:
    """Persistent attack state for a target."""

    target: str
    current_phase: AttackPhase = AttackPhase.RECONNAISSANCE
    aggression: AggressionLevel = AggressionLevel.NORMAL
    privilege_level: str = "none"  # none, user, admin, system, root
    access_achieved: bool = False
    shell_type: str = ""  # none, reverse, bind, webshell
    successful_exploits: list[str] = field(default_factory=list)
    failed_attempts: dict[str, list[str]] = field(default_factory=dict)  # module -> [errors]
    attack_paths: list[list[str]] = field(default_factory=list)
    credentials_found: list[dict[str, str]] = field(default_factory=list)
    loot: list[str] = field(default_factory=list)
    pivot_targets: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    recon_result: HostReconResult | None = None
    # Phase 2.2: persistence methods confirmed installed on the target
    # (e.g. ["cron", "schtask", "webshell"]). Populated only by the opt-in
    # _phase_persistence handler; empty when the persistence phase is off.
    persistence_established: list[str] = field(default_factory=list)
    # Domain targeting: the operator's original --target (domain or IP) and
    # the resolved IP for a domain target. When original_target is a domain,
    # the orchestrator runs subdomain expansion after recon to discover the
    # full attack surface and auto-authorizes each discovered host.
    original_target: str = ""
    resolved_ip: str = ""
    discovered_subdomains: list[dict[str, str]] = field(default_factory=list)
    # Phase 5: hard-target accounting. Counts adaptive rounds that produced no
    # novel candidate modules and no access; when it crosses
    # ``hard_target_max_rounds`` the campaign gives up on this target instead
    # of burning the remaining ``max_cycles`` budget. Reset per target.
    hard_target_rounds: int = 0
    # p2-09: retry accounting persisted per target. ``total_retries`` counts
    # consumed batch retries (bounded by the campaign retry budget);
    # ``last_error`` is the most recent attempt's error text.
    total_retries: int = 0
    last_error: str = ""

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
            # Domain targeting: persist so a resumed campaign still knows it
            # was a domain run and doesn't lose the discovered-subdomain set.
            "original_target": self.original_target,
            "resolved_ip": self.resolved_ip,
            "discovered_subdomains": list(self.discovered_subdomains),
            "hard_target_rounds": int(self.hard_target_rounds),
            "total_retries": int(self.total_retries),
            "last_error": self.last_error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackState":
        """Reconstruct an AttackState from its serialized form (Tier 1.3 resume).

        This is what makes a resumed autonomous campaign CONTINUE rather than
        restart: the recovered ``current_phase``, ``successful_exploits``,
        ``failed_attempts``, ``credentials_found``, ``access_achieved`` and
        ``recon_result`` mean the orchestrator skips already-done recon and
        doesn't re-fire modules that already succeeded/failed. Unknown enum
        strings degrade to defaults (never raise). ``recon_result`` is rebuilt
        via ``HostReconResult.from_dict`` so the prior scan's open ports live
        on across the restart.
        """

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
            # Domain targeting: restore so a resumed domain campaign keeps its
            # original_target/resolved_ip and discovered subdomains.
            original_target=str(data.get("original_target", "") or ""),
            resolved_ip=str(data.get("resolved_ip", "") or ""),
            discovered_subdomains=[
                dict(s) for s in (data.get("discovered_subdomains", []) or []) if isinstance(s, dict)
            ],
            hard_target_rounds=int(data.get("hard_target_rounds", 0) or 0),
            total_retries=int(data.get("total_retries", 0) or 0),
            last_error=str(data.get("last_error", "") or ""),
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
        if module_name not in self.failed_attempts:
            self.failed_attempts[module_name] = []
        self.failed_attempts[module_name].append(error)

    def record_success(self, module_name: str, result: dict[str, Any]) -> None:
        self.successful_exploits.append(module_name)
        if result.get("shell_type"):
            self.shell_type = result["shell_type"]
            self.access_achieved = True
            # Surface the foothold to the operator so a long autonomous campaign
            # shows the breakthrough on the console, not just in the log file.
            ui.compromise(
                action_num=len(self.successful_exploits),
                shell_type=result.get("shell_type", ""),
                privilege_level=result.get("privilege_level", ""),
            )
        if result.get("privilege_level"):
            self.privilege_level = result["privilege_level"]
        if result.get("credentials"):
            self.credentials_found.extend(result["credentials"])
            ui.cred_dump(action_num=len(self.successful_exploits))
        if result.get("loot"):
            self.loot.extend(result["loot"])
        if result.get("pivot_targets"):
            self.pivot_targets.extend(result["pivot_targets"])

    def escalate_aggression(self) -> None:
        """Escalate aggression level after failures."""
        levels = [AggressionLevel.STEALTH, AggressionLevel.NORMAL, AggressionLevel.AGGRESSIVE, AggressionLevel.MAXIMUM]
        idx = levels.index(self.aggression)
        if idx < len(levels) - 1:
            self.aggression = levels[idx + 1]
            logger.info(f"Aggression escalated to {self.aggression.value} for {self.target}")
            # Surface aggression escalation to the operator — it drives which
            # modules the next round runs, so the user should see the campaign
            # getting more aggressive in real time.
            ui.warning(f"Aggression escalated to {self.aggression.value} — retrying failed modules")

    def should_continue(self) -> bool:
        """Determine if attack should continue based on state."""
        # Continue if:
        # 1. No access achieved yet
        # 2. Access achieved but not at max privilege
        # 3. There are pivot targets
        # 4. There are unexploited services
        if not self.access_achieved:
            return True
        if self.privilege_level not in ("system", "root", "admin"):
            return True
        if self.pivot_targets:
            return True
        return False


# ---------------------------------------------------------------------------
# Retry engine with parameter modification
# ---------------------------------------------------------------------------


class RetryEngine:
    """Intelligent retry with parameter modification."""

    # p2-09: per-model rate-limit hook. ``record_rate_limited`` notes a
    # backend-throttle signal for a model key; ``rate_limit_delay`` returns
    # the extra delay the batch loop must observe before the next attempt
    # with that model. External code can replace the policy wholesale via
    # ``register_model_rate_limit_hook`` (tests use it to avoid sleeping).
    _MODEL_RATE_LIMIT_HITS: dict[str, list[float]] = {}
    _MODEL_RATE_LIMIT_HOOK: Callable[[str], float] | None = None

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
        "default": [
            {"timeout": 30},
            {"timeout": 60, "retries": 2},
            {"timeout": 120, "retries": 3, "aggressive": True},
        ],
    }

    @classmethod
    def get_retry_parameters(cls, module_name: str, attempt: int) -> dict[str, Any]:
        """Get modified parameters for retry attempt.

        p2-09: frozen at the last strategy verbatim once the table is
        exhausted — the old ``timeout*4`` + forced ``aggressive=True``
        escalation is deleted. Unbounded escalation burned time on doomed
        tasks and escalated aggression without operator intent; the campaign
        retry budget (see ``tools/campaign/batch.py``) is the bound now.
        """
        strategies = cls.RETRY_STRATEGIES.get(module_name, cls.RETRY_STRATEGIES["default"])
        if attempt < len(strategies):
            return dict(strategies[attempt])
        return dict(strategies[-1])

    @classmethod
    def should_retry(cls, module_name: str, error: str, attempt: int, max_attempts: int) -> bool:
        """Determine if a failed attempt should be retried."""
        if attempt >= max_attempts:
            return False

        # First, classify via the shared failure taxonomy. Permanent
        # classes (scope_blocked / false_positive) are never retried -- the
        # substring blacklist below stays as the conservative fallback for
        # anything the classifier misses or when the taxonomy import fails.
        try:
            from tools.failure_taxonomy import classify_failure, is_permanent

            fc = classify_failure(error)
            if is_permanent(fc):
                return False
        except Exception:  # noqa: BLE001 -- taxonomy import must never break retries
            pass

        # Don't retry on permanent failures
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

        # Don't retry if tool is not available
        if "not found" in error_lower or "not installed" in error_lower:
            return False

        return True

    # ── p2-09: bounded backoff + per-model rate-limit hook ──────────────

    @classmethod
    def compute_backoff(cls, attempt: int, *, base: float = 2.0, cap: float = 60.0) -> float:
        """Exponential backoff with jitter for retry ``attempt`` (1-based).

        ``base**attempt`` seconds plus up-to-1s uniform jitter, capped at
        ``cap`` (default 60s). Pure function of the attempt number so tests
        can assert the bound without sleeping.
        """
        import random

        return min(float(cap), float(base) ** max(0, int(attempt)) + random.uniform(0, 1))

    @classmethod
    def register_model_rate_limit_hook(cls, hook: Callable[[str], float] | None) -> None:
        """Override the per-model rate-limit delay policy (tests/ops seam).

        The hook receives a model key and returns extra seconds to wait
        before the next attempt. ``None`` restores the default tracker.
        """
        cls._MODEL_RATE_LIMIT_HOOK = hook

    @classmethod
    def record_rate_limited(cls, model: str) -> None:
        """Note a backend-throttle signal for ``model`` (decays after 60s)."""
        if not model:
            return
        now = time.monotonic()
        hits = cls._MODEL_RATE_LIMIT_HITS.setdefault(model, [])
        hits.append(now)
        del hits[:-10]

    @classmethod
    def rate_limit_delay(cls, model: str = "") -> float:
        """Extra delay seconds for ``model`` from recent throttle signals."""
        if cls._MODEL_RATE_LIMIT_HOOK is not None:
            try:
                return max(0.0, float(cls._MODEL_RATE_LIMIT_HOOK(model)))
            except Exception:  # noqa: BLE001 -- a broken hook must never stall retries
                return 0.0
        if not model:
            return 0.0
        now = time.monotonic()
        hits = [t for t in cls._MODEL_RATE_LIMIT_HITS.get(model, []) if now - t < 60.0]
        cls._MODEL_RATE_LIMIT_HITS[model] = hits
        return min(60.0, 5.0 * len(hits))
