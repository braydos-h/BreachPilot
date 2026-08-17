"""Typed contracts shared between the CLI and the WebUI API daemon.

The CLI (``main.async_main``) and the API (``tools/api/run_manager.py``) both
drive an assessment through ``AssessmentService``. These dataclasses are the
transport-neutral surface: a ``RunRequest`` goes in, a ``RunPreview`` comes
back for operator confirmation, then ``execute`` produces a ``RunResult``.
Decisions (start confirmation, goal selection, tool approvals) and live
events (boot, progress, tool calls, completion) flow through provider/sink
protocols so the terminal UI and the REST/WebSocket API can each render them
in their own medium without the service knowing which one is calling.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RunState(str, Enum):
    """Lifecycle states for a single assessment run."""
    DRAFT = "draft"                          # created, not yet confirmed
    AWAITING_CONFIRMATION = "awaiting_confirmation"  # preview ready, waiting on start_confirm decision
    QUEUED = "queued"                        # confirmed, waiting for execution slot
    RUNNING = "running"                      # execution in progress
    AWAITING_INPUT = "awaiting_input"        # blocked on a tool_approval / goal_select decision
    CANCELLING = "cancelling"                # cancel requested, tearing down
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"              # daemon restarted while run was live


class RunKind(str, Enum):
    """What kind of run this is."""
    AGENT = "agent"     # full autonomous/semi-autonomous assessment
    # MANUAL was removed: it advertised "MCP tool gateway only, no agent loop"
    # but AssessmentService.execute never branched on it and ran the normal
    # agent path. Re-add a distinct branch if genuine manual-only mode is
    # needed (manual MCP tool calls are already available via the Tools tab
    # on an active run).


class DecisionKind(str, Enum):
    START_CONFIRM = "start_confirm"       # ready-to-begin gate (destructive or normal)
    GOAL_SELECT = "goal_select"           # recon-first goal selection from suggestions
    TOOL_APPROVAL = "tool_approval"        # approve_only policy: allow/deny a tool call
    CAMPAIGN_NEXT_STEP = "campaign_next_step"  # mid-run operator checkpoint at a verified-access or no-path milestone


class DecisionStatus(str, Enum):
    PENDING = "pending"
    ANSWERED = "answered"
    DENIED = "denied"
    EXPIRED = "expired"                    # run cancelled/failed before answered


# ---------------------------------------------------------------------------
# Run request / preview / result
# ---------------------------------------------------------------------------

RunMode = Literal["recon", "attack"]


@dataclass
class RunRequest:
    """Transport-neutral description of an assessment the operator wants to run.

    Built from CLI args (``main.async_main``) or from a ``POST /runs`` JSON
    body (``tools/api/routes/runs.py``). Everything the service needs to
    prepare a preview is here; nothing that requires I/O is resolved yet.
    """
    target: str
    mode: RunMode = "attack"
    goal_name: str = ""
    custom_goal: str = ""
    recon_first: bool | None = None          # None = auto (recon-first when no goal)
    model_alias: str = ""
    config_path: Path = Path("config.yaml")
    reports_dir: Path = Path("reports")
    # Execution options
    swarm: bool = False
    parallel_swarm: bool = False
    critic: bool = False
    reflection: bool = False
    adaptive_exploits: bool = False
    long_session: bool = False
    multi_model_consult: bool | None = None
    observer_mode: str = "hybrid"
    ultrathink: bool = False
    debug: bool = False
    plain: bool = False
    json_output: bool = False
    yes: bool = False                        # skip the start_confirm gate
    # Skills overrides (advisory; never scope/permission)
    skills_mode: str | None = None           # on/off/hints/lookup
    skills_include: list[str] = field(default_factory=list)
    skills_exclude: list[str] = field(default_factory=list)
    skills_no_reselect: bool = False
    # Resume
    resume_source: str = ""                  # run_id or session_id
    # Kind
    kind: RunKind = RunKind.AGENT
    # API-only: whether this run was created interactively (target entered via menu)
    interactive: bool = False


@dataclass
class RunPreview:
    """Everything the operator sees at the ready-to-begin gate, computed by
    ``AssessmentService.prepare`` before any I/O side effects.

    The CLI renders this via ``AttackUi``; the API returns it from
    ``POST /runs`` so the WebUI can display the same summary and ask for
    confirmation. ``required_confirmation_text`` is non-empty for destructive
    runs (the operator must type ``ALLOW <target>``).
    """
    run_id: str
    reports_dir: Path
    config_path: Path
    target_ip: str
    original_target: str
    resolved_ip: str | None
    resolved_domain: str | None
    mode: RunMode
    goal_name: str
    goal_description: str
    model_alias: str
    model_label: str
    transport_summary: str
    permission: str
    attack_mode: bool
    swarm: bool
    parallel_swarm: bool
    multi_model: bool
    destructive: bool
    required_confirmation_text: str         # "" for non-destructive; "ALLOW <ip>" for destructive
    budgets: dict[str, Any] = field(default_factory=dict)  # commands/rounds/duration
    skill_activations: list[dict[str, str]] = field(default_factory=list)
    skill_errors: list[str] = field(default_factory=list)
    # Resume info
    resumed_from: str = ""


@dataclass
class RunResult:
    """Sanitized, serializable outcome of a completed/failed run."""
    run_id: str
    target_ip: str
    mode: RunMode
    goal_name: str
    goal_description: str
    total_actions: int = 0
    workspace: str = ""
    audit_path: str = ""
    records: list[dict[str, Any]] = field(default_factory=list)
    messages: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    swarm_result: dict[str, Any] | None = None
    active_skills: list[dict[str, Any]] = field(default_factory=list)
    outcome_summary: str = ""
    telemetry: dict[str, Any] | None = None
    safety_review: dict[str, Any] | None = None
    reports_dir: str = ""
    summary_path: str = ""
    run_json_path: str = ""
    # Operator cancelled the run at a mid-run checkpoint (CAMPAIGN_NEXT_STEP).
    # Set by AssessmentService when the loop surfaces ``cancelled_by_operator``
    # in its result dict; consumed by RunManager._execute_run to map the run
    # to the ``cancelled`` state instead of ``completed``/``failed``.
    cancelled: bool = False
    # Operator-selected objective transitions recorded at mid-run checkpoints
    # (e.g. "recon_only" → "privesc", "backdoor" → "data_exfil"). Each entry is
    # ``{"from": str, "to": str, "at_checkpoint": "access"|"no_path"}``. Empty
    # when no checkpoint transitioned the objective.
    objective_transitions: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Decisions and events
# ---------------------------------------------------------------------------

@dataclass
class Decision:
    """A point where the run pauses for operator input.

    The CLI fulfills these via ``AttackUi`` prompts; the API persists them and
    a WebUI answers them via ``POST /runs/{id}/decisions/{decision_id}``.
    """
    id: str
    run_id: str
    kind: DecisionKind
    prompt_text: str
    required_text: str = ""                  # exact text the answer must match (e.g. "ALLOW 10.0.0.50")
    options: list[dict[str, Any]] = field(default_factory=list)  # for goal_select: [{name, description, ...}]
    status: DecisionStatus = DecisionStatus.PENDING
    answer: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    answered_at: str = ""


@dataclass
class Event:
    """A structured event emitted during a run.

    The terminal ``EventSink`` is a no-op (the CLI prints directly via
    ``AttackUi``); the API ``EventSink`` appends to ``events.jsonl`` and
    pushes to WebSocket subscribers. ``sequence`` is monotonically increasing
    per run.
    """
    sequence: int
    timestamp: str
    run_id: str
    type: str
    payload: dict[str, Any] = field(default_factory=dict)


# Event type constants (kept as plain strings for easy grepping).
EVENT_STATE = "state"                   # run state transition
EVENT_BOOT = "boot"                       # MCP boot step ([BOOT]/[OK])
EVENT_PROGRESS = "progress"               # heartbeat: round/action/phase
EVENT_PHASE = "phase"                      # agent phase transition (recon/enum/...)
EVENT_GOAL_SUGGESTIONS = "goal_suggestions"
EVENT_RECON = "recon_assessment"          # recon-first assessment (OS/ports/CVEs/score)
EVENT_ASSISTANT = "assistant"             # LLM output text
EVENT_TOOL_REQUEST = "tool_request"      # agent decided to call a tool
EVENT_TOOL_START = "tool_start"
EVENT_TOOL_RESULT = "tool_result"
EVENT_APPROVAL = "approval"              # tool approval requested/answered
EVENT_SWARM = "swarm"                     # swarm progress update
EVENT_ARTIFACT = "artifact"               # file written (reports/audit/etc)
EVENT_COMPLETION = "completion"
EVENT_ERROR = "error"
