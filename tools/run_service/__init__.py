"""Transport-neutral assessment preparation and execution service.

Both the CLI (``main.async_main``) and the WebUI API daemon
(``tools/api/run_manager.py``) drive assessments through ``AssessmentService``.
The CLI supplies ``TerminalDecisionProvider`` / ``TerminalEventSink`` /
``TerminalApprovalProvider`` adapters (backed by ``AttackUi``); the API
supplies ``ApiDecisionProvider`` / ``ApiEventSink`` / ``ApiApprovalProvider``
adapters (backed by persisted decision rows + WebSocket event pushes).
"""

from tools.run_service.models import (
    Decision,
    DecisionKind,
    DecisionStatus,
    Event,
    EVENT_APPROVAL,
    EVENT_ARTIFACT,
    EVENT_ASSISTANT,
    EVENT_BOOT,
    EVENT_COMPLETION,
    EVENT_ERROR,
    EVENT_GOAL_SUGGESTIONS,
    EVENT_PROGRESS,
    EVENT_STATE,
    EVENT_SWARM,
    EVENT_TOOL_REQUEST,
    EVENT_TOOL_RESULT,
    EVENT_TOOL_START,
    RunKind,
    RunMode,
    RunPreview,
    RunRequest,
    RunResult,
    RunState,
)
from tools.run_service.providers import (
    ApiApprovalProvider,
    ApiDecisionProvider,
    ApiEventSink,
    ApprovalProvider,
    CancellationToken,
    DecisionProvider,
    EventSink,
    TerminalApprovalProvider,
    TerminalDecisionProvider,
    TerminalEventSink,
)
from tools.run_service.service import AssessmentService, Callables

__all__ = [
    "AssessmentService",
    "ApprovalProvider",
    "ApiApprovalProvider",
    "ApiDecisionProvider",
    "ApiEventSink",
    "Callables",
    "CancellationToken",
    "Decision",
    "DecisionKind",
    "DecisionProvider",
    "DecisionStatus",
    "Event",
    "EventSink",
    "EVENT_APPROVAL",
    "EVENT_ARTIFACT",
    "EVENT_ASSISTANT",
    "EVENT_BOOT",
    "EVENT_COMPLETION",
    "EVENT_ERROR",
    "EVENT_GOAL_SUGGESTIONS",
    "EVENT_PROGRESS",
    "EVENT_STATE",
    "EVENT_SWARM",
    "EVENT_TOOL_REQUEST",
    "EVENT_TOOL_RESULT",
    "EVENT_TOOL_START",
    "RunKind",
    "RunMode",
    "RunPreview",
    "RunRequest",
    "RunResult",
    "RunState",
    "TerminalApprovalProvider",
    "TerminalDecisionProvider",
    "TerminalEventSink",
]