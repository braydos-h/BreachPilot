"""Shared failure classification + recovery strategy taxonomy.

Single source of truth for "why did this action fail" and "what should the
planner do about it". Three previously-disjoint classifiers express on top of
this module instead of growing more string-sniffing:

- autonomous_orchestrator.RetryEngine.should_retry (permanent-failure gate)
- exploit_agent loop replan/reflection prompts (failure-class hints)
- attack_modules results (ModuleResult.failure_class field)

The classifier is deliberately deterministic and ordered: first regex rule
that matches wins. It never calls a model -- classification is cheap Python;
judgment about *what to do next* stays with the planner/model.
"""

from __future__ import annotations

import enum
import re


class FailureClass(str, enum.Enum):
    """Why an action/module/tool call failed (or produced no usable result)."""

    TARGET_UNREACHABLE = "target_unreachable"
    TIMEOUT = "timeout"
    UNSUPPORTED_TARGET = "unsupported_target"
    PREREQUISITE_MISSING = "prerequisite_missing"
    AUTH_FAILED = "auth_failed"
    TOOL_UNAVAILABLE = "tool_unavailable"
    MALFORMED_CODE = "malformed_code"
    UNEXPECTED_OUTPUT = "unexpected_output"
    FALSE_POSITIVE = "false_positive_hypothesis"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    SCOPE_BLOCKED = "scope_blocked"
    TRANSPORT_ERROR = "transport_error"
    SCHEMA_ERROR = "schema_error"
    UNKNOWN = "unknown"


class RecoveryAction(str, enum.Enum):
    """What the planner should do about a failure class."""

    RETRY_SAME = "retry_same"  # transient; bounded by attempt budget
    RETRY_WITH_PARAMS = "retry_with_params"  # alter parameters before retry
    REPAIR_CODE = "repair_code"  # fix the generated helper and retest
    CREATE_PREREQUISITE = "create_prerequisite"  # schedule the missing capability first
    SWITCH_CAPABILITY = "switch_capability"  # alternate module/tool for same goal
    GATHER_INFO = "gather_info"  # more recon before re-attempting
    STOP = "stop"  # permanent: never retry this action
    ESCALATE_OPERATOR = "escalate_operator"  # needs an operator decision


# class -> (recovery, human/planner-facing hint)
_RECOVERY: dict[FailureClass, tuple[RecoveryAction, str]] = {
    FailureClass.TARGET_UNREACHABLE: (
        RecoveryAction.GATHER_INFO,
        "Confirm the host is up (check_os/quick_scan) before retrying; do not rerun the same module.",
    ),
    FailureClass.TIMEOUT: (
        RecoveryAction.RETRY_WITH_PARAMS,
        "Retry once with a higher timeout or narrower scope; a second timeout means stop.",
    ),
    FailureClass.UNSUPPORTED_TARGET: (
        RecoveryAction.SWITCH_CAPABILITY,
        "Target does not satisfy this capability's requirements; pick an alternate module via query_capabilities.",
    ),
    FailureClass.PREREQUISITE_MISSING: (
        RecoveryAction.CREATE_PREREQUISITE,
        "A required artifact (credentials/foothold/privilege) is missing; create a task for a capability that produces it.",
    ),
    FailureClass.AUTH_FAILED: (
        RecoveryAction.CREATE_PREREQUISITE,
        "Authentication failed; obtain or validate credentials before retrying.",
    ),
    FailureClass.TOOL_UNAVAILABLE: (
        RecoveryAction.SWITCH_CAPABILITY,
        "The required binary/tool is absent on the operator box; check_environment, then choose a capability that does not need it.",
    ),
    FailureClass.MALFORMED_CODE: (
        RecoveryAction.REPAIR_CODE,
        "The generated helper has a coding error; repair the script (syntax/name errors first) and rerun within the repair budget.",
    ),
    FailureClass.UNEXPECTED_OUTPUT: (
        RecoveryAction.GATHER_INFO,
        "Output did not match expectations; inspect the raw evidence artifact before concluding success or failure.",
    ),
    FailureClass.FALSE_POSITIVE: (
        RecoveryAction.STOP,
        "The hypothesis was explicitly refuted (e.g. VULN_NOT_CONFIRMED); mark the hypothesis refuted and move on.",
    ),
    FailureClass.INSUFFICIENT_EVIDENCE: (
        RecoveryAction.GATHER_INFO,
        "Result is inconclusive; gather corroborating evidence before treating any hypothesis as confirmed.",
    ),
    FailureClass.SCOPE_BLOCKED: (
        RecoveryAction.STOP,
        "Action is outside the authorized target set; never retry it against another host.",
    ),
    FailureClass.TRANSPORT_ERROR: (
        RecoveryAction.RETRY_SAME,
        "Transient transport/model-backend error; retry with backoff. Repeated transport errors mean the backend is down -- stop.",
    ),
    FailureClass.SCHEMA_ERROR: (
        RecoveryAction.REPAIR_CODE,
        "The tool call itself was malformed (bad arguments/schema); fix the call shape, not the target.",
    ),
    FailureClass.UNKNOWN: (
        RecoveryAction.RETRY_WITH_PARAMS,
        "Unrecognized failure; inspect evidence, then retry once with different parameters. Identical repeat failures mean stop.",
    ),
}

# Ordered (pattern, class) rules; first match wins on lowercased text.
# Kept conservative: patterns map onto signals the codebase already emits
# (BLOCKED:/ERROR: markers, canonical stdout markers, common tool stderr).
_RULES: tuple[tuple[str, FailureClass], ...] = (
    (
        r"not in the (explicit )?allowlist|blocked by scope|out of scope|not authorized|^blocked\b|BLOCKED:",
        FailureClass.SCOPE_BLOCKED,
    ),
    (r"vuln_not_confirmed|not vulnerable|patched version", FailureClass.FALSE_POSITIVE),
    (r"insufficient evidence|inconclusive|cannot determine", FailureClass.INSUFFICIENT_EVIDENCE),
    (
        r"connection refused|no route to host|host is down|target unreachable|unreachable host|network is unreachable",
        FailureClass.TARGET_UNREACHABLE,
    ),
    (r"timed? ?out|timeout|deadline exceeded|readtimeout", FailureClass.TIMEOUT),
    (
        r"permission denied|access denied|authentication failed|login failed|invalid credentials|status_logon_failure|auth.*fail",
        FailureClass.AUTH_FAILED,
    ),
    (
        r"requires? (a |an )?(credential|foothold|session|admin|root|privilege)|missing (credential|prerequisite)|no (valid )?credentials|no active session|foothold required",
        FailureClass.PREREQUISITE_MISSING,
    ),
    (
        r"command not found|not installed|no such file or directory.*(bin|sbin|usr)|executable not found|tool.*not available|unavailable_tool",
        FailureClass.TOOL_UNAVAILABLE,
    ),
    (
        r"syntaxerror|indentationerror|nameerror|typeerror|attributeerror|traceback \(most recent call last\)|compile error|malformed (code|script|json)",
        FailureClass.MALFORMED_CODE,
    ),
    (
        r"invalid (argument|parameter)|unexpected keyword|schema|recoverable_error|unknown_tool",
        FailureClass.SCHEMA_ERROR,
    ),
    (
        r"remoteprotocolerror|connecterror|connection reset|connection aborted|server disconnected|broken pipe",
        FailureClass.TRANSPORT_ERROR,
    ),
    (r"unsupported (target|os|service|protocol)|does not apply|not applicable", FailureClass.UNSUPPORTED_TARGET),
)


def classify_failure(text: str) -> FailureClass:
    """Classify a failure/outcome text into a FailureClass.

    Accepts tool result text, stderr, exception text, or a module note. The
    empty string and None-ish input classify as UNKNOWN. Deterministic; no I/O.
    """
    blob = (text or "").strip().lower()
    if not blob:
        return FailureClass.UNKNOWN
    for pattern, fc in _RULES:
        if re.search(pattern, blob, re.IGNORECASE):
            return fc
    if "error" in blob or "failed" in blob or "exception" in blob:
        return FailureClass.UNKNOWN
    return FailureClass.UNEXPECTED_OUTPUT


def recovery_for(failure_class: FailureClass | str) -> RecoveryAction:
    fc = _coerce(failure_class)
    return _RECOVERY[fc][0]


def recovery_hint(failure_class: FailureClass | str) -> str:
    fc = _coerce(failure_class)
    return _RECOVERY[fc][1]


def is_retryable(failure_class: FailureClass | str) -> bool:
    """True when the recovery action involves retrying (possibly modified)."""
    return recovery_for(failure_class) in {
        RecoveryAction.RETRY_SAME,
        RecoveryAction.RETRY_WITH_PARAMS,
        RecoveryAction.REPAIR_CODE,
    }


def is_permanent(failure_class: FailureClass | str) -> bool:
    """True when retrying this action is prohibited (scope/false-positive)."""
    return recovery_for(failure_class) in {
        RecoveryAction.STOP,
        RecoveryAction.ESCALATE_OPERATOR,
    }


def _coerce(failure_class: FailureClass | str) -> FailureClass:
    if isinstance(failure_class, FailureClass):
        return failure_class
    try:
        return FailureClass(str(failure_class))
    except ValueError:
        return FailureClass.UNKNOWN
