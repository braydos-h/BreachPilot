"""Attempt fingerprinting: canonical identity for an attempted action.

Two attempts are *materially equivalent* when they share target, service,
action family, parameters, hypothesis, technique category, and expected
observation. Equivalence is what drives dedup and retry justification in
`tracker.py`.
"""

from __future__ import annotations

import enum
import hashlib
import re
from dataclasses import dataclass

__all__ = [
    "ActionFamily",
    "Attempt",
    "AttemptStatus",
    "RetryJustification",
    "RetryJustifier",
    "mask_secrets",
]


class AttemptStatus(str, enum.Enum):
    """Lifecycle of one recorded attempt."""

    ATTEMPTED = "attempted"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    BLOCKED = "blocked"
    REFUTED = "refuted"
    CONFIRMED = "confirmed"


class ActionFamily(str, enum.Enum):
    """High-level family of an action, coarse enough to survive tool churn."""

    RECON_SCAN = "recon_scan"
    PORT_SCAN = "port_scan"
    SERVICE_BANNER = "service_banner"
    CVE_CHECK = "cve_check"
    EXPLOIT = "exploit"
    BRUTE_FORCE = "brute_force"
    WEB_REQUEST = "web_request"
    OS_FINGERPRINT = "os_fingerprint"
    CRED_VALIDATION = "cred_validation"
    SCRIPT_EXEC = "script_exec"
    TOOL_OTHER = "tool_other"

    @classmethod
    def for_tool(cls, tool_name: str) -> "ActionFamily":
        """Map a tool name (basename or substring) to an action family.

        Known substrings win; otherwise ``TOOL_OTHER``.
        """
        name = (tool_name or "").lower()
        for marker, family in _TOOL_MAP.items():
            if marker in name:
                return family
        return cls.TOOL_OTHER


_TOOL_MAP: dict[str, "ActionFamily"] = {
    "nmap": ActionFamily.RECON_SCAN,
    "masscan": ActionFamily.RECON_SCAN,
    "msf": ActionFamily.EXPLOIT,
    "metasploit": ActionFamily.EXPLOIT,
    "searchsploit": ActionFamily.CVE_CHECK,
    "nuclei": ActionFamily.CVE_CHECK,
    "nikto": ActionFamily.CVE_CHECK,
    "hydra": ActionFamily.BRUTE_FORCE,
    "medusa": ActionFamily.BRUTE_FORCE,
    "ncrack": ActionFamily.BRUTE_FORCE,
    "john": ActionFamily.BRUTE_FORCE,
    "hashcat": ActionFamily.BRUTE_FORCE,
    "curl": ActionFamily.WEB_REQUEST,
    "wget": ActionFamily.WEB_REQUEST,
    "requests": ActionFamily.WEB_REQUEST,
    "python": ActionFamily.SCRIPT_EXEC,
    "bash": ActionFamily.SCRIPT_EXEC,
    "sh": ActionFamily.SCRIPT_EXEC,
    "crackmapexec": ActionFamily.CRED_VALIDATION,
    "impacket": ActionFamily.CRED_VALIDATION,
    "smbclient": ActionFamily.SERVICE_BANNER,
    "netcat": ActionFamily.SERVICE_BANNER,
    "nc": ActionFamily.SERVICE_BANNER,
}

_PARAM_SPLIT = re.compile(r"[\s,;]+")


def _normalize_params(parameters: tuple[str, ...]) -> tuple[str, ...]:
    """Split, trim, drop empties, sort. Order-insensitive by design."""
    return tuple(sorted(p.strip() for p in _PARAM_SPLIT.split(" ".join(parameters)) if p.strip()))


@dataclass(frozen=True, slots=True)
class Attempt:
    """Fingerprint inputs of one attempted action.

    ``parameters`` is a tuple of parameter strings; order is *not*
    significant — the fingerprint canonicalizes them sorted. **Redact
    credentials before recording** (see :func:`mask_secrets`).
    """

    target: str
    service: str = ""
    action_family: ActionFamily = ActionFamily.TOOL_OTHER
    parameters: tuple[str, ...] = ()
    hypothesis: str = ""
    technique_category: str = ""
    expected_observation: str = ""

    def fingerprint(self) -> str:
        """sha256 of canonicalized fields; equal for materially equal attempts."""
        canonical = "|".join(
            [
                (self.target or "").strip().lower(),
                (self.service or "").strip().lower(),
                self.action_family.value,
                ",".join(_normalize_params(self.parameters)),
                (self.hypothesis or "").strip().lower(),
                (self.technique_category or "").strip().lower(),
                (self.expected_observation or "").strip().lower(),
            ]
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def mask_secrets(data: dict, secret_keys: tuple[str, ...] = ("password", "pass", "secret", "token", "key")) -> dict:
    """Return a copy with secret values replaced by ``"<redacted>"``.

    Non-secret fields are preserved: only values under the given
    (case-insensitive) key names are masked. Safe on any dict.
    """
    lower = {k.lower(): k for k in data}
    out = dict(data)
    for secret in secret_keys:
        original = lower.get(secret)
        if original is not None and out[original]:
            out[original] = "<redacted>"
    return out


class RetryJustification(str, enum.Enum):
    """Why a retry of a previously failed attempt is justified."""

    NEW_VERSION_EVIDENCE = "new_version_evidence"
    NEW_IDENTITY_CONTEXT = "new_identity_context"
    SERVICE_STATE_CHANGED = "service_state_changed"
    NEW_CONFIGURATION_EVIDENCE = "new_configuration_evidence"
    DIFFERENT_VALIDATION_METHOD = "different_validation_method"
    NONE = "none"


class RetryJustifier:
    """Deterministic: compare current evidence keys vs the previous snapshot.

    First matching change wins; the field order below is the priority order.
    """

    _KEY_FIELDS: tuple[tuple[str, str, RetryJustification], ...] = (
        ("version_known", "version evidence", RetryJustification.NEW_VERSION_EVIDENCE),
        ("identity_context", "identity context", RetryJustification.NEW_IDENTITY_CONTEXT),
        ("service_state", "service state", RetryJustification.SERVICE_STATE_CHANGED),
        ("config_evidence", "configuration evidence", RetryJustification.NEW_CONFIGURATION_EVIDENCE),
        ("validation_method", "validation method", RetryJustification.DIFFERENT_VALIDATION_METHOD),
    )

    def evaluate(self, attempt: Attempt, evidence_snapshot: dict) -> tuple[RetryJustification, str]:
        """Compare the snapshot to its ``previous_evidence`` key.

        ``attempt`` is carried for API symmetry with the tracker; the
        comparison is purely over evidence keys. Returns
        ``(RetryJustification, detail)``; deterministic — a change on one key
        always yields the same reason.
        """
        snapshot = evidence_snapshot or {}
        return self._evaluate_snapshot(snapshot.get("previous_evidence") or {}, snapshot)

    def _evaluate_snapshot(self, previous: dict, snapshot: dict) -> tuple[RetryJustification, str]:
        for key, human, reason in self._KEY_FIELDS:
            old, new = previous.get(key), snapshot.get(key)
            if old != new:
                return reason, f"{human}: {old!r} -> {new!r}"
        return RetryJustification.NONE, "no material evidence change"

    def describe(self, justification: RetryJustification, detail: str) -> str:
        """Human sentence for a justification."""
        if justification is RetryJustification.NONE:
            return "Retry not justified: no material evidence change."
        return f"Retry justified because {detail}."
