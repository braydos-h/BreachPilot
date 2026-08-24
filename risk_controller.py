"""Risk Controller — gates high-risk actions in the research agent.

Enforces:
- Non-destructive testing by default
- Rate limiting per target
- Human approval for high-risk actions (when mission profile requires it)
- Max command/task budgets enforced per session
- No destructive actions without explicit opt-in in mission config

Works in conjunction with ScopeGate. ScopeGate checks WHAT you can touch.
RiskController checks HOW you can touch it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Kept for backwards compatibility (tests import this name). Matching is now
# done by the word-boundary regexes in ``_DESTRUCTIVE_PATTERNS`` below, which
# normalize whitespace/shell separators and avoid the substring false-positive
# / false-negative problems the old frozenset had (M32).
DESTRUCTIVE_KEYWORDS = frozenset({
    "delete", "drop", "truncate", "overwrite", "rm ", "rm -rf", "dd if",
    "format", "wipe", "shred", "mkfs", "fdisk", "parted",
    "chmod 777", "chown", "unlink", "kill -9", "pkill",
})

# Destructive command patterns with word boundaries. Whitespace and shell
# separators (;|&) are normalized to single spaces before matching so that
# chained / oddly-spaced commands such as "rm\t-rf" or "rm;-rf" are caught
# (M32). The verb set is broadened beyond the original ``rm``/``dd if`` pair
# to include shred, wipe, format, truncate, overwrite and mkfs variants.
_DESTRUCTIVE_PATTERNS = [
    re.compile(r"\brm\b\s*[-rf]?"),          # rm with optional -r/-f flags
    re.compile(r"\bdd\b\s+(?:if|of)\b"),      # dd if=/of=
    re.compile(r"\bkill(?:all)?\b\s*-"),     # kill -9, killall -HUP
    re.compile(r"\bpkill\b"),
    re.compile(r"\bshred\b"),
    re.compile(r"\bwipe\b"),
    re.compile(r"\bformat\b"),
    re.compile(r"\btruncate\b"),
    re.compile(r"\boverwrite\b"),
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bfdisk\b"),
    re.compile(r"\bparted\b"),
    re.compile(r"\bchmod\b\s+(?:-[a-zA-Z]+\s+)*[-+]?0*777\b"),
    re.compile(r"\bchown\b"),
    re.compile(r"\bunlink\b"),
    re.compile(r"\bdrop\b"),
    re.compile(r"\bdelete\b"),
]

# Overwrite/clobber of sensitive system files via shell redirect or tee.
# These operators' target is unambiguous (the path right after the operator),
# so they are safe to block without false-positiveing legitimate reads. cp/mv
# are intentionally NOT matched here: their source-vs-destination ambiguity
# would block safe reads like ``cp /etc/passwd /tmp/backup``.
_SENSITIVE_SYSTEM_DIRS = (
    "etc", "usr", "bin", "sbin", "boot", "lib", "lib64",
    "root", "proc", "sys", "dev", "var/log",
)
_SENSITIVE_OVERWRITE_PATTERNS = [
    # `echo x > /etc/passwd`, `cat y >> /etc/shadow`, `2> /etc/cron.d/x`, `&> /etc/x`
    re.compile(r"(?:>>?|&>|[12]>)\s*/(?:" + "|".join(_SENSITIVE_SYSTEM_DIRS) + r")(?:/|\b)"),
    # `tee /etc/passwd`, `tee -a /etc/cron.d/x`
    re.compile(r"\btee\b\s+(?:-[a-z]+\s+)?/(?:" + "|".join(_SENSITIVE_SYSTEM_DIRS) + r")(?:/|\b)"),
]

DANGEROUS_TOOL_PATTERNS = frozenset({
    "hydra", "medusa", "ncrack", "patator", "brute", "crackmapexec",
    "msfvenom", "msfconsole", "exploit/multi/", "exploit/windows/",
    "meterpreter", "payload/", "reverse_", "bind_", "shell_reverse",
    "mimikatz", "lsadump", "sekurlsa", "hashdump",
    "generate_payload", "lateral_exec", "dump_credentials", "kerberoast",
    "wmiexec", "smbexec", "psexec", "atexec",
    "secretsdump", "GetUserSPNs", "GetUserSPNs.py",
})


@dataclass
class RiskAssessment:
    """Result of risk evaluation for a proposed action."""

    allowed: bool
    risk_level: str = "low"  # low, medium, high
    reason: str = ""
    requires_human_approval: bool = False
    warnings: list[str] = field(default_factory=list)
    mitigation_suggestions: list[str] = field(default_factory=list)


class RiskController:
    """Evaluates and gates risk for proposed actions."""

    def __init__(
        self,
        risk_profile: str = "low_noise_non_destructive",
        *,
        max_commands: int = 100,
        max_tasks: int = 20,
        allow_exploitation: bool = False,
        allow_pivoting: bool = False,
        allow_credential_testing: bool = False,
    ) -> None:
        self._risk_profile = risk_profile
        self._max_commands = max_commands
        self._max_tasks = max_tasks
        self._allow_exploitation = allow_exploitation
        self._allow_pivoting = allow_pivoting
        self._allow_credential_testing = allow_credential_testing
        self._commands_executed = 0
        self._tasks_completed = 0

    # ── Main API ────────────────────────────────────────────────────────

    def assess_action(
        self,
        action_type: str,
        tool_name: str,
        command_or_args: str,
        target: str = "",
        risk_level: str = "low",
    ) -> RiskAssessment:
        """Evaluate whether a proposed action is safe to execute.

        Args:
            action_type: Phase or action category (recon, test, exploit, validate, etc.)
            tool_name: Specific tool being invoked
            command_or_args: Command or arguments for context analysis
            target: Target asset
            risk_level: Declared risk level of the action

        Returns:
            RiskAssessment with allowed status and optional warnings.
        """
        warnings: list[str] = []
        mitigations: list[str] = []

        action_type_lower = action_type.lower()

        # ── 0. Budget checks ──
        # Task budget gate (M34): deny once the completed-task count is reached.
        if self._tasks_completed >= self._max_tasks:
            return RiskAssessment(
                allowed=False,
                risk_level=risk_level,
                reason=f"Task budget exhausted ({self._max_tasks}).",
            )
        if self._commands_executed >= self._max_commands:
            return RiskAssessment(
                allowed=False,
                risk_level=risk_level,
                reason=f"Command budget exhausted ({self._max_commands}).",
            )

        # ── 0b. Action-type permission gates (H19) ──
        # Coarse allow/deny based on the declared action category, independent
        # of the tool/command introspection below. Mission profile flags must
        # permit the category before any further consideration.
        if action_type_lower in ("exploit", "test_exploit") and not self._allow_exploitation:
            return RiskAssessment(
                allowed=False,
                risk_level="high",
                reason="Exploitation not permitted by mission profile.",
            )
        if ("pivot" in action_type_lower or "lateral" in action_type_lower) and not self._allow_pivoting:
            return RiskAssessment(
                allowed=False,
                risk_level="high",
                reason="Pivoting not permitted by mission profile.",
            )
        if (
            "credential" in action_type_lower or "cred_test" in action_type_lower
        ) and not self._allow_credential_testing:
            return RiskAssessment(
                allowed=False,
                risk_level="high",
                reason="Credential testing not permitted by mission profile.",
            )

        # ── 1. Destructive action detection ──
        # Block *any* destructive pattern unconditionally. The previous logic
        # nested the blocking ``return`` inside ``if kw in ("rm ", "rm -rf")``,
        # so only ``rm`` / ``rm -rf`` were ever blocked -- ``delete`` / ``drop``
        # / ``dd if`` / ``shred`` / ``wipe`` / ``format`` / ``mkfs`` / ``chown``
        # / ``kill -9`` etc. all fell through and were silently allowed. The
        # hard-forbidden *actions* live in ScopeGate; RiskController is the
        # HOW-gate that refuses to run a destructive command regardless of
        # risk profile (a pentest tool verifies, it does not destroy).
        # M32: whitespace and shell separators (;|&) are normalized to single
        # spaces and matched with word-boundary regexes so ``rm\t-rf`` and
        # ``rm;-rf`` are caught alongside the plain ``rm -rf`` form.
        cmd_lower = command_or_args.lower()
        cmd_norm = re.sub(r"[\s;|&]+", " ", cmd_lower).strip()
        for pattern in _DESTRUCTIVE_PATTERNS:
            m = pattern.search(cmd_norm)
            if m:
                kw = m.group(0).strip()
                return RiskAssessment(
                    allowed=False,
                    risk_level="high",
                    reason=f"Command contains destructive keyword '{kw}'. Blocked by default.",
                    warnings=[f"Destructive action detected: {kw}"],
                )

        # Overwrite/clobber of sensitive system files via shell redirect/tee
        # (e.g. ``echo x > /etc/passwd``, ``tee /etc/cron.d/x``) — these escape
        # the verb list above because ``>``/``tee`` are not destructive verbs
        # on their own, only when pointed at a system path.
        for pattern in _SENSITIVE_OVERWRITE_PATTERNS:
            m = pattern.search(cmd_norm)
            if m:
                kw = m.group(0).strip()
                return RiskAssessment(
                    allowed=False,
                    risk_level="high",
                    reason=f"Command overwrites sensitive system path '{kw}'. Blocked by default.",
                    warnings=[f"Destructive system-path overwrite: {kw}"],
                )

        # ── 2. Exploitation gating ──
        is_exploit_action = any(
            pat in tool_name.lower() or pat in cmd_lower
            for pat in DANGEROUS_TOOL_PATTERNS
        )
        if is_exploit_action and not self._allow_exploitation:
            return RiskAssessment(
                allowed=False,
                risk_level="high",
                reason=(
                    f"Exploitation tool '{tool_name}' is not allowed under the current "
                    f"risk profile '{self._risk_profile}'. Only recon and analysis are permitted."
                ),
                warnings=[f"Exploitation blocked by risk profile: {self._risk_profile}"],
            )

        # ── 3. Pivoting gating ──
        is_pivot_action = any(
            kw in cmd_lower
            for kw in ("pivot", "lateral", "proxy", "tunnel", "port_forward", "_scan ")
        )
        if is_pivot_action and not self._allow_pivoting:
            return RiskAssessment(
                allowed=False,
                risk_level="high",
                reason="Pivoting is not allowed under the current risk profile.",
            )

        # ── 4. Rate-limit check ──
        # (Rate limits are enforced in ScopeGate; RiskController does budget tracking)

        # ── 5. High risk gating ──
        requires_human = False
        if risk_level == "high":
            if self._risk_profile == "low_noise_non_destructive":
                return RiskAssessment(
                    allowed=False,
                    risk_level="high",
                    reason="High-risk actions are not permitted with low_noise_non_destructive profile.",
                )
            if self._risk_profile == "standard_authorized":
                requires_human = True
                warnings.append("High-risk action requires human approval.")
                mitigations.append("Ensure non-destructive testing methods are used.")

        # ── 6. Generate warnings for medium-risk actions ──
        if risk_level == "medium":
            warnings.append("This is a medium-risk action. Proceed with caution.")
            mitigations.append("Verify action is reversible or non-destructive.")

        return RiskAssessment(
            allowed=True,
            risk_level=risk_level,
            reason="Risk assessment passed.",
            requires_human_approval=requires_human,
            warnings=warnings,
            mitigation_suggestions=mitigations,
        )

    def record_execution(self) -> None:
        self._commands_executed += 1

    def record_task_complete(self) -> None:
        self._tasks_completed += 1

    def budgets(self) -> dict[str, Any]:
        return {
            "commands_executed": self._commands_executed,
            "commands_max": self._max_commands,
            "tasks_completed": self._tasks_completed,
            "tasks_max": self._max_tasks,
            "commands_remaining": max(0, self._max_commands - self._commands_executed),
        }

    def can_proceed(self) -> bool:
        return self._commands_executed < self._max_commands
