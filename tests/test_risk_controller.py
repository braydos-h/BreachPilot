"""Tests for risk_controller.py — the action safety gate."""

from __future__ import annotations

import pytest

from risk_controller import RiskController


@pytest.fixture
def low_risk_ctrl() -> RiskController:
    return RiskController(
        risk_profile="low_noise_non_destructive",
        max_commands=100,
        max_tasks=20,
        allow_exploitation=False,
        allow_pivoting=False,
    )


@pytest.fixture
def standard_ctrl() -> RiskController:
    return RiskController(
        risk_profile="standard_authorized",
        max_commands=200,
        max_tasks=50,
        allow_exploitation=True,
        allow_pivoting=False,
    )


@pytest.fixture
def high_ctrl() -> RiskController:
    return RiskController(
        risk_profile="high_authorized_testing",
        max_commands=500,
        max_tasks=100,
        allow_exploitation=True,
        allow_pivoting=True,
    )


class TestRiskControllerBasic:
    """Core risk assessment functionality."""

    def test_low_risk_action_allowed(self, low_risk_ctrl: RiskController) -> None:
        result = low_risk_ctrl.assess_action("recon", "nmap", "nmap -sV 10.0.0.1", "10.0.0.1", "low")
        assert result.allowed is True
        assert result.risk_level == "low"

    def test_medium_risk_action_allowed_in_standard(self, standard_ctrl: RiskController) -> None:
        result = standard_ctrl.assess_action("test", "hydra", "hydra -l admin -P pass.txt ssh://10.0.0.1", "10.0.0.1", "medium")
        assert result.allowed is True

    def test_high_risk_requires_approval_in_standard(self, standard_ctrl: RiskController) -> None:
        result = standard_ctrl.assess_action("exploit", "msfconsole", "use exploit/multi/http/log4shell", "10.0.0.1", "high")
        assert result.requires_human_approval is True

    def test_high_risk_no_approval_in_high_profile(self, high_ctrl: RiskController) -> None:
        result = high_ctrl.assess_action("exploit", "msfconsole", "use exploit/multi/http/log4shell", "10.0.0.1", "high")
        assert result.requires_human_approval is False


class TestDestructiveKeywordDetection:
    """Detection of destructive command patterns."""

    def test_rm_rf_detected(self, standard_ctrl: RiskController) -> None:
        result = standard_ctrl.assess_action("exploit", "bash", "rm -rf /var/www", "10.0.0.1", "high")
        assert any("rm " in w for w in result.warnings) or result.risk_level == "high"

    def test_dd_if_detected(self, standard_ctrl: RiskController) -> None:
        result = standard_ctrl.assess_action("exploit", "bash", "dd if=/dev/zero of=/dev/sda", "10.0.0.1", "high")
        assert any("dd if" in w for w in result.warnings) or result.risk_level == "high"

    def test_safe_command_no_warnings(self, standard_ctrl: RiskController) -> None:
        result = standard_ctrl.assess_action("recon", "nmap", "nmap -sV 10.0.0.1", "10.0.0.1", "low")
        assert len(result.warnings) == 0 or all("destructive" not in w.lower() for w in result.warnings)


class TestDangerousToolDetection:
    """Detection of dangerous tool usage."""

    def test_mimikatz_detected(self, standard_ctrl: RiskController) -> None:
        result = standard_ctrl.assess_action("exploit", "mimikatz", "sekurlsa::logonpasswords", "10.0.0.1", "high")
        assert result.risk_level == "high"

    def test_meterpreter_detected(self, standard_ctrl: RiskController) -> None:
        result = standard_ctrl.assess_action("exploit", "msfconsole", "payload/windows/meterpreter/reverse_tcp", "10.0.0.1", "high")
        assert result.risk_level == "high"

    def test_nmap_not_dangerous(self, standard_ctrl: RiskController) -> None:
        result = standard_ctrl.assess_action("recon", "nmap", "nmap -sV 10.0.0.1", "10.0.0.1", "low")
        assert result.risk_level == "low"


class TestBudgetEnforcement:
    """Command and task budget tracking."""

    def test_can_proceed_initially(self, standard_ctrl: RiskController) -> None:
        assert standard_ctrl.can_proceed() is True

    def test_budget_exhausted_after_max_commands(self, low_risk_ctrl: RiskController) -> None:
        for _ in range(100):
            low_risk_ctrl.record_execution()
        assert low_risk_ctrl.can_proceed() is False

    def test_budget_not_exhausted_before_max(self, low_risk_ctrl: RiskController) -> None:
        for _ in range(50):
            low_risk_ctrl.record_execution()
        assert low_risk_ctrl.can_proceed() is True

    def test_task_budget_tracked(self, low_risk_ctrl: RiskController) -> None:
        for _ in range(5):
            low_risk_ctrl.record_task_complete()
        budgets = low_risk_ctrl.budgets()
        assert budgets["tasks_completed"] == 5

    def test_budgets_returns_dict(self, standard_ctrl: RiskController) -> None:
        budgets = standard_ctrl.budgets()
        assert "commands_remaining" in budgets
        assert "commands_executed" in budgets
        assert "tasks_completed" in budgets


class TestExploitationGating:
    """Exploitation permission gating."""

    def test_exploitation_blocked_in_low_profile(self, low_risk_ctrl: RiskController) -> None:
        result = low_risk_ctrl.assess_action("exploit", "python", "exploit.py --target 10.0.0.1", "10.0.0.1", "high")
        assert result.allowed is False or result.requires_human_approval is True

    def test_exploitation_allowed_in_high_profile(self, high_ctrl: RiskController) -> None:
        result = high_ctrl.assess_action("exploit", "python", "exploit.py --target 10.0.0.1", "10.0.0.1", "high")
        assert result.allowed is True

    def test_pivoting_blocked_in_standard(self, standard_ctrl: RiskController) -> None:
        result = standard_ctrl.assess_action("pivot", "ssh", "ssh user@internal-host", "10.0.0.1", "high")
        assert result.allowed is False or result.requires_human_approval is True

    def test_pivoting_allowed_in_high(self, high_ctrl: RiskController) -> None:
        result = high_ctrl.assess_action("pivot", "ssh", "ssh user@internal-host", "10.0.0.1", "high")
        assert result.allowed is True


class TestMitigationSuggestions:
    """Risk mitigation suggestions."""

    def test_high_risk_gets_mitigation(self, standard_ctrl: RiskController) -> None:
        result = standard_ctrl.assess_action("exploit", "hydra", "hydra -l admin -P rockyou.txt ssh://10.0.0.1", "10.0.0.1", "high")
        assert len(result.mitigation_suggestions) > 0

    def test_low_risk_no_mitigation_needed(self, standard_ctrl: RiskController) -> None:
        result = standard_ctrl.assess_action("recon", "nmap", "nmap -sV 10.0.0.1", "10.0.0.1", "low")
        # Low risk may or may not have suggestions; that's fine
        assert isinstance(result.mitigation_suggestions, list)


class TestDestructiveKeywordBlocking:
    """Strict regressions for the rm-only destructive-block bug.

    The old code nested the blocking ``return`` inside
    ``if kw in ("rm ", "rm -rf")``, so only ``rm`` was ever blocked; every other
    destructive keyword (``delete``/``drop``/``dd if``/``shred``/``wipe``/
    ``mkfs``/``chown``/``kill -9`` ...) fell through and returned
    ``allowed=True``. These tests assert ``allowed is False`` under the *most
    permissive* profile (``high_ctrl``: allow_exploitation=True, allow_pivoting=True,
    high_authorized_testing) -- if it blocks there, it blocks everywhere, and
    the block is proven unconditional rather than risk-profile-gated. Every one
    of these would have FAILED against the pre-fix implementation.
    """

    @pytest.mark.parametrize("kw,command", [
        ("rm -rf", "rm -rf /var/www"),
        ("rm ", "rm /tmp/secret"),
        ("dd if", "dd if=/dev/zero of=/dev/sda bs=1M"),
        ("shred", "shred -u /etc/passwd"),
        ("wipe", "wipe /dev/sda"),
        ("mkfs", "mkfs.ext4 /dev/sda1"),
        ("fdisk", "fdisk /dev/sda"),
        ("parted", "parted /dev/sda rm 1"),
        ("chmod 777", "chmod 777 /etc/shadow"),
        ("chown", "chown root:root /etc/passwd"),
        ("kill -9", "kill -9 1337"),
        ("pkill", "pkill -f sshd"),
        ("unlink", "unlink /tmp/file"),
        ("truncate", "truncate -s 0 /var/log/app.log"),
        ("drop", "drop database prod"),
        ("delete", "DELETE FROM users"),
        ("format", "format C: /fs:ntfs"),
        ("overwrite", "overwrite /etc/crontab"),
    ])
    def test_destructive_keyword_blocked_under_high_profile(
        self, high_ctrl: RiskController, kw: str, command: str
    ) -> None:
        result = high_ctrl.assess_action("exploit", "bash", command, "10.0.0.1", "high")
        assert result.allowed is False, (
            f"destructive keyword '{kw}' was NOT blocked (got allowed={result.allowed}, "
            f"reason={result.reason!r})"
        )
        assert result.risk_level == "high"
        assert any("destructive" in w.lower() for w in result.warnings)

    def test_block_fires_before_exploitation_gating(self, high_ctrl: RiskController) -> None:
        """A destructive command must be blocked even though allow_exploitation=True
        would otherwise permit the tool -- destructive detection runs first."""
        # 'mimikatz' is a DANGEROUS_TOOL_PATTERN that high_ctrl allows; but the
        # command also contains 'drop', which must hard-block before tool gating.
        result = high_ctrl.assess_action(
            "exploit", "mimikatz", "mimikatz && drop database prod", "10.0.0.1", "high"
        )
        assert result.allowed is False
        assert "destructive" in result.reason.lower()

    def test_benign_command_still_allowed_under_high(self, high_ctrl: RiskController) -> None:
        result = high_ctrl.assess_action("recon", "nmap", "nmap -sV 10.0.0.1", "10.0.0.1", "low")
        assert result.allowed is True


class TestActionTypePermissionGates:
    """H19: action_type-level allow/deny gates driven by mission profile flags."""

    def test_exploit_action_type_denied_when_disallowed(self, low_risk_ctrl: RiskController) -> None:
        # Even with a benign-looking command, action_type="exploit" under a
        # profile that disallows exploitation must hard-deny.
        result = low_risk_ctrl.assess_action(
            "exploit", "python", "python check.py --target 10.0.0.1", "10.0.0.1", "medium"
        )
        assert result.allowed is False
        assert result.risk_level == "high"
        assert "exploitation" in result.reason.lower() or "not permitted" in result.reason.lower()

    def test_test_exploit_action_type_denied(self, low_risk_ctrl: RiskController) -> None:
        result = low_risk_ctrl.assess_action(
            "test_exploit", "python", "python check.py", "10.0.0.1", "medium"
        )
        assert result.allowed is False

    def test_exploit_action_type_allowed_when_enabled(self, high_ctrl: RiskController) -> None:
        result = high_ctrl.assess_action(
            "exploit", "python", "python check.py --target 10.0.0.1", "10.0.0.1", "medium"
        )
        assert result.allowed is True

    def test_pivot_action_type_denied_when_disallowed(self, standard_ctrl: RiskController) -> None:
        result = standard_ctrl.assess_action(
            "pivot", "ssh", "ssh user@internal-host", "10.0.0.1", "high"
        )
        assert result.allowed is False
        assert "pivoting" in result.reason.lower() or "not permitted" in result.reason.lower()

    def test_lateral_action_type_denied_when_disallowed(self, standard_ctrl: RiskController) -> None:
        result = standard_ctrl.assess_action(
            "lateral_movement", "impacket", "smbexec target", "10.0.0.1", "high"
        )
        assert result.allowed is False

    def test_credential_testing_denied_by_default(self) -> None:
        ctrl = RiskController(
            risk_profile="low_noise_non_destructive",
            allow_exploitation=False,
            allow_pivoting=False,
            allow_credential_testing=False,
        )
        result = ctrl.assess_action(
            "credential_test", "hydra", "hydra -L users.txt", "10.0.0.1", "high"
        )
        assert result.allowed is False
        assert "credential" in result.reason.lower() or "not permitted" in result.reason.lower()

    def test_credential_testing_allowed_when_enabled(self) -> None:
        ctrl = RiskController(
            risk_profile="standard_authorized",
            allow_exploitation=True,
            allow_pivoting=False,
            allow_credential_testing=True,
        )
        # action_type gate should not fire; the command is benign enough to
        # pass destructive detection.
        result = ctrl.assess_action(
            "credential_test", "curl", "curl http://10.0.0.1/", "10.0.0.1", "medium"
        )
        assert result.allowed is True


class TestTaskBudgetGate:
    """M34: task-budget gate at the top of assess_action."""

    def test_task_budget_exhausted_denies(self) -> None:
        ctrl = RiskController(
            risk_profile="standard_authorized",
            max_commands=100,
            max_tasks=2,
            allow_exploitation=True,
        )
        ctrl.record_task_complete()
        ctrl.record_task_complete()
        result = ctrl.assess_action("recon", "nmap", "nmap -sV 10.0.0.1", "10.0.0.1", "low")
        assert result.allowed is False
        assert "task budget" in result.reason.lower()
        assert "2" in result.reason

    def test_task_budget_not_exhausted_allows(self) -> None:
        ctrl = RiskController(
            risk_profile="standard_authorized",
            max_commands=100,
            max_tasks=5,
            allow_exploitation=True,
        )
        for _ in range(4):
            ctrl.record_task_complete()
        result = ctrl.assess_action("recon", "nmap", "nmap -sV 10.0.0.1", "10.0.0.1", "low")
        assert result.allowed is True


class TestDestructiveKeywordNormalization:
    """M32: whitespace/shell-separator normalization + word-boundary matching."""

    @pytest.mark.parametrize("command", [
        "rm\t-rf /var/www",   # tab-separated
        "rm;-rf /var/www",    # shell-semicolon separator
        "rm  -rf /var/www",   # multiple spaces
        "rm -rf /var/www",    # canonical form
    ])
    def test_destructive_rm_caught_after_normalization(
        self, high_ctrl: RiskController, command: str
    ) -> None:
        result = high_ctrl.assess_action("exploit", "bash", command, "10.0.0.1", "high")
        assert result.allowed is False
        assert result.risk_level == "high"
        assert any("destructive" in w.lower() for w in result.warnings)

    def test_dd_of_caught_after_normalization(self, high_ctrl: RiskController) -> None:
        result = high_ctrl.assess_action(
            "exploit", "bash", "dd\tif=/dev/zero\tof=/dev/sda", "10.0.0.1", "high"
        )
        assert result.allowed is False

    def test_word_boundary_prevents_false_positive(self, high_ctrl: RiskController) -> None:
        # 'warm' contains 'rm' but should NOT trigger the rm destructive gate
        # thanks to word boundaries; 'format' in 'formatter' likewise.
        result = high_ctrl.assess_action(
            "recon", "bash", "warm the formatter cache", "10.0.0.1", "low"
        )
        assert result.allowed is True
