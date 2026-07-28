"""Phase 1.1 — richer outcome taxonomy in ``_ToolOutcomeTracker``.

Covers the new ``record_compromise`` / ``record_partial`` / ``record_cred_dump``
methods, the ``should_escalate`` / ``should_pivot`` signals, and confirms the
existing ``record_success`` / ``record_exploit_success`` /
``record_exploit_failure`` / ``record_blocked`` / ``should_consult_peers`` /
``summary`` paths still behave. The tracker is a pure in-memory object (no DB
/ IO) so the tests are synchronous and self-contained.
"""

from __future__ import annotations

from tools.exploit_agent.tool_calls import _ToolOutcomeTracker


# ── record_compromise ──────────────────────────────────────────────────────


def test_record_compromise_increments_count_and_sets_last_outcome():
    t = _ToolOutcomeTracker()
    t.record_compromise(shell_type="meterpreter", privilege_level="root")
    assert t.compromise_count == 1
    assert t.last_outcome == "compromise"
    assert t.last_shell_type == "meterpreter"
    assert t.last_privilege_level == "root"


def test_record_compromise_resets_consecutive_exploit_failures():
    t = _ToolOutcomeTracker()
    t.record_exploit_failure()
    t.record_exploit_failure()
    assert t.consecutive_exploit_failures == 2
    t.record_compromise(shell_type="sh", privilege_level="www-data")
    assert t.consecutive_exploit_failures == 0


def test_record_compromise_resets_consecutive_blocked():
    t = _ToolOutcomeTracker()
    t.record_blocked("run_exploit_terminal", {"command": "x"}, "nope")
    t.record_blocked("run_exploit_terminal", {"command": "x"}, "nope")
    assert t.consecutive_blocked == 2
    t.record_compromise(shell_type="sh", privilege_level="www-data")
    assert t.consecutive_blocked == 0


def test_record_compromise_without_args_defaults_to_empty_strings():
    t = _ToolOutcomeTracker()
    t.record_compromise()
    assert t.compromise_count == 1
    assert t.last_shell_type == ""
    assert t.last_privilege_level == ""


# ── record_partial ──────────────────────────────────────────────────────────


def test_record_partial_increments_count_and_sets_last_outcome():
    t = _ToolOutcomeTracker()
    t.record_partial(reason="access is denied")
    assert t.partial_count == 1
    assert t.last_outcome == "partial"
    assert "access is denied" in t.last_reason


def test_record_partial_does_not_increment_exploit_failures():
    t = _ToolOutcomeTracker()
    t.record_exploit_failure()
    before = t.consecutive_exploit_failures
    t.record_partial(reason="limited")
    assert t.consecutive_exploit_failures == before


def test_record_partial_without_reason_leaves_last_reason_unchanged():
    t = _ToolOutcomeTracker()
    t.record_blocked("foo", {}, "blocked reason")
    t.record_partial()
    assert t.partial_count == 1
    # last_reason was set by the blocked call; record_partial() with no reason
    # must not clobber it.
    assert t.last_reason == "blocked reason"


# ── record_cred_dump ────────────────────────────────────────────────────────


def test_record_cred_dump_increments_count_and_sets_last_outcome():
    t = _ToolOutcomeTracker()
    t.record_cred_dump()
    assert t.cred_dump_count == 1
    assert t.last_outcome == "cred_dump"


def test_record_cred_dump_does_not_reset_compromise_counters():
    t = _ToolOutcomeTracker()
    t.record_compromise(shell_type="sh", privilege_level="www-data")
    t.record_exploit_failure()
    t.record_cred_dump()
    # A cred dump is a strong signal but distinct from a shell compromise: it
    # must not reset the exploit-failure counter or the compromise counters.
    assert t.consecutive_exploit_failures == 1
    assert t.compromise_count == 1


# ── should_escalate ─────────────────────────────────────────────────────────


def test_should_escalate_true_when_compromise_without_root():
    t = _ToolOutcomeTracker()
    t.record_compromise(shell_type="sh", privilege_level="www-data")
    assert t.should_escalate() is True


def test_should_escalate_false_when_no_compromise():
    t = _ToolOutcomeTracker()
    assert t.should_escalate() is False
    t.record_exploit_success()
    assert t.should_escalate() is False


def test_should_escalate_false_when_privilege_is_root():
    t = _ToolOutcomeTracker()
    t.record_compromise(shell_type="sh", privilege_level="root")
    assert t.should_escalate() is False


def test_should_escalate_false_when_privilege_is_system():
    t = _ToolOutcomeTracker()
    t.record_compromise(shell_type="cmd", privilege_level="NT AUTHORITY\\SYSTEM")
    assert t.should_escalate() is False


def test_should_escalate_false_after_escalation_confirmed_flag():
    t = _ToolOutcomeTracker()
    t.record_compromise(shell_type="sh", privilege_level="www-data")
    assert t.should_escalate() is True
    t.escalation_confirmed = True
    assert t.should_escalate() is False


def test_should_escalate_true_when_privilege_level_unknown():
    # A compromise recorded without a privilege level is treated as not-yet-
    # escalated (the orchestrator should investigate).
    t = _ToolOutcomeTracker()
    t.record_compromise(shell_type="meterpreter")
    assert t.should_escalate() is True


# ── should_pivot ────────────────────────────────────────────────────────────


def test_should_pivot_false_when_no_compromise():
    t = _ToolOutcomeTracker()
    t.pivot_targets = {"10.0.0.5"}
    assert t.should_pivot() is False


def test_should_pivot_false_when_no_pivot_targets():
    t = _ToolOutcomeTracker()
    t.record_compromise(shell_type="sh", privilege_level="www-data")
    assert t.should_pivot() is False


def test_should_pivot_true_when_compromise_and_targets_remain():
    t = _ToolOutcomeTracker()
    t.record_compromise(shell_type="sh", privilege_level="www-data")
    t.pivot_targets = {"10.0.0.5", "10.0.0.6"}
    assert t.should_pivot() is True


def test_should_pivot_false_when_pivot_targets_exhausted():
    t = _ToolOutcomeTracker()
    t.record_compromise(shell_type="sh", privilege_level="www-data")
    t.pivot_targets = {"10.0.0.5"}
    t.pivot_targets_exhausted = True
    assert t.should_pivot() is False


def test_should_pivot_becomes_false_when_targets_drained():
    t = _ToolOutcomeTracker()
    t.record_compromise(shell_type="sh", privilege_level="www-data")
    t.pivot_targets = {"10.0.0.5"}
    assert t.should_pivot() is True
    t.pivot_targets.clear()
    assert t.should_pivot() is False


# ── Existing methods preserved ──────────────────────────────────────────────


def test_record_success_resets_blocked_and_sets_last_outcome():
    t = _ToolOutcomeTracker()
    t.record_blocked("foo", {}, "nope")
    t.record_success()
    assert t.consecutive_blocked == 0
    assert t.last_outcome == "success"


def test_record_exploit_success_resets_failures_and_sets_last_outcome():
    t = _ToolOutcomeTracker()
    t.record_exploit_failure()
    t.record_exploit_success()
    assert t.consecutive_exploit_failures == 0
    assert t.last_outcome == "success"


def test_record_exploit_failure_sets_last_outcome():
    t = _ToolOutcomeTracker()
    n = t.record_exploit_failure()
    assert n == 1
    assert t.last_outcome == "failure"


def test_should_consult_peers_threshold_gate():
    t = _ToolOutcomeTracker()
    t.record_exploit_failure()
    t.record_exploit_failure()
    assert t.should_consult_peers(3) is False
    t.record_exploit_failure()
    assert t.should_consult_peers(3) is True
    # threshold <= 0 disables
    assert t.should_consult_peers(0) is False


def test_record_blocked_sets_last_outcome_and_returns_constraint_flag():
    t = _ToolOutcomeTracker(threshold=2)
    first = t.record_blocked("foo", {"x": 1}, "nope")
    assert first is False
    assert t.last_outcome == "blocked"
    second = t.record_blocked("foo", {"x": 1}, "nope")
    assert second is True  # threshold reached


# ── summary ─────────────────────────────────────────────────────────────────


def test_summary_includes_new_counts_when_nonzero():
    t = _ToolOutcomeTracker()
    t.record_compromise(shell_type="sh", privilege_level="www-data")
    t.record_cred_dump()
    t.record_partial(reason="limited")
    s = t.summary()
    assert "compromises: 1" in s
    assert "cred dumps: 1" in s
    assert "partials: 1" in s
    # last_outcome reflects the most recent call (record_partial).
    assert "last outcome: partial" in s
    assert "shell: sh" in s
    assert "privilege: www-data" in s


def test_summary_omits_zero_taxonomy_counts():
    t = _ToolOutcomeTracker()
    # Only a blocked call, no compromise/cred/partial.
    t.record_blocked("foo", {}, "nope")
    s = t.summary()
    assert "compromises" not in s
    assert "cred dumps" not in s
    assert "partials" not in s
    # last_outcome is "blocked" which is still surfaced.
    assert "last outcome: blocked" in s


def test_summary_preserves_blocked_and_repeated_call_sections():
    t = _ToolOutcomeTracker()
    t.record_blocked("foo", {"x": 1}, "nope")
    t.record_blocked("foo", {"x": 1}, "nope")
    s = t.summary()
    assert "consecutive blocked/unavailable outcomes: 2" in s
    assert "repeated calls:" in s
    assert "last tool: foo" in s