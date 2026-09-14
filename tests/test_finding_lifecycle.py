"""Canonical finding lifecycle (#04): the machine every surface enforces."""

from __future__ import annotations

import pytest

from tools.kernel.finding_lifecycle import (
    APPROVED,
    FIXED,
    HOLDING,
    INCONCLUSIVE,
    PROPOSED,
    REJECTED,
    STILL_OPEN,
    VERIFIED,
    allowed_transitions,
    check_transition,
)


def test_human_approval_path():
    assert check_transition(PROPOSED, APPROVED, "human").actor == "human"
    assert check_transition(PROPOSED, REJECTED, "human").to_state == REJECTED


def test_agent_cannot_self_approve_or_verify():
    with pytest.raises(ValueError):
        check_transition(PROPOSED, APPROVED, "agent")
    with pytest.raises(ValueError):
        check_transition(APPROVED, VERIFIED, "agent")
    with pytest.raises(ValueError):
        check_transition(PROPOSED, VERIFIED, "agent")
    with pytest.raises(ValueError):
        check_transition(PROPOSED, APPROVED, "oracle")


def test_only_oracle_verifies():
    assert check_transition(APPROVED, VERIFIED, "oracle").to_state == VERIFIED
    assert check_transition(PROPOSED, VERIFIED, "oracle").to_state == VERIFIED
    assert check_transition(APPROVED, HOLDING, "oracle").to_state == HOLDING
    with pytest.raises(ValueError):
        check_transition(APPROVED, VERIFIED, "human")


def test_only_retest_closes_verified():
    assert check_transition(VERIFIED, STILL_OPEN, "retest").to_state == STILL_OPEN
    assert check_transition(VERIFIED, FIXED, "retest").to_state == FIXED
    assert check_transition(STILL_OPEN, FIXED, "retest").to_state == FIXED
    with pytest.raises(ValueError):
        check_transition(VERIFIED, FIXED, "oracle")
    with pytest.raises(ValueError):
        check_transition(VERIFIED, FIXED, "human")


def test_terminal_states_accept_nothing():
    assert allowed_transitions(REJECTED) == {}
    assert allowed_transitions(FIXED) == {}
    with pytest.raises(ValueError):
        check_transition(REJECTED, APPROVED, "human")
    with pytest.raises(ValueError):
        check_transition(FIXED, STILL_OPEN, "retest")
    with pytest.raises(ValueError):
        check_transition("BOGUS", APPROVED, "human")


def test_lifecycle_version_pinned():
    from tools.kernel.finding_lifecycle import LIFECYCLE_VERSION

    assert LIFECYCLE_VERSION == 1
    assert INCONCLUSIVE in allowed_transitions(HOLDING)
