"""Adversarial tests: the anti-brute-force behavior of the fingerprint system.

These prove the tracker refuses to promote unjustified retries (spelling
variants, case/whitespace churn, REFUTED-without-evidence) and only yields
when material evidence actually changed.
"""

from tools.intelligence.fingerprint import (
    ActionFamily,
    Attempt,
    AttemptStatus,
    AttemptTracker,
    RetryJustification,
)


def _ssh_brute(target: str) -> Attempt:
    return Attempt(
        target=target,
        service="ssh",
        action_family=ActionFamily.BRUTE_FORCE,
        parameters=("user=root", "passwords=<redacted>"),
        hypothesis="weak root password",
        technique_category="ssh brute force",
        expected_observation="auth success",
    )


def test_a_ten_spelling_variants_dedup_to_one_fingerprint():
    targets = [
        "10.0.0.1",
        " 10.0.0.1",
        "10.0.0.1 ",
        "10.0.0.1  ",
        " 10.0.0.1 ",
        "10.0.0.1\t",
        "\t10.0.0.1\t",
        "10.0.0.1\n",
        "10.0.0.1 ",
        " 10.0.0.1  ",
    ]
    tracker = AttemptTracker()
    keys = {tracker.record(_ssh_brute(t), AttemptStatus.ATTEMPTED) for t in targets}
    assert len(keys) == 1
    assert len(tracker.all_fingerprints()) == 1


def test_b_refuted_retry_without_evidence_not_promoted():
    tracker = AttemptTracker()
    attempt = _ssh_brute("10.0.0.1")
    key = tracker.record(attempt, AttemptStatus.REFUTED, detail="hypothesis contradicted", evidence_snapshot={"version_known": "2.0"})
    is_rep, reason, detail = tracker.is_repetition(key, {"version_known": "2.0"})
    assert is_rep is True
    assert reason is RetryJustification.NONE
    assert "no material evidence change" in detail


def test_c_refuted_retry_with_new_version_is_justified():
    tracker = AttemptTracker()
    attempt = _ssh_brute("10.0.0.1")
    key = tracker.record(attempt, AttemptStatus.REFUTED, detail="hypothesis contradicted", evidence_snapshot={"version_known": "2.0"})
    is_rep, reason, _detail = tracker.is_repetition(key, {"version_known": "2.1"})
    assert is_rep is True
    assert reason is RetryJustification.NEW_VERSION_EVIDENCE


def test_d_blocked_is_not_terminal():
    tracker = AttemptTracker()
    attempt = _ssh_brute("10.0.0.1")
    key = tracker.record(attempt, AttemptStatus.BLOCKED, detail="scope gate", evidence_snapshot={"version_known": "2.0"})
    is_rep, reason, _detail = tracker.is_repetition(key, {"version_known": "2.0"})
    assert is_rep is False
    assert reason is RetryJustification.NONE


def test_e_case_and_whitespace_normalize_to_same_fingerprint():
    a = _ssh_brute("10.0.0.1")
    b = _ssh_brute("10.0.0.1 ")
    assert a.fingerprint() == b.fingerprint()
    assert _ssh_brute("10.0.0.1").fingerprint() == _ssh_brute("10.0.0.1").fingerprint()
