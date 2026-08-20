"""Unit tests for tools/intelligence/fingerprint — dedup, justification, masking."""

from tools.intelligence.fingerprint import (
    PERMANENT_FAILURE_MARKERS,
    ActionFamily,
    Attempt,
    AttemptStatus,
    AttemptTracker,
    RetryJustification,
    RetryJustifier,
    is_permanent_failure,
    mask_secrets,
)


def _attempt(**overrides) -> Attempt:
    base = dict(
        target="10.0.0.5",
        service="ssh",
        action_family=ActionFamily.BRUTE_FORCE,
        parameters=("user=admin", "threads=4"),
        hypothesis="default creds",
        technique_category="password spray",
        expected_observation="auth success",
    )
    base.update(overrides)
    return Attempt(**base)


def test_identical_attempts_same_fingerprint():
    assert _attempt().fingerprint() == _attempt().fingerprint()


def test_params_sorted_at_canonicalization():
    a = _attempt(parameters=("threads=4", "user=admin"))
    b = _attempt(parameters=("user=admin", "threads=4"))
    assert a.fingerprint() == b.fingerprint()


def test_different_targets_different_fingerprints():
    assert _attempt(target="10.0.0.6").fingerprint() != _attempt().fingerprint()


def test_different_services_different_fingerprints():
    assert _attempt(service="http").fingerprint() != _attempt().fingerprint()


def test_record_dedup_returns_same_key_and_bumps_repeat():
    tracker = AttemptTracker()
    key1 = tracker.record(_attempt(), AttemptStatus.ATTEMPTED, detail="first")
    key2 = tracker.record(_attempt(), AttemptStatus.ATTEMPTED, detail="second")
    assert key1 == key2
    assert len(tracker.all_fingerprints()) == 1
    assert tracker.status_of(key1) is AttemptStatus.ATTEMPTED
    assert tracker.retry_history(key1)[-1] == ("", "repeat", "second")


def test_justifier_version_change():
    justifier = RetryJustifier()
    attempt = _attempt()
    reason, detail = justifier.evaluate(
        attempt,
        {
            "version_known": "2.1",
            "previous_evidence": {"version_known": "2.0"},
        },
    )
    assert reason is RetryJustification.NEW_VERSION_EVIDENCE
    assert "version" in detail


def test_justifier_no_change_is_none():
    justifier = RetryJustifier()
    reason, _detail = justifier.evaluate(
        _attempt(),
        {
            "version_known": "2.0",
            "previous_evidence": {"version_known": "2.0"},
        },
    )
    assert reason is RetryJustification.NONE


def test_is_repetition_true_unchanged_after_failed():
    tracker = AttemptTracker()
    attempt = _attempt()
    key = tracker.record(attempt, AttemptStatus.FAILED, detail="auth failed", evidence_snapshot={"version_known": "2.0"})
    is_rep, reason, detail = tracker.is_repetition(key, {"version_known": "2.0"})
    assert is_rep is True
    assert reason is RetryJustification.NONE
    assert "no material evidence change" in detail


def test_is_repetition_false_when_evidence_changed():
    tracker = AttemptTracker()
    attempt = _attempt()
    key = tracker.record(attempt, AttemptStatus.FAILED, evidence_snapshot={"version_known": "2.0"})
    is_rep, reason, _detail = tracker.is_repetition(key, {"version_known": "2.1"})
    assert is_rep is True
    assert reason is RetryJustification.NEW_VERSION_EVIDENCE


def test_permanent_failure_markers():
    assert is_permanent_failure("ERROR: out of scope")
    assert is_permanent_failure("Connection Refused")
    assert not is_permanent_failure("grep: no such file")


def test_action_family_for_tool():
    assert ActionFamily.for_tool("nmap") is ActionFamily.RECON_SCAN
    assert ActionFamily.for_tool("hydra") is ActionFamily.BRUTE_FORCE
    assert ActionFamily.for_tool("custom_fuzz_tool") is ActionFamily.TOOL_OTHER


def test_mask_secrets_preserves_username():
    masked = mask_secrets({"username": "admin", "password": "hunter2"})
    assert masked["username"] == "admin"
    assert masked["password"] == "<redacted>"


def test_markers_tuple_is_complete_vocabulary():
    assert "out of scope" in PERMANENT_FAILURE_MARKERS
    assert "connection refused" in PERMANENT_FAILURE_MARKERS
