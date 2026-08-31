"""Domain-model contract tests for tools/browser (architecture-only build).

Verifies the provider-neutral browser session/action/observation/artifact
models: deterministic to_dict, tolerant from_dict, enum fallbacks, the session
lifecycle transition map, and the failure-class mapping onto the global
taxonomy (``tools/failure_taxonomy.py``). No browser, no network, no backend.
"""

from __future__ import annotations

import pytest

from tools.browser.models import (
    REDACTED,
    BrowserAction,
    BrowserActionKind,
    BrowserArtifact,
    BrowserArtifactKind,
    BrowserCookie,
    BrowserError,
    BrowserEventDirection,
    BrowserFailureClass,
    BrowserNetworkEvent,
    BrowserObservation,
    BrowserObservationKind,
    BrowserPageState,
    BrowserResult,
    BrowserSession,
    BrowserSessionState,
    BrowserStorageKind,
    BrowserStorageSnapshot,
    new_session_id,
    validate_session_transition,
)
from tools.browser.errors import BrowserTransitionError
from tools.failure_taxonomy import FailureClass


# ── Deterministic serialization ───────────────────────────────────────────


@pytest.mark.parametrize(
    "obj",
    [
        BrowserAction(action_id="a-1", session_id="bs-0001-ab",
                      parameters={"url": "http://127.0.0.1/login"}, target_ip="10.0.0.50"),
        BrowserResult(success=False, failure_class=BrowserFailureClass.TIMEOUT, retryable=True, confidence=0.5),
        BrowserSession(session_id="bs-0001-ab", run_id="run-1", target_ip="10.0.0.50"),
        BrowserPageState(session_id="bs-0001-ab", url="http://127.0.0.1/", title="Login"),
        BrowserCookie(name="session", value="sekrit"),
    ],
)
def test_to_dict_is_deterministic(obj):
    """to_dict twice yields identical key order and values (house convention)."""
    assert obj.to_dict() == obj.to_dict()
    assert list(obj.to_dict()) == list(obj.to_dict())


def test_session_id_format():
    sid = new_session_id(7)
    assert sid.startswith("bs-0007-")
    assert len(sid.split("-")[-1]) == 12


# ── Tolerant from_dict ────────────────────────────────────────────────────


def test_from_dict_tolerates_unknown_enum_and_missing_keys():
    payload = {
        "action_id": "a-2",  # session_id/kind omitted
        "kind": "quantum_leap",  # unknown kind -> default (navigate)
    }
    action = BrowserAction.from_dict(payload)
    assert action.session_id == ""
    assert action.kind is BrowserActionKind.NAVIGATE
    assert action.parameters == {}
    assert action.target_ip == ""


def test_from_dict_none_yields_defaults():
    result = BrowserResult.from_dict(None)
    assert result.success is False
    assert result.failure_class is BrowserFailureClass.UNKNOWN
    assert result.error is None


def test_result_roundtrip_preserves_errors_and_refs():
    result = BrowserResult(
        success=False,
        failure_class=BrowserFailureClass.BACKEND_UNAVAILABLE,
        retryable=False,
        action_id="a-3",
        evidence_refs=["exploit_audit:10.0.0.50:att1"],
        follow_ups=["recheck backend config"],
        error=BrowserError(failure_class=BrowserFailureClass.BACKEND_UNAVAILABLE, message="none", source="manager"),
    )
    revived = BrowserResult.from_dict(result.to_dict())
    assert revived == result


# ── Session lifecycle transitions ─────────────────────────────────────────


def test_valid_lifecycle_transitions_pass():
    validate_session_transition(BrowserSessionState.PENDING, BrowserSessionState.STARTING)
    validate_session_transition(BrowserSessionState.STARTING, BrowserSessionState.READY)
    validate_session_transition(BrowserSessionState.READY, BrowserSessionState.ACTIVE)
    validate_session_transition(BrowserSessionState.ACTIVE, BrowserSessionState.STOPPING)
    validate_session_transition(BrowserSessionState.STOPPING, BrowserSessionState.CLOSED)


@pytest.mark.parametrize(
    ("current", "new"),
    [
        (BrowserSessionState.PENDING, BrowserSessionState.READY),  # must pass through STARTING
        (BrowserSessionState.CLOSED, BrowserSessionState.READY),  # terminal is terminal
        (BrowserSessionState.FAILED, BrowserSessionState.ACTIVE),
        (BrowserSessionState.STOPPING, BrowserSessionState.ACTIVE),
        (BrowserSessionState.ACTIVE, BrowserSessionState.PENDING),
    ],
)
def test_invalid_transitions_raise(current, new):
    with pytest.raises(BrowserTransitionError):
        validate_session_transition(current, new)


# ── Failure-class taxonomy mapping ────────────────────────────────────────


def test_overlapping_failure_classes_map_to_global_taxonomy():
    assert BrowserFailureClass.BACKEND_UNAVAILABLE.failure_class() is FailureClass.TOOL_UNAVAILABLE
    assert BrowserFailureClass.SCOPE_BLOCKED.failure_class() is FailureClass.SCOPE_BLOCKED
    assert BrowserFailureClass.NETWORK_ERROR.failure_class() is FailureClass.TRANSPORT_ERROR
    assert BrowserFailureClass.TIMEOUT.failure_class() is FailureClass.TIMEOUT


def test_browser_only_failure_classes_have_no_global_mapping():
    for cls in (BrowserFailureClass.SESSION_NOT_FOUND, BrowserFailureClass.INVALID_TRANSITION,
                BrowserFailureClass.NAVIGATION_FAILED, BrowserFailureClass.SCRIPT_ERROR):
        assert cls.failure_class() is None


def test_network_event_direction_defaults():
    event = BrowserNetworkEvent(event_id="e-1", session_id="s-1")
    assert event.direction is BrowserEventDirection.REQUEST
    revived = BrowserNetworkEvent.from_dict(event.to_dict())
    assert revived == event


def test_artifact_evidence_type_default_maps_to_legacy_store():
    art = BrowserArtifact(artifact_id="ba-1", session_id="s-1", kind=BrowserArtifactKind.SCREENSHOT)
    assert art.evidence_type == "file"
    assert BrowserArtifact.from_dict(art.to_dict()) == art


# ── Observation audit digest ──────────────────────────────────────────────


def test_observation_audit_dict_drops_payload():
    obs = BrowserObservation(
        observation_id="o-1", session_id="s-1", kind=BrowserObservationKind.PAGE_STATE,
        payload={"title": "admin panel", "secret": "hunter2"}, evidence_refs=["browser_artifact:ba-1"],
    )
    audit = obs.to_audit_dict()
    assert "payload" not in audit  # raw payload must never reach generic audit metadata
    assert audit["payload_digest"]["keys"] == ["secret", "title"]
    assert audit["payload_digest"]["field_count"] == 2
    assert audit["evidence_refs"] == ["browser_artifact:ba-1"]


def test_storage_snapshot_kind_serialized_via_value():
    snap = BrowserStorageSnapshot(origin="http://10.0.0.50", storage_kind=BrowserStorageKind.LOCAL_STORAGE)
    assert snap.to_dict()["storage_kind"] == "local_storage"
    assert BrowserStorageSnapshot.from_dict(snap.to_dict()) == snap


def test_redacted_marker_constant():
    assert REDACTED == "***REDACTED***"