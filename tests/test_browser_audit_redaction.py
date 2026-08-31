"""Secret-redaction tests for browser serialization surfaces (design §audit).

Contract (docs/browser-agent-design.md): browser material is full of secrets —
cookie values, bearer tokens, Authorization headers, URL credentials,
localStorage/sessionStorage entries. NONE of it may ever reach generic audit
metadata, logs, or unredacted evidence. Every browser serialization surface
must structurally redact by default, and the generic-audit form (``to_audit_
dict`` / digest rows) must drop payloads entirely.
"""

from __future__ import annotations

import json

import pytest

from tools.browser.models import (
    BrowserCookie,
    BrowserNetworkEvent,
    BrowserObservation,
    BrowserObservationKind,
    BrowserStorageKind,
    BrowserStorageSnapshot,
    redact_value,
)

SECRET_TOKEN = "sk-SUPER-SECRET-SESSION-TOKEN-1234567890abcdef"
BEARER = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.STAGE_SECRET_SIGNATURE_PART"
URL_WITH_CREDS = "https://admin:hunter2pass@10.0.0.50/admin/login"


def _assert_no_secret(obj, label):
    blob = json.dumps(obj)
    assert "SUPER-SECRET-SESSION-TOKEN" not in blob, f"{label} leaked the session token"
    assert "STAGE_SECRET_SIGNATURE_PART" not in blob, f"{label} leaked the bearer token"
    assert "hunter2pass" not in blob, f"{label} leaked URL credentials"  # noqa: S105


# ── Cookies / storage: redacted by default ────────────────────────────────


def test_cookie_to_dict_redacts_value_by_default():
    cookie = BrowserCookie(name="session", value=SECRET_TOKEN, domain="10.0.0.50")
    assert cookie.to_dict()["value"] == "***REDACTED***"
    _assert_no_secret(cookie.to_dict(), "BrowserCookie.to_dict")


def test_cookie_raw_value_requires_explicit_opt_in():
    cookie = BrowserCookie(name="session", value=SECRET_TOKEN)
    assert cookie.to_dict(redact=False)["value"] == SECRET_TOKEN


def test_storage_snapshot_redacts_entry_values_by_default():
    snap = BrowserStorageSnapshot(
        origin="http://10.0.0.50",
        storage_kind=BrowserStorageKind.LOCAL_STORAGE,
        entries=[{"key": "auth_token", "value": SECRET_TOKEN}, {"key": "theme", "value": "dark"}],
    )
    entries = snap.to_dict()["entries"]
    assert entries[0]["value"] == "***REDACTED***"
    # Storage entry VALUES are credential material — every one is redacted;
    # key structure survives ("key": "theme" is intact).
    assert entries[1]["value"] == "***REDACTED***"
    assert entries[1]["key"] == "theme"
    _assert_no_secret(snap.to_dict(), "BrowserStorageSnapshot.to_dict")


# ── Network events: headers/body/url must be redacted before logging ──────


def _network_event() -> BrowserNetworkEvent:
    return BrowserNetworkEvent(
        event_id="e-1",
        session_id="s-1",
        method="POST",
        url=URL_WITH_CREDS,
        request_headers={"Authorization": BEARER, "X-Custom": "fine"},
        response_headers={"Set-Cookie": f"session={SECRET_TOKEN}; Path=/"},
        body_sample=f'{{"password": "{SECRET_TOKEN}"}}',
    )


def test_raw_network_event_to_dict_keeps_values_in_memory_only():
    """to_dict is the internal in-memory shape; it is NOT audit-safe by design."""
    raw = _network_event().to_dict()
    assert raw["request_headers"]["Authorization"] == BEARER  # caller must redact


def test_redacted_network_event_masks_secrets():
    red = _network_event().to_redacted_dict()
    _assert_no_secret(red, "BrowserNetworkEvent.to_redacted_dict")
    # Non-secret header values survive.
    assert red["request_headers"]["X-Custom"] == "fine"
    # Secret-named keys are redacted, not dropped (structure preserved).
    assert red["response_headers"]["Set-Cookie"] != f"session={SECRET_TOKEN}; Path=/"
    assert red["body_sample"] != _network_event().body_sample


# ── Generic audit metadata: payload never serialized ──────────────────────


def test_observation_audit_form_never_carries_secrets():
    obs = BrowserObservation(
        observation_id="o-1",
        session_id="s-1",
        kind=BrowserObservationKind.NETWORK,
        sensitive=True,
        payload={"events": [{"url": URL_WITH_CREDS, "authorization": BEARER, "password": SECRET_TOKEN}]},
        metadata={"run_id": "run-1"},
    )
    # The ONLY shape that may enter generic audit metadata is the digest form.
    _assert_no_secret(obs.to_audit_dict(), "BrowserObservation.to_audit_dict")
    assert "payload" not in obs.to_audit_dict()

    # Even the redacted full form must not leak the secrets.
    _assert_no_secret(obs.to_redacted_dict(), "BrowserObservation.to_redacted_dict")


def test_sensitive_observation_redaction_masks_nested_storage_payload():
    obs = BrowserObservation(
        observation_id="o-2",
        session_id="s-1",
        kind=BrowserObservationKind.STORAGE,
        sensitive=True,
        payload={"sessionStorage": {"auth_token": SECRET_TOKEN}, "cookie_value": SECRET_TOKEN},
    )
    red = obs.to_redacted_dict()
    payload = red["payload"]
    # Secret-named keys are redacted by the shared kernel redactor.
    _assert_no_secret(payload, "sensitive observation payload")
    assert payload["sessionStorage"] != {"auth_token": SECRET_TOKEN}


def test_redact_value_uses_the_kernel_audit_table():
    """One redaction table with the rest of the audit trail (no parallel system)."""
    from tools.kernel.audit import _REDACTED as KERNEL_REDACTED

    assert redact_value({"password": SECRET_TOKEN}) == {"password": KERNEL_REDACTED}
    assert KERNEL_REDACTED in redact_value(f"Authorization: {BEARER}")
    assert "hunter2pass" not in str(redact_value(URL_WITH_CREDS))


@pytest.mark.parametrize(
    "surface_name",
    ["cookie", "storage", "network"],
)
def test_json_roundtrip_of_redacted_forms_is_secret_free(surface_name):
    """Even serialized redacted artifacts (e.g. pasted into a report) stay safe."""
    surfaces = {
        "cookie": [BrowserCookie(name="session", value=SECRET_TOKEN).to_dict()],
        "storage": [
            BrowserStorageSnapshot(origin="http://10.0.0.50", entries=[{"key": "t", "value": SECRET_TOKEN}]).to_dict()
        ],
        "network": [_network_event().to_redacted_dict()],
    }
    _assert_no_secret(surfaces[surface_name], surface_name)
