"""Sandbox family-audit registration for the FUTURE browser family.

Design contract (docs/browser-agent-design.md §sandbox requirements): the
browser family is registered in the sandbox containment audit as
``planned`` — architecture exists (tools/browser/), implementation does not,
and NOTHING launches a browser today. The pre-committed containment terms:
when the backend lands it MUST be registered as sandboxed (or a documented
host exception), and its execution must run inside the sandbox worker with
the same effective target allowlist as other offensive tooling.
"""

from __future__ import annotations

from tools.sandbox.family_audit import (
    HOST_EXCEPTIONS,
    PLANNED_FAMILIES,
    SANDBOXED_FAMILIES,
    audit_families,
    describe_family_audit,
)


def test_browser_is_registered_as_a_planned_family():
    assert "browser" in PLANNED_FAMILIES
    entry = PLANNED_FAMILIES["browser"]
    assert entry.status == "planned"
    assert entry.target_touching is True
    # The contract must be written down: future backend must be sandboxed +
    # target-allowlisted — no host fallback, no weakening of the audit tests.
    assert "sandbox" in entry.reason
    assert "allowlist" in entry.reason


def test_planned_family_is_not_active_capability():
    """Planned = no module file, no subprocess, no network capability today."""
    assert PLANNED_FAMILIES["browser"].status not in ("sandboxed", "host_exception")


def test_planned_families_never_appear_as_audit_rows():
    """Rows describe real module files only; planned entries are metadata."""
    rows = audit_families()
    assert rows, "the audit must still cover the real subprocess-using families"
    assert not [r for r in rows if r["module"] == "browser"]
    # Planned entries are additive metadata, never audit coverage regressions.
    assert not [r for r in rows if r.get("status") == "planned"]


def test_planned_families_do_not_count_as_problems():
    summary = describe_family_audit()
    assert summary["unregistered"] == 0
    assert summary["problems"] == []
    assert [p["module"] for p in summary.get("planned", [])] == ["browser"]


def test_registry_split_still_separates_real_statuses():
    """The real registries remain untouched by the planned-family addition."""
    for entry in HOST_EXCEPTIONS.values():
        assert entry.status == "host_exception"
    for entry in SANDBOXED_FAMILIES.values():
        assert entry.status == "sandboxed"
    for entry in PLANNED_FAMILIES.values():
        assert entry.status == "planned"
