"""Unit tests for _PhaseTracker extracted to phase_tracker.py."""

from __future__ import annotations

import pytest

from tools.exploit_agent.phase_tracker import _PhaseTracker


def test_initial_state_cannot_terminate():
    pt = _PhaseTracker()
    can, reason = pt.can_terminate()
    assert not can
    assert "recon" in reason


def test_recon_minimum_enforced():
    pt = _PhaseTracker()
    pt.record_action("recon")
    can, reason = pt.can_terminate()
    assert not can
    assert "recon" in reason
    pt.record_action("recon")
    can, reason = pt.can_terminate()
    assert not can
    assert "service" in reason.lower() or "reporting" in reason.lower()


def test_service_enumeration_scales_with_detected():
    pt = _PhaseTracker()
    pt.record_action("recon")
    pt.record_action("recon")
    pt.set_services_detected(3)
    pt.record_action("service_enumeration")
    assert not pt.can_terminate()[0]
    pt.record_action("service_enumeration")
    pt.record_action("service_enumeration")
    assert not pt.can_terminate()[0]


def test_vulnerability_research_scales_with_versions():
    pt = _PhaseTracker()
    pt.record_action("recon")
    pt.record_action("recon")
    pt.set_services_detected(1)
    pt.record_action("service_enumeration")
    pt.set_versions_identified(2)
    pt.record_action("vulnerability_research")
    assert not pt.can_terminate()[0]
    pt.record_action("vulnerability_research")
    pt.record_action("reporting")
    assert pt.can_terminate()[0]


def test_all_minima_satisfied():
    pt = _PhaseTracker()
    pt.record_action("recon")
    pt.record_action("recon")
    pt.set_services_detected(1)
    pt.record_action("service_enumeration")
    pt.set_versions_identified(1)
    pt.record_action("vulnerability_research")
    pt.record_action("reporting")
    can, reason = pt.can_terminate()
    assert can
    assert "satisfied" in reason


def test_remaining_requirements():
    pt = _PhaseTracker()
    req = pt.remaining_requirements()
    assert req["recon"] == 2
    assert req["service_enumeration"] == 1
    assert req["reporting"] == 1
    pt.record_action("recon")
    assert pt.remaining_requirements()["recon"] == 1
    pt.set_services_detected(2)
    assert pt.remaining_requirements()["service_enumeration"] == 2
    pt.record_action("service_enumeration")
    assert pt.remaining_requirements()["service_enumeration"] == 1


def test_record_action_updates_current_phase():
    pt = _PhaseTracker()
    assert pt._current_phase == "recon"
    pt.record_action("vulnerability_research")
    assert pt._current_phase == "vulnerability_research"
    pt.record_action("reporting")
    assert pt._current_phase == "reporting"


def test_importable_via_legacy_paths():
    from tools.exploit_agent import _PhaseTracker as PTviaRoot  # noqa: F401
    from tools.exploit_agent.loop import _PhaseTracker as PTviaLoop  # noqa: F401
    from tools.exploit_agent.phase_tracker import _PhaseTracker as PTviaModule

    assert PTviaRoot is PTviaModule
    assert PTviaLoop is PTviaModule


def test_phase_order_constant():
    assert _PhaseTracker.PHASE_ORDER == [
        "recon",
        "service_enumeration",
        "vulnerability_research",
        "validation",
        "reporting",
    ]
