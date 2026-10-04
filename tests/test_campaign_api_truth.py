"""Campaign reporting must not mistake module names for compromised hosts."""

from tools.campaign.state import AttackState
from tools.mcp_tools.modules.campaign import _compromised_hosts_for_state, _record_campaign_step_result


def test_campaign_report_excludes_claimed_success_without_verified_access() -> None:
    state = AttackState(target="example.test", resolved_ip="192.0.2.10")
    state.successful_exploits.append("SelfReportingModule")

    assert _compromised_hosts_for_state(state) == []


def test_campaign_report_uses_resolved_target_for_verified_access() -> None:
    state = AttackState(target="example.test", resolved_ip="192.0.2.10", access_achieved=True)

    assert _compromised_hosts_for_state(state) == ["192.0.2.10"]


def test_campaign_report_does_not_report_empty_target() -> None:
    state = AttackState(target="", resolved_ip="", access_achieved=True)

    assert _compromised_hosts_for_state(state) == []


def test_generated_campaign_step_counts_completion_without_claiming_compromise() -> None:
    state = AttackState(target="192.0.2.20")
    state.successful_exploits.append("SelfReportingModule")
    state_data = {"tasks": {"completed": 1, "failed": 0}}

    _record_campaign_step_result(state, state_data, "script_generated")

    assert state_data["tasks"] == {"completed": 2, "failed": 0}
    assert state_data["compromised_hosts"] == []


def test_failed_campaign_step_does_not_add_a_compromised_host() -> None:
    state = AttackState(target="192.0.2.20")
    state_data = {"tasks": {"completed": 0, "failed": 0}}

    _record_campaign_step_result(state, state_data, "failed")

    assert state_data["tasks"] == {"completed": 0, "failed": 1}
    assert state_data["compromised_hosts"] == []
