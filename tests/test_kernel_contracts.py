"""Wave 2 foundation contracts: observation schema (#69), tool manifests (#12), budgets (#34)."""

from __future__ import annotations

# ── #69 observation schema ─────────────────────────────────────────────


def test_make_observation_hashes_content():
    from tools.kernel.observation import make_observation

    obs = make_observation(source="nmap", kind="scan", subject="10.0.0.5", summary="3 ports", full_content="raw-bytes")
    assert obs.content_hash != ""
    assert obs.observation_id != ""
    assert obs.timestamp != ""
    assert obs.invocation.tool_name == "nmap"
    assert obs.invocation.target == "10.0.0.5"
    twin = make_observation(source="nmap", kind="scan", summary="3 ports", full_content="raw-bytes")
    assert twin.content_hash == obs.content_hash
    assert twin.observation_id != obs.observation_id


def test_observation_from_trial_dict_degrades_safely():
    from tools.kernel.observation import observation_from_trial_dict

    obs = observation_from_trial_dict({"target_id": "dvwa", "outcome_summary": "compromises: 1"})
    assert obs.subject == "dvwa"
    assert obs.content_hash != ""
    empty = observation_from_trial_dict({})
    assert empty.subject == ""
    assert observation_from_trial_dict(None).kind == "trial_result"  # type: ignore[arg-type]


# ── #12 tool manifests ──────────────────────────────────────────────────


def test_collect_manifests_covers_tool_surface():
    from tools.mcp_tools.manifest import catalog_hash, collect_manifests

    manifests = collect_manifests()
    assert len(manifests) > 100, f"expected the full tool surface, got {len(manifests)}"
    by_name = {m.name: m for m in manifests}
    assert by_name["check_os"].requires_allowlist is True
    assert by_name["check_os"].allowlist_param == "target_ip"
    assert by_name["run_hash_crack"].requires_allowlist is False
    assert catalog_hash(manifests) == catalog_hash(collect_manifests())


def test_manifest_shape_is_versioned():
    from tools.mcp_tools.manifest import MANIFEST_VERSION, ToolManifest

    assert MANIFEST_VERSION == 1
    assert ToolManifest(name="x", family="y").manifest_version == 1
    assert set(ToolManifest(name="x", family="y").to_dict()) >= {
        "name",
        "family",
        "requires_allowlist",
        "allowlist_param",
        "summary",
    }


# ── #34 budgets ─────────────────────────────────────────────────────────


def test_budget_tracker_reports_exhausted_dimension():
    from tools.kernel.budgets import BudgetLimits, BudgetTracker

    tracker = BudgetTracker(limits=BudgetLimits(actions=3, tokens=100))
    assert tracker.stop_reason() == ""
    tracker.add(actions=2, tokens=50)
    assert tracker.stop_reason() == ""
    tracker.add(actions=1)
    assert tracker.exhausted() == ["actions"]
    assert tracker.stop_reason() == "budget exhausted (actions)"


def test_budget_tracker_rejects_negative_deltas():
    import pytest

    from tools.kernel.budgets import BudgetTracker

    with pytest.raises(ValueError):
        BudgetTracker().add(actions=-1)


def test_budget_time_limit_eventually_hits():
    import time

    from tools.kernel.budgets import BudgetLimits, BudgetTracker

    tracker = BudgetTracker(limits=BudgetLimits(time_seconds=0.01))
    time.sleep(0.02)
    assert tracker.exhausted() == ["time"]
