"""Tests for tools.detection_coverage (read-only detection-coverage helpers).

Pure stdlib, no network. These helpers back the read-only detection/OPSEC
attack modules in tools/attack_modules/modules/detection.py.
"""

from __future__ import annotations

import copy

from tools.detection_coverage import (
    canary_command,
    detection_probe_plan,
    footprint_summary,
)

TARGET = "10.0.0.50"


# ── footprint_summary ──────────────────────────────────────────────────────


def test_footprint_summary_empty_returns_defaults():
    out = footprint_summary([])
    assert out["total_actions"] == 0
    assert out["noisy_actions"] == 0
    assert out["commands_executed"] == 0
    assert out["unique_targets"] == 0
    assert out["unique_tools"] == 0
    # Additive enriched fields.
    assert out["commands"] == 0
    assert out["distinct_tools"] == []
    assert out["target_ips"] == []
    assert out["egress_endpoints"] == []
    assert out["noisy_examples"] == []


def test_footprint_summary_none_treated_as_empty():
    out = footprint_summary(None)
    assert out["total_actions"] == 0
    assert out["noisy_examples"] == []


def test_footprint_summary_counts_total_and_commands():
    records = [
        {"tool": "run_exploit_terminal", "target": TARGET, "command": "whoami"},
        {"tool": "run_python_file", "target": TARGET, "command": "ls -la"},
        {"tool": "list_workspace"},
    ]
    out = footprint_summary(records)
    assert out["total_actions"] == 3
    # run_exploit_terminal + run_python_file each add 1 (tool bucket), and each
    # has a command key adding another 1; list_workspace has neither.
    assert out["commands_executed"] >= 2
    assert out["commands"] == out["commands_executed"]


def test_footprint_summary_distinct_tools_sorted_deduped():
    records = [
        {"tool": "run_exploit_terminal"},
        {"tool": "run_python_file"},
        {"tool": "run_exploit_terminal"},
        {"action": "check_os"},
    ]
    out = footprint_summary(records)
    assert out["distinct_tools"] == ["check_os", "run_exploit_terminal", "run_python_file"]
    assert out["unique_tools"] == 3


def test_footprint_summary_target_ips_sorted_deduped():
    records = [
        {"target": "10.0.0.50"},
        {"target_ip": "10.0.0.10"},
        {"asset": "10.0.0.50"},
    ]
    out = footprint_summary(records)
    assert out["target_ips"] == ["10.0.0.10", "10.0.0.50"]
    assert out["unique_targets"] == 2


def test_footprint_summary_egress_endpoints_extracted():
    records = [
        {"command": "curl http://10.0.0.99:8080/ and ssh 10.0.0.50"},
        {"args": "https://example.com/path"},
        {"tool": "list_workspace"},
    ]
    out = footprint_summary(records)
    eps = out["egress_endpoints"]
    assert "10.0.0.99" in eps
    assert "10.0.0.50" in eps
    assert "example.com" in eps
    assert out["egress_endpoints"] == sorted(eps)


def test_footprint_summary_noisy_flag_and_pattern_count():
    records = [
        {"noisy": True, "command": "whoami"},
        {"noisy": False, "command": "nmap -T5 -p- 10.0.0.50"},
        {"noisy": False, "command": "ls"},
    ]
    out = footprint_summary(records)
    # One explicit noisy flag + one noisy-pattern (-T5) match = 2.
    assert out["noisy_actions"] == 2


def test_footprint_summary_noisy_examples_capped_and_from_commands():
    records = [
        {"noisy": True, "command": "whoami"},
        {"noisy": True, "command": "nmap -T5 10.0.0.50"},
        {"noisy": True, "command": "masscan 10.0.0.50/24"},
        {"noisy": True, "command": "hydra -L users 10.0.0.50"},
        {"noisy": True, "command": "nuclei -u http://10.0.0.50"},
        {"noisy": True, "command": "ffuf -u http://10.0.0.50/FUZZ"},
        {"noisy": True, "command": "gobuster dir -u http://10.0.0.50"},
    ]
    out = footprint_summary(records)
    assert out["noisy_actions"] == 7
    # Capped at 5.
    assert len(out["noisy_examples"]) == 5
    assert all(isinstance(c, str) and c for c in out["noisy_examples"])


def test_footprint_summary_tolerates_malformed_records():
    records = [
        {},
        {"foo": "bar"},
        "not-a-dict",  # type: ignore[list-item]
        None,  # type: ignore[list-item]
        {"tool": "run_exploit_terminal", "target": TARGET, "command": "id"},
    ]
    out = footprint_summary(records)
    # The three dict records (including {} and {"foo":"bar"}) count; the
    # non-dict entries ("not-a-dict", None) are skipped.
    assert out["total_actions"] == 3
    # Only the well-formed record contributed a target.
    assert out["target_ips"] == [TARGET]


def test_footprint_summary_does_not_mutate_input():
    records = [
        {"tool": "run_exploit_terminal", "target": TARGET, "noisy": True, "command": "nmap -T5 10.0.0.50"},
    ]
    snapshot = copy.deepcopy(records)
    footprint_summary(records)
    assert records == snapshot


# ── canary_command / detection_probe_plan ───────────────────────────────────


def test_canary_command_returns_target_locked_readonly_dict():
    entry = canary_command(
        category="auth",
        description="failed ssh login",
        command=f"ssh operator_canary@{TARGET} true",
        detection_hint="SIEM auth log",
        target_ip=TARGET,
    )
    assert entry["category"] == "auth"
    assert entry["target_ip"] == TARGET
    assert entry["read_only"] is True
    assert "command" in entry and "detection_hint" in entry and "description" in entry


def test_detection_probe_plan_has_four_target_locked_entries():
    plan = detection_probe_plan(TARGET)
    assert isinstance(plan, list)
    assert len(plan) == 4
    categories = {e["category"] for e in plan}
    assert categories == {"auth", "file", "exec", "network"}
    for entry in plan:
        assert entry["target_ip"] == TARGET
        assert entry["read_only"] is True
        assert entry["command"]
        assert entry["detection_hint"]


def test_detection_probe_plan_commands_embed_target_ip():
    # The canary commands must reference the authorized target (target-locked).
    plan = detection_probe_plan(TARGET)
    # At least the auth + file + network categories embed the target IP in the
    # command string (exec is a generic recon command that does not).
    embedded = [e for e in plan if TARGET in e["command"]]
    assert len(embedded) >= 3
