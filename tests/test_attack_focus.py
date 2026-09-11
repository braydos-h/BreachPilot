"""Unit tests for the attack-focus branch controller (Flow A).

Covers: candidate creation, deterministic selection, pinning, drift
prevention, progress/stagnation, duplicate fingerprints, hypothesis
lifecycle, exhaustion, switching, verified-success priority, and no-path.
"""

from __future__ import annotations

import pytest

from tools.exploit_agent.branch import (
    AttackFocusController,
    BranchStatus,
    HypothesisStatus,
    refresh_focus_message,
)
from tools.exploit_agent.branch_knowledge import (
    _canonical_attempt,
    extract_web_signals,
    families_for_service,
    family_for_tool,
)

TARGET = "10.0.0.50"

SSH_BANNERS = [
    {
        "host": TARGET,
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "product": "OpenSSH",
        "version": "8.5p1",
        "os_guess": "LINUX",
        "raw_banner": "Port 22/tcp: open - OpenSSH_8.5p1",
    }
]

WEB_BANNERS = [
    {
        "host": TARGET,
        "port": 443,
        "protocol": "tcp",
        "service": "https",
        "product": "nginx",
        "version": "1.24.0",
        "os_guess": "LINUX",
        "raw_banner": "Port 443/tcp: open - nginx/1.24.0",
    }
]


def _focus(**overrides):
    cfg = {"agent": {"attack_focus_enabled": True}}
    cfg["agent"].update(overrides)
    return AttackFocusController(TARGET, config=cfg)


# ── candidate creation + deterministic selection ─────────────────────────────


def test_ingest_creates_candidates_with_evidence_backed_hypotheses():
    focus = _focus()
    focus.ingest_services(WEB_BANNERS, action_count=1)
    branch = focus.branches.get("https:443")
    assert branch is not None
    assert branch.service == "https"
    assert branch.port == 443
    assert branch.version == "1.24.0"
    assert branch.evidence
    assert branch.open_hypotheses(), "version evidence must seed a cve-exploit hypothesis"


def test_selection_prefers_highest_evidence_not_first_seen():
    focus = _focus()
    focus.ingest_services(SSH_BANNERS, action_count=1)
    assert focus.active_branch_id == "ssh:22"
    # Web arrives later with version evidence: higher base + version bonus wins.
    focus.ingest_services(WEB_BANNERS, action_count=2)
    assert focus.active_branch_id == "https:443"


def test_selection_is_deterministic_on_ties():
    first = _focus()
    first.ingest_services(WEB_BANNERS, action_count=1)
    second = _focus()
    second.ingest_services(WEB_BANNERS, action_count=1)
    assert first.active_branch_id == second.active_branch_id == "https:443"


def test_no_hardcoded_port_ranking():
    # An ssh branch with creds + CVE beats a bare https branch: evidence wins.
    focus = _focus()
    focus.ingest_services(WEB_BANNERS, action_count=1)
    focus.ingest_services(SSH_BANNERS, action_count=1)
    assert focus.active_branch_id == "https:443"
    ssh = focus.branches["ssh:22"]
    ssh.has_creds = True
    ssh.has_cve = True
    focus._maybe_select(3, reason="test")
    assert focus.active_branch_id == "ssh:22"


# ── pinning + drift prevention ───────────────────────────────────────────────


def test_active_branch_pinned_against_small_margin():
    focus = _focus()
    focus.ingest_services(WEB_BANNERS, action_count=1)
    focus.ingest_services(SSH_BANNERS, action_count=1)
    assert focus.active_branch_id == "https:443"
    # Re-ingest: no genuinely new evidence, margin keeps the incumbent.
    focus.ingest_services(SSH_BANNERS, action_count=2)
    assert focus.active_branch_id == "https:443"


def test_broad_recon_allowed_before_minima_then_refused():
    focus = _focus()
    focus.ingest_services(WEB_BANNERS, action_count=2)
    # Fewer than 2 recon actions seen: pinning has not bitten yet.
    focus._recon_actions_seen = 1
    assert focus.check_tool_call("quick_scan", {}) is None
    focus._recon_actions_seen = 2
    gate = focus.check_tool_call("quick_scan", {})
    assert gate is not None and gate[0] == "drift"
    assert "https:443" in gate[1]


def test_untargeted_scanner_sweep_refused_but_focused_scan_allowed():
    focus = _focus()
    focus.ingest_services(WEB_BANNERS, action_count=2)
    focus._recon_actions_seen = 2
    gate = focus.check_tool_call("run_exploit_terminal", {"command": "nmap -sV 10.0.0.50"})
    assert gate is not None and gate[0] == "drift"
    assert focus.check_tool_call("run_exploit_terminal", {"command": "nmap -sV -p443 10.0.0.50"}) is None


def test_single_failed_command_is_not_exhaustion():
    focus = _focus()
    focus.ingest_services(WEB_BANNERS, action_count=1)
    branch = focus.branches["https:443"]
    focus.observe_result(
        tool_name="run_exploit_terminal",
        args={"command": "curl -sk https://10.0.0.50/"},
        result_text="connection reset",
        action_count=2,
        success=False,
    )
    assert branch.status == BranchStatus.ACTIVE


# ── progress resets stagnation ───────────────────────────────────────────────


def test_new_web_observation_resets_stagnation_counter():
    focus = _focus(no_progress_action_limit=50)
    focus.ingest_services(WEB_BANNERS, action_count=1)
    branch = focus.branches["https:443"]
    focus.observe_result(
        tool_name="run_exploit_terminal",
        args={"command": "curl -sk https://10.0.0.50/"},
        result_text="ok",
        action_count=2,
        success=True,
    )
    assert branch.actions_since_progress == 0
    focus.observe_result(
        tool_name="run_exploit_terminal",
        args={"command": "curl -sk https://10.0.0.50/login"},
        result_text='<html><form action="/login"><input name="password"></form> server: nginx',
        action_count=3,
        success=True,
    )
    assert branch.has_auth_surface
    assert branch.actions_since_progress == 0
    assert "/login" in branch.attack_surface


def test_no_progress_intervention_mints_new_hypotheses():
    focus = _focus(no_progress_action_limit=2, branch_max_actions=50)
    focus.ingest_services(WEB_BANNERS, action_count=1)
    branch = focus.branches["https:443"]
    # Ingest seeds 4 hypotheses (cve/route/dir/sqli; default-creds needs auth
    # evidence). Resolve each with a distinct-family observation; the 5th
    # observation finds nothing open, nothing seedable, no new signals.
    assert len(branch.open_hypotheses()) == 4
    repeat = {"command": "curl -sk https://10.0.0.50/"}
    for action in range(2, 6):
        focus.observe_result(
            tool_name="run_exploit_terminal", args=repeat, result_text="", action_count=action, success=True
        )
    assert not branch.open_hypotheses()
    assert branch.actions_since_progress == 0  # last resolution was progress
    focus.observe_result(tool_name="run_exploit_terminal", args=repeat, result_text="", action_count=6, success=True)
    assert branch.actions_since_progress == 1
    follow_ups = focus.observe_result(
        tool_name="run_exploit_terminal", args=repeat, result_text="", action_count=7, success=True
    )
    assert branch.status == BranchStatus.ACTIVE
    assert any("NO-PROGRESS INTERVENTION" in msg for msg in follow_ups)
    assert branch.open_hypotheses(), "intervention must mint untried-family hypotheses"


def test_resolved_family_is_not_reseeded():
    focus = _focus()
    focus.ingest_services(WEB_BANNERS, action_count=1)
    branch = focus.branches["https:443"]
    families_before = {h.family for h in branch.hypotheses.values()}
    focus.observe_result(
        tool_name="run_exploit_terminal",
        args={"command": "curl -sk https://10.0.0.50/"},
        result_text="",
        action_count=2,
        success=True,
    )
    families_after = {h.family for h in branch.hypotheses.values()}
    # No family appears twice: seeding never re-mints an answered question.
    assert len(branch.hypotheses) == len(families_after)
    assert families_before <= families_after


# ── duplicate detection ──────────────────────────────────────────────────────


def test_equivalent_curl_attempts_share_fingerprint():
    first = _canonical_attempt("run_exploit_terminal", {"command": "curl https://10.0.0.50/"})
    second = _canonical_attempt("run_exploit_terminal", {"command": "curl -sk https://10.0.0.50/"})
    assert first == second


def test_materially_different_attempts_allowed():
    focus = _focus()
    focus.ingest_services(WEB_BANNERS, action_count=2)
    focus._recon_actions_seen = 2
    root = {"command": "curl -sk https://10.0.0.50/"}
    login = {"command": "curl -sk https://10.0.0.50/login"}
    assert _canonical_attempt("run_exploit_terminal", root) != _canonical_attempt("run_exploit_terminal", login)
    assert focus.check_tool_call("run_exploit_terminal", root) is None
    focus.observe_result(tool_name="run_exploit_terminal", args=root, result_text="ok", action_count=3, success=True)
    gate = focus.check_tool_call("run_exploit_terminal", root)
    assert gate is not None and gate[0] == "duplicate"
    # A different path answers a different question: allowed.
    assert focus.check_tool_call("run_exploit_terminal", login) is None


def test_duplicate_allowed_again_after_progress():
    focus = _focus()
    focus.ingest_services(WEB_BANNERS, action_count=2)
    focus._recon_actions_seen = 2
    attempt = {"command": "curl -sk https://10.0.0.50/"}
    focus.observe_result(tool_name="run_exploit_terminal", args=attempt, result_text="ok", action_count=3, success=True)
    assert focus.check_tool_call("run_exploit_terminal", attempt) is not None
    # New evidence = new progress = the retry now answers a new question.
    focus.observe_result(
        tool_name="run_exploit_terminal",
        args={"command": "curl -sk https://10.0.0.50/login"},
        result_text='<form action="/login">',
        action_count=4,
        success=True,
    )
    assert focus.check_tool_call("run_exploit_terminal", attempt) is None


# ── hypothesis lifecycle ─────────────────────────────────────────────────────


def test_hypothesis_resolved_per_validation_action():
    focus = _focus()
    focus.ingest_services(SSH_BANNERS, action_count=1)
    branch = focus.branches["ssh:22"]
    assert branch.open_hypotheses()
    focus.observe_result(
        tool_name="run_exploit_terminal",
        args={"command": "hydra -l admin -p admin ssh://10.0.0.50"},
        result_text="VULN_NOT_CONFIRMED: no valid credentials",
        action_count=2,
        success=False,
        failure_class="false_positive_hypothesis",
    )
    assert any(h.status == HypothesisStatus.REFUTED for h in branch.hypotheses.values())


def test_web_signals_seed_auth_hypothesis():
    focus = _focus()
    focus.ingest_services(
        [
            {
                "host": TARGET,
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "product": "",
                "version": "",
                "os_guess": "",
                "raw_banner": "Port 443/tcp: open",
            }
        ],
        action_count=1,
    )
    branch = focus.branches["https:443"]
    assert not any(h.family == "default-creds" for h in branch.open_hypotheses())
    focus.observe_result(
        tool_name="run_exploit_terminal",
        args={"command": "curl -sk https://10.0.0.50/"},
        result_text='<form action="/login"><input name="username"><input name="password">',
        action_count=2,
        success=True,
    )
    assert any(h.family == "default-creds" for h in branch.open_hypotheses())


# ── exhaustion + switching ───────────────────────────────────────────────────


def test_branch_exhaustion_switches_to_next_candidate():
    focus = _focus(branch_max_actions=2)
    focus.ingest_services(WEB_BANNERS, action_count=1)
    focus.ingest_services(SSH_BANNERS, action_count=1)
    assert focus.active_branch_id == "https:443"
    follow_ups = focus.observe_result(
        tool_name="run_exploit_terminal",
        args={"command": "curl -sk https://10.0.0.50/"},
        result_text="ok",
        action_count=2,
        success=True,
    )
    follow_ups += focus.observe_result(
        tool_name="run_exploit_terminal",
        args={"command": "curl -sk https://10.0.0.50/login"},
        result_text="ok",
        action_count=3,
        success=True,
    )
    assert focus.branches["https:443"].status == BranchStatus.EXHAUSTED
    assert focus.active_branch_id == "ssh:22"
    assert any("BRANCH EXHAUSTED" in msg for msg in follow_ups)


def test_all_exhausted_says_no_path():
    focus = _focus(branch_max_actions=1)
    focus.ingest_services(WEB_BANNERS, action_count=1)
    follow_ups = focus.observe_result(
        tool_name="run_exploit_terminal",
        args={"command": "curl -sk https://10.0.0.50/"},
        result_text="ok",
        action_count=2,
        success=True,
    )
    assert focus.branches["https:443"].status == BranchStatus.EXHAUSTED
    assert any("ALL branches exhausted" in msg for msg in follow_ups)
    summary = focus.no_path_summary()
    assert "https:443" in summary and "exhausted" in summary


# ── success wins immediately ─────────────────────────────────────────────────


def test_verified_success_marks_branch_succeeded_not_exhausted():
    focus = _focus(branch_max_actions=1)
    focus.ingest_services(WEB_BANNERS, action_count=1)
    follow_ups = focus.observe_result(
        tool_name="run_python_file",
        args={"path": "exploit.py"},
        result_text="COMPROMISE: shell target=10.0.0.50\nuid=0(root)",
        action_count=2,
        success=True,
        verified_success=True,
    )
    assert focus.branches["https:443"].status == BranchStatus.SUCCEEDED
    assert follow_ups == []


# ── knowledge helpers ────────────────────────────────────────────────────────


def test_family_mapping_covers_web_probes():
    assert family_for_tool("ssti_probe", {}) == "ssti-probe"
    assert family_for_tool("run_web_scan", {"scanner": "nuclei"}) == "vuln-scan"
    assert family_for_tool("run_web_scan", {"scanner": "gobuster"}) == "dir-bruteforce"
    assert family_for_tool("run_exploit_terminal", {"command": "curl https://t/"}) == "http-fingerprint"
    assert family_for_tool("run_exploit_terminal", {"command": "curl https://t/login"}) == "route-enum"
    assert family_for_tool("run_exploit_terminal", {"command": "nmap -sV t"}) == "recon-sweep"


def test_web_signal_extraction():
    signals = extract_web_signals(
        '<html><form action="/login"><input name="password"></form>'
        '<a href="/admin">x</a>\nserver: nginx/1.24.0\nx-powered-by: express'
    )
    assert "/login" in signals["routes"]
    assert "/admin" in signals["routes"]
    assert "login-form" in signals["auth_surface"]
    assert "nginx" in signals["technologies"]


def test_families_cover_web_branch_needs():
    families = families_for_service("https")
    for needed in ("route-enum", "login-probe", "dir-bruteforce", "sqli-probe", "cve-exploit"):
        assert needed in families


def test_focus_block_renders_and_refresh_is_singular():
    focus = _focus()
    assert focus.render_focus_block() == ""
    focus.ingest_services(WEB_BANNERS, action_count=1)
    block = focus.render_focus_block()
    assert "https:443" in block and "HYPOTHESES" not in block  # compact labels
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "old"}]
    messages = refresh_focus_message(messages, block)
    messages = refresh_focus_message(messages, block + " v2")
    assert sum(1 for m in messages if "ATTACK_FOCUS" in str(m.get("content") or "")) == 1


def test_disabled_controller_is_inert():
    focus = AttackFocusController(TARGET, config={"agent": {"attack_focus_enabled": False}})
    assert not focus.enabled
    focus.ingest_services(WEB_BANNERS, action_count=1)
    assert focus.branches == {}
    assert focus.check_tool_call("quick_scan", {}) is None
    assert focus.render_focus_block() == ""
    assert focus.needed_tool_names() == set()


def test_branch_events_drain():
    focus = _focus()
    focus.ingest_services(WEB_BANNERS, action_count=1)
    events = focus.drain_events()
    assert events and all(kind == "branch" for kind, _ in events)
    assert focus.drain_events() == []
