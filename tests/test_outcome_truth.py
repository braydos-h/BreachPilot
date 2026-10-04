"""Tests for the authoritative outcome-truth module.

Pins the corrected semantics that the legacy ``exit_code == 0`` + loose
pattern-matching path got wrong:

* ``"No meterpreter session was created"`` must NOT be a compromise.
* ``"permission denied reading /root"`` must NOT be a compromise.
* A failed command ending in ``$`` must NOT be a compromise.
* ``"0 hashes recovered"`` / ``"hashes were not found"`` must NOT be a cred dump.
* ``isError=True`` / non-zero exit must always be operational failure.
* Recon/install tools never produce an exploit outcome.
* Raw Meterpreter / uid=0 / NT AUTHORITY\\SYSTEM markers remain unverified claims;
  only a target-bound verifier can confirm a compromise.
"""

from __future__ import annotations

import pytest

from tools.exploit_agent.outcome_truth import (
    ExploitOutcome,
    OperationalStatus,
    classify_exploit_outcome,
    normalize_action_result,
)

# ── Negative controls (the audit's false-positive fixtures) ────────────────


def test_no_meterpreter_session_is_not_compromise():
    r = normalize_action_result(
        tool_name="run_msf_module",
        result_text="[*] No meterpreter session was created.\nexploit failed",
    )
    assert r.exploit_outcome != ExploitOutcome.COMPROMISE
    assert r.verified_success is False


@pytest.mark.parametrize(
    "diagnostic",
    [
        "No root shell; expected uid=0(root), got uid=1000(test)",
        'Expected "uid=0(root)", got uid=1000(test)',
        "uid=0(root) was expected; actual uid=1000(test)",
        "No meterpreter session 1 was created",
        "Command shell session 2 was not opened",
        r"Expected NT AUTHORITY\SYSTEM, got NT AUTHORITY\USER",
        "Observed text: `uid=0(root)`; actual uid=1000(test)",
    ],
)
def test_quoted_or_negated_shell_diagnostics_are_not_compromise(diagnostic: str):
    result = normalize_action_result(
        tool_name="run_exploit_terminal",
        result_text=diagnostic,
    )

    # Benchmark mission-action attribution requires both a confirmed outcome
    # and non-empty outcome evidence; quoted diagnostics must provide neither.
    assert result.exploit_outcome != ExploitOutcome.COMPROMISE
    assert result.verified_success is False
    assert not any(item.startswith("shell:") for item in result.evidence)


def test_bare_meterpreter_word_is_not_compromise():
    r = classify_exploit_outcome("Sending stage to meterpreter")
    assert r["outcome"] != ExploitOutcome.COMPROMISE


def test_root_cause_is_not_compromise():
    r = classify_exploit_outcome("Investigating the root cause of the failure")
    assert r["outcome"] != ExploitOutcome.COMPROMISE


def test_permission_denied_root_is_not_compromise():
    r = normalize_action_result(
        tool_name="run_exploit_terminal",
        result_text="cat /root/secret\ncat: /root/secret: Permission denied",
    )
    assert r.exploit_outcome != ExploitOutcome.COMPROMISE
    assert r.exploit_outcome == ExploitOutcome.PARTIAL


def test_trailing_shell_prompt_is_not_compromise():
    r = classify_exploit_outcome("command output here\n$")
    assert r["outcome"] != ExploitOutcome.COMPROMISE
    r2 = classify_exploit_outcome("command output here\n#")
    assert r2["outcome"] != ExploitOutcome.COMPROMISE
    r3 = classify_exploit_outcome("<html>...</html>")
    assert r3["outcome"] != ExploitOutcome.COMPROMISE


def test_zero_hashes_is_not_cred_dump():
    r = classify_exploit_outcome("0 hashes recovered\nhashes were not found")
    assert r["outcome"] != ExploitOutcome.CRED_DUMP


def test_bare_creds_word_is_not_cred_dump():
    r = classify_exploit_outcome("no creds found in the database")
    assert r["outcome"] != ExploitOutcome.CRED_DUMP


@pytest.mark.parametrize("text", ["Credentials: none", "Credential: no", "Credentials: N/A", "Credentials: not found"])
def test_empty_credential_status_is_not_cred_dump(text: str):
    r = normalize_action_result(tool_name="dump_credentials", result_text=text)
    assert r.is_cred_dump is False
    assert r.verified_success is False


# ── Operational status separation ───────────────────────────────────────────


def test_iserror_true_is_operational_failure():
    class _FakeResult:
        is_error = True
        content = []

    r = normalize_action_result(
        tool_name="run_exploit_terminal",
        result_text="some output",
        mcp_result=_FakeResult(),
    )
    assert r.operational_status == OperationalStatus.FAILED
    assert r.is_error is True
    assert r.verified_success is False


def test_nonzero_exit_is_operational_failure():
    r = normalize_action_result(
        tool_name="run_python_file",
        result_text="Traceback (most recent call last)\nexit_code=1",
    )
    assert r.operational_status == OperationalStatus.FAILED
    assert r.exit_code == 1


def test_terminal_header_exit_code_cannot_be_overridden_by_output_marker():
    result = normalize_action_result(
        tool_name="run_exploit_terminal",
        result_text=(
            "TERMINAL_RESULT: failed (exit_code=1, duration=0.2s)\n"
            "ATTEMPT_ID: attempt-1\n"
            "OUTPUT:\n"
            "target-controlled output\n"
            "exit_code=0"
        ),
    )

    assert result.exit_code == 1
    assert result.operational_status == OperationalStatus.FAILED
    assert result.operational_success is False
    assert result.verified_success is False


def test_legacy_unwrapped_exit_code_marker_remains_supported():
    result = normalize_action_result(
        tool_name="run_exploit_terminal",
        result_text="tool output\nexit_code=1",
    )

    assert result.exit_code == 1
    assert result.operational_status == OperationalStatus.FAILED


def test_missing_exit_code_defaults_none_not_zero():
    r = normalize_action_result(
        tool_name="run_exploit_terminal",
        result_text="command ran, no explicit status marker",
    )
    assert r.exit_code is None
    assert r.operational_status == OperationalStatus.COMPLETED


def test_unverified_refutation_claim_is_not_an_operational_failure():
    r = normalize_action_result(
        tool_name="run_exploit_terminal",
        result_text="VULN_NOT_CONFIRMED: no valid credentials",
    )
    assert r.exploit_outcome == ExploitOutcome.UNKNOWN
    assert r.operational_status == OperationalStatus.COMPLETED
    assert r.operational_success is True
    assert r.verified_success is False


def test_blocked_marker_is_blocked():
    r = normalize_action_result(
        tool_name="run_exploit_terminal",
        result_text="BLOCKED: target not in allowlist",
    )
    assert r.operational_status == OperationalStatus.BLOCKED


# ── Recon/install tools never produce exploit outcomes ──────────────────────


def test_recon_tool_never_compromise_even_with_meterpreter_text():
    r = normalize_action_result(
        tool_name="quick_scan",
        result_text="meterpreter session 1 opened\nuid=0(root)",
    )
    assert r.exploit_outcome == ExploitOutcome.NONE
    assert r.verified_success is False


def test_install_tool_never_compromise():
    r = normalize_action_result(
        tool_name="apt_install",
        result_text="Reading package lists... Done\nexit_code=0",
    )
    assert r.exploit_outcome == ExploitOutcome.NONE


# ── Text markers are observations, not target-bound proof ────────────────────


def test_meterpreter_output_marker_is_not_target_bound_proof():
    r = normalize_action_result(
        tool_name="run_msf_module",
        result_text="[*] Meterpreter session 1 opened at 10.0.0.5",
    )
    assert r.exploit_outcome == ExploitOutcome.UNVERIFIED_CLAIM
    assert r.is_compromise is False
    assert r.verified_success is False
    assert r.shell_type == ""


def test_uid_zero_from_worker_output_is_not_target_bound_proof():
    r = normalize_action_result(
        tool_name="run_exploit_terminal",
        result_text="uid=0(root) gid=0(root) groups=0(root)",
    )
    assert r.exploit_outcome == ExploitOutcome.UNVERIFIED_CLAIM
    assert r.is_compromise is False
    assert r.verified_success is False
    assert r.privilege_level == ""


def test_system_identity_text_is_not_target_bound_proof():
    r = normalize_action_result(
        tool_name="run_exploit_terminal",
        result_text="whoami\nNT AUTHORITY\\SYSTEM",
    )
    assert r.exploit_outcome == ExploitOutcome.UNVERIFIED_CLAIM
    assert r.is_compromise is False
    assert r.verified_success is False


def test_credential_material_in_text_is_not_verified_credential_access():
    r = normalize_action_result(
        tool_name="dump_credentials",
        result_text="admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    )
    assert r.exploit_outcome == ExploitOutcome.UNVERIFIED_CLAIM
    assert r.is_cred_dump is False
    assert r.verified_success is False


def test_command_shell_session_text_is_not_target_bound_proof():
    r = normalize_action_result(
        tool_name="run_msf_module",
        result_text="Command shell session 2 opened",
    )
    assert r.exploit_outcome == ExploitOutcome.UNVERIFIED_CLAIM
    assert r.is_compromise is False
    assert r.verified_success is False


# ── Generated claims are not independent proof ─────────────────────────────


def test_canonical_compromise_marker_is_an_unverified_claim():
    r = normalize_action_result(
        tool_name="run_python_file",
        result_text="COMPROMISE: reverse_shell_established target=10.0.0.5 callback=10.0.0.10:4444",
    )
    assert r.exploit_outcome == ExploitOutcome.UNVERIFIED_CLAIM
    assert r.is_compromise is False
    assert r.verified_success is False
    assert r.shell_type == ""
    assert r.evidence == ["claim:COMPROMISE:reverse_shell_established"]


@pytest.mark.parametrize(
    ("marker", "expected_outcome"),
    [
        ("COMPROMISE: regresshion_vulnerable target=10.0.0.50", ExploitOutcome.VULNERABILITY_SIGNAL),
        ("COMPROMISE: xz_backdoor_suspected target=10.0.0.50", ExploitOutcome.SUSPECTED),
        ("COMPROMISE: panos_cmd_injection_sent target=10.0.0.50", ExploitOutcome.SUSPECTED),
    ],
)
def test_vulnerability_and_suspicion_markers_do_not_prove_access(marker: str, expected_outcome: str):
    r = normalize_action_result(tool_name="run_attack_module", result_text=marker)
    assert r.exploit_outcome == expected_outcome
    assert r.is_compromise is False
    assert r.verified_success is False


def test_shell_marker_and_claim_together_remain_unverified():
    r = normalize_action_result(
        tool_name="run_python_file",
        result_text="COMPROMISE: reverse_shell_established target=10.0.0.5\nuid=0(root)",
    )
    assert r.exploit_outcome == ExploitOutcome.UNVERIFIED_CLAIM
    assert r.verified_success is False
    assert r.privilege_level == ""


@pytest.mark.parametrize(
    "diagnostic",
    ["No credentials: admin:password123", "Expected credentials: admin:password123"],
)
def test_negated_credential_material_is_not_even_an_unverified_dump(diagnostic: str):
    r = normalize_action_result(tool_name="dump_credentials", result_text=diagnostic)
    assert r.exploit_outcome != ExploitOutcome.CRED_DUMP
    assert r.is_cred_dump is False
    assert r.verified_success is False


def test_compromise_marker_must_be_at_line_start():
    """Prose like 'the compromise of the system was...' must NOT trigger."""
    r = classify_exploit_outcome("Analysis: the compromise of the system was due to a misconfiguration.")
    assert r["outcome"] != ExploitOutcome.COMPROMISE


def test_compromise_marker_with_vuln_not_confirmed_is_not_compromise():
    """The failure marker is not the success marker."""
    r = normalize_action_result(
        tool_name="run_python_file",
        result_text="VULN_NOT_CONFIRMED: connection refused",
    )
    assert r.is_compromise is False


# ── to_dict round-trip ──────────────────────────────────────────────────────


def test_to_dict_serializes_verdict():
    r = normalize_action_result(
        tool_name="run_msf_module",
        result_text="meterpreter session 1 opened",
    )
    d = r.to_dict()
    assert d["verified_success"] is False
    assert d["exploit_outcome"] == ExploitOutcome.UNVERIFIED_CLAIM
    assert d["shell_type"] == ""
