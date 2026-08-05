"""Tests for the authoritative outcome-truth module.

Pins the corrected semantics that the legacy ``exit_code == 0`` + loose
pattern-matching path got wrong:

* ``"No meterpreter session was created"`` must NOT be a compromise.
* ``"permission denied reading /root"`` must NOT be a compromise.
* A failed command ending in ``$`` must NOT be a compromise.
* ``"0 hashes recovered"`` / ``"hashes were not found"`` must NOT be a cred dump.
* ``isError=True`` / non-zero exit must always be operational failure.
* Recon/install tools never produce an exploit outcome.
* Exploit-validation tools with a real Meterpreter session / uid=0 / NT AUTHORITY\\SYSTEM
  marker ARE confirmed compromises.
"""

from __future__ import annotations

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


def test_missing_exit_code_defaults_none_not_zero():
    r = normalize_action_result(
        tool_name="run_exploit_terminal",
        result_text="command ran, no explicit status marker",
    )
    assert r.exit_code is None
    assert r.operational_status == OperationalStatus.COMPLETED


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


# ── Positive controls (real compromise markers still work) ──────────────────


def test_real_meterpreter_session_is_compromise():
    r = normalize_action_result(
        tool_name="run_msf_module",
        result_text="[*] Meterpreter session 1 opened at 10.0.0.5",
    )
    assert r.is_compromise is True
    assert r.verified_success is True
    assert r.shell_type == "meterpreter"


def test_real_uid0_is_compromise():
    r = normalize_action_result(
        tool_name="run_exploit_terminal",
        result_text="uid=0(root) gid=0(root) groups=0(root)",
    )
    assert r.is_compromise is True
    assert r.privilege_level == "root"


def test_real_nt_authority_system_is_compromise():
    r = normalize_action_result(
        tool_name="run_exploit_terminal",
        result_text="whoami\nNT AUTHORITY\\SYSTEM",
    )
    assert r.is_compromise is True
    assert r.privilege_level == "NT AUTHORITY\\SYSTEM"


def test_real_cred_dump_with_hash_hex_is_cred_dump():
    r = normalize_action_result(
        tool_name="dump_credentials",
        result_text="admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    )
    assert r.is_cred_dump is True
    assert r.verified_success is True


def test_command_shell_session_n_is_compromise():
    r = normalize_action_result(
        tool_name="run_msf_module",
        result_text="Command shell session 2 opened",
    )
    assert r.is_compromise is True


# ── to_dict round-trip ──────────────────────────────────────────────────────


def test_to_dict_serializes_verdict():
    r = normalize_action_result(
        tool_name="run_msf_module",
        result_text="meterpreter session 1 opened",
    )
    d = r.to_dict()
    assert d["verified_success"] is True
    assert d["exploit_outcome"] == ExploitOutcome.COMPROMISE
    assert d["shell_type"] == "meterpreter"
