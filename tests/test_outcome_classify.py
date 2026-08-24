"""Phase 1.1 — ``classify_exploit_result`` conservative result-text classifier.

Verifies the outcome taxonomy (compromise / cred_dump / partial / failure /
unknown), the shell-type / privilege extraction, and the conservativeness
invariants: generic ``success``/``completed`` words are NOT a compromise, and
absent a strong signal + absent an error marker the result is ``unknown``
(not ``failure``).
"""

from __future__ import annotations

from tools.exploit_agent.outcome_classify import classify_exploit_result

# ── Compromise ──────────────────────────────────────────────────────────────


def test_compromise_meterpreter_session():
    r = classify_exploit_result("[*] Meterpreter session 1 opened at 10.0.0.5")
    assert r["outcome"] == "compromise"
    assert r["shell_type"] == "meterpreter"
    assert any("meterpreter" in e for e in r["evidence"])


def test_compromise_meterpreter_bare_marker():
    r = classify_exploit_result("Sending stage to meterpreter")
    assert r["outcome"] == "compromise"
    assert r["shell_type"] == "meterpreter"


def test_compromise_windows_system():
    r = classify_exploit_result("whoami\nnt authority\\system")
    assert r["outcome"] == "compromise"
    assert r["shell_type"] == "cmd"
    assert r["privilege_level"] == "NT AUTHORITY\\SYSTEM"


def test_compromise_command_shell_session():
    r = classify_exploit_result("Command shell session 2 opened")
    assert r["outcome"] == "compromise"
    assert r["shell_type"] == "cmd"


def test_compromise_uid0():
    r = classify_exploit_result("uid=0(root) gid=0(root) groups=0(root)")
    assert r["outcome"] == "compromise"
    assert r["shell_type"] == "sh"
    assert r["privilege_level"] == "root"


def test_compromise_whoami_root():
    r = classify_exploit_result("whoami\nroot")
    # "root" with trailing newline matches the \broot\b[\s@] pattern
    assert r["outcome"] == "compromise"
    assert r["shell_type"] == "sh"


def test_compromise_takes_precedence_over_cred_dump():
    # Both a shell marker and cred markers present — compromise wins, cred is
    # still surfaced in evidence.
    r = classify_exploit_result("uid=0(root)\nDumping credentials\nNTLM hashes")
    assert r["outcome"] == "compromise"
    assert any("creds" in e for e in r["evidence"])


# ── Credential dump ─────────────────────────────────────────────────────────


def test_cred_dump_credentials_marker():
    r = classify_exploit_result("Credentials:\nuser: hash")
    assert r["outcome"] == "cred_dump"
    assert r["shell_type"] == ""
    assert any("creds" in e for e in r["evidence"])


def test_cred_dump_ntlm():
    r = classify_exploit_result("Dumping NTLM hashes for all users")
    assert r["outcome"] == "cred_dump"


def test_cred_dump_kerberos_keys():
    r = classify_exploit_result("Kerberos keys extracted")
    assert r["outcome"] == "cred_dump"


def test_cred_dump_sam_dumped():
    r = classify_exploit_result("SAM database dumped successfully")
    assert r["outcome"] == "cred_dump"


# ── Partial ─────────────────────────────────────────────────────────────────


def test_partial_access_denied():
    r = classify_exploit_result("System error 5 - Access is denied.")
    assert r["outcome"] == "partial"
    assert any("partial" in e for e in r["evidence"])


def test_partial_permission_denied():
    r = classify_exploit_result("bash: /etc/shadow: Permission denied")
    assert r["outcome"] == "partial"


def test_partial_limited_keyword():
    r = classify_exploit_result("Limited data retrieved from target")
    assert r["outcome"] == "partial"


def test_partial_does_not_fire_when_compromise_present():
    # A shell marker + "permission denied" should still read as compromise.
    r = classify_exploit_result("uid=0(root)\nPermission denied for /root/.ssh")
    assert r["outcome"] == "compromise"


# ── Failure ─────────────────────────────────────────────────────────────────


def test_failure_on_exploit_failed_marker():
    r = classify_exploit_result("[-] Exploit failed: connection refused")
    assert r["outcome"] == "failure"
    assert any("failure" in e for e in r["evidence"])


def test_failure_on_nonzero_exit_code():
    r = classify_exploit_result("Command finished with exit code: 1")
    assert r["outcome"] == "failure"


def test_failure_on_no_session_created():
    r = classify_exploit_result("[-] Handler failed to bind\nNo session created")
    assert r["outcome"] == "failure"


def test_failure_does_not_fire_on_compromise():
    r = classify_exploit_result("Meterpreter session 1 opened\nexit code: 0")
    assert r["outcome"] == "compromise"


# ── Unknown / conservative ──────────────────────────────────────────────────


def test_unknown_on_empty_string():
    r = classify_exploit_result("")
    assert r["outcome"] == "unknown"
    assert r["evidence"] == []


def test_unknown_on_none_input():
    r = classify_exploit_result(None)  # type: ignore[arg-type]
    assert r["outcome"] == "unknown"


def test_unknown_on_generic_success_word_is_not_compromise():
    # "success"/"completed" are operational words, NOT evidential. The
    # classifier must not call this a compromise (see outcome_judge._STOPWORDS).
    r = classify_exploit_result("Task completed successfully.")
    assert r["outcome"] == "unknown"
    assert r["shell_type"] == ""


def test_unknown_on_benign_output_with_no_markers():
    r = classify_exploit_result("Scanning host 10.0.0.5 ... 4 ports open")
    assert r["outcome"] == "unknown"


def test_unknown_when_only_exit_code_zero():
    # exit_code == 0 is not a failure marker (the failure regex is [1-9]); it
    # is also not a compromise marker on its own.
    r = classify_exploit_result("Command finished with exit code: 0")
    assert r["outcome"] == "unknown"


# ── Shape ───────────────────────────────────────────────────────────────────


def test_return_shape_has_all_keys():
    r = classify_exploit_result("uid=0(root)")
    assert set(r.keys()) == {"outcome", "shell_type", "privilege_level", "evidence"}
    assert isinstance(r["evidence"], list)


def test_evidence_list_populated_on_match():
    r = classify_exploit_result("Dumping NTLM hashes")
    assert len(r["evidence"]) >= 1
    assert all(isinstance(e, str) for e in r["evidence"])
