"""Tests for the FILE & KEY HANDLING prompt guidance (Issue 6)."""

from __future__ import annotations

import inspect


def test_prompt_contains_key_handling_rules() -> None:
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(attacker_os="Linux", target_ip="10.0.0.1")
    assert "FILE & KEY HANDLING" in prompt
    assert "write_python_file" in prompt
    assert "ssh -i ~/.ssh/id_ed25519" in prompt
    assert "heredoc" in prompt
    assert "chmod 600" in prompt


def test_prompt_key_handling_present_for_windows_attacker_too() -> None:
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(attacker_os="Windows", target_ip="10.0.0.1")
    # The block is OS-independent; it must appear regardless of attacker OS.
    assert "FILE & KEY HANDLING" in prompt
    assert "ssh -i ~/.ssh/id_ed25519" in prompt


def test_mcp_instructions_contain_key_handling() -> None:
    import mcp_exploit_server

    source = inspect.getsource(mcp_exploit_server)
    assert "heredoc" in source
    assert "write_python_file" in source
    assert "ssh -i ~/.ssh/id_ed25519" in source
