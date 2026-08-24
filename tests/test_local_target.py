"""Tests for local-target awareness (Issue 5).

``is_local_target`` drives the LOCAL TARGET PLAYBOOK injected into the exploit
system prompt so that a loopback target (e.g. 127.0.0.1) is attacked via local
filesystem reads instead of network brute-force against the agent's own host.
"""

from __future__ import annotations

from unittest.mock import patch


def test_loopback_ipv4_is_local():
    from tools.validation_utils import is_local_target

    assert is_local_target("127.0.0.1") is True
    assert is_local_target("127.1.2.3") is True  # whole 127.0.0.0/8 is loopback


def test_loopback_ipv6_is_local():
    from tools.validation_utils import is_local_target

    assert is_local_target("::1") is True


def test_localhost_name_is_local():
    from tools.validation_utils import is_local_target

    assert is_local_target("localhost") is True
    assert is_local_target("Localhost") is True


def test_remote_ip_is_not_local():
    from tools.validation_utils import is_local_target

    assert is_local_target("10.0.0.50") is False
    assert is_local_target("8.8.8.8") is False


def test_empty_and_garbage_not_local():
    from tools.validation_utils import is_local_target

    assert is_local_target("") is False
    assert is_local_target(None) is False  # type: ignore[arg-type]
    assert is_local_target("not-an-ip") is False


def test_local_interface_ip_is_local():
    """An IP bound on a local interface must be detected as local."""
    from tools.validation_utils import is_local_target

    fake = "192.168.123.234"
    with (
        patch("socket.gethostname", return_value="thisbox"),
        patch("socket.gethostbyname", return_value=fake),
        patch("socket.getaddrinfo", return_value=[]),
    ):
        assert is_local_target(fake) is True


def test_prompt_includes_local_playbook_for_loopback():
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(attacker_os="Linux", target_ip="127.0.0.1")
    assert "LOCAL TARGET PLAYBOOK" in prompt
    assert "/etc/shadow" in prompt
    assert "SUID" in prompt or "-perm -4000" in prompt
    assert "SKIP the PIVOT phase" in prompt


def test_prompt_excludes_local_playbook_for_remote_target():
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(attacker_os="Linux", target_ip="10.0.0.50")
    assert "LOCAL TARGET PLAYBOOK" not in prompt
