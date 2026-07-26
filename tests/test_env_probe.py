"""Tests for the pre-flight environment probe (Issue 4)."""

from __future__ import annotations

from unittest.mock import patch


def test_render_empty_when_nothing_missing():
    from tools.env_probe import render_env_context

    probe = {
        "installed": ["nmap", "curl", "python3"],
        "missing": [],
        "passwordless_sudo": False,
        "pip_available": True,
        "recommendations": {},
    }
    assert render_env_context(probe) == ""


def test_missing_without_sudo_flags_python_fallback():
    from tools.env_probe import preflight_env_probe, render_env_context

    # Simulate a sudo-less box missing hydra + searchsploit, with nmap present.
    def fake_which(t):
        return "/usr/bin/" + t if t in {"nmap", "curl", "python3", "git"} else None

    with patch("tools.env_probe.shutil.which", side_effect=fake_which), \
            patch("tools.env_probe._can_passwordless_sudo", return_value=False):
        probe = preflight_env_probe()

    assert "hydra" in probe["missing"]
    assert "searchsploit" in probe["missing"]
    assert probe["passwordless_sudo"] is False
    assert probe["recommendations"]["hydra"] == "write_python_fallback"
    assert probe["recommendations"]["searchsploit"] == "write_python_fallback"

    rendered = render_env_context(probe)
    assert "PRE-FLIGHT ENVIRONMENT" in rendered
    assert "PIVOT NOW" in rendered
    assert "hydra" in rendered
    assert "DO NOT call apt_install" in rendered


def test_missing_with_sudo_flags_apt_install():
    from tools.env_probe import preflight_env_probe

    # gobuster is in _PYTHON_FALLBACK but NOT _PIP_INSTALLABLE, so with sudo
    # available the recommendation is install_via_apt.
    def fake_which(t):
        return None if t == "gobuster" else "/usr/bin/" + t

    with patch("tools.env_probe.shutil.which", side_effect=fake_which), \
            patch("tools.env_probe._can_passwordless_sudo", return_value=True):
        probe = preflight_env_probe()

    assert probe["recommendations"]["gobuster"] == "install_via_apt"
    assert probe["passwordless_sudo"] is True


def test_can_passwordless_sudo_false_on_windows():
    from tools.env_probe import _can_passwordless_sudo

    with patch("tools.env_probe.platform.system", return_value="Windows"):
        assert _can_passwordless_sudo() is False


def test_prompt_carries_env_context_block():
    from tools.exploit_agent import build_exploit_system_prompt

    env = (
        "PRE-FLIGHT ENVIRONMENT (probed at startup — do NOT re-discover by failing):\n"
        "  Missing:   hydra\n"
        "  PIVOT NOW (no sudo, apt_install will fail): hydra\n"
    )
    prompt = build_exploit_system_prompt(
        attacker_os="Linux", target_ip="10.0.0.5", env_context=env
    )
    assert "PRE-FLIGHT ENVIRONMENT" in prompt
    assert "PIVOT NOW" in prompt
    # Must appear after the ATTACKER ENVIRONMENT header.
    assert prompt.index("ATTACKER ENVIRONMENT") < prompt.index("PRE-FLIGHT ENVIRONMENT")


def test_prompt_without_env_context_unchanged():
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(attacker_os="Linux", target_ip="10.0.0.5")
    assert "PRE-FLIGHT ENVIRONMENT" not in prompt