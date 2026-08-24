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

    with (
        patch("tools.env_probe.shutil.which", side_effect=fake_which),
        patch("tools.env_probe._can_passwordless_sudo", return_value=False),
    ):
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

    with (
        patch("tools.env_probe.shutil.which", side_effect=fake_which),
        patch("tools.env_probe._can_passwordless_sudo", return_value=True),
    ):
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
    prompt = build_exploit_system_prompt(attacker_os="Linux", target_ip="10.0.0.5", env_context=env)
    assert "PRE-FLIGHT ENVIRONMENT" in prompt
    assert "PIVOT NOW" in prompt
    # Must appear after the ATTACKER ENVIRONMENT header.
    assert prompt.index("ATTACKER ENVIRONMENT") < prompt.index("PRE-FLIGHT ENVIRONMENT")


def test_prompt_without_env_context_unchanged():
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(attacker_os="Linux", target_ip="10.0.0.5")
    assert "PRE-FLIGHT ENVIRONMENT" not in prompt


def test_windows_guidance_names_specific_failure_modes():
    """The Windows attacker guidance must name the specifics the runtime log
    showed failing: use `python` not `python3`, no pip installs, no netcat, and
    that nmap 0xC0000005 crashes are deterministic (not retried). Generic
    guidance let the AI burn rounds on pip/python3/nc."""
    from tools.env_probe import ENV_TOOLS
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(attacker_os="Windows", target_ip="10.0.0.5")
    assert "WINDOWS ATTACKER GUIDANCE" in prompt
    assert "`python3`" in prompt and "use `python`" in prompt
    assert "pip install" in prompt  # told NOT to use it
    assert "netcat" in prompt
    assert "0xC0000005" in prompt
    assert "not retried" in prompt or "do NOT retry" in prompt
    # The probe registry must include the Windows interpreter names so the
    # startup env report can confirm a working `python` (not just `python3`).
    assert "python" in ENV_TOOLS
    assert "py" in ENV_TOOLS


# ── Gap 5: single source of truth for the required-tool registry ────────────


def test_env_tools_public_and_alias_backward_compat():
    """ENV_TOOLS is the public registry; _ENV_TOOLS is the same list object."""
    from tools.env_probe import _ENV_TOOLS, ENV_TOOLS

    assert ENV_TOOLS is _ENV_TOOLS
    # Sanity: a few core pentest tools are present.
    for t in ("nmap", "hydra", "searchsploit", "msfconsole"):
        assert t in ENV_TOOLS


def test_check_environment_default_derives_from_env_tools():
    """check_environment's default list = ENV_TOOLS + explicit extras (no dup)."""
    from tools.env_probe import ENV_TOOLS
    from tools.mcp_tools.terminal import _check_env_default_tools

    default = _check_env_default_tools()
    # Every curated tool is surfaced.
    for t in ENV_TOOLS:
        assert t in default, f"{t} missing from check_environment default"
    # The explicit extras are present too.
    for t in ("masscan", "rustscan", "feroxbuster", "nuclei", "metasploit-framework"):
        assert t in default
    # No duplicates.
    assert len(default) == len(set(default))
    # ldapsearch is an extra (not in ENV_TOOLS) but is in the default list.
    assert "ldapsearch" in default
    assert "ldapsearch" not in ENV_TOOLS
