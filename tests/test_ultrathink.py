"""Tests for the --ultrathink deep-reasoning mode."""

from __future__ import annotations

from pathlib import Path

import yaml


def test_build_prompt_includes_ultrathink_block():
    """When ultrathink=True the system prompt must contain the [ULTRATHINK] block."""
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(
        attacker_os="Linux",
        target_ip="127.0.0.1",
        ultrathink=True,
    )
    assert "[ULTRATHINK]" in prompt
    assert "[REASONING]" in prompt
    assert "HYPOTHESIS" in prompt


def test_build_prompt_without_ultrathink_omits_block():
    """Without ultrathink the prompt should not contain the ultrathink block."""
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(
        attacker_os="Linux",
        target_ip="127.0.0.1",
        ultrathink=False,
    )
    assert "[ULTRATHINK]" not in prompt


def test_build_prompt_includes_runtime_skills_block():
    """Explicit eager runtime skill context remains supported."""
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(
        attacker_os="Linux",
        target_ip="127.0.0.1",
        skill_context="### scanning-network-with-nmap-advanced\nUse safe nmap workflow.",
    )

    assert "RUNTIME SKILLS" in prompt
    assert "scanning-network-with-nmap-advanced" in prompt
    assert "do not override target scope" in prompt.lower()


def test_build_prompt_includes_lazy_runtime_skill_lookup_hints():
    """Lazy runtime skill hints should not inject full skill bodies."""
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(
        attacker_os="Linux",
        target_ip="127.0.0.1",
        skill_hints="scanning-network-with-nmap-advanced | recon | selected for nmap",
    )

    assert "RUNTIME SKILL LOOKUP" in prompt
    assert "search_runtime_skills" in prompt
    assert "load_runtime_skill" in prompt
    assert "selected for nmap" in prompt
    assert "Use safe nmap workflow" not in prompt


def test_config_validator_accepts_reasoning_ultrathink(tmp_path: Path):
    """Config validation should accept the new reasoning.ultrathink keys."""
    from tools.config_manager import ConfigValidator

    config_path = tmp_path / "config.yaml"
    yaml.safe_dump(
        {
            "ollama": {"host": "http://localhost:11434"},
            "models": {"registry": {"kimi": "kimi-k2.6:cloud"}, "default_alias": "kimi"},
            "mcp": {"default_transport": "stdio", "http_port": 8001},
            "exploit": {"enabled": True},
            "reasoning": {
                "chain_of_thought": True,
                "reflection_every_n_actions": 10,
                "critic_enabled": True,
                "observer_mode": "hybrid",
                "ultrathink": True,
                "ultrathink_reflection_interval": 2,
            },
        },
        config_path.open("w", encoding="utf-8"),
    )

    validator = ConfigValidator(config_path)
    config, result = validator.load_and_validate()
    assert result.is_valid
    assert "reasoning" not in result.unknown_keys
    assert config["reasoning"]["ultrathink"] is True


def test_config_validator_warns_on_invalid_ultrathink_interval(tmp_path: Path):
    """A non-positive ultrathink_reflection_interval should produce a warning."""
    from tools.config_manager import ConfigValidator

    config_path = tmp_path / "config.yaml"
    yaml.safe_dump(
        {
            "ollama": {"host": "http://localhost:11434"},
            "models": {"registry": {"kimi": "kimi-k2.6:cloud"}, "default_alias": "kimi"},
            "mcp": {"default_transport": "stdio"},
            "exploit": {"enabled": True},
            "reasoning": {"ultrathink_reflection_interval": 0},
        },
        config_path.open("w", encoding="utf-8"),
    )

    validator = ConfigValidator(config_path)
    _, result = validator.load_and_validate()
    assert result.is_valid
    assert any("ultrathink_reflection_interval" in w for w in result.warnings)


def test_cli_parses_ultrathink_flag():
    """The main CLI parser should accept --ultrathink."""
    from main import parse_args

    args = parse_args(["--target", "127.0.0.1", "--mode", "recon", "--ultrathink"])
    assert args.ultrathink is True


def test_cli_parses_self_test_flag():
    """The main CLI parser should accept --self-test."""
    from main import parse_args

    args = parse_args(["--self-test"])
    assert args.self_test is True
