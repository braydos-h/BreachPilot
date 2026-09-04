"""Config contract tests for the browser block (architecture-only build).

Verifies that the ``browser:`` config block ships DISABLED by default and that
existing installs behave byte-identically: schema defaults, config.yaml
mirroring, validator warnings, and zero-behavior-change when absent.
"""

from __future__ import annotations

from tools.config.schema import CONFIG_SCHEMA

BROWSER_DEFAULTS = {
    "enabled": False,
    "backend": "none",
    "headless": True,
    "max_sessions": 2,
    "session_timeout_seconds": 300,
    "navigation_timeout_seconds": 30,
    "capture_screenshots": True,
    "capture_network": True,
    "capture_console": False,
    "persist_storage": False,
    "allow_mutating_actions": False,
    "console_max_events": 200,
    "network_max_events": 500,
    "body_sample_max_bytes": 4096,
    "dom_summary_max_chars": 8000,
    "artifact_dir": "",
    "executable_path": "",
    "worker_image": "",
}


# ── Schema defaults ───────────────────────────────────────────────────────


def test_browser_defaults_are_disabled():
    assert CONFIG_SCHEMA.get("browser") == BROWSER_DEFAULTS
    # Zero-behavior-change guarantee: the block is OFF and names no backend.
    assert CONFIG_SCHEMA["browser"]["enabled"] is False
    assert CONFIG_SCHEMA["browser"]["backend"] == "none"
    # Storage harvest persists nothing by default (credential-store rule).
    assert CONFIG_SCHEMA["browser"]["persist_storage"] is False


def test_ollama_provider_untouched_by_browser_block():
    """The browser block adds no hard dependency — Playwright stays optional."""
    block = str(CONFIG_SCHEMA.get("browser"))
    assert "playwright>=" not in block
    assert "pip install" not in block


# ── Load-time behavior ────────────────────────────────────────────────────


def test_missing_browser_block_loads_disabled_and_actives_nothing(tmp_path):
    """A config file with no browser key loads the disabled defaults + no capabilities."""
    from tools.browser.capabilities import browser_available, browser_capabilities
    from tools.config.loader import load_validated_config

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\nmodels:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n",
        encoding="utf-8",
    )
    cfg = load_validated_config(config_path)
    assert cfg["browser"] == BROWSER_DEFAULTS
    assert browser_available(cfg) is False
    records = {r["name"]: r["available"] for r in browser_capabilities(cfg)}
    assert records and not any(records.values())


def test_validator_warns_on_bad_browser_values(tmp_path):
    from tools.config.loader import validate_config_file

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        'browser:\n  enabled: "yes-please"\n  backend: 7\n  max_sessions: -3\n  capture_screenshots: "sure"\n'
        '  allow_mutating_actions: "maybe"\n  network_max_events: 0\n  artifact_dir: 7\n',
        encoding="utf-8",
    )
    result = validate_config_file(config_path)
    joined = "; ".join(result.warnings)
    assert "browser.enabled must be a boolean." in joined
    assert "browser.backend must be a string." in joined
    assert "browser.max_sessions must be a positive integer." in joined
    assert "browser.capture_screenshots must be a boolean." in joined
    assert "browser.allow_mutating_actions must be a boolean." in joined
    assert "browser.network_max_events must be a positive integer." in joined
    assert "browser.artifact_dir must be a string." in joined
    assert result.is_valid  # warnings, not errors — never breaks existing installs


def test_validator_errors_when_browser_is_not_a_mapping(tmp_path):
    from tools.config.loader import validate_config_file

    config_path = tmp_path / "config.yaml"
    config_path.write_text("browser: 12345\n", encoding="utf-8")
    result = validate_config_file(config_path)
    assert "'browser' must be a mapping." in result.errors
    assert not result.is_valid


def test_validator_silent_on_stock_browser_block(tmp_path):
    from tools.config.loader import validate_config_file

    config_path = tmp_path / "config.yaml"
    lines = ["browser:"]
    for key, value in BROWSER_DEFAULTS.items():
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        elif value == "none":
            rendered = "none"
        else:
            rendered = str(value)
        lines.append(f"  {key}: {rendered}")
    config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = validate_config_file(config_path)
    assert not [w for w in result.warnings if w.startswith("browser.")]
