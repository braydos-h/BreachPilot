"""Tests for the config manager / validator module."""

from __future__ import annotations

import tempfile
from pathlib import Path

import yaml


def test_config_validator_import():
    """Verify the config_manager module can be imported."""
    from tools.config_manager import (
        CONFIG_SCHEMA,
        KNOWN_TOP_KEYS,
    )

    assert CONFIG_SCHEMA is not None
    assert "ollama" in CONFIG_SCHEMA
    assert "models" in CONFIG_SCHEMA
    assert "mcp" in CONFIG_SCHEMA
    assert "exploit" in CONFIG_SCHEMA
    assert "stealth" in CONFIG_SCHEMA
    assert "cve_lookup" in CONFIG_SCHEMA
    assert "research" in CONFIG_SCHEMA
    assert "swarm" in CONFIG_SCHEMA
    assert "reasoning" in CONFIG_SCHEMA
    assert "memory" in CONFIG_SCHEMA
    assert "adaptive_exploits" in CONFIG_SCHEMA
    assert "multi_model" in CONFIG_SCHEMA
    assert "skills" in CONFIG_SCHEMA
    assert "agent" in CONFIG_SCHEMA
    assert "ollama" in KNOWN_TOP_KEYS
    assert "research" in KNOWN_TOP_KEYS
    assert "swarm" in KNOWN_TOP_KEYS
    assert "reasoning" in KNOWN_TOP_KEYS
    assert "memory" in KNOWN_TOP_KEYS
    assert "adaptive_exploits" in KNOWN_TOP_KEYS
    assert "multi_model" in KNOWN_TOP_KEYS
    assert "skills" in KNOWN_TOP_KEYS
    assert "agent" in KNOWN_TOP_KEYS


def test_validation_result_defaults():
    """ConfigValidationResult should start with no errors."""
    from tools.config_manager import ConfigValidationResult

    result = ConfigValidationResult()
    assert result.is_valid
    assert not result.has_warnings
    assert result.errors == []
    assert result.warnings == []
    assert result.unknown_keys == []


def test_validation_result_with_errors():
    """ConfigValidationResult should detect errors."""
    from tools.config_manager import ConfigValidationResult

    result = ConfigValidationResult()
    result.errors.append("Something is wrong")
    assert not result.is_valid


def test_validation_result_with_warnings():
    """ConfigValidationResult should detect warnings."""
    from tools.config_manager import ConfigValidationResult

    result = ConfigValidationResult()
    result.warnings.append("Be careful")
    assert result.has_warnings


def test_validate_valid_config():
    """A valid config should pass validation."""
    from tools.config_manager import ConfigValidator

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.safe_dump(
            {
                "ollama": {"host": "http://localhost:11434"},
                "models": {
                    "registry": {"kimi": "kimi-k2.6:cloud"},
                    "default_alias": "kimi",
                },
                "mcp": {"default_transport": "stdio", "http_port": 8001},
                "exploit": {"enabled": True},
                "multi_model": {
                    "enabled": False,
                    "consult_aliases": ["kimi", "deepseek"],
                    "max_consultations": 3,
                    "max_question_chars": 1000,
                    "max_answer_chars": 2000,
                },
            },
            f,
        )
        temp_path = f.name

    try:
        validator = ConfigValidator(temp_path)
        config, result = validator.load_and_validate()
        assert result.is_valid
        assert "ollama" in config
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_validate_missing_file():
    """Missing config file should use defaults."""
    from tools.config_manager import ConfigValidator

    validator = ConfigValidator("/nonexistent/path/config.yaml")
    config = validator.load()
    assert config == validator._build_defaults()


def test_validate_unknown_keys():
    """Unknown top-level keys should be flagged."""
    from tools.config_manager import ConfigValidator

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.safe_dump(
            {
                "ollama": {"host": "http://localhost:11434"},
                "models": {"registry": {"kimi": "kimi-k2.6:cloud"}},
                "mcp": {"default_transport": "stdio"},
                "exploit": {"enabled": True},
                "unknown_section": {"foo": "bar"},
            },
            f,
        )
        temp_path = f.name

    try:
        validator = ConfigValidator(temp_path)
        _, result = validator.load_and_validate()
        assert "unknown_section" in result.unknown_keys
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_apply_defaults_fills_missing():
    """apply_defaults should fill missing sections."""
    from tools.config_manager import ConfigValidator

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.safe_dump(
            {
                "ollama": {"host": "http://custom:11434"},
            },
            f,
        )
        temp_path = f.name

    try:
        validator = ConfigValidator(temp_path)
        validator.load()
        config = validator.apply_defaults()
        assert "models" in config
        assert "mcp" in config
        assert "exploit" in config
        assert "stealth" in config
        assert "multi_model" in config
        assert "skills" in config
        assert config["multi_model"]["enabled"] is False
        assert "deepseek" in config["multi_model"]["consult_aliases"]
        assert "deepseek_flash" in config["models"]["registry"]
        assert config["models"]["registry"]["deepseek_flash"] == "deepseek-v4-flash:cloud"
        assert config["models"]["info"]["deepseek_flash"]["context_window"] == 1000000
        assert "deepseek_flash" in config["multi_model"]["consult_aliases"]
        assert config["skills"]["enabled"] is True
        assert config["skills"]["inject_startup_context"] is False
        assert config["ollama"]["host"] == "http://custom:11434"
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_convenience_accessors():
    """Convenience accessors should return correct values."""
    from tools.config_manager import ConfigValidator

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.safe_dump(
            {
                "ollama": {"host": "http://ollama:11434"},
                "models": {
                    "registry": {"kimi": "kimi-model", "deepseek": "ds-model"},
                    "default_alias": "deepseek",
                },
                "mcp": {"default_transport": "http", "http_port": 9000},
                "exploit": {"enabled": True, "max_rounds": 100},
                "stealth": {"rotate_ua": True},
                "multi_model": {"enabled": True, "max_consultations": 2},
            },
            f,
        )
        temp_path = f.name

    try:
        validator = ConfigValidator(temp_path)
        validator.load()

        assert validator.get_ollama_host() == "http://ollama:11434"
        assert validator.get_default_model() == "deepseek"
        assert validator.get_mcp_transport() == "http"
        assert validator.get_mcp_http_port() == 9000
        assert validator.get_exploit_config()["max_rounds"] == 100
        assert validator.get_stealth_config()["rotate_ua"] is True
        assert validator.get_multi_model_config()["enabled"] is True
        assert validator.get_multi_model_config()["max_consultations"] == 2
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_runtime_sections_are_not_unknown_keys():
    """Checked-in runtime sections should validate without unknown-key noise."""
    from tools.config_manager import ConfigValidator

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.safe_dump(
            {
                "ollama": {"host": "http://localhost:11434"},
                "models": {"registry": {"glm": "glm-5.2:cloud"}, "default_alias": "glm"},
                "mcp": {"default_transport": "stdio"},
                "exploit": {"enabled": True},
                "stealth": {"rotate_ua": False},
                "cve_lookup": {"enabled": True},
                "research": {"enabled": True},
                "swarm": {"enabled": True},
                "reasoning": {"chain_of_thought": True},
                "memory": {"semantic_enabled": True},
                "adaptive_exploits": {"enabled": True},
                "multi_model": {"enabled": False},
            },
            f,
        )
        temp_path = f.name

    try:
        validator = ConfigValidator(temp_path)
        _, result = validator.load_and_validate()
        assert result.is_valid
        assert result.unknown_keys == []
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_load_validated_config_does_not_log_unknown_for_runtime_sections(caplog):
    """Attack startup calls load_validated_config repeatedly; runtime keys must stay quiet."""
    from tools.config_manager import load_validated_config

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.safe_dump(
            {
                "ollama": {"host": "http://localhost:11434"},
                "models": {"registry": {"glm": "glm-5.2:cloud"}, "default_alias": "glm"},
                "mcp": {"default_transport": "stdio"},
                "exploit": {"enabled": True},
                "research": {"enabled": True},
                "swarm": {"enabled": True},
                "memory": {"semantic_enabled": True},
                "adaptive_exploits": {"enabled": True},
            },
            f,
        )
        temp_path = f.name

    try:
        with caplog.at_level("WARNING", logger="tools.config_manager"):
            cfg = load_validated_config(temp_path)
        assert cfg["research"]["enabled"] is True
        assert "Unknown config key" not in caplog.text
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_validate_multi_model_warnings():
    """Invalid multi_model values should warn without breaking other config."""
    from tools.config_manager import ConfigValidator

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.safe_dump(
            {
                "ollama": {"host": "http://localhost:11434"},
                "models": {"registry": {"kimi": "kimi-model"}, "default_alias": "kimi"},
                "mcp": {"default_transport": "stdio"},
                "exploit": {"enabled": True},
                "multi_model": {
                    "enabled": "yes",
                    "consult_aliases": "kimi",
                    "max_consultations": 0,
                },
            },
            f,
        )
        temp_path = f.name

    try:
        validator = ConfigValidator(temp_path)
        _, result = validator.load_and_validate()
        assert result.is_valid
        joined = "\n".join(result.warnings)
        assert "multi_model.enabled" in joined
        assert "multi_model.consult_aliases" in joined
        assert "multi_model.max_consultations" in joined
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_validate_skills_warnings(tmp_path: Path):
    """Invalid runtime skill settings should warn without breaking other config."""
    from tools.config_manager import ConfigValidator

    config_path = tmp_path / "config.yaml"
    yaml.safe_dump(
        {
            "ollama": {"host": "http://localhost:11434"},
            "models": {"registry": {"glm": "glm-5.2:cloud"}, "default_alias": "glm"},
            "mcp": {"default_transport": "stdio"},
            "exploit": {"enabled": True},
            "skills": {
                "enabled": "yes",
                "inject_startup_context": "yes",
                "roots": "skills",
                "max_active_skills": 0,
                "min_contextual_skills": 0,
                "default_skill_weight": "high",
                "context_skill_weight": 0,
                "semantic_min_similarity": 2,
                "diversity_penalty": -1,
            },
        },
        config_path.open("w", encoding="utf-8"),
    )

    validator = ConfigValidator(config_path)
    _, result = validator.load_and_validate()

    assert result.is_valid
    joined = "\n".join(result.warnings)
    assert "skills.enabled" in joined
    assert "skills.inject_startup_context" in joined
    assert "skills.roots" in joined
    assert "skills.max_active_skills" in joined
    assert "skills.min_contextual_skills" in joined
    assert "skills.default_skill_weight" in joined
    assert "skills.context_skill_weight" in joined
    assert "skills.semantic_min_similarity" in joined
    assert "skills.diversity_penalty" in joined


def test_save_config():
    """Saving config should write valid YAML."""
    from tools.config_manager import ConfigValidator

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.safe_dump({"ollama": {"host": "http://localhost:11434"}}, f)
        temp_path = f.name

    try:
        validator = ConfigValidator(temp_path)
        validator.load()
        validator._config["new_key"] = "new_value"
        validator.save()

        # Read back and verify
        reloaded = yaml.safe_load(Path(temp_path).read_text(encoding="utf-8"))
        assert reloaded["new_key"] == "new_value"
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_outcome_judgment_defaults_and_validation(tmp_path):
    from tools.config_manager import ConfigValidator

    path = tmp_path / "outcome-config.yaml"
    path.write_text(
        """
ollama:
  host: http://localhost:11434
models:
  registry: {glm: glm-5.2:cloud}
  default_alias: glm
mcp:
  default_transport: stdio
exploit:
  enabled: true
outcome_judgment:
  max_inconclusive_attempts: 1
  confirmation_threshold: 1.5
  refutation_threshold: 0.25
  min_evidence_references: 0
""",
        encoding="utf-8",
    )
    validator = ConfigValidator(path)
    _, result = validator.load_and_validate()
    assert result.is_valid
    assert any("max_inconclusive_attempts" in warning for warning in result.warnings)
    assert any("confirmation_threshold" in warning for warning in result.warnings)
    assert any("refutation_threshold" in warning for warning in result.warnings)
    assert any("min_evidence_references" in warning for warning in result.warnings)

    defaults = validator._build_defaults()["outcome_judgment"]
    assert defaults == {
        "max_inconclusive_attempts": 3,
        "confirmation_threshold": 0.75,
        "refutation_threshold": 0.75,
        "min_evidence_references": 1,
        # Phase 1.2: Flow A exploit-engine outcome judgment toggle (opt-in, default OFF).
        "flow_a": False,
        # D3: cross-model outcome grading (advisory; deterministic judge stays authority).
        "peer_review": False,
    }


def test_agent_block_schema_and_defaults():
    """The capability-upgrade agent block is in CONFIG_SCHEMA and apply_defaults fills it."""
    from tools.config_manager import CONFIG_SCHEMA, ConfigValidator

    agent = CONFIG_SCHEMA["agent"]
    assert agent["task_graph_enabled"] is True
    assert agent["capability_discovery_enabled"] is True
    assert agent["state_tools_enabled"] is True
    assert agent["planner_hints_enabled"] is True
    assert agent["decision_log_enabled"] is True
    assert agent["reflection_enabled"] is True
    assert agent["max_retries_per_task"] == 2
    assert agent["max_actions"] == 0
    assert agent["generated_code_repair_attempts"] == 3

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.safe_dump({"ollama": {"host": "http://localhost:11434"}}, f)
        temp_path = f.name
    try:
        validator = ConfigValidator(temp_path)
        validator.load()
        config = validator.apply_defaults()
        assert config["agent"]["task_graph_enabled"] is True
        assert config["agent"]["max_retries_per_task"] == 2
        assert config["agent"]["max_actions"] == 0
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_agent_block_disabled_validates_without_error(tmp_path: Path):
    """agent.decision_log_enabled=false validates (warning-free for that key)."""
    from tools.config_manager import ConfigValidator

    path = tmp_path / "agent-config.yaml"
    yaml.safe_dump(
        {
            "ollama": {"host": "http://localhost:11434"},
            "models": {"registry": {"glm": "glm-5.2:cloud"}, "default_alias": "glm"},
            "mcp": {"default_transport": "stdio"},
            "exploit": {"enabled": True},
            "agent": {"decision_log_enabled": False},
        },
        path.open("w", encoding="utf-8"),
    )

    validator = ConfigValidator(path)
    _, result = validator.load_and_validate()
    assert result.is_valid
    assert "agent.decision_log_enabled" not in "\n".join(result.warnings)


def test_agent_block_invalid_values_warn_not_error(tmp_path: Path):
    """Bad agent.* types warn but keep config valid (warn-not-reject convention)."""
    from tools.config_manager import ConfigValidator

    path = tmp_path / "bad-agent.yaml"
    yaml.safe_dump(
        {
            "ollama": {"host": "http://localhost:11434"},
            "models": {"registry": {"glm": "glm-5.2:cloud"}, "default_alias": "glm"},
            "mcp": {"default_transport": "stdio"},
            "exploit": {"enabled": True},
            "agent": {
                "task_graph_enabled": "yes",
                "max_retries_per_task": -1,
                "max_actions": "many",
                "generated_code_repair_attempts": True,
            },
        },
        path.open("w", encoding="utf-8"),
    )

    validator = ConfigValidator(path)
    _, result = validator.load_and_validate()
    assert result.is_valid
    joined = "\n".join(result.warnings)
    assert "agent.task_graph_enabled" in joined
    assert "agent.max_retries_per_task" in joined
    assert "agent.max_actions" in joined
    # bool is rejected for the int keys (isinstance(True, int) guard)
    assert "agent.generated_code_repair_attempts" in joined


def test_models_roles_schema_and_validation(tmp_path: Path):
    """models.roles block defaults empty strings and warns on bad aliases."""
    # Schema advertises all six roles, each defaulting to empty string.
    from tools.config_manager import CONFIG_SCHEMA, ConfigValidator

    roles = CONFIG_SCHEMA["models"]["roles"]
    for role in ("planner", "executor", "interpreter", "code_generator", "critic", "summarizer"):
        assert roles[role] == ""

    path = tmp_path / "roles-config.yaml"
    yaml.safe_dump(
        {
            "ollama": {"host": "http://localhost:11434"},
            "models": {
                "registry": {"glm": "glm-5.2:cloud"},
                "default_alias": "glm",
                "roles": {
                    "planner": "glm",
                    "executor": "",
                    "critic": "no_such_alias",
                    "summarizer": 5,
                },
            },
            "mcp": {"default_transport": "stdio"},
            "exploit": {"enabled": True},
        },
        path.open("w", encoding="utf-8"),
    )

    validator = ConfigValidator(path)
    _, result = validator.load_and_validate()
    assert result.is_valid
    joined = "\n".join(result.warnings)
    # valid alias + empty string: no warning
    assert "models.roles.planner" not in joined
    assert "models.roles.executor" not in joined
    # unknown alias: warn
    assert "models.roles.critic" in joined
    # non-string: warn
    assert "models.roles.summarizer" in joined


def test_config_yaml_keys_subset_of_schema():
    """Phase 5 drift guard: every top-level key in config.yaml must be in CONFIG_SCHEMA.

    Prevents silent drift where a checked-in config adds a new block (e.g.
    caldera/ics) that the validator then warns as unknown. The schema is the
    runtime truth; config.yaml must not contain keys outside it (except
    plugin-registered sections, which are allowed via PLUGIN_REGISTRY).
    """
    import yaml

    from tools.config_manager import CONFIG_SCHEMA

    cfg_path = Path("config.yaml")
    assert cfg_path.exists(), "config.yaml must exist at repo root"
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    assert isinstance(cfg, dict), "config.yaml must be a mapping"
    schema_keys = set(CONFIG_SCHEMA.keys())
    cfg_keys = set(cfg.keys())
    # plugin sections are allowed to be extra (they are not in schema)
    try:
        from tools.plugins import PLUGIN_REGISTRY

        plugin_keys = set(PLUGIN_REGISTRY.config_sections.keys())
    except Exception:
        plugin_keys = set()
    extra = cfg_keys - schema_keys - plugin_keys
    assert not extra, (
        f"config.yaml has keys not in CONFIG_SCHEMA: {sorted(extra)} (add them to CONFIG_SCHEMA or PLUGIN_REGISTRY.config_sections)"
    )
