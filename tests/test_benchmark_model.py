"""Benchmark model selection follows the configured provider adapter."""

from tools.benchmark.envinfo import resolve_model_metadata
from tools.benchmark.model import resolve_model_alias


def test_resolves_chatgpt_default_model_instead_of_ollama_alias() -> None:
    config = {
        "models": {"provider": "chatgpt", "default_alias": "glm"},
        "chatgpt": {"default_model": "gpt-5.2"},
    }

    assert resolve_model_alias(config) == "gpt-5.2"


def test_resolves_opencode_default_model_from_modern_provider_config() -> None:
    config = {
        "models": {"provider": "opencode_go", "default_alias": "glm"},
        "providers": {"opencode_go": {"default_model": "muse-spark-1.2-contributor"}},
    }

    assert resolve_model_alias(config) == "muse-spark-1.2-contributor"


def test_resolves_ollama_alias_to_concrete_registry_model() -> None:
    config = {"models": {"provider": "ollama", "default_alias": "glm", "registry": {"glm": "glm-5.2:cloud"}}}

    assert resolve_model_alias(config) == "glm-5.2:cloud"


def test_explicit_benchmark_model_takes_precedence() -> None:
    config = {"models": {"provider": "chatgpt", "default_alias": "glm"}}

    assert resolve_model_alias(config, "gpt-5-mini") == "gpt-5-mini"


def test_provider_default_model_id_is_retained_in_environment_metadata() -> None:
    config = {
        "models": {
            "provider": "opencode_go",
            "default_alias": "glm",
            "registry": {"glm": "glm-5.2:cloud"},
        },
        "providers": {"opencode_go": {"default_model": "muse-spark-1.2-contributor"}},
    }

    metadata = resolve_model_metadata(config, resolve_model_alias(config))

    assert metadata["model_id"] == "muse-spark-1.2-contributor"
    assert metadata["model_alias"] == "muse-spark-1.2-contributor"


def test_registry_model_id_is_retained_when_runner_receives_concrete_id() -> None:
    config = {
        "models": {"provider": "ollama", "default_alias": "glm", "registry": {"glm": "glm-5.2:cloud"}},
        "ollama": {"model": "glm-5.2:cloud"},
    }

    metadata = resolve_model_metadata(config, resolve_model_alias(config))

    assert metadata["model_id"] == "glm-5.2:cloud"
    assert metadata["model_version"] == "5.2:cloud"
