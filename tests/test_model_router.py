from __future__ import annotations


def test_model_choice_formatter_includes_deepseek_flash_metadata() -> None:
    from tools.model_router import DEFAULT_MODEL_REGISTRY, format_model_choice

    label = format_model_choice("deepseek_flash", registry=DEFAULT_MODEL_REGISTRY)

    assert "deepseek_flash" in label
    assert "DeepSeek V4 Flash" in label
    assert "deepseek-v4-flash:cloud" in label
    assert "1M ctx" in label
