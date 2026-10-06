from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts.prepare_ci_lab_config import prepare_ci_lab_config


def test_ci_lab_config_enables_only_explicit_loopback_mapping(tmp_path: Path) -> None:
    source = tmp_path / "config.yaml"
    output = tmp_path / "reports" / "ci-lab-config.yaml"
    source.write_text(
        "sandbox:\n"
        "  enabled: true\n"
        "  network:\n"
        "    enforce: true\n"
        "    fail_closed: true\n"
        "    map_host_loopback: false\n",
        encoding="utf-8",
    )

    assert prepare_ci_lab_config(source, output) == output
    original = yaml.safe_load(source.read_text(encoding="utf-8"))
    generated = yaml.safe_load(output.read_text(encoding="utf-8"))

    assert original["sandbox"]["network"]["map_host_loopback"] is False
    assert generated["sandbox"]["network"]["map_host_loopback"] is True
    assert generated["sandbox"]["enabled"] is True
    assert generated["sandbox"]["network"]["enforce"] is True
    assert generated["sandbox"]["network"]["fail_closed"] is True


def test_checked_in_config_produces_validated_local_lab_config(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[1]
    output = tmp_path / "reports" / "ci-lab-config.yaml"
    prepare_ci_lab_config(repository / "config.yaml", output)

    from tools.config.loader import load_validated_config

    config = load_validated_config(output)
    assert config["models"]["provider"] == "opencode_go"
    assert config["sandbox"]["enabled"] is True
    assert config["sandbox"]["network"]["enforce"] is True
    assert config["sandbox"]["network"]["fail_closed"] is True
    assert config["sandbox"]["network"]["map_host_loopback"] is True


@pytest.mark.parametrize(
    ("sandbox", "expected_error"),
    [
        ({"enabled": False, "network": {"enforce": True, "fail_closed": True}}, "sandbox.enabled"),
        ({"enabled": True, "network": {"enforce": False, "fail_closed": True}}, "enforcement"),
        ({"enabled": True, "network": {"enforce": True, "fail_closed": False}}, "enforcement"),
    ],
)
def test_ci_lab_config_refuses_to_weaken_sandbox(tmp_path: Path, sandbox, expected_error: str) -> None:
    source = tmp_path / "config.yaml"
    output = tmp_path / "reports" / "ci-lab-config.yaml"
    source.write_text(yaml.safe_dump({"sandbox": sandbox}), encoding="utf-8")

    with pytest.raises(ValueError, match=expected_error):
        prepare_ci_lab_config(source, output)
    assert not output.exists()
