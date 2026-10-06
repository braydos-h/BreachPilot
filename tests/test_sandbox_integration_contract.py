"""Offline regression checks for the real-Docker test harness contract."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest


@pytest.fixture
def harness():
    source = Path(__file__).with_name("test_sandbox_integration.py")
    spec = importlib.util.spec_from_file_location("sandbox_integration_contract_subject", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Importing the integration module in offline collection must never probe Docker.
    with patch("subprocess.run", side_effect=AssertionError("Docker probed during collection")):
        spec.loader.exec_module(module)
    return module


def test_required_integration_fails_instead_of_skipping(harness, monkeypatch):
    monkeypatch.setenv(harness.REQUIRED_ENV, "1")
    monkeypatch.setattr(harness, "_daemon_ok", lambda: False)
    with pytest.raises(pytest.fail.Exception, match="requires Docker"):
        harness._require_prerequisites()


def test_optional_integration_skips_missing_prerequisites(harness, monkeypatch):
    monkeypatch.delenv(harness.REQUIRED_ENV, raising=False)
    monkeypatch.setattr(harness, "_daemon_ok", lambda: False)
    with pytest.raises(pytest.skip.Exception, match="requires Docker"):
        harness._require_prerequisites()


@pytest.mark.parametrize("failure", [RuntimeError("attach failed"), pytest.skip.Exception("setup skip")])
def test_partial_setup_always_removes_helper_and_worker(harness, monkeypatch, tmp_path, failure):
    import tools.sandbox

    manager = SimpleNamespace(
        execute=Mock(return_value=SimpleNamespace(status="completed")),
        destroy=Mock(return_value={"container_removed": True, "network_removed": True}),
        network_name="owned-network",
    )
    monkeypatch.setattr(tools.sandbox, "resolve_manager", lambda *args: manager)
    docker = Mock(return_value=(0, "", ""))
    monkeypatch.setattr(harness, "_docker", docker)

    def fail_setup(*args, **kwargs):
        raise failure

    monkeypatch.setattr(harness, "_ensure_target_container", fail_setup)
    factory = SimpleNamespace(mktemp=lambda name: tmp_path)
    fixture = harness.it_env.__wrapped__(factory)
    with pytest.raises(type(failure)):
        next(fixture)
    manager.destroy.assert_called_once()
    assert docker.call_count == 1
    args = docker.call_args.args
    assert args[:2] == ("rm", "-f")
    assert args[2].startswith("breachpilot-it-allowed-")
