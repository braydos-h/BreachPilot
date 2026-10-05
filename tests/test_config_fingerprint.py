"""Regression coverage for API accepted-config identity at MCP startup."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml

from tools.kernel.config import load_config
from tools.kernel.config_fingerprint import (
    ConfigFingerprintMismatch,
    config_fingerprint,
    verify_config_fingerprint,
)


def test_fingerprint_matches_child_load_and_ignores_only_webui_override(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "mcp:\n  http_port: 8001\nexploit:\n  allowed_targets:\n    - 192.0.2.10\napi:\n  host: 127.0.0.1\n",
        encoding="utf-8",
    )

    accepted_snapshot = load_config(config_path)
    expected = config_fingerprint(accepted_snapshot)
    child_loaded_config = load_config(config_path)
    verify_config_fingerprint(child_loaded_config, expected)

    # --web changes this one in-memory flag without writing config.yaml; MCP
    # children never read it, so it is intentionally outside their fingerprint.
    accepted_snapshot["api"]["serve_webui"] = True
    verify_config_fingerprint(child_loaded_config, config_fingerprint(accepted_snapshot))

    changed = dict(child_loaded_config)
    changed["exploit"] = {"allowed_targets": ["192.0.2.11"]}
    with pytest.raises(ConfigFingerprintMismatch):
        verify_config_fingerprint(changed, expected)

    changed_api = dict(child_loaded_config)
    changed_api["api"] = {"host": "0.0.0.0"}
    with pytest.raises(ConfigFingerprintMismatch):
        verify_config_fingerprint(changed_api, expected)


def test_fingerprint_mismatch_error_does_not_include_config_values_or_digest() -> None:
    secret_like_value = "provider-key-value-that-must-not-appear"
    expected = config_fingerprint({"provider": {"key_ref": "OPENCODE_GO_API_KEY"}})
    actual = {"provider": {"key_ref": secret_like_value}}

    with pytest.raises(ConfigFingerprintMismatch) as exc_info:
        verify_config_fingerprint(actual, expected)

    assert secret_like_value not in str(exc_info.value)
    assert expected not in str(exc_info.value)


def test_mcp_child_rejects_changed_config_before_key_bootstrap_or_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mcp_exploit_server

    accepted = {
        "exploit": {"allowed_targets": ["192.0.2.10"]},
        "providers": {"opencode_go": {"api_key_env": "OPENCODE_GO_API_KEY"}},
    }
    changed = {
        "exploit": {"allowed_targets": ["192.0.2.11"]},
        "providers": {"opencode_go": {"api_key_env": "OPENCODE_GO_API_KEY"}},
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(changed), encoding="utf-8")
    expected = config_fingerprint(accepted)

    key_bootstrap = MagicMock()
    builder = MagicMock()
    cve_builder = MagicMock()
    researcher_builder = MagicMock()
    server_factory = MagicMock()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(mcp_exploit_server, "load_api_keys_into_env", key_bootstrap)
    monkeypatch.setattr(mcp_exploit_server, "build_search", builder)
    monkeypatch.setattr(mcp_exploit_server, "build_cve_search", cve_builder)
    monkeypatch.setattr(mcp_exploit_server, "build_researcher", researcher_builder)
    monkeypatch.setattr(mcp_exploit_server, "create_mcp_server", server_factory)

    with pytest.raises(ConfigFingerprintMismatch):
        mcp_exploit_server.main(
            [
                "--transport",
                "stdio",
                "--config",
                str(config_path),
                "--expected-config-sha256",
                expected,
            ]
        )

    key_bootstrap.assert_not_called()
    builder.assert_not_called()
    cve_builder.assert_not_called()
    researcher_builder.assert_not_called()
    server_factory.assert_not_called()


def test_mcp_child_rejects_missing_snapshot_secret_before_key_bootstrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mcp_exploit_server
    from tools.kernel.mcp_config_snapshot import McpConfigSnapshotError, private_mcp_config_snapshot

    key_bootstrap = MagicMock()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(mcp_exploit_server, "load_api_keys_into_env", key_bootstrap)

    with private_mcp_config_snapshot({"recon": {"shodan_api_key": "snapshot-secret-value"}}) as snapshot:
        env_name = next(iter(snapshot.secret_env))
        monkeypatch.delenv(env_name, raising=False)
        with pytest.raises(McpConfigSnapshotError, match="secret reference is unavailable"):
            mcp_exploit_server.main(
                [
                    "--transport",
                    "stdio",
                    "--private-config-snapshot",
                    "--config",
                    str(snapshot.config_path),
                    "--expected-config-sha256",
                    config_fingerprint({"recon": {"shodan_api_key": "snapshot-secret-value"}}),
                ]
            )

    key_bootstrap.assert_not_called()


def test_private_snapshot_requires_expected_fingerprint() -> None:
    import mcp_exploit_server

    with pytest.raises(SystemExit) as exc_info:
        mcp_exploit_server.parse_args(["--private-config-snapshot"])

    assert exc_info.value.code == 2


def test_private_snapshot_keeps_credentials_embedded_in_any_url_out_of_yaml() -> None:
    from tools.kernel.mcp_config_snapshot import private_mcp_config_snapshot, resolve_mcp_config_secret_refs

    credential_url = "https://operator:credential-value@tickets.example.test/api"
    network_path_url = "//operator:network-path-secret@proxy.example.test/api"
    whitespace_network_path_url = " \t//operator:whitespace-secret@proxy.example.test/api"
    embedded_control_urls = [
        "https:\n//operator:linebreak-secret@example.test/api",
        "https:\r//operator:carriage-secret@example.test/api",
        "https:\t//operator:tab-secret@example.test/api",
    ]
    ordinary_url = "https://tickets.example.test/api"
    config = {
        "ticketing": {"base_url": credential_url},
        "providers": {"base_url": ordinary_url},
        "proxies": [network_path_url, whitespace_network_path_url, *embedded_control_urls, ordinary_url],
        "webhooks": {"url": embedded_control_urls[0]},
    }

    with private_mcp_config_snapshot(config) as snapshot:
        artifact = snapshot.config_path.read_text(encoding="utf-8")
        assert credential_url not in artifact
        assert network_path_url not in artifact
        assert whitespace_network_path_url not in artifact
        assert "credential-value" not in artifact
        assert "network-path-secret" not in artifact
        assert "whitespace-secret" not in artifact
        for secret in ("linebreak-secret", "carriage-secret", "tab-secret"):
            assert secret not in artifact
        assert ordinary_url in artifact
        assert credential_url in snapshot.secret_env.values()
        assert network_path_url in snapshot.secret_env.values()
        assert whitespace_network_path_url in snapshot.secret_env.values()
        assert all(url in snapshot.secret_env.values() for url in embedded_control_urls)
        serialized = yaml.safe_load(artifact)
        child_config = resolve_mcp_config_secret_refs(serialized, snapshot.secret_env)
        assert child_config == config


@pytest.mark.parametrize("secret_value", [123456, True, None, {}, []])
def test_private_snapshot_rejects_non_string_secret_values(secret_value: Any) -> None:
    from tools.kernel.mcp_config_snapshot import McpConfigSnapshotError, private_mcp_config_snapshot

    with pytest.raises(McpConfigSnapshotError, match="secret values must be strings"):
        with private_mcp_config_snapshot({"provider": {"api_key": secret_value}}):
            pytest.fail("invalid secret values must not enter the private snapshot")


@pytest.mark.asyncio
async def test_stdio_session_passes_fingerprint_to_child_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mcp
    import mcp.client.stdio as mcp_stdio

    from tools.mcp_session import open_exploit_mcp_session

    expected = "a" * 64
    captured_params: list[Any] = []

    class _Session:
        async def initialize(self) -> None:
            return None

        async def __aenter__(self) -> _Session:
            return self

        async def __aexit__(self, *_exc_info: object) -> bool:
            return False

    @contextlib.asynccontextmanager
    async def _stdio_client(params: Any):
        captured_params.append(params)
        yield "read", "write"

    monkeypatch.setattr(mcp, "ClientSession", lambda *_args: _Session())
    monkeypatch.setattr(mcp_stdio, "stdio_client", _stdio_client)

    async with open_exploit_mcp_session(
        transport="stdio",
        config_path=tmp_path / "config.yaml",
        target_ip="192.0.2.10",
        exploit_port=8001,
        workspace=tmp_path / "worker",
        config_fingerprint=expected,
    ) as session:
        assert isinstance(session, _Session)

    args = captured_params[0].args
    flag_index = args.index("--expected-config-sha256")
    assert args[flag_index + 1] == expected


@pytest.mark.asyncio
async def test_api_child_uses_private_accepted_snapshot_after_live_config_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import mcp
    import mcp.client.stdio as mcp_stdio

    import mcp_exploit_server
    from tools.kernel.mcp_config_snapshot import resolve_mcp_config_secret_refs
    from tools.mcp_session import open_exploit_mcp_session

    accepted = {
        "mcp": {"http_port": 8123},
        "exploit": {"allowed_targets": ["192.0.2.10"]},
        "research": {"require_api_key_for_mcp_tools": True},
        "recon": {"shodan_api_key": "accepted-shodan-secret"},
        "webhook_notify": {"url": "https://hooks.example.test/accepted-secret"},
    }
    changed = {
        "mcp": {"http_port": 8124},
        "exploit": {"allowed_targets": ["192.0.2.11"]},
        "research": {"require_api_key_for_mcp_tools": True},
        "recon": {"shodan_api_key": "changed-shodan-secret"},
        "webhook_notify": {"url": "https://hooks.example.test/changed-secret"},
    }
    live_config = tmp_path / "config.yaml"
    live_config.write_text(yaml.safe_dump(accepted), encoding="utf-8")
    accepted_digest = config_fingerprint(accepted)
    live_config.write_text(yaml.safe_dump(changed), encoding="utf-8")

    reports_dir = tmp_path / "reports"
    workspace = reports_dir / "run-1" / "workspace"
    captured_params: list[Any] = []
    observed_child_config: list[dict[str, Any]] = []

    class _Session:
        async def initialize(self) -> None:
            return None

        async def __aenter__(self) -> _Session:
            return self

        async def __aexit__(self, *_exc_info: object) -> bool:
            return False

    class _Server:
        def run(self, *, transport: str) -> None:
            assert transport == "stdio"

    def _create_server(_search, _nvd, _researcher, _workspace, config):
        observed_child_config.append(config)
        return _Server()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(mcp, "ClientSession", lambda *_args: _Session())
    monkeypatch.setattr(mcp_exploit_server, "load_api_keys_into_env", lambda *_args: [])
    monkeypatch.setattr(mcp_exploit_server, "build_search", lambda config: object())
    monkeypatch.setattr(mcp_exploit_server, "build_cve_search", lambda config: object())
    monkeypatch.setattr(mcp_exploit_server, "build_researcher", lambda config: object())
    monkeypatch.setattr(mcp_exploit_server, "create_mcp_server", _create_server)

    def _inspect_child_launch(arguments: list[str], child_env: dict[str, str], protected_workspace: Path) -> Path:
        rendered_args = " ".join(arguments)
        config_path = Path(arguments[arguments.index("--config") + 1])
        assert "--private-config-snapshot" in arguments
        assert "--expected-config-sha256" in arguments
        assert config_path.exists()
        assert config_path.stat().st_mode & 0o777 == 0o600
        assert config_path.parent.stat().st_mode & 0o777 == 0o700
        assert not config_path.is_relative_to(protected_workspace)
        assert not config_path.is_relative_to(reports_dir)

        artifact_text = config_path.read_text(encoding="utf-8")
        assert "accepted-shodan-secret" not in artifact_text
        assert "https://hooks.example.test/accepted-secret" not in artifact_text
        assert "changed-shodan-secret" not in artifact_text
        assert "changed-secret" not in artifact_text
        assert "accepted-shodan-secret" not in rendered_args
        assert "https://hooks.example.test/accepted-secret" not in rendered_args
        serialized = yaml.safe_load(artifact_text)
        resolved = resolve_mcp_config_secret_refs(serialized, child_env)
        verify_config_fingerprint(resolved, accepted_digest)

        for name, value in child_env.items():
            if name.startswith("BREACHPILOT_MCP_CONFIG_SECRET_"):
                monkeypatch.setenv(name, value)
        assert mcp_exploit_server.main(arguments) == 0
        assert observed_child_config[-1] == accepted
        return config_path

    @contextlib.asynccontextmanager
    async def _stdio_client(params: Any):
        captured_params.append(params)
        arguments = params.args[1:]
        _inspect_child_launch(arguments, params.env, workspace)
        assert params.env["EXPLOIT_WORKSPACE"] == str(workspace.resolve())
        yield "read", "write"

    monkeypatch.setattr(mcp_stdio, "stdio_client", _stdio_client)

    async with open_exploit_mcp_session(
        transport="stdio",
        config_path=live_config,
        target_ip="192.0.2.10",
        exploit_port=8123,
        workspace=workspace,
        config_snapshot=accepted,
        config_fingerprint=accepted_digest,
        snapshot_excluded_paths=(reports_dir,),
    ) as session:
        assert isinstance(session, _Session)
        first_path = Path(captured_params[-1].args[captured_params[-1].args.index("--config") + 1])
        assert first_path.exists()

    assert len(observed_child_config) == 1
    assert observed_child_config[0]["exploit"]["allowed_targets"] == ["192.0.2.10"]
    assert not first_path.exists()
    assert not first_path.parent.exists()

    snapshot_workspace = reports_dir / "run-2" / "workspace"
    workspace = snapshot_workspace
    async with open_exploit_mcp_session(
        transport="http",
        config_path=live_config,
        target_ip="192.0.2.10",
        exploit_port=8123,
        workspace=snapshot_workspace,
        config_snapshot=accepted,
        config_fingerprint=accepted_digest,
        snapshot_excluded_paths=(reports_dir,),
        fallback_to_stdio=False,
    ) as session:
        assert isinstance(session, _Session)
        args = captured_params[-1].args
        assert args[args.index("--transport") + 1] == "stdio"
        snapshot_path = Path(args[args.index("--config") + 1])
        assert snapshot_path.exists()

    assert not snapshot_path.exists()
    assert not snapshot_path.parent.exists()
    assert len(observed_child_config) == 2
    assert observed_child_config[-1] == accepted
    captured_output = capsys.readouterr()
    assert "accepted-shodan-secret" not in captured_output.out + captured_output.err
    assert "https://hooks.example.test/accepted-secret" not in captured_output.out + captured_output.err


def test_http_child_command_receives_config_fingerprint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.mcp_session as mcp_session

    expected = "d" * 64
    captured: dict[str, Any] = {}
    log_handle = MagicMock()

    monkeypatch.setattr(mcp_session, "port_is_open", lambda *_args: False)
    monkeypatch.setattr(Path, "mkdir", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(Path, "open", lambda *_args, **_kwargs: log_handle)

    def _popen(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return MagicMock()

    monkeypatch.setattr(mcp_session.subprocess, "Popen", _popen)
    mcp_session.start_exploit_http_server(
        server_path=tmp_path / "mcp_exploit_server.py",
        config_path=tmp_path / "config.yaml",
        port=8001,
        workspace=tmp_path / "worker",
        env={},
        config_fingerprint=expected,
        private_config_snapshot=True,
    )

    args = captured["args"]
    assert "--private-config-snapshot" in args
    flag_index = args.index("--expected-config-sha256")
    assert args[flag_index + 1] == expected


@pytest.mark.asyncio
async def test_normal_run_session_uses_accepted_config_snapshot(tmp_path: Path) -> None:
    from tools.exploit_agent.policy import ExploitSettings
    from tools.goal_engine import GoalEngine
    from tools.run_service import AssessmentService
    from tools.run_service.providers import CancellationToken
    from tools.run_service.service import Callables

    config = {"mcp": {"http_port": 8012}, "exploit": {"permission": "read_only"}}
    expected = config_fingerprint(config)
    seen: dict[str, Any] = {}

    async def _run_session(**kwargs):
        seen.update(kwargs)
        return {"total_actions": 0, "workspace": str(tmp_path), "audit_path": ""}

    service = AssessmentService(callables=Callables(run_session=_run_session))

    class _Sink:
        async def emit(self, *_args, **_kwargs):
            return None

    await service._run_session(
        model_client=object(),
        model_alias="glm",
        target_ip="192.0.2.10",
        mode="attack",
        goal=GoalEngine().get("recon_only"),
        exploit_settings=ExploitSettings(),
        config_path=tmp_path / "config.yaml",
        reports_dir=tmp_path,
        assessment=None,
        approval_prompt=None,
        approval_provider=None,
        swarm_attach=None,
        heartbeat=None,
        original_target=None,
        resolved_ip=None,
        recon_first=False,
        resume_state=None,
        event_sink=_Sink(),
        cancellation=CancellationToken(),
        config=config,
        config_fingerprint=expected,
    )

    assert seen["config"] == config
    assert seen["config_fingerprint"] == expected
    assert seen["exploit_port"] == 8012


@pytest.mark.asyncio
async def test_benchmark_mission_and_verifier_receive_accepted_fingerprint(tmp_path: Path, monkeypatch) -> None:
    from contextlib import asynccontextmanager

    from tools.benchmark.agent_runner import MissionRunner
    from tools.benchmark.models import BenchmarkScenario, TrialResult
    from tools.benchmark.runner import BenchmarkRunner

    config = {"mcp": {"http_port": 8001}, "sandbox": {"enabled": False}}
    expected = config_fingerprint(config)
    calls: list[dict[str, Any]] = []

    async def _run_session(**kwargs):
        calls.append(kwargs)
        return {"total_actions": 0, "audit_path": "", "records": []}

    mission = MissionRunner(
        config,
        tmp_path / "config.yaml",
        model_alias="glm",
        run_session=_run_session,
        config_fingerprint=expected,
    )
    monkeypatch.setattr(mission, "_build_model_client", lambda: object())
    scenario = BenchmarkScenario(
        suite="fingerprint",
        scenario_id="s1",
        target_type="host",
        target_host="192.0.2.10",
        oracle={"flags": []},
    )
    await mission.run_mission(scenario, workspace=tmp_path / "trial", trial_id="s1#t1")

    assert calls[0]["config"] == config
    assert calls[0]["config_fingerprint"] == expected

    @contextlib.asynccontextmanager
    async def _open_session(**kwargs):
        calls.append(kwargs)
        yield object()

    monkeypatch.setattr("tools.mcp_session.open_exploit_mcp_session", _open_session)
    runner = BenchmarkRunner(config, tmp_path / "config.yaml", config_fingerprint=expected)

    class _Verifier:
        async def verify(self):
            return object()

    runner._verifier_factory = lambda _scenario: _Verifier()

    class _EventLogger:
        def log(self, *_args, **_kwargs):
            return None

    await runner._verify(
        scenario,
        TrialResult(trial_id="s1#t1", scenario_id="s1"),
        _EventLogger(),
        workspace=tmp_path / "trial",
    )
    assert calls[1]["config_fingerprint"] == expected
    assert calls[1]["config_snapshot"] == config
    assert calls[1]["snapshot_excluded_paths"] == (tmp_path / "trial", runner.storage.root)


def test_child_config_fingerprint_is_stable_across_yaml_serialization() -> None:
    config = {
        "mcp": {"http_port": 8001},
        "exploit": {"allowed_targets": ["192.0.2.10"], "nested": {"enabled": True}},
    }
    reloaded = json.loads(json.dumps(config, sort_keys=True))
    verify_config_fingerprint(reloaded, config_fingerprint(config))


@pytest.mark.asyncio
async def test_api_run_keeps_config_frozen_across_patch_before_mcp_startup(tmp_path: Path, monkeypatch) -> None:
    import asyncio

    from tools.api.event_broker import EventBrokerRegistry
    from tools.api.persistence import ApiPersistence
    from tools.api.run_manager import RunManager
    from tools.run_service.models import RunPreview, RunRequest, RunResult

    live_config: dict[str, Any] = {
        "api": {"max_concurrent_runs": 2},
        "mcp": {"http_port": 8001},
        "exploit": {"allowed_targets": ["192.0.2.10"]},
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(live_config), encoding="utf-8")
    prepare_release = asyncio.Event()
    execute_release = asyncio.Event()
    observed: dict[str, Any] = {}

    class _Service:
        def __init__(self, *, config, **_kwargs):
            self.config = config

        async def prepare(self, request, *, run_id=None, progress=None):
            await prepare_release.wait()
            return RunPreview(
                run_id=run_id,
                reports_dir=tmp_path / "reports" / run_id,
                config_path=config_path,
                target_ip=request.target,
                original_target=request.target,
                resolved_ip=request.target,
                resolved_domain=None,
                mode=request.mode,
                goal_name="recon_only",
                goal_description="test",
                model_alias="glm",
                model_label="glm",
                transport_summary="stdio",
                permission="read_only",
                attack_mode=True,
                swarm=False,
                parallel_swarm=False,
                multi_model=False,
                destructive=False,
                required_confirmation_text="",
            )

        async def execute(self, request, preview, **kwargs):
            observed["config"] = kwargs["config"]
            observed["fingerprint"] = kwargs["config_fingerprint"]
            await execute_release.wait()
            return RunResult(
                run_id=preview.run_id,
                target_ip=preview.target_ip,
                mode=preview.mode,
                goal_name=preview.goal_name,
                goal_description=preview.goal_description,
            )

    monkeypatch.setattr("tools.run_service.AssessmentService", _Service)
    manager = RunManager(
        ApiPersistence(tmp_path / "reports"),
        EventBrokerRegistry(tmp_path / "reports"),
        config=live_config,
        config_path=config_path,
    )
    accepted_config = json.loads(json.dumps(live_config))

    run_id, _, _ = await manager.create_run(RunRequest(target="192.0.2.10", yes=True))
    # Mirrors PATCH /config: mutate the same app dictionary and replace YAML
    # while the accepted run is still preparing, before any MCP child starts.
    live_config["exploit"]["allowed_targets"] = ["192.0.2.11"]
    config_path.write_text(yaml.safe_dump(live_config), encoding="utf-8")
    prepare_release.set()

    handle = await manager.wait_for_prepared(run_id)
    execute_release.set()
    if handle.task is not None:
        await handle.task
    await handle.prep_task
    await manager.shutdown()

    assert observed["config"] == accepted_config
    assert observed["fingerprint"] == config_fingerprint(accepted_config)
    with pytest.raises(ConfigFingerprintMismatch):
        verify_config_fingerprint(load_config(config_path), observed["fingerprint"])


@pytest.mark.asyncio
async def test_benchmark_service_freezes_config_when_run_is_accepted(tmp_path: Path, monkeypatch) -> None:
    import asyncio

    from tools.benchmark import BenchmarkScenario, seed_fake_suite
    from tools.benchmark.service import BenchmarkService

    live_config: dict[str, Any] = {
        "benchmark": {"output_dir": str(tmp_path / "bench"), "sandbox_required": False},
        "api": {"max_concurrent_runs": 1},
        "mcp": {"http_port": 8001},
        "exploit": {"allowed_targets": ["192.0.2.10"]},
    }
    scenario = BenchmarkScenario(
        suite="config-snapshot",
        scenario_id="s1",
        name="snapshot fixture",
        target_type="host",
        target_host="192.0.2.10",
    )
    seed_fake_suite([scenario])
    run_release = asyncio.Event()
    observed: dict[str, Any] = {}

    class _Runner:
        def __init__(self, config, _path, **kwargs):
            observed["config"] = config
            observed["fingerprint"] = kwargs["config_fingerprint"]

        async def run(self, _run_config, *, cancel=None, progress=None):
            if progress is not None:
                progress({"run_id": "benchmark-snapshot-run"})
            await run_release.wait()
            return {"run_id": "benchmark-snapshot-run", "summary": {}}

    monkeypatch.setattr("tools.benchmark.service.BenchmarkRunner", _Runner)
    service = BenchmarkService(live_config, tmp_path / "config.yaml")
    accepted_config = json.loads(json.dumps(live_config))
    result = await service.start_run({"suite": "config-snapshot", "scenarios": ["s1"], "sandbox_required": False})

    live_config["exploit"]["allowed_targets"] = ["192.0.2.11"]
    assert result["run_id"] == "benchmark-snapshot-run"
    assert observed["config"] == accepted_config
    assert observed["fingerprint"] == config_fingerprint(accepted_config)
    with pytest.raises(ConfigFingerprintMismatch):
        verify_config_fingerprint(live_config, observed["fingerprint"])

    run_task = service._active_task
    run_release.set()
    if run_task is not None:
        await run_task
