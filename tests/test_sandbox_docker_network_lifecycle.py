"""Regression tests for the sandbox Docker network-lifecycle false-negative.

Root cause (fixed): ``SandboxManager._destroy_resources`` called
``DockerBackend.destroy`` (which already removes the network) AND a second
direct ``docker_network_rm``. The second delete hit "No such network" (rc != 0)
and overwrote the first True with False -- container cleanup succeeded while
network teardown falsely reported failure. ``docker_rm`` / ``docker_network_rm``
also mapped every non-zero rc to False, so delete-after-delete could never
succeed and the "has active endpoints" detach race had no retry.

What this pins (all via the monkeypatched ``_docker`` seam -- no live daemon):

- delete-after-delete succeeds for networks and containers (idempotent True);
- the detach race ("has active endpoints") retries to success;
- name vs ID confusion is resolved via inspect to the canonical ID;
- error-string matching maps only "not found" variants to True;
- leaked-network scans are empty after destroy (no stale leak);
- fail-closed: ``SandboxError`` -> ``SANDBOX_*`` block, never host execution.
"""

from __future__ import annotations

import json
from typing import Any

from tools.mcp_tools.sandbox_exec import sandbox_error_block
from tools.sandbox import docker_backend as db
from tools.sandbox.exceptions import SandboxError, SandboxUnavailableError


def _install(monkeypatch, handler) -> list[tuple[str, ...]]:
    """Monkeypatch the single Docker seam; record every argv."""
    calls: list[tuple[str, ...]] = []

    def _fake(*args: str, timeout: int = 60, input_text: str = "") -> tuple[int, str, str]:
        calls.append(tuple(args))
        return handler(tuple(args))

    monkeypatch.setattr(db, "_docker", _fake)
    # Detach-race retries sleep; tests must stay instant.
    monkeypatch.setattr(db.time, "sleep", lambda _s: None)
    return calls


def _network_inspect_payload(name: str, nid: str) -> str:
    return json.dumps({"Name": name, "Id": nid, "Containers": {}})


class TestDeleteAfterDelete:
    def test_network_rm_second_delete_succeeds(self, monkeypatch) -> None:
        state = {"exists": True}
        nid = "abc123netid"

        def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
            if argv[:2] == ("network", "inspect"):
                if state["exists"]:
                    return 0, _network_inspect_payload("bp-net-1", nid), ""
                return 1, "", "Error: No such network: bp-net-1"
            if argv[:2] == ("network", "rm"):
                if state["exists"]:
                    state["exists"] = False
                    return 0, "bp-net-1", ""
                return 1, "", "Error response from daemon: No such network: bp-net-1"
            raise AssertionError(f"unexpected docker argv {argv}")

        _install(monkeypatch, handler)
        assert db.docker_network_rm("bp-net-1", retry_delay=0) is True
        # Delete-after-delete must succeed (idempotent), not false-negative.
        assert db.docker_network_rm("bp-net-1", retry_delay=0) is True

    def test_container_rm_second_delete_succeeds(self, monkeypatch) -> None:
        state = {"exists": True}

        def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
            if argv[:1] == ("inspect",):
                if state["exists"]:
                    return 0, '[{"Id": "ctr1"}]', ""
                return 1, "", "Error: No such object: ctr1"
            if argv[:2] == ("rm", "-f"):
                if state["exists"]:
                    state["exists"] = False
                    return 0, "ctr1", ""
                return 1, "", "Error: No such container: ctr1"
            raise AssertionError(f"unexpected docker argv {argv}")

        _install(monkeypatch, handler)
        assert db.docker_rm("ctr1") is True
        assert db.docker_rm("ctr1") is True

    def test_empty_names_are_noop_success(self, monkeypatch) -> None:
        calls = _install(monkeypatch, lambda argv: (1, "", "should not be called"))
        assert db.docker_network_rm("") is True
        assert db.docker_rm("") is True
        assert db.docker_network_disconnect("", "ctr") is True
        assert db.docker_network_disconnect("net", "") is True
        assert calls == []


class TestDetachRace:
    def test_network_rm_retries_active_endpoints(self, monkeypatch) -> None:
        nid = "race-net-id"
        attempts = {"rm": 0}

        def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
            if argv[:2] == ("network", "inspect"):
                return 0, _network_inspect_payload("bp-net-race", nid), ""
            if argv[:2] == ("network", "rm"):
                attempts["rm"] += 1
                if attempts["rm"] == 1:
                    return (
                        1,
                        "",
                        "Error response from daemon: error while removing network: "
                        "network bp-net-race has active endpoints",
                    )
                return 0, "bp-net-race", ""
            raise AssertionError(f"unexpected docker argv {argv}")

        _install(monkeypatch, handler)
        assert db.docker_network_rm("bp-net-race", retry_delay=0) is True
        assert attempts["rm"] == 2, "active-endpoints race must be retried, not reported as failure"

    def test_backend_destroy_disconnects_then_removes(self, monkeypatch) -> None:
        seen: list[tuple[str, ...]] = []

        def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
            if argv[:1] == ("inspect",):
                return 0, '[{"Id": "ctr9"}]', ""
            if argv[:2] == ("rm", "-f"):
                return 0, "ctr9", ""
            if argv[:3] == ("network", "disconnect", "-f"):
                return 0, "", ""
            if argv[:2] == ("network", "inspect"):
                return 0, _network_inspect_payload("bp-net-9", "nid9"), ""
            if argv[:2] == ("network", "rm"):
                return 0, "bp-net-9", ""
            raise AssertionError(f"unexpected docker argv {argv}")

        seen = _install(monkeypatch, handler)
        backend = db.DockerBackend()
        results = backend.destroy("ctr9", "bp-net-9")
        assert results == {"container_removed": True, "network_removed": True}
        kinds = [c[:2] for c in seen]
        assert ("network", "disconnect") in kinds, "destroy must best-effort disconnect before rm"
        rm_calls = [c for c in seen if c[:2] == ("network", "rm")]
        assert len(rm_calls) == 1, "exactly one logical network delete per destroy"


class TestNameVsIdAndErrors:
    def test_rm_uses_inspected_id(self, monkeypatch) -> None:
        rm_targets: list[str] = []

        def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
            if argv[:2] == ("network", "inspect"):
                return 0, _network_inspect_payload("bp-net-named", "canonical-id-77"), ""
            if argv[:2] == ("network", "rm"):
                rm_targets.append(argv[2])
                return 0, "bp-net-named", ""
            raise AssertionError(f"unexpected docker argv {argv}")

        _install(monkeypatch, handler)
        assert db.docker_network_rm("bp-net-named", retry_delay=0) is True
        assert rm_targets == ["canonical-id-77"], "rm must use the canonical ID, not the ambiguous name"

    def test_not_found_variants_map_to_success(self, monkeypatch) -> None:
        variants = [
            "Error: No such network: xyz",
            "Error response from daemon: No such network: xyz",
            "Error: No such object: xyz",
            "Error: not found: xyz",
            "404: network not found",
        ]
        for text in variants:
            def handler(argv: tuple[str, ...], _t: str = text) -> tuple[int, str, str]:
                if argv[:2] == ("network", "inspect"):
                    return 1, "", _t
                raise AssertionError(f"unexpected docker argv {argv}")

            _install(monkeypatch, handler)
            assert db.docker_network_rm("xyz", retry_delay=0) is True, f"variant must be benign: {text!r}"

    def test_real_errors_stay_failure(self, monkeypatch) -> None:
        def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
            if argv[:2] == ("network", "inspect"):
                return 0, _network_inspect_payload("n", "nid"), ""
            if argv[:2] == ("network", "rm"):
                return 1, "", "Error response from daemon: permission denied while removing network"
            raise AssertionError(f"unexpected docker argv {argv}")

        _install(monkeypatch, handler)
        assert db.docker_network_rm("n", retry_delay=0) is False

    def test_daemon_down_maps_to_failure(self, monkeypatch) -> None:
        def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
            raise SandboxUnavailableError("docker daemon down")

        _install(monkeypatch, handler)
        assert db.docker_network_rm("n", retry_delay=0) is False
        assert db.docker_rm("c") is False


class TestNoLeakAndSingleDelete:
    def test_manager_destroy_reports_true_once_and_scan_empty(self, monkeypatch, tmp_path) -> None:
        from tools.sandbox.manager import SandboxManager
        from tools.sandbox.models import SandboxConfig

        state = {"networks": {"bp-net-mgr": "nid-mgr"}, "containers": {"ctr-mgr"}}
        rm_count = {"n": 0}

        def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
            if argv[:3] == ("stop", "-t", "5") or (argv[:1] == ("stop",)):
                return 0, "", ""
            if argv[:1] == ("inspect",):
                token = argv[-1]
                if token in state["containers"]:
                    return 0, '[{"State": {"Status": "running"}}]', ""
                return 1, "", f"Error: No such object: {token}"
            if argv[:2] == ("rm", "-f"):
                state["containers"].discard(argv[2])
                return 0, argv[2], ""
            if argv[:3] == ("network", "disconnect", "-f"):
                return 0, "", ""
            if argv[:2] == ("network", "inspect"):
                token = argv[2]
                for name, nid in state["networks"].items():
                    if token in (name, nid):
                        return 0, _network_inspect_payload(name, nid), ""
                return 1, "", f"Error: No such network: {token}"
            if argv[:2] == ("network", "rm"):
                rm_count["n"] += 1
                target = argv[2]
                for name, nid in list(state["networks"].items()):
                    if target in (name, nid):
                        del state["networks"][name]
                        return 0, name, ""
                return 1, "", f"Error: No such network: {target}"
            if argv[:2] == ("network", "ls"):
                return 0, "\n".join(state["networks"]), ""
            raise AssertionError(f"unexpected docker argv {argv}")

        _install(monkeypatch, handler)
        cfg = SandboxConfig.from_config({"sandbox": {"enabled": True}})
        ws = tmp_path / "ws"
        ws.mkdir(parents=True)
        mgr = SandboxManager(cfg, ws, config_dict={"sandbox": {"enabled": True}}, backend=db.DockerBackend())
        mgr.container_id = "ctr-mgr"
        mgr.network_name = "bp-net-mgr"
        try:
            results = mgr.destroy()
        finally:
            # Detach the atexit hook from Docker so interpreter shutdown is silent.
            try:
                import atexit

                atexit.unregister(mgr._atexit_destroy)
            except Exception:  # noqa: BLE001 -- best-effort test hygiene
                pass
        assert results == {"container_removed": True, "network_removed": True}
        assert rm_count["n"] == 1, "manager must not double-delete the network (the false-negative)"
        # Delete-after-delete succeeds at the seam level too.
        assert db.docker_network_rm("bp-net-mgr", retry_delay=0) is True
        # Leaked-network scan is empty: nothing labeled left behind.
        assert db.docker_network_list_stale() == []
        assert state["networks"] == {}

    def test_network_without_container_deletes_directly(self, monkeypatch, tmp_path) -> None:
        from tools.sandbox.manager import SandboxManager
        from tools.sandbox.models import SandboxConfig

        def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
            if argv[:2] == ("network", "inspect"):
                return 0, _network_inspect_payload("bp-net-orphan", "nid-orphan"), ""
            if argv[:2] == ("network", "rm"):
                return 0, "bp-net-orphan", ""
            raise AssertionError(f"unexpected docker argv {argv}")

        _install(monkeypatch, handler)
        cfg = SandboxConfig.from_config({"sandbox": {"enabled": True}})
        ws = tmp_path / "ws2"
        ws.mkdir(parents=True)
        mgr = SandboxManager(cfg, ws, config_dict={"sandbox": {"enabled": True}}, backend=db.DockerBackend())
        mgr.container_id = ""
        mgr.network_name = "bp-net-orphan"
        try:
            results = mgr.destroy()
        finally:
            try:
                import atexit

                atexit.unregister(mgr._atexit_destroy)
            except Exception:  # noqa: BLE001 -- best-effort test hygiene
                pass
        assert results["network_removed"] is True


class TestFailClosed:
    def test_sandbox_error_becomes_block_never_host(self) -> None:
        block = sandbox_error_block(SandboxUnavailableError("docker daemon down"), tool_name="run_exploit_terminal")
        assert "SANDBOX_UNAVAILABLE" in block
        assert "nowhere" in block, "fail-closed block must state the command ran nowhere"
        assert "host" not in block.lower().replace("not run on the host", ""), (
            "block must never direct host execution"
        )

    def test_manager_execute_failure_raises_without_host_subprocess(self, monkeypatch, tmp_path) -> None:
        import subprocess as _subprocess

        from tools.sandbox.manager import SandboxManager
        from tools.sandbox.models import SandboxConfig

        def _no_host_run(*a: Any, **k: Any) -> Any:
            raise AssertionError("host subprocess must never run agent commands")

        def _no_host_popen(*a: Any, **k: Any) -> Any:
            raise AssertionError("host Popen must never run agent commands")

        monkeypatch.setattr(_subprocess, "run", _no_host_run)
        monkeypatch.setattr(_subprocess, "Popen", _no_host_popen)

        class DeadBackend:
            def ensure_docker(self) -> None:
                raise SandboxUnavailableError("daemon down")

            def ensure_image(self, image: str) -> None:
                raise SandboxUnavailableError("daemon down")

        cfg = SandboxConfig.from_config({"sandbox": {"enabled": True}})
        ws = tmp_path / "ws3"
        ws.mkdir(parents=True)
        mgr = SandboxManager(
            cfg,
            ws,
            config_dict={"sandbox": {"enabled": True}},
            backend=DeadBackend(),  # type: ignore[arg-type]
        )
        try:
            mgr.execute("id", target_ip="192.0.2.5")
        except SandboxError as exc:
            block = sandbox_error_block(exc, tool_name="run_exploit_terminal")
            assert "SANDBOX_" in block
            assert "nowhere" in block
        else:
            raise AssertionError("dead Docker stack must fail closed, never execute")
        finally:
            try:
                import atexit

                atexit.unregister(mgr._atexit_destroy)
            except Exception:  # noqa: BLE001 -- best-effort test hygiene
                pass
            mgr._destroyed = True
        # Reaching here without AssertionError proves the fail-closed path never
        # touched host subprocess: any host run/Popen would have raised above.
