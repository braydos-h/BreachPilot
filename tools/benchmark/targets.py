"""Benchmark target lifecycle: provision / reset / destroy.

One manager per benchmark run. For ``docker`` scenarios it starts one container
per trial (``recreate``), restarts it between trials (``restart``), or leaves a
static target alone (``none``). A static target cannot be reused for an
independent repeated trial: requesting a reset without a supported reset
mechanism is an infrastructure error, never a silent no-op. Every docker call
goes through the module-level ``_docker_run`` seam so tests monkeypatch it (same pattern as
``tools/snapshots.py`` / ``tools/eval_harness.docker_suite_up``).

Failures raise :class:`TargetProvisionError` — the runner converts that into
``INFRASTRUCTURE_ERROR`` (or ``FAILED`` with ``TARGET_RESET_FAILED``), never
into a fake exploitation failure.
"""

from __future__ import annotations

import socket
import subprocess
from typing import Any

from tools.benchmark.models import BenchmarkScenario, ResetStrategy, TargetSnapshot

__all__ = [
    "TargetProvisionError",
    "TargetManager",
    "_docker_run",
    "target_ports_reachable",
]


class TargetProvisionError(RuntimeError):
    """Target provisioning/reset failed (INFRASTRUCTURE_ERROR territory)."""


def _docker_run(*args: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    """Docker seam: run one ``docker`` command. Tests monkeypatch this."""
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def target_ports_reachable(host: str, ports: list[int], timeout: float = 1.0) -> bool:
    """True when at least one declared target port accepts TCP.

    Stdlib connect probe so a down lab (``eval_targets/docker-compose`` not
    up) fails fast as infrastructure error instead of burning the whole
    mission budget on recon rounds against refused ports. Shared by the
    runner preflight and the ``/suites/{id}/readiness`` endpoint.
    """
    for port in ports or []:
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


class TargetManager:
    """Provisions and resets benchmark target containers for one run."""

    def __init__(self, *, docker: Any = None) -> None:
        # ``docker`` overrides the seam entirely (fully fake managers in tests).
        self._docker = docker if docker is not None else _docker_run
        self._containers: dict[str, str] = {}  # scenario_id -> container id

    # ---------------------------------------------------------------- helpers

    def _run(self, *args: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
        return self._docker(*args, timeout=timeout)

    def _container_image_digest(self, container: str) -> str:
        """Record the immutable image ID Docker actually assigned to a container."""
        if not container:
            return "unknown"
        try:
            proc = self._run("inspect", "--format", "{{.Image}}", container, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"
        image_id = proc.stdout.strip() if proc.returncode == 0 else ""
        if len(image_id) == 71 and image_id.startswith("sha256:"):
            suffix = image_id[7:]
            if all(character in "0123456789abcdef" for character in suffix.lower()):
                return image_id.lower()
        return "unknown"

    # ----------------------------------------------------------------- public

    def provision(self, scenario: BenchmarkScenario) -> TargetSnapshot:
        """Start (or adopt) the target for one trial. Returns a TargetSnapshot.

        ``host`` targets are adopted as-is (operator-managed lab machines).
        ``docker`` targets are started with fixed host-port mappings from
        ``scenario.target_ports`` so the oracle's URLs keep working.
        """
        snapshot = TargetSnapshot(
            host=scenario.target_host,
            ports=list(scenario.target_ports),
            image=scenario.target_image or "unknown",
            image_digest="unknown",
            reset_strategy=scenario.reset_strategy,
        )
        if scenario.reset_strategy not in {strategy.value for strategy in ResetStrategy}:
            raise TargetProvisionError(
                f"scenario {scenario.scenario_id}: unsupported reset strategy {scenario.reset_strategy!r}"
            )
        if scenario.target_type != "docker":
            # A host target is operator-managed. Record the reset behavior we
            # can actually provide; if another trial is requested, reset()
            # will fail explicitly instead of pretending this host was reset.
            snapshot.reset_strategy = ResetStrategy.NONE.value
            return snapshot
        if not scenario.target_image:
            raise TargetProvisionError(f"scenario {scenario.scenario_id}: docker target without target_image")

        proc = self._run(
            "run",
            "-d",
            "--rm",
            "--name",
            f"breachpilot-bench-{scenario.scenario_id}",
            *self._port_args(scenario),
            scenario.target_image,
        )
        if proc.returncode != 0:
            raise TargetProvisionError(
                f"docker run failed for {scenario.scenario_id}: {(proc.stderr or proc.stdout).strip()[:300]}"
            )
        container_id = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
        snapshot.container_id = container_id
        snapshot.image_digest = self._container_image_digest(container_id)
        self._containers[scenario.scenario_id] = container_id
        return snapshot

    def reset(self, scenario: BenchmarkScenario) -> TargetSnapshot:
        """Restore a Docker target before the next trial or fail explicitly.

        ``none`` means the target is static and operator-managed; it does not
        mean a repeated trial may reuse state left by the previous trial.
        """
        strategy = scenario.reset_strategy
        if strategy not in {item.value for item in ResetStrategy}:
            raise TargetProvisionError(f"scenario {scenario.scenario_id}: unsupported reset strategy {strategy!r}")
        if strategy == ResetStrategy.NONE.value:
            raise TargetProvisionError(
                f"scenario {scenario.scenario_id}: reset_strategy='none' cannot provide an independent repeated "
                "trial; reset the target externally between separate single-trial runs or use a resettable target"
            )
        if scenario.target_type != "docker":
            raise TargetProvisionError(
                f"scenario {scenario.scenario_id}: host-managed targets cannot be reset automatically; "
                "provide a target manager with an explicit reset mechanism"
            )
        if strategy == ResetStrategy.RESTART.value:
            container = self._containers.get(scenario.scenario_id, "")
            if not container:
                return self.provision(scenario)
            proc = self._run("restart", container, timeout=120)
            if proc.returncode != 0:
                raise TargetProvisionError(
                    f"docker restart failed for {scenario.scenario_id}: {(proc.stderr or proc.stdout).strip()[:300]}"
                )
            return TargetSnapshot(
                host=scenario.target_host,
                ports=list(scenario.target_ports),
                image=scenario.target_image or "unknown",
                image_digest=self._container_image_digest(container),
                container_id=container,
                reset_strategy=strategy,
            )
        # RECREATE (default): destroy then provision fresh.
        self.destroy(scenario)
        return self.provision(scenario)

    def destroy(self, scenario: BenchmarkScenario) -> None:
        """Stop/remove the scenario container (best-effort, never raises)."""
        container = self._containers.pop(scenario.scenario_id, "")
        if not container:
            return
        try:
            self._run("rm", "-f", container, timeout=60)
        except Exception:  # noqa: BLE001 -- teardown is best-effort
            pass

    def destroy_all(self) -> None:
        """Teardown every container this manager started."""
        for scenario_id in list(self._containers):
            try:
                self._run("rm", "-f", self._containers[scenario_id], timeout=60)
            except Exception:  # noqa: BLE001 -- teardown is best-effort
                pass
        self._containers.clear()

    @staticmethod
    def _port_args(scenario: BenchmarkScenario) -> list[str]:
        """``-p host:container`` args. Container port == host port by convention."""
        args: list[str] = []
        for port in scenario.target_ports:
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            args.extend(["-p", f"{port}:{port}"])
        return args
