from __future__ import annotations

from pathlib import Path

import pytest

from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings, verify_audit_chain
from tools.kernel.audit_paths import (
    external_audit_path,
    prepare_external_audit_path,
    validate_external_audit_path,
    validate_run_workspace,
)


def test_audit_path_moves_beside_workspace_when_preferred_path_is_mounted(tmp_path: Path) -> None:
    workspace = tmp_path / "reports" / "trial-1" / "exploit_workspace"
    workspace.mkdir(parents=True)

    audit_path = external_audit_path(workspace, workspace / "exploit_audit.jsonl")

    assert audit_path == workspace.parent / "exploit_workspace-exploit_audit.jsonl"
    assert workspace not in audit_path.parents


def test_audit_path_rejects_a_symlink_alias_into_worker_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "worker"
    workspace.mkdir()
    (workspace / "alias.jsonl").symlink_to(workspace / "exploit_audit.jsonl")

    with pytest.raises(ValueError, match="outside the writable worker workspace"):
        validate_external_audit_path(workspace, workspace / "alias.jsonl")


@pytest.mark.parametrize("workspace_name", [".", ".."])
def test_run_workspace_cannot_contain_host_report_directory(tmp_path: Path, workspace_name: str) -> None:
    reports_dir = tmp_path / "reports" / "run-1"
    reports_dir.mkdir(parents=True)
    workspace = reports_dir if workspace_name == "." else reports_dir.parent

    with pytest.raises(ValueError, match="must not contain the run report directory"):
        validate_run_workspace(workspace, reports_dir)


def test_prepared_external_path_stays_authoritative_when_worker_copy_is_poisoned(tmp_path: Path) -> None:
    workspace = tmp_path / "reports" / "run-1" / "exploit_workspace"
    workspace.mkdir(parents=True)
    canonical = prepare_external_audit_path(workspace, workspace.parent / "exploit_audit.jsonl")
    worker_copy = workspace / "exploit_audit.jsonl"
    worker_copy.write_text('{"tool_name":"forged","status":"completed"}\n', encoding="utf-8")

    assert canonical.is_file()
    assert canonical.read_text(encoding="utf-8") == ""
    assert canonical != worker_copy
    assert workspace not in canonical.parents


def test_benchmark_reads_the_explicit_operator_audit_path(tmp_path: Path) -> None:
    from tools.benchmark.agent_runner import _extract_sandbox_facts

    workspace = tmp_path / "trial-workspace"
    workspace.mkdir()
    canonical = tmp_path / "trial-workspace-exploit_audit.jsonl"
    canonical.write_text('{"sandbox":{"enabled":true,"image":"pinned"}}\n', encoding="utf-8")
    (workspace / "exploit_audit.jsonl").write_text('{"sandbox":{"enabled":false,"image":"forged"}}\n', encoding="utf-8")

    snapshot = _extract_sandbox_facts(workspace, required=True, audit_path=canonical)

    assert snapshot.enabled is True
    assert snapshot.image == "pinned"


@pytest.mark.asyncio
async def test_exploit_policy_keeps_chain_on_external_path(tmp_path: Path) -> None:
    workspace = tmp_path / "exploit_workspace"
    workspace.mkdir()
    audit_path = prepare_external_audit_path(workspace, tmp_path / "exploit_audit.jsonl")
    settings = ExploitSettings(
        enabled=True,
        mode="standalone",
        target_ip="192.0.2.10",
        workspace_root=workspace,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
    )
    policy = ExploitPolicy(settings, workspace, audit_path=audit_path)

    row = await policy.record(action="run_exploit_terminal", command="id", status="completed")

    assert row.hash
    assert verify_audit_chain(audit_path)[0]
    assert not (workspace / "exploit_audit.jsonl").exists()


def test_exploit_policy_rejects_audit_path_inside_worker_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "exploit_workspace"
    settings = ExploitSettings(
        enabled=True,
        mode="standalone",
        target_ip="192.0.2.10",
        workspace_root=workspace,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
    )

    with pytest.raises(ValueError, match="outside the writable worker workspace"):
        ExploitPolicy(settings, workspace, audit_path=workspace / "exploit_audit.jsonl")
