"""Snapshot MCP tool registration (design §snapshots).

Three tools that expose the snapshot/rollback layer to the agent:

  - ``snapshot_create(vm_id, label)``  take a snapshot (target-touching)
  - ``snapshot_revert(vm_id, ref)``    roll the infrastructure back
  - ``snapshot_list(vm_id)``           read-only listing

Infrastructure-touching: gated on BOTH the allowlist (the vm_id/container
must be operator-authorized — the allowlist IS the lock) AND
``snapshots.enabled`` (default false — nothing registers when disabled,
matching the replay_simulator conditional-registration precedent).
"""

from __future__ import annotations

from typing import Any

from tools.mcp_tools.registry import *


def register_snapshot_tools(mcp: Any, *, ctx: ToolContext) -> None:
    config = ctx.config
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist
    snap_cfg = (config or {}).get("snapshots", {}) or {}
    if not bool(snap_cfg.get("enabled", False)):
        return

    from tools.snapshots import SnapshotManager, _vm_id_for_target

    # The manager persists its index beside the workspace audit trail.
    manager = SnapshotManager(config, index_dir=ctx.workspace)

    # ------------------------------------------------------------------
    # 1. snapshot_create
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("vm_id")
    def snapshot_create(vm_id: str, label: str = "") -> str:
        """Take a snapshot of an allowlisted target's backing VM/container (docker commit for containers; hypervisor checkpoints for VMs). Infrastructure-touching: refused unless snapshots.enabled AND the target is allowlisted. Returns SNAPSHOT_CREATED: with the ref, or BLOCKED:/ERROR:."""
        if not vm_id or not vm_id.strip():
            return "BLOCKED: vm_id is required."
        resolved = _vm_id_for_target(vm_id.strip(), config)
        try:
            ref = manager.before_destructive(resolved, label.strip() or f"manual-{manager._now_fn()}")
        except Exception as exc:  # noqa: BLE001  # ponytail: bare except intentional
            return f"ERROR: snapshot_create failed: {exc}"
        if ref is None:
            return "BLOCKED: snapshots disabled or the snapshot failed (no ref returned)."
        return (
            "SNAPSHOT_CREATED:\n"
            f"VM_ID: {ref.vm_id}\n"
            f"SNAPSHOT_ID: {ref.snapshot_id}\n"
            f"LABEL: {ref.label}\n"
            f"PROVIDER: {ref.provider}\n"
            f"CREATED_AT: {ref.created_at}"
        )

    # ------------------------------------------------------------------
    # 2. snapshot_revert
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("vm_id")
    def snapshot_revert(vm_id: str, ref: str = "") -> str:
        """Roll an allowlisted target's backing VM/container back to a snapshot (empty ref = latest recorded). Infrastructure-touching: refused unless snapshots.enabled AND the target is allowlisted. Returns SNAPSHOT_REVERTED: on success, ERROR:/BLOCKED: on failure."""
        if not vm_id or not vm_id.strip():
            return "BLOCKED: vm_id is required."
        resolved = _vm_id_for_target(vm_id.strip(), config)
        ref_arg = ref.strip()
        if ref_arg:
            used = manager.revert(resolved, ref_arg)
        else:
            # Empty ref = most recent recorded snapshot for this vm_id.
            snaps = manager.list(resolved)
            used = manager.revert(resolved, snaps[-1]) if snaps else None
        if used is None:
            return "ERROR: snapshot_revert failed (snapshots disabled, unknown ref, or the provider refused)."
        return (
            "SNAPSHOT_REVERTED:\n"
            f"VM_ID: {used.vm_id}\n"
            f"SNAPSHOT_ID: {used.snapshot_id}\n"
            f"PROVIDER: {used.provider or '(unindexed ref)'}"
        )

    # ------------------------------------------------------------------
    # 3. snapshot_list -- read-only
    # ------------------------------------------------------------------
    @mcp.tool()
    @audit_tool
    @require_allowlist("vm_id")
    def snapshot_list(vm_id: str) -> str:
        """List recorded snapshots for an allowlisted target (read-only; no target touch). Returns a SNAPSHOT_LIST: block."""
        if not vm_id or not vm_id.strip():
            return "BLOCKED: vm_id is required."
        resolved = _vm_id_for_target(vm_id.strip(), config)
        try:
            refs = manager.list(resolved)
        except Exception as exc:  # noqa: BLE001  # ponytail: bare except intentional
            return f"ERROR: snapshot_list failed: {exc}"
        lines = [f"SNAPSHOT_LIST:\nVM_ID: {resolved}\nCOUNT: {len(refs)}"]
        for r in refs:
            lines.append(f"  - {r.snapshot_id}  label={r.label}  created={r.created_at}")
        return "\n".join(lines)


__all__ = ["register_snapshot_tools"]
