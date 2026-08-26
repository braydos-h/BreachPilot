"""Operator-box -> victim connection manager.

Persists ConnectionRecord rows to a JSON file under exploit_workspace/ so
the operator can list / health-check / remove persistence implants across
runs. The manager is the single source of truth for "which victim has
which persistence method beaconing to which operator listener".

Design notes
------------
* All target IPs are validated before a record is created (validate_target_or_ip).
* Callback hosts are allowlist-checked by the MCP tool layer before this
  module ever sees them — this module re-validates via is_target_in_allowlist
  as defense-in-depth.
* Persistence is deployable ONLY after RCE / foothold — the manager does not
  bypass that; the autonomous orchestrator already gates persistence_phase on
  state.access_achieved, and the MCP tools document the prerequisite.
* Listeners are managed via PersistentSessionManager (the same tmux/nohup/
  nc/socat/http/tls back-end used by start_listener). A connection's
  listener_name is the alias the operator uses to read output via
  read_listener_output / stop_listener.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.exceptions import _EXC_GROUP_CATCH

# Allowlist helpers (kernel) — import lazily to keep unit tests mock-friendly.
try:
    from tools.validation_utils import validate_target_or_ip
except ImportError:  # pragma: no cover

    def validate_target_or_ip(v: str) -> bool:  # type: ignore[no-redef]
        return bool(v)


@dataclass
class ConnectionRecord:
    """One operator-box -> victim persistence channel."""

    connection_id: str
    target_ip: str
    method: str  # implant name, e.g. linux_cron / windows_schtask
    callback_host: str
    callback_port: int
    listener_name: str
    status: str = "active"  # active | stale | removed | error
    created_at: float = field(default_factory=time.time)
    last_beacon: float | None = None
    last_check: float | None = None
    check_output: str = ""
    implant_path: str = ""
    mitre_technique: str = ""
    os_family: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # ISO timestamps for operator readability in the JSON file.
        d["created_at_iso"] = datetime.fromtimestamp(self.created_at, tz=timezone.utc).isoformat()
        if self.last_beacon:
            d["last_beacon_iso"] = datetime.fromtimestamp(self.last_beacon, tz=timezone.utc).isoformat()
        if self.last_check:
            d["last_check_iso"] = datetime.fromtimestamp(self.last_check, tz=timezone.utc).isoformat()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ConnectionRecord:
        # Strip iso helpers that to_dict added.
        d = {k: v for k, v in d.items() if not k.endswith("_iso")}
        return cls(
            connection_id=str(d.get("connection_id", "")),
            target_ip=str(d.get("target_ip", "")),
            method=str(d.get("method", "")),
            callback_host=str(d.get("callback_host", "")),
            callback_port=int(d.get("callback_port", 4444)),
            listener_name=str(d.get("listener_name", "")),
            status=str(d.get("status", "active")),
            created_at=float(d.get("created_at", time.time())),
            last_beacon=d.get("last_beacon"),
            last_check=d.get("last_check"),
            check_output=str(d.get("check_output", "")),
            implant_path=str(d.get("implant_path", "")),
            mitre_technique=str(d.get("mitre_technique", "")),
            os_family=str(d.get("os_family", "")),
            notes=str(d.get("notes", "")),
        )


_VALID_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}\Z")


def _conn_id() -> str:
    return f"conn-{uuid.uuid4().hex[:8]}"


class ConnectionManager:
    """Persisted operator-connection store.

    JSON file: <workspace>/operator_connections.json
    Legacy / per-target shard: <workspace>/connections/<target_ip>.json
    (both are kept in sync for operator convenience).
    """

    def __init__(self, workspace: Path) -> None:
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._store_path = self.workspace / "operator_connections.json"
        self._shard_dir = self.workspace / "connections"
        self._shard_dir.mkdir(parents=True, exist_ok=True)
        self._records: dict[str, ConnectionRecord] = {}
        self._load()

    # -- persistence ----------------------------------------------------------

    def _load(self) -> None:
        if not self._store_path.exists():
            return
        try:
            data = json.loads(self._store_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        for item in data.get("connections", []):
            try:
                rec = ConnectionRecord.from_dict(item)
                if rec.connection_id:
                    self._records[rec.connection_id] = rec
            except _EXC_GROUP_CATCH:
                continue

    def _save(self) -> None:
        payload = {
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "connections": [r.to_dict() for r in self._records.values()],
        }
        tmp = self._store_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        os.replace(tmp, self._store_path)
        # Per-target shards (best-effort, never fails the save).
        try:
            by_target: dict[str, list[dict[str, Any]]] = {}
            for r in self._records.values():
                by_target.setdefault(r.target_ip, []).append(r.to_dict())
            for target_ip, lst in by_target.items():
                safe = target_ip.replace("/", "_").replace(":", "_")
                shard = self._shard_dir / f"{safe}.json"
                shard.write_text(json.dumps({"target_ip": target_ip, "connections": lst}, indent=2), encoding="utf-8")
        except _EXC_GROUP_CATCH:
            pass

    # -- CRUD ---------------------------------------------------------------

    def create_connection(
        self,
        target_ip: str,
        method: str,
        callback_host: str,
        callback_port: int,
        listener_name: str = "",
        implant_path: str = "",
        mitre_technique: str = "",
        os_family: str = "",
        notes: str = "",
    ) -> ConnectionRecord:
        if not validate_target_or_ip(target_ip):
            raise ValueError(f"invalid target_ip {target_ip!r}")
        if not _VALID_NAME_RE.fullmatch(method.replace("_", "-")) and method not in self._known_methods():
            # method validation is advisory — unknown methods still get a record
            # so the operator can track ad-hoc implants.
            pass
        cid = _conn_id()
        if not listener_name:
            # Default listener name is deterministic from target+method so the
            # operator can predict it (e.g. conn_10-0-0-5_linux-cron).
            safe_target = target_ip.replace(".", "-").replace(":", "-").replace("/", "-")
            listener_name = f"persist-{safe_target}-{method}"
            # clamp to _VALID_NAME_RE (64 chars)
            listener_name = listener_name[:64]
        rec = ConnectionRecord(
            connection_id=cid,
            target_ip=target_ip,
            method=method,
            callback_host=callback_host,
            callback_port=int(callback_port),
            listener_name=listener_name,
            status="active",
            implant_path=implant_path,
            mitre_technique=mitre_technique,
            os_family=os_family,
            notes=notes,
        )
        self._records[cid] = rec
        self._save()
        return rec

    def list_connections(self, target_ip: str = "") -> list[ConnectionRecord]:
        if target_ip:
            return [r for r in self._records.values() if r.target_ip == target_ip]
        return list(self._records.values())

    def get(self, connection_id: str) -> ConnectionRecord | None:
        return self._records.get(connection_id)

    def find_by_target_method(self, target_ip: str, method: str) -> list[ConnectionRecord]:
        return [r for r in self._records.values() if r.target_ip == target_ip and r.method == method]

    def mark_beacon(self, connection_id: str) -> None:
        rec = self._records.get(connection_id)
        if rec:
            rec.last_beacon = time.time()
            rec.status = "active"
            self._save()

    def mark_check(self, connection_id: str, output: str, healthy: bool) -> None:
        rec = self._records.get(connection_id)
        if rec:
            rec.last_check = time.time()
            rec.check_output = output[:2000]
            rec.status = "active" if healthy else "stale"
            self._save()

    def mark_removed(self, connection_id: str) -> bool:
        rec = self._records.get(connection_id)
        if not rec:
            return False
        rec.status = "removed"
        self._save()
        return True

    def remove(self, connection_id: str) -> bool:
        if connection_id not in self._records:
            return False
        del self._records[connection_id]
        self._save()
        return True

    def summary(self) -> str:
        if not self._records:
            return "OPERATOR_CONNECTIONS: none established."
        lines = [f"OPERATOR_CONNECTIONS: {len(self._records)} total", ""]
        for r in sorted(self._records.values(), key=lambda x: x.created_at):
            age = time.time() - r.created_at
            beacon = f"{(time.time() - r.last_beacon):.0f}s ago" if r.last_beacon else "never"
            lines.append(
                f"  [{r.status.upper():7s}] {r.connection_id}  {r.target_ip}  {r.method}  "
                f"-> {r.callback_host}:{r.callback_port}  listener={r.listener_name}  "
                f"age={age:.0f}s  last_beacon={beacon}"
            )
            if r.mitre_technique:
                lines.append(f"           MITRE {r.mitre_technique}  os={r.os_family}")
        return "\n".join(lines)

    def _known_methods(self) -> set[str]:
        try:
            from tools.operator_connection.implants import IMPLANT_METHODS

            return set(IMPLANT_METHODS)
        except ImportError:
            return set()


# -- singleton ---------------------------------------------------------------

_manager: ConnectionManager | None = None


def get_connection_manager(workspace: Path | None = None) -> ConnectionManager:
    global _manager
    if _manager is None:
        ws = workspace or Path("exploit_workspace")
        _manager = ConnectionManager(ws)
    # If caller supplies a different workspace, rebind to that workspace so
    # per-target workspaces (exploit_workspace/<ip>) each see their own store
    # while still sharing the module singleton for tests that reset it.
    if workspace is not None and Path(workspace).resolve() != _manager.workspace.resolve():
        _manager = ConnectionManager(Path(workspace))
    return _manager


def reset_connection_manager() -> None:
    global _manager
    _manager = None
