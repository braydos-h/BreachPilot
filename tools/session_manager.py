"""Session manager for long-running autonomous exploitation.

Provides:
- SessionState: serializable state of an exploitation session
- SessionManager: persist/resume across process restarts
- Workspace recovery: reads previous attempts and plan state on startup
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.attack_planner import AttackPlanner


@dataclass
class SessionState:
    session_id: str
    target_ip: str
    target_cve: str
    target_os: str | None = None
    known_cves: list[str] = field(default_factory=list)
    service_context: str = ""
    attacker_os: str = ""
    attack_mode: bool = False
    started_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    total_actions: int = 0
    successful_exploits: int = 0
    current_phase: str = "recon"
    plan: dict[str, Any] | None = None
    context_history: list[dict[str, Any]] = field(default_factory=list)
    loot: list[dict[str, Any]] = field(default_factory=list)
    credentials: list[dict[str, Any]] = field(default_factory=list)
    compromised_hosts: list[str] = field(default_factory=list)
    messages: list[dict[str, Any]] = field(default_factory=list)
    # ponytail: when True (long-session mode), to_json persists the compacted
    # messages list (bounded to last 200) so a crashed run resumes with real
    # conversation context. Default False → old behavior (reconstituted
    # condensed from context_history) → backward compat with existing state files.
    persist_messages: bool = False
    reasoning_log: list[dict[str, Any]] = field(default_factory=list)  # NEW: tracks critic approvals and reflections

    def touch(self) -> None:
        self.last_activity = time.time()

    def to_json(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_ip": self.target_ip,
            "target_cve": self.target_cve,
            "target_os": self.target_os,
            "known_cves": self.known_cves,
            "service_context": self.service_context,
            "attacker_os": self.attacker_os,
            "attack_mode": self.attack_mode,
            "started_at": self.started_at,
            "last_activity": self.last_activity,
            "total_actions": self.total_actions,
            "successful_exploits": self.successful_exploits,
            "current_phase": self.current_phase,
            "plan": self.plan,
            "context_history": self.context_history[-50:],
            "loot": self.loot[-100:],
            "credentials": self.credentials,
            "compromised_hosts": self.compromised_hosts,
            "messages": self.messages[-200:] if self.persist_messages else [],
            "persist_messages": self.persist_messages,
            "reasoning_log": self.reasoning_log[-50:],
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> SessionState:
        state = cls(
            session_id=str(data.get("session_id", "")),
            target_ip=str(data.get("target_ip", "")),
            target_cve=str(data.get("target_cve", "")),
            target_os=data.get("target_os") if data.get("target_os") else None,
            known_cves=data.get("known_cves", []),
            service_context=str(data.get("service_context", "")),
            attacker_os=str(data.get("attacker_os", "")),
            attack_mode=bool(data.get("attack_mode", False)),
            started_at=data.get("started_at", time.time()),
            last_activity=data.get("last_activity", time.time()),
            total_actions=int(data.get("total_actions", 0)),
            successful_exploits=int(data.get("successful_exploits", 0)),
            current_phase=str(data.get("current_phase", "recon")),
            plan=data.get("plan"),
            context_history=data.get("context_history", []),
            loot=data.get("loot", []),
            credentials=data.get("credentials", []),
            compromised_hosts=data.get("compromised_hosts", []),
            reasoning_log=data.get("reasoning_log", []),
            persist_messages=bool(data.get("persist_messages", False)),
            messages=data.get("messages", []) if data.get("persist_messages", False) else [],
        )
        return state


class SessionManager:
    """Persist and resume exploitation sessions across restarts."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._state_path = workspace / "session_state.json"
        self._state: SessionState | None = None
        self._planner = AttackPlanner(workspace)
        self._dirty: bool = False
        self._pending_save_count: int = 0
        self._save_interval: int = 10

    def new_session(
        self,
        *,
        target_ip: str,
        target_cve: str = "",
        target_os: str | None = None,
        known_cves: list[str] | None = None,
        service_context: str = "",
        attacker_os: str = "",
        attack_mode: bool = False,
    ) -> SessionState:
        session_id = f"{target_ip.replace('.', '_')}_{int(time.time())}"
        self._state = SessionState(
            session_id=session_id,
            target_ip=target_ip,
            target_cve=target_cve,
            target_os=target_os,
            known_cves=known_cves or [],
            service_context=service_context,
            attacker_os=attacker_os,
            attack_mode=attack_mode,
            current_phase="recon",
        )
        self._dirty = True
        self._flush()
        return self._state

    def resume_or_new(
        self,
        *,
        target_ip: str,
        target_cve: str = "",
        target_os: str | None = None,
        known_cves: list[str] | None = None,
        service_context: str = "",
        attacker_os: str = "",
        attack_mode: bool = False,
    ) -> SessionState:
        existing = self.load()
        if existing and existing.target_ip == target_ip:
            print(f"[SessionManager] Resuming session {existing.session_id} for {target_ip}")
            existing.touch()
            existing.attacker_os = attacker_os or existing.attacker_os
            existing.attack_mode = attack_mode
            self._state = existing
            self._pending_save_count = 0
            self._dirty = True
            self._flush()
            return existing
        return self.new_session(
            target_ip=target_ip,
            target_cve=target_cve,
            target_os=target_os,
            known_cves=known_cves,
            service_context=service_context,
            attacker_os=attacker_os,
            attack_mode=attack_mode,
        )

    def _mark_dirty(self) -> None:
        self._dirty = True
        self._pending_save_count += 1
        if self._pending_save_count >= self._save_interval:
            self._flush()

    def _flush(self) -> None:
        if self._state is None or not self._dirty:
            return
        self._state.touch()
        self._state_path.write_text(json.dumps(self._state.to_json(), indent=2, default=str), encoding="utf-8")
        self._dirty = False
        self._pending_save_count = 0

    def save(self) -> None:
        self._flush()

    def load(self) -> SessionState | None:
        if not self._state_path.exists():
            return None
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            self._state = SessionState.from_json(data)
            return self._state
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def record_action(self, action: str, result: str, success: bool = False) -> None:
        if self._state is None:
            return
        self._state.total_actions += 1
        if success:
            self._state.successful_exploits += 1
        self._state.context_history.append({
            "timestamp": time.time(),
            "action": action,
            "result": result[:1000],
            "success": success,
        })
        if len(self._state.context_history) > 100:
            self._state.context_history = self._state.context_history[-100:]
        self._mark_dirty()

    def record_phase(self, phase: str) -> None:
        if self._state is None:
            return
        self._state.current_phase = phase
        self._mark_dirty()

    def record_loot(self, loot_type: str, data: dict[str, Any]) -> None:
        if self._state is None:
            return
        self._state.loot.append({
            "timestamp": time.time(),
            "type": loot_type,
            "data": data,
        })
        self._mark_dirty()

    def record_credentials(self, host: str, username: str, password: str, source: str) -> None:
        if self._state is None:
            return
        self._state.credentials.append({
            "timestamp": time.time(),
            "host": host,
            "username": username,
            "password": password,
            "source": source,
        })
        self._mark_dirty()

    def mark_compromised(self, host: str) -> None:
        if self._state is None:
            return
        if host not in self._state.compromised_hosts:
            self._state.compromised_hosts.append(host)
            self._mark_dirty()

    def get_context_summary(self) -> str:
        """Generate a running summary for context compaction."""
        if self._state is None:
            return "No session state."
        lines = [
            f"Session: {self._state.session_id}",
            f"Target: {self._state.target_ip}",
            f"Phase: {self._state.current_phase}",
            f"Actions: {self._state.total_actions}",
            f"Successful Exploits: {self._state.successful_exploits}",
            f"Compromised Hosts: {', '.join(self._state.compromised_hosts) or 'None'}",
        ]
        if self._state.credentials:
            lines.append(f"Credentials Found: {len(self._state.credentials)}")
        if self._state.loot:
            lines.append(f"Loot Items: {len(self._state.loot)}")
        lines.append("Recent Context:")
        for entry in self._state.context_history[-10:]:
            status = "✓" if entry["success"] else "✗"
            lines.append(f"  [{status}] {entry['action']}: {entry['result'][:100]}")
        return "\n".join(lines)

    def build_resume_messages(
        self,
        system_prompt: str,
    ) -> list[dict[str, Any]]:
        """Reconstitute message history for the LLM from saved state."""
        # ponytail: long-session mode persisted the already-compacted messages
        # (system + memory + summary + recent turns via _build_compacted_messages).
        # Return them verbatim instead of the lossy condensed rebuild. Old state
        # files / non-long runs have persist_messages=False → empty list → fall
        # through to the existing rebuild (backward compat).
        if self._state and self._state.persist_messages and self._state.messages:
            return list(self._state.messages)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Resuming active exploitation session.\n{self.get_context_summary()}\nContinue from where you left off."},
        ]
        # Add recent context as condensed tool results
        if self._state:
            for entry in self._state.context_history[-20:]:
                messages.append({
                    "role": "tool",
                    "tool_name": entry["action"],
                    "content": f"[{ 'SUCCESS' if entry['success'] else 'FAILED'}] {entry['result'][:300]}",
                })
        return messages
