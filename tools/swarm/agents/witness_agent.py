"""Witness Agent — advisory real-time audit-stream watcher (agent-on-agent safety).

The critic is a PRE-execution reviewer: it sees a proposed action and
approves / denies / modifies it before the action runs. Once the action runs,
its record lands in the audit trail (``exploit_audit.jsonl`` written by
``tools/mcp_shared._audit_log`` and ``activity.jsonl`` written by
``tools/activity_log.ActivityLog``) — but nothing watches that trail mid-run.

The witness is that watcher. It is **advisory-only**: it reads the audit
stream, flags anomalies, and writes flags to a witness log + an optional
event callback (so Agent 03's webhook plugin can notify the operator if
wired). It does NOT block, modify, or kill runs. A flag here is a signal,
not a gate.

Anomaly signals watched (initial set — false positives are acceptable, the
witness is advisory):

1. **Allowlist breach** — a tool call with a ``target_ip`` not in
   ``_allowed_target_list``. If the target-IP lock holds this should NEVER
   fire; a flag here means the lock broke, which is critical.
2. **PoC escape attempt** — a ``verify_poc`` / ``run_python_file`` call that
   did NOT set ``--network=none`` (a PoC reaching out to the network is an
   escape attempt).
3. **Permission escalation** — an unexpected ``read_only`` → ``full_access``
   transition mid-run without an operator action.
4. **Prompt-injection pattern** — ``write_python_file`` immediately after
   ``search_threat_intel`` / ``search_web_exploit`` returned untrusted text
   without a sanitization step in between (heuristic).
5. **DoS drift** — rapid repeated failures on the same target (N failures in
   a short window) suggesting the agent is drifting into denial-of-service.

Failure modes:

- Witness crashes MUST NOT take the run down. The poll loop runs in a side
  task and swallows exceptions via ``_EXC_GROUP_CATCH`` (anyio task groups
  raise ``BaseExceptionGroup``, not ``Exception`` — see
  ``tools/exceptions.py``).
- Audit stream stalls: a poll that reads no new records just waits the
  interval and tries again. A missing audit file is treated as "no records
  yet" (the run may not have started).
- False-positive storm: flags are rate-capped per signal type
  (``max_flags_per_signal_per_minute``) so a flapping detector cannot spam
  the broker / witness log.

Config (``config.yaml``):

.. code-block:: yaml

    witness:
      enabled: false              # default-off; advisory watcher
      log_path: reports/witness.jsonl
      poll_interval_seconds: 5
      escalate_to_event_broker: true

Rollback: ``witness.enabled: false``.
"""

from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from tools.exceptions import _EXC_GROUP_CATCH

# ── Data shapes ─────────────────────────────────────────────────────────


@dataclass
class WitnessFlag:
    """One anomaly flagged by the witness. Advisory — never a gate."""

    signal: str
    severity: str  # "critical" | "high" | "medium" | "low"
    message: str
    record: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal,
            "severity": self.severity,
            "message": self.message,
            "record": self.record,
            "timestamp": self.timestamp or _now_iso(),
        }


@dataclass
class WitnessConfig:
    """Parsed ``witness`` config block. All fields have safe defaults so a
    missing/partial config never raises."""

    enabled: bool = False
    log_path: str = "reports/witness.jsonl"
    poll_interval_seconds: float = 5.0
    escalate_to_event_broker: bool = True
    # Rate cap: at most N flags per signal per minute. A flapping detector
    # cannot spam the broker / log. ponytail: per-signal sliding window of
    # timestamps; upgrade to a token bucket if burstiness matters.
    max_flags_per_signal_per_minute: int = 10
    # DoS-drift detector: N failures on the same target within this window
    # (seconds) flags a drift toward denial-of-service.
    dos_failure_window_seconds: float = 60.0
    dos_failure_threshold: int = 8

    @classmethod
    def from_config(cls, config: dict[str, Any] | None) -> "WitnessConfig":
        cfg = (config or {}).get("witness", {}) or {}
        return cls(
            enabled=bool(cfg.get("enabled", False)),
            log_path=str(cfg.get("log_path", "reports/witness.jsonl")),
            poll_interval_seconds=float(cfg.get("poll_interval_seconds", 5.0)),
            escalate_to_event_broker=bool(cfg.get("escalate_to_event_broker", True)),
            max_flags_per_signal_per_minute=int(cfg.get("max_flags_per_signal_per_minute", 10)),
            dos_failure_window_seconds=float(cfg.get("dos_failure_window_seconds", 60.0)),
            dos_failure_threshold=int(cfg.get("dos_failure_threshold", 8)),
        )


# ── Anomaly detectors ───────────────────────────────────────────────────
#
# Each detector is a pure function: (record, ctx) -> WitnessFlag | None.
# ``record`` is one parsed JSONL line from the audit stream. ``ctx`` is the
# ``WitnessContext`` carrying the allowlist + recent-call window so detectors
# can do cross-record pattern matching (prompt injection, DoS drift). Pure
# functions keep the watcher testable without a running loop.


# Tools that run Python/PoC code where a ``--network=none`` flag (or
# equivalent offline marker) is expected. ``run_python_file`` takes a script
# body, not a CLI flag, so for it we look for the marker in the script text
# instead. ``verify_poc`` is the canonical PoC verifier.
_POC_TOOLS = {"verify_poc", "run_python_file"}
# Offline markers we accept as "the PoC is network-isolated". A record whose
# command / args contains any of these is considered safe. ``--network=none``
# is the Docker / podman isolation flag; ``# offline`` / ``# no-network`` are
# ponytail: comment markers a generated script can carry to assert it doesn't
# reach out. Heuristic — a determined escape could omit the marker; the
# witness is advisory, the container lockdown is the real control.
_OFFLINE_MARKERS = ("--network=none", "# offline", "# no-network", "offline=True")
# Tools whose output is UNTRUSTED text (threat intel, web search). A
# ``write_python_file`` immediately after one of these, with nothing in
# between, is a prompt-injection pattern heuristic.
_UNTRUSTED_SOURCE_TOOLS = {"search_threat_intel", "search_web_exploit", "fetch_webpage", "deep_research"}
# Tools that count as a "sanitization step" between an untrusted source and a
# file write. Crude — the real sanitization is in ``tools/skill_registry``
# untrusted-guidance stripping + the agent's own review; this detector only
# catches the naked ``search → write`` sequence.
_SANITIZATION_TOOLS = {"read_workspace_file", "list_workspace", "check_os"}


@dataclass
class WitnessContext:
    """Mutable state shared across detectors for a single poll batch.

    Carries the allowlist (so the allowlist-breach detector doesn't re-read
    env on every record), a sliding window of recent tool calls (for the
    prompt-injection + DoS-drift heuristics), a per-target failure
    counter for DoS-drift detection, and a clock so detectors don't call
    ``time.time`` directly (tests inject a fake clock).
    """

    allowed_targets: list[str] = field(default_factory=list)
    # Recent tool calls as (timestamp, tool_name, target_ip, status) tuples,
    # newest last. Bounded to ``_RECENT_WINDOW`` entries.
    recent_calls: deque[tuple[float, str, str, str]] = field(default_factory=deque)
    # target_ip -> list of failure timestamps (epoch seconds).
    failures_per_target: dict[str, list[float]] = field(default_factory=dict)
    # Highest permission seen so far in the stream ("read_only" | "approve_only"
    # | "full_access"). Used by the escalation detector.
    highest_permission: str = "read_only"
    # Clock injected from the WitnessAgent so detectors read a controlled time
    # in tests. Defaults to ``time.time`` for standalone use.
    clock: Callable[[], float] = field(default=time.time)

    def record_call(self, ts: float, tool: str, target: str, status: str) -> None:
        self.recent_calls.append((ts, tool, target, status))
        if len(self.recent_calls) > _RECENT_WINDOW:
            self.recent_calls.popleft()
        if status.lower() in ("failed", "error", "blocked"):
            self.failures_per_target.setdefault(target, []).append(ts)

    def prune_failures(self, now: float, window: float) -> None:
        for tgt in list(self.failures_per_target):
            self.failures_per_target[tgt] = [t for t in self.failures_per_target[tgt] if now - t <= window]
            if not self.failures_per_target[tgt]:
                del self.failures_per_target[tgt]


_RECENT_WINDOW = 50


def _det_allowlist_breach(record: dict[str, Any], ctx: WitnessContext) -> WitnessFlag | None:
    """Flag a tool call whose target_ip is not in the allowlist.
    Critical — if the lock holds this never fires."""
    target = record.get("target_ip") or record.get("target") or ""
    if not target:
        return None
    # Reuse the same matcher the MCP tool layer uses (supports CIDR /
    # wildcard / domain) so the witness's notion of "in allowlist" matches
    # the lock's notion exactly.
    from tools.validation_utils import is_target_in_allowlist

    if ctx.allowed_targets and not is_target_in_allowlist(str(target), ctx.allowed_targets):
        return WitnessFlag(
            signal="allowlist_breach",
            severity="critical",
            message=(
                f"Tool {record.get('tool_name', '?')} touched target "
                f"{target} which is NOT in the allowlist. The target-IP lock "
                f"may have been bypassed — this is critical."
            ),
            record=record,
        )
    return None


def _det_poc_escape(record: dict[str, Any], ctx: WitnessContext) -> WitnessFlag | None:
    """Flag a PoC-running tool call that did NOT set --network=none."""
    tool = record.get("tool_name", "")
    if tool not in _POC_TOOLS:
        return None
    blob = json.dumps(record.get("args", {})) + " " + str(record.get("command", ""))
    if any(marker in blob for marker in _OFFLINE_MARKERS):
        return None
    return WitnessFlag(
        signal="poc_no_network_isolation",
        severity="high",
        message=(
            f"PoC tool {tool} was invoked without an offline marker "
            f"(--network=none / # offline). The PoC may reach the network."
        ),
        record=record,
    )


def _det_permission_escalation(record: dict[str, Any], ctx: WitnessContext) -> WitnessFlag | None:
    """Flag a read_only -> full_access transition mid-run."""
    perm = record.get("permission") or record.get("args", {}).get("permission")
    if not perm:
        return None
    perm = str(perm).lower()
    order = {"read_only": 0, "approve_only": 1, "full_access": 2}
    cur = order.get(ctx.highest_permission, 0)
    new = order.get(perm, cur)
    if new > cur:
        flag = None
        if ctx.highest_permission != "read_only" or perm == "full_access":
            flag = WitnessFlag(
                signal="permission_escalation",
                severity="high",
                message=(
                    f"Permission escalated from {ctx.highest_permission} to {perm} mid-run without an operator action."
                ),
                record=record,
            )
        ctx.highest_permission = perm
        return flag
    return None


def _det_prompt_injection(record: dict[str, Any], ctx: WitnessContext) -> WitnessFlag | None:
    """Flag write_python_file immediately after an untrusted-source tool
    with no sanitization step in between. Heuristic — false positives
    acceptable (the witness is advisory)."""
    tool = record.get("tool_name", "")
    if tool != "write_python_file":
        return None
    # Walk the recent-calls window backwards looking for the last non-write
    # call. If it was an untrusted-source tool, flag.
    for ts, prev_tool, _target, _status in reversed(ctx.recent_calls):
        if prev_tool == tool:
            continue
        if prev_tool in _UNTRUSTED_SOURCE_TOOLS:
            return WitnessFlag(
                signal="prompt_injection_pattern",
                severity="medium",
                message=(
                    f"write_python_file immediately after {prev_tool} "
                    f"(untrusted source) with no sanitization step in between. "
                    f"Possible prompt-injection-driven script write."
                ),
                record=record,
            )
        # Any other tool (incl. sanitization tools) breaks the pattern.
        return None
    return None


def _det_dos_drift(record: dict[str, Any], ctx: WitnessContext) -> WitnessFlag | None:
    """Flag rapid repeated failures on the same target (DoS drift)."""
    target = record.get("target_ip") or record.get("target") or ""
    status = str(record.get("status", "")).lower()
    if not target or status not in ("failed", "error"):
        return None
    now = ctx.clock()
    failures = ctx.failures_per_target.get(target, [])
    recent = [t for t in failures if now - t <= 60.0]
    if len(recent) >= 8:
        return WitnessFlag(
            signal="dos_drift",
            severity="medium",
            message=(f"{len(recent)} failures on target {target} within 60s — possible denial-of-service drift."),
            record=record,
        )
    return None


# Ordered list of detectors. Each poll batch runs every record through every
# detector. Order matters only for deterministic test output; the rate cap
# + log write are outside the detector loop.
_DETECTORS: tuple[Callable[[dict[str, Any], WitnessContext], WitnessFlag | None], ...] = (
    _det_allowlist_breach,
    _det_poc_escape,
    _det_permission_escalation,
    _det_prompt_injection,
    _det_dos_drift,
)


# ── Witness agent ───────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class WitnessAgent:
    """Advisory audit-stream watcher. Not a swarm specialist agent (it has
    no ``run(task, context)`` — it runs a poll loop), but it lives in
    ``tools/swarm/agents/`` alongside the other safety-minded agents
    (critic, reflection) so the safety surface is co-located.

    The agent is intentionally NOT a subclass of ``tools.swarm.base.Agent``
    because it is never routed to by ``SwarmOrchestrator`` — it runs as a
    side task alongside a run, not as a task in the run. Making it an ``Agent``
    would imply the orchestrator can route to it, which it must not (the
    witness has no task output; it only flags).
    """

    def __init__(
        self,
        config: dict[str, Any] | None,
        *,
        audit_paths: Iterable[Path | str] | None = None,
        event_callback: Callable[[str, dict[str, Any]], None] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._cfg = WitnessConfig.from_config(config)
        self._audit_paths: list[Path] = []
        # Default audit streams: the exploit audit trail + the activity log.
        # Caller can override with explicit paths (tests do this).
        if audit_paths is not None:
            self._audit_paths = [Path(p) for p in audit_paths]
        else:
            self._audit_paths = [Path("exploit_workspace/exploit_audit.jsonl"), Path("reports/activity.jsonl")]
        self._event_callback = event_callback
        self._clock = clock
        self._ctx = WitnessContext(allowed_targets=_resolve_allowlist(config))
        self._log_path = Path(self._cfg.log_path)
        # Per-path byte offset so we only read NEW records on each poll.
        self._offsets: dict[Path, int] = {p: 0 for p in self._audit_paths}
        # Rate cap: signal -> deque of flag timestamps in the last 60s.
        self._flag_times: dict[str, deque[float]] = {}
        self._stopped = False
        # Records seen so far (for the cross-record detectors). Bounded.
        self._seen: int = 0

    # ── Public API ─────────────────────────────────────────────────────

    def scan_once(self) -> list[WitnessFlag]:
        """Do ONE poll: read new records from every audit path, run them
        through the detectors, write + emit any flags. Returns the flags
        raised this poll. Safe to call repeatedly (the witness poll loop
        does so every ``poll_interval_seconds``).

        Never raises: any exception (including ``BaseExceptionGroup`` if a
        detector somehow trips an anyio boundary) is swallowed so a witness
        crash cannot take the run down. A swallowed error is recorded as a
        low-severity ``witness_error`` flag so the operator knows the
        watcher is unhealthy.
        """
        if not self._cfg.enabled:
            return []
        try:
            records = self._read_new_records()
            flags: list[WitnessFlag] = []
            for record in records:
                self._ctx.record_call(
                    self._clock(),
                    str(record.get("tool_name", "")),
                    str(record.get("target_ip") or record.get("target") or ""),
                    str(record.get("status", "")),
                )
                self._ctx.prune_failures(self._clock(), self._cfg.dos_failure_window_seconds)
                for detector in _DETECTORS:
                    flag = detector(record, self._ctx)
                    if flag is not None and self._under_rate_cap(flag.signal):
                        flags.append(flag)
            self._write_flags(flags)
            return flags
        except _EXC_GROUP_CATCH as exc:
            # ponytail: swallow + record. The witness must NOT take the run
            # down. Upgrade: structured retry / circuit breaker if a path is
            # persistently unreadable.
            err_flag = WitnessFlag(
                signal="witness_error",
                severity="low",
                message=f"Witness scan raised {type(exc).__name__}: {exc}",
                record={},
            )
            self._write_flags([err_flag])
            return [err_flag]

    def add_audit_path(self, path: Path | str) -> bool:
        """Register an additional audit stream to tail (e.g. the per-attempt
        ``exploit_audit.jsonl`` once the run exposes its path). Returns True
        if added, False when the path was already registered (so callers can
        safely hand the same path twice — no duplicate reads/flags)."""
        p = Path(path)
        if p in self._audit_paths:
            return False
        self._audit_paths.append(p)
        self._offsets[p] = 0
        return True

    def stop(self) -> None:
        """Stop the poll loop after the current scan finishes."""
        self._stopped = True

    @property
    def stopped(self) -> bool:
        return self._stopped

    @property
    def seen_count(self) -> int:
        """Total audit records processed so far (for diagnostics)."""
        return self._seen

    # ── Internals ──────────────────────────────────────────────────────

    def _read_new_records(self) -> list[dict[str, Any]]:
        """Read new JSONL records from every audit path since the last poll."""
        out: list[dict[str, Any]] = []
        for path in self._audit_paths:
            if not path.exists():
                continue
            offset = self._offsets.get(path, 0)
            try:
                with path.open("r", encoding="utf-8") as f:
                    f.seek(offset)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(rec, dict):
                            out.append(rec)
                    self._offsets[path] = f.tell()
            except OSError:
                continue
        self._seen += len(out)
        return out

    def _under_rate_cap(self, signal: str) -> bool:
        """Rate cap: at most N flags per signal per rolling 60s window."""
        now = self._clock()
        times = self._flag_times.setdefault(signal, deque())
        while times and now - times[0] > 60.0:
            times.popleft()
        if len(times) >= self._cfg.max_flags_per_signal_per_minute:
            return False
        times.append(now)
        return True

    def _write_flags(self, flags: list[WitnessFlag]) -> None:
        """Append flags to the witness log + emit to the event callback."""
        if not flags:
            return
        try:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with self._log_path.open("a", encoding="utf-8") as f:
                for flag in flags:
                    entry = flag.to_dict()
                    f.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            pass
        if self._cfg.escalate_to_event_broker and self._event_callback is not None:
            for flag in flags:
                try:
                    self._event_callback("witness_flag", flag.to_dict())
                except Exception:
                    pass


def _resolve_allowlist(config: dict[str, Any] | None) -> list[str]:
    """Resolve the effective allowlist for the allowlist-breach detector.

    Reuses ``tools.mcp_shared._allowed_target_list`` so the witness's notion
    of "in allowlist" matches the target-IP lock's notion exactly (same env
    vars, same config key, same union semantics). Falls back to an empty
    list if the helper is unavailable (e.g. a minimal test import) — an
    empty allowlist means the breach detector stays silent (it only fires
    when a target is NOT in a NON-EMPTY allowlist, matching
    ``_check_allowlist``).
    """
    try:
        from tools.mcp_shared import _allowed_target_list

        return _allowed_target_list(config)
    except Exception:
        return []


# ── demo() self-check ──────────────────────────────────────────────────


def _synthetic_stream() -> list[dict[str, Any]]:
    """A small synthetic audit stream for the ``demo()`` self-check: one
    benign record + one anomalous record (allowlist breach + PoC escape)."""
    return [
        {
            "timestamp": _now_iso(),
            "tool_name": "run_exploit_terminal",
            "target_ip": "127.0.0.1",
            "status": "ok",
            "command": "nmap -sV 127.0.0.1",
            "args": {"target_ip": "127.0.0.1"},
        },
        {
            "timestamp": _now_iso(),
            "tool_name": "run_python_file",
            "target_ip": "10.0.0.99",
            "status": "ok",
            "command": "python /tmp/poc.py --connect 10.0.0.99",
            "args": {"target_ip": "10.0.0.99", "script": "import socket; socket.connect(('10.0.0.99', 4444))"},
        },
    ]


def demo() -> None:
    """Self-check: feed a synthetic audit stream (one benign + one
    anomalous record) through the witness and print the flags. Does NOT
    touch a real run, a real audit file, or a real event broker.

    Run with: ``python -m tools.swarm.agents.witness_agent``
    """
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="witness_demo_"))
    audit_path = tmp / "exploit_audit.jsonl"
    audit_path.write_text(
        "\n".join(json.dumps(r, default=str) for r in _synthetic_stream()) + "\n",
        encoding="utf-8",
    )
    witness_log = tmp / "witness.jsonl"
    # Allowlist = 127.0.0.1 only, so 10.0.0.99 is a breach. The PoC record
    # also lacks an offline marker, so it fires the escape detector too.
    config = {
        "witness": {"enabled": True, "log_path": str(witness_log), "poll_interval_seconds": 1},
        "exploit": {"allowed_targets": ["127.0.0.1"], "require_explicit_allowlist": True},
    }
    flags_seen: list[dict[str, Any]] = []

    def capture(_event: str, payload: dict[str, Any]) -> None:
        flags_seen.append(payload)

    agent = WitnessAgent(config, audit_paths=[audit_path], event_callback=capture)
    flags = agent.scan_once()
    print(f" witness demo: scanned {agent.seen_count} records, raised {len(flags)} flag(s)")
    for flag in flags:
        print(f"   [{flag.severity:8}] {flag.signal}: {flag.message}")
    assert any(f.signal == "allowlist_breach" for f in flags), "allowlist_breach detector did not fire"
    assert any(f.signal == "poc_no_network_isolation" for f in flags), "poc escape detector did not fire"
    # The benign 127.0.0.1 record must NOT have raised a breach flag.
    assert all(f.record.get("target_ip") != "127.0.0.1" or f.signal != "allowlist_breach" for f in flags), (
        "benign 127.0.0.1 record was flagged as an allowlist breach (false positive)"
    )
    print(" witness demo: OK (anomalies flagged, benign record ignored)")
    print(f" witness log: {witness_log}")


if __name__ == "__main__":
    demo()
