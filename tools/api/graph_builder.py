"""Per-run AttackGraph v2 ingestion for the WebUI graph explorer.

Turns a run's artifacts into an ``AttackGraphStore`` (scope = run id):

- run metadata      -> DOMAIN / IP root nodes (+ RESOLVES_TO edge)
- exploit_audit     -> OBSERVATION nodes per (tool, target) + OBSERVED_ON edges
- enhanced report   -> FINDING / VULNERABILITY_CANDIDATE / EVIDENCE nodes,
                       affected-asset HOST nodes, AFFECTED_BY / SUPPORTED_BY /
                       DERIVED_FROM edges, exploitation-chain OBSERVATION steps
                       with DEPENDS_ON edges

All data comes from real artifact fields; nothing is invented. Command/args
are deliberately NOT copied into node properties (they may hold credentials).
Conflicts are captured from ``GraphMergeEngine`` per source batch so the
explorer can surface them instead of silently merging.

``scope`` = run_id everywhere, which gives per-run isolation for free: every
query filters by scope, so one run's graph can never leak into another's.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from tools.intelligence.graph.merge import GraphMergeEngine
from tools.intelligence.graph.store import AttackGraphStore
from tools.intelligence.graph.types import (
    EdgeType,
    GraphEdge,
    GraphNode,
    GraphUpdate,
    NodeStatus,
    NodeType,
)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Confidence -> status heuristic for findings. A finding with an
# exploitation_result is CONFIRMED (a verified outcome); otherwise the report's
# confidence field drives the belief state. Documented here so the mapping is
# auditable, not magic.
_FINDING_STATUS_BY_CONFIDENCE = (
    (0.75, NodeStatus.LIKELY),
    (0.5, NodeStatus.SUSPECTED),
)


def scope_for_run(run_id: str) -> str:
    return f"run:{run_id}"


# ── value helpers ────────────────────────────────────────────────────────────


def classify_target(value: str) -> str:
    """Return ``"ip"`` when ``value`` is an IPv4/IPv6 address, else ``"domain"``."""
    try:
        ipaddress.ip_address(value.strip())
        return "ip"
    except ValueError:
        return "domain"


def _slug(value: str, max_len: int = 60) -> str:
    slug = re.sub(r"[^0-9a-zA-Z]+", "-", value.strip().lower()).strip("-")
    return slug[:max_len]


def _node_id(scope: str, node_type, value: str) -> str:
    return f"{scope}|{node_type.value}|{_slug(value)}"


def _edge_id(src: str, dst: str, edge_type: EdgeType) -> str:
    return f"{src}->{dst}|{edge_type.value}"


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


# ── artifact readers (tolerant, mirror the legacy graph route) ──────────────


def read_audit(run_dir: Path) -> list[dict[str, Any]]:
    """Read exploit_audit.jsonl records (tries the two on-disk locations)."""
    for candidate in (
        run_dir / "exploit_audit.jsonl",
        run_dir / "exploit_workspace" / "exploit_audit.jsonl",
    ):
        if not candidate.is_file():
            continue
        records: list[dict[str, Any]] = []
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                records.append(rec)
        return records
    return []


def read_enhanced_report(run_dir: Path) -> dict[str, Any]:
    """Read enhanced/enhanced_report.json or {}."""
    path = run_dir / "enhanced" / "enhanced_report.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _run_timestamp(run: dict[str, Any]) -> str:
    return str(run.get("created_at") or run.get("updated_at") or _now_iso())


# ── builders ─────────────────────────────────────────────────────────────────


def build_run_root_nodes(
    store: AttackGraphStore,
    scope: str,
    run: dict[str, Any],
    conflicts: list[Any],
) -> None:
    """Root nodes from run metadata: target (domain) -> resolved IP."""
    request = run.get("request") or {}
    preview = run.get("preview") or {}
    target = str(request.get("target") or "").strip()
    resolved_ip = str(preview.get("target_ip") or "").strip()
    original_target = str(preview.get("original_target") or target).strip()
    if not target and not resolved_ip:
        return

    engine = GraphMergeEngine(store)
    update = GraphUpdate(
        source_agent="run",
        timestamp=_build_timestamp(run),
        reason="run metadata",
    )
    ts = _build_timestamp(run)

    for value, ntype in (
        (original_t or resolved_ip, NodeType.DOMAIN if classify_target(original_t) == "domain" else NodeType.IP)
        for original_t in ((original_target,) if original_target else ())
    ):
        pass

    # Host/domain node for the operator-supplied target.
    if original_target:
        update.node_updates.append(
            _node(scope, NodeType.HOST if classify_target(original_target) == "domain" else NodeType.IP, original_target, ts)
        )
    # Resolved IP node.
    if resolved_ip and resolved_ip.lower() != original_target.lower():
        update.node_updates.append(_node(scope, NodeType.IP, resolved_ip, ts))
    elif resolved_ip and not original_target:
        update.node_updates.append(_node(scope, NodeType.IP, resolved_ip, ts))

    _apply(engine, update, conflicts)


def _node(
    scope: str,
    node_type: NodeType,
    value: str,
    ts: str,
    *,
    status: NodeStatus = NodeStatus.UNKNOWN,
    confidence: float = 0.5,
    properties: dict[str, Any] | None = None,
    source: str = "",
    evidence_refs: tuple[str, ...] = (),
) -> GraphNode:
    return GraphNode(
        node_id=_node_id(scope, node_type, value),
        node_type=node_type,
        value=value,
        scope=scope,
        properties=properties or {},
        confidence=confidence,
        first_seen=ts,
        last_seen=ts,
        evidence_refs=evidence_refs,
        status=status,
        source=source,
    )


def _apply(engine: GraphMergeEngine, update: GraphUpdate, conflicts: list[Any]) -> None:
    conflicts.extend(engine.apply(update))
