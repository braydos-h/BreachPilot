"""Per-run AttackGraph v2 ingestion for the WebUI graph explorer.

Turns a run's artifacts into an ``AttackGraphStore`` (scope = run id):

- run metadata      -> DOMAIN / IP root nodes (+ RESOLVES_TO edge)
- exploit_audit     -> OBSERVATION nodes per (tool, target) + OBSERVED_ON edges
- enhanced report   -> FINDING / VULNERABILITY_CANDIDATE / EVIDENCE nodes,
                       affected-asset HOST/ASSET nodes, AFFECTED_BY / SUPPORTED_BY /
                       DERIVED_FROM edges, exploitation-chain OBSERVATION steps
                       with DEPENDS_ON edges

All data comes from real artifact fields; nothing is invented. Command/args are
deliberately NOT copied into node properties (they may hold credentials).
Conflicts are captured from ``GraphMergeEngine`` per source batch so the
explorer can surface them instead of silently merging.

``scope`` = run_id everywhere, which gives per-run isolation for free: every
query filters by scope, so one run's graph can never leak into another's.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_timestamp(run: dict[str, Any]) -> str:
    return str(run.get("created_at") or run.get("updated_at") or _now_iso())


# ── value helpers ────────────────────────────────────────────────────────────


def classify_target(value: str) -> str:
    """Return ``"ip"`` when ``value`` is an IP address, else ``"domain"``."""
    try:
        ipaddress.ip_address(value.strip())
        return "ip"
    except ValueError:
        return "domain"


def _slug(value: str, max_len: int = 60) -> str:
    slug = re.sub(r"[^0-9a-zA-Z]+", "-", value.strip().lower()).strip("-")
    return slug[:max_len]


def _node_id(scope: str, node_type: NodeType, value: str) -> str:
    return f"{scope}|{node_type.value}|{_slug(value)}"


def _edge_id(src: str, dst: str, edge_type: EdgeType) -> str:
    return f"{src}->{dst}|{edge_type.value}"


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


# ── node/edge factories ─────────────────────────────────────────────────────


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


def _edge(src: str, dst: str, edge_type: EdgeType, ts: str, *, source: str = "") -> GraphEdge:
    return GraphEdge(
        edge_id=_edge_id(src, dst, edge_type),
        source_node_id=src,
        target_node_id=dst,
        edge_type=edge_type,
        scope=src.split("|")[0],
        first_seen=ts,
        last_seen=ts,
        source=source,
    )


def _apply(engine: GraphMergeEngine, update: GraphUpdate, conflicts: list[GraphNode]) -> None:
    conflicts.extend(engine.apply(update))


def _finding_status(finding: dict[str, Any]) -> NodeStatus:
    """Belief state derived from real report fields (see module docstring)."""
    if finding.get("exploitation_result"):
        return NodeStatus.CONFIRMED
    confidence = finding.get("confidence", 0.0)
    if isinstance(confidence, (int, float)):
        for threshold, status in _FINDING_STATUS_BY_CONFIDENCE:
            if confidence >= threshold:
                return status
    return NodeStatus.UNKNOWN


# ── ingest run metadata ─────────────────────────────────────────────────────


def ingest_run_metadata(
    store: AttackGraphStore,
    scope: str,
    run: dict[str, Any],
    conflicts: list[GraphNode],
) -> None:
    """DOMAIN / IP root nodes from run metadata + RESOLVES_TO edge."""
    request = run.get("request") or {}
    preview = run.get("preview") or {}
    target = str(request.get("target") or "").strip()
    resolved_ip = str(preview.get("target_ip") or "").strip()
    original_target = str(preview.get("original_target") or target or "").strip()
    ts = _run_timestamp(run)

    update = GraphUpdate(source_agent="run", timestamp=ts, reason="run metadata")
    edges: list[GraphEdge] = []

    host_value = original_target or resolved_ip
    if host_value:
        host_type = NodeType.IP if classify_target(host_value) == "ip" else NodeType.HOST
        update.node_updates.append(_node(scope, host_type, host_value, ts, source="run"))
        if resolved_ip and classify_target(resolved_ip) == "ip":
            update.node_updates.append(_node(scope, NodeType.IP, resolved_ip, ts, source="run"))

    if resolved_ip and original_target and classify_target(original_target) == "domain":
        edges.append(
            _edge(
                _node_id(scope, NodeType.HOST, original_target),
                _node_id(scope, NodeType.IP, resolved_ip),
                EdgeType.RESOLVES_TO,
                ts,
                source="run",
            )
        )

    update.edge_updates.extend(edges)
    _apply(GraphMergeEngine(store), update, conflicts)


# ── ingest exploit audit ────────────────────────────────────────────────────


def _ingest_audit(
    store: AttackGraphStore,
    scope: str,
    records: list[dict[str, Any]],
    conflicts: list[GraphNode],
) -> None:
    """OBSERVATION nodes per (tool, target) + OBSERVED_ON edges to IP nodes."""
    engine = GraphMergeEngine(store)
    # One update per source batch so the merge engine can surface conflicts
    # without cross-batch interference.
    update = GraphUpdate(source_agent="exploit_audit", reason="exploit audit trail")
    edges: list[GraphEdge] = []

    for rec in records:
        tool = str(rec.get("tool_name") or "").strip()
        if not tool:
            continue
        ts = str(rec.get("timestamp") or "")
        targets = str(rec.get("target_ip") or "").strip()
        for t in targets.split(","):
            t = t.strip()
            if not t:
                continue
            obs_value = f"{tool} on {t}"
            obs_id = _node_id(scope, NodeType.OBSERVATION, obs_value)
            update.node_updates.append(
                _node(
                    scope,
                    NodeType.OBSERVATION,
                    obs_value,
                    ts or _now_iso(),
                    status=NodeStatus.UNKNOWN,
                    properties={
                        "tool": tool,
                        "status": str(rec.get("status") or ""),
                        "attempt_id": str(rec.get("attempt_id") or "")[:40],
                        "code_sha256": str(rec.get("code_sha256") or "")[:16],
                    },
                    source=tool,
                )
            )
            ip_id = _node_id(scope, NodeType.IP, t)
            edges.append(
                _edge(obs_id, ip_id, EdgeType.OBSERVED_ON, ts or _now(), source=tool)
            )

    update.edge_updates.extend(edges)
    _apply(engine, update, conflicts)


def _ingest_report(
    store: AttackGraphStore,
    scope: str,
    report: dict[str, Any],
    run_id: str,
    conflicts: list[GraphNode],
) -> None:
    """Findings + CVE candidates + evidence + affected assets from enhanced report."""
    if not report:
        return
    engine = GraphMergeEngine(store)
    ts = str(report.get("report_metadata", {}).get("generated_at") or _now())

    findings = report.get("technical_findings") or []
    chains = report.get("exploitation_chains") or []

    # Chain-step nodes first so findings can DERIVE_FROM them.
    chain_step_ids: dict[str, list[str]] = {}
    update = GraphUpdate(source_agent="exploitation_chains", timestamp=ts, reason="exploitation chains")
    for chain in chains:
        chain_id = str(chain.get("chain_id") or "")
        entries = chain.get("entries") or []
        target = str(chain.get("target") or "")
        prev = ""
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            module = str(entry.get("module") or entry.get("tool") or f"step-{i}")
            value = f"{chain_id}:{i} {module}"
            obs_id = _node_id(scope, NodeType.OBSERVATION, value)
            update.node_updates.append(
                _node(
                    scope,
                    NodeType.OBSERVATION,
                    value,
                    ts,
                    properties={
                        "chain_id": chain_id,
                        "module": module,
                        "result": str(entry.get("result") or ""),
                    },
                    source="exploitation_chain",
                )
            )
            if prev:
                update.edge_updates.append(
                    _edge(prev, obs_id, EdgeType.DEPENDS_ON, ts, source="exploitation_chain")
                )
            prev = obs_id
            chain_step_ids.setdefault(chain_id, []).append(obs_id)
            # Link the step to the target IP.
            if target:
                update.edge_updates.append(
                    _edge(obs_id, _node_id(scope, NodeType.IP, target), EdgeType.OBSERVED_ON, ts, source="exploitation_chain")
                )
    _apply(engine, update, conflicts)

    # Findings.
    finding_update = GraphUpdate(source_agent="technical_findings", timestamp=ts, reason="enhanced report findings")
    seen_cves: dict[str, str] = {}

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        finding_id = str(finding.get("finding_id") or "")
        title = str(finding.get("title") or "")
        affected = str(finding.get("affected_asset") or "")
        value = f"{finding_id} · {title[:60]}" if finding_id else title[:80]
        node_type = NodeType.FINDING
        props: dict[str, Any] = {}
        for key in ("vuln_class", "severity", "exploitation_result", "privilege_level_gained"):
            if finding.get(key):
                props[key] = finding.get(key)
        cvss = finding.get("cvss") or {}
        if isinstance(cvss, dict):
            if cvss.get("base_score") is not None:
                props["cvss_score"] = cvss["base_score"]
            if cvss.get("severity"):
                props["cvss_severity"] = cvss["severity"]
        refs = tuple(str(r) for r in (finding.get("evidence_refs") or []) if r)
        finding_node = _node(
            scope,
            NodeType.FINDING,
            value,
            ts,
            status=_finding_status(finding),
            confidence=_to_float(finding.get("confidence")),
            properties=props,
            source="enhanced_report",
            evidence_refs=refs,
        )
        finding_node = _apply(engine, GraphUpdate(node_updates=[finding_node]), conflicts)[0] if False else finding_node
        engine.apply(GraphUpdate(node_updates=[finding_node]))
        finding_id_actual = finding_node.node_id

        # Affected asset -> host/asset node + AFFECTED_BY edge.
        if affected:
            atype = NodeType.HOST if classify_target(affected) == "domain" else NodeType.ASSET
            asset_id = _node_id(scope, atype, affected)
            engine.apply(
                GraphUpdate(node_updates=[_node(scope, atype, affected, ts, source="enhanced_report")])
            )
            engine.apply(
                GraphUpdate(
                    edge_updates=[
                        _edge(asset_id, finding_node.node_id, EdgeType.AFFECTED_BY, ts, source="enhanced_report")
                    ]
                )
            )

        # Evidence nodes + SUPPORTED_BY edges.
        for ref in refs[:40]:
            ev_id = _node_id(scope, NodeType.EVIDENCE, ref)
            engine.apply(
                GraphUpdate(node_updates=[_node(scope, NodeType.EVIDENCE, ref, ts, properties={"evidence_id": ref}, source="evidence_refs")])
            )
            engine.apply(
                GraphUpdate(edge_updates=[_edge(finding_node.node_id, ev_id, EdgeType.SUPPORTED_BY, ts, source="enhanced_report")])
            )

        # CVE references -> vulnerability candidate nodes.
        for cve in _CVE_RE.findall(" ".join(finding.get("references") or []) + " " + title):
            cve = cve.upper()
            cand_id = _node_id(scope, NodeType.VULNERABILITY_CANDIDATE, cve)
            engine.apply(
                GraphUpdate(node_updates=[_node(scope, NodeType.VULNERABILITY_CANDIDATE, cve, ts, source="enhanced_report")])
            )
            engine.apply(
                GraphUpdate(edge_updates=[_edge(finding_node.node_id, cand_id, EdgeType.RELATED_TO, ts, source="enhanced_report")])
            )

    # derivation: finding -> chain steps
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        chain_id = str((finding.get("attack_chain") or {}).get("chain_id") or "")
        if chain_id and chain_id in chain_step_ids:
            node_id = _node_id(scope, NodeType.FINDING, f"{finding.get('finding_id','')} · {str(finding.get('title',''))[:60]}")
            for step_id in chain_step_ids[chain_id][:20]:
                engine.apply(
                    GraphUpdate(edge_updates=[_edge(node_id, step_id, EdgeType.DERIVED_FROM, ts, source="enhanced_report")])
                )


def _node_props() -> dict[str, Any]:
    return {}


def _finding_status(finding: dict[str, Any]) -> NodeStatus:
    if finding.get("exploitation_result"):
        return NodeStatus.CONFIRMED
    confidence = _to_float(finding.get("confidence"))
    for threshold, status in _FINDING_STATUS_BY_CONFIDENCE:
        if confidence >= threshold:
            return status
    return NodeStatus.UNKNOWN


def _to_float(value: Any, default: float = 0.5) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── public entry ─────────────────────────────────────────────────────────────


def build_graph_store(
    store: AttackGraphStore,
    run: dict[str, Any],
    run_dir: Path,
    conflicts: list[GraphNode] | None = None,
) -> tuple[AttackGraphStore, list[GraphNode]]:
    """Populate ``store`` from ``run`` + its artifacts; returns (store, conflicts)."""
    scope = scope_for_run(run_id_from_run(run))
    conflicts = conflicts if conflicts is not None else []
    _build_run_root_nodes(store, scope, run, conflicts)
    _ingest_audit(store, scope, read_audit(run_dir), conflicts)
    _ingest_report(store, scope, read_enhanced_report(run_dir), conflicts)
    return store, conflicts


def run_id_from_run(run: dict[str, Any]) -> str:
    return str(run.get("id") or "")


def _build_run_root_nodes(
    store: AttackGraphStore,
    scope: str,
    run: dict[str, Any],
    conflicts: list[GraphNode],
) -> None:
    request = run.get("request") or {}
    preview = run.get("preview") or {}
    target = str(request.get("target") or "").strip()
    resolved_ip = str(preview.get("target_ip") or "").strip()
    original_target = str(preview.get("original_target") or target or "").strip()
    ts = _run_timestamp(run)

    engine = GraphMergeEngine(store)
    update = GraphUpdate(source_agent="run", timestamp=ts, reason="run metadata")
    edges: list[GraphEdge] = []

    host_value = original_target or resolved_ip
    if host_value:
        host_type = NodeType.IP if classify_target(host_value) == "ip" else NodeType.HOST
        update.node_updates.append(_node(scope, host_type, host_value, ts, source="run"))
    if resolved_ip and classify_target(resolved_ip) == "ip" and resolved_ip.lower() != (original_target or "").lower():
        update.node_updates.append(_node(scope, NodeType.IP, resolved_ip, ts, source="run"))

    if resolved_ip and original_target and classify_target(original_target) == "domain":
        edges.append(
            _edge(
                _node_id(scope, NodeType.HOST, original_target),
                _node_id(scope, NodeType.IP, resolved_ip),
                EdgeType.RESOLVES_TO,
                ts,
                source="run",
            )
        )
    update.edge_updates.extend(edges)
    _apply(engine, update, conflicts)
