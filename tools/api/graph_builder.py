"""Per-run AttackGraph v2 ingestion for the WebUI graph explorer.

Turns a run's artifacts into an ``AttackGraphStore`` (scope = run id):

- run metadata      -> HOST/DOMAIN or IP root node (+ RESOLVES_TO edge)
- exploit_audit     -> OBSERVATION nodes per (tool, target) + OBSERVED_ON edges
- enhanced report   -> FINDING / VULNERABILITY_CANDIDATE / EVIDENCE nodes,
                       affected-asset HOST/ASSET nodes, AFFECTED_BY / SUPPORTED_BY /
                       DERIVED_FROM edges, exploitation-chain OBSERVATION steps
                       with DEPENDS_ON edges

Everything comes from real artifact fields; nothing is invented. Command/args
are deliberately NOT copied into node properties (they may hold credentials).
Conflicts are captured from ``GraphMergeEngine`` per source batch so the
explorer can surface them instead of silently merging.

``scope`` = run id everywhere, which gives per-run isolation for free: every
query filters by scope, so one run's graph can never leak into another's.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.intelligence.graph.merge import GraphMergeConflict, GraphMergeEngine, GraphMergeError
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

# Confidence -> status heuristic for findings (documented derivation, see below).
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


# ── factories ────────────────────────────────────────────────────────────────


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


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _affected_type(value: str) -> NodeType:
    """Map an affected-asset string to a node type without fabricating one.

    IP addresses -> IP; hostname-like strings -> HOST; anything else (a service
    name, a URL, prose) -> ASSET. Reusing IP/HOST for real addresses keeps
    affected-asset edges from colliding with the same value created elsewhere.
    """
    if classify_target(value) == "ip":
        return NodeType.IP
    if re.fullmatch(r"[a-zA-Z0-9._:\-]+", value):
        return NodeType.HOST
    return NodeType.ASSET


def _safe_apply(
    store: AttackGraphStore,
    update: GraphUpdate,
    conflicts: list[GraphMergeConflict],
) -> None:
    """Apply ``update``; record merge-engine rejections instead of crashing.

    A GraphMergeError (e.g. an edge referencing a node the engine skipped for
    a type conflict) is recorded as a conflict entry so the whole ingestion
    stays resilient to messy artifact data.
    """
    try:
        conflicts.extend(GraphMergeEngine(store).apply(update))
    except GraphMergeError:
        conflicts.append(
            GraphMergeConflict(
                edge_type=None,
                node_value=str(update.reason),
                reason="ingest skip: edge referenced a node the merge engine rejected",
                existing_confidence=0.0,
                proposed_confidence=0.0,
            )
        )


def _finding_status(finding: dict[str, Any]) -> NodeStatus:
    """Belief state derived from real report fields.

    A finding with an ``exploitation_result`` is CONFIRMED (a verified
    outcome); otherwise the report's confidence drives the state.
    """
    if finding.get("exploitation_result"):
        return NodeStatus.CONFIRMED
    confidence = _to_float(finding.get("confidence"))
    if confidence is not None:
        for threshold, status in _FINDING_STATUS_BY_CONFIDENCE:
            if confidence >= threshold:
                return status
    return NodeStatus.UNKNOWN


# ── ingest run metadata ─────────────────────────────────────────────────────


def ingest_run_metadata(
    store: AttackGraphStore,
    run: dict[str, Any],
    conflicts: list[GraphMergeConflict],
) -> None:
    """Root HOST/DOMAIN/IP nodes from run metadata + RESOLVES_TO edge."""
    scope = store.scope
    request = run.get("request") or {}
    preview = run.get("preview") or {}
    target = str(request.get("target") or "").strip()
    resolved_ip = str(preview.get("target_ip") or "").strip()
    original_target = str(preview.get("original_target") or target or "").strip()
    ts = _run_timestamp(run)

    update = GraphUpdate(source_agent="run", timestamp=ts, reason="run metadata")
    host_value = original_target or resolved_ip
    if host_value:
        host_type = NodeType.IP if classify_target(host_value) == "ip" else NodeType.HOST
        update.node_updates.append(_node(scope, host_type, host_value, ts, source="run"))
    if resolved_ip and classify_target(resolved_ip) == "ip" and resolved_ip.lower() != (original_target or "").lower():
        update.node_updates.append(_node(scope, NodeType.IP, resolved_ip, ts, source="run"))
    if original_target and resolved_ip and classify_target(original_target) == "domain":
        update.edge_updates.append(
            _edge(
                _node_id(scope, NodeType.HOST, original_target),
                _node_id(scope, NodeType.IP, resolved_ip),
                EdgeType.RESOLVES_TO,
                ts,
                source="run",
            )
        )
    _safe_apply(store, update, conflicts)


# ── ingest exploit audit ────────────────────────────────────────────────────


def ingest_audit(
    store: AttackGraphStore,
    run_dir: Path,
    conflicts: list[GraphMergeConflict],
) -> None:
    """OBSERVATION nodes per (tool, target) + OBSERVED_ON edges to IP nodes."""
    scope = store.scope
    records = read_audit(run_dir)
    if not records:
        return
    update = GraphUpdate(source_agent="exploit_audit", reason="exploit audit trail")
    ts = _now_iso()
    for rec in records:
        tool = str(rec.get("tool_name") or "").strip()
        if not tool:
            continue
        for t in str(rec.get("target_ip") or "").split(","):
            t = t.strip()
            if not t:
                continue
            rec_ts = str(rec.get("timestamp") or ts)
            obs_value = f"{tool} on {t}"
            obs_id = _node_id(scope, NodeType.OBSERVATION, obs_value)
            update.node_updates.append(
                _node(
                    scope,
                    NodeType.OBSERVATION,
                    obs_value,
                    rec_ts,
                    properties={
                        "tool": tool,
                        "status": str(rec.get("status") or ""),
                        "attempt_id": str(rec.get("attempt_id") or "")[:40],
                        "code_sha256": str(rec.get("code_sha256") or "")[:16],
                    },
                    source=tool,
                )
            )
            update.edge_updates.append(
                _edge(obs_id, _node_id(scope, NodeType.IP, t), EdgeType.OBSERVED_ON, rec_ts, source=tool)
            )
    _safe_apply(store, update, conflicts)


# ── ingest enhanced report ──────────────────────────────────────────────────


def ingest_report(
    store: AttackGraphStore,
    run_dir: Path,
    conflicts: list[GraphMergeConflict],
) -> None:
    """Findings, CVE candidates, evidence, affected assets, chain steps."""
    scope = store.scope
    report = read_enhanced_report(run_dir)
    if not report:
        return
    ts = str(report.get("report_metadata", {}).get("generated_at") or _now_iso())
    findings = report.get("technical_findings") or []
    chains = report.get("exploitation_chains") or []

    chain_step_ids: dict[str, list[str]] = {}
    chain_update = GraphUpdate(source_agent="exploitation_chains", timestamp=ts, reason="exploitation chains")
    for chain in chains:
        chain_id = str(chain.get("chain_id") or "")
        target = str(chain.get("target") or "")
        prev = ""
        entries = chain.get("entries") or []
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            module = str(entry.get("module") or entry.get("tool") or f"step-{i}")
            value = f"{chain_id}:{i} {module}"
            obs_id = _node_id(scope, NodeType.OBSERVATION, value)
            chain_update.node_updates.append(
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
                chain_update.edge_updates.append(
                    _edge(prev, obs_id, EdgeType.DEPENDS_ON, ts, source="exploitation_chain")
                )
            if target:
                ttype = _affected_type(target)
                chain_update.node_updates.append(_node(scope, ttype, target, ts, source="exploitation_chain"))
                chain_update.edge_updates.append(
                    _edge(obs_id, _node_id(scope, ttype, target), EdgeType.OBSERVED_ON, ts, source="exploitation_chain")
                )
            prev = obs_id
            chain_step_ids.setdefault(chain_id, []).append(obs_id)
    _safe_apply(store, chain_update, conflicts)

    finding_update = GraphUpdate(source_agent="technical_findings", timestamp=ts, reason="enhanced report findings")
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        finding_id = str(finding.get("finding_id") or "")
        title = str(finding.get("title") or "")
        value = f"{finding_id} · {title[:60]}" if finding_id else title[:80]
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
            confidence=_to_float(finding.get("confidence")) or 0.5,
            properties=props,
            source="enhanced_report",
            evidence_refs=refs,
        )
        finding_update.node_updates.append(finding_node)

        affected = str(finding.get("affected_asset") or "").strip()
        if affected:
            atype = _affected_type(affected)
            asset_id = _node_id(scope, atype, affected)
            finding_update.node_updates.append(_node(scope, atype, affected, ts, source="enhanced_report"))
            finding_update.edge_updates.append(
                _edge(asset_id, finding_node.node_id, EdgeType.AFFECTED_BY, ts, source="enhanced_report")
            )

        for ref in refs[:40]:
            ev_id = _node_id(scope, NodeType.EVIDENCE, ref)
            finding_update.node_updates.append(
                _node(scope, NodeType.EVIDENCE, ref, ts, properties={"evidence_id": ref}, source="evidence_refs")
            )
            finding_update.edge_updates.append(
                _edge(finding_node.node_id, ev_id, EdgeType.SUPPORTED_BY, ts, source="enhanced_report")
            )

        for cve in _CVE_RE.findall(" ".join(finding.get("references") or []) + " " + title):
            cve = cve.upper()
            cand_id = _node_id(scope, NodeType.VULNERABILITY_CANDIDATE, cve)
            finding_update.node_updates.append(
                _node(scope, NodeType.VULNERABILITY_CANDIDATE, cve, ts, source="enhanced_report")
            )
            finding_update.edge_updates.append(
                _edge(finding_node.node_id, cand_id, EdgeType.RELATED_TO, ts, source="enhanced_report")
            )

        chain_id = str((finding.get("attack_chain") or {}).get("chain_id") or "")
        if chain_id:
            for step_id in chain_step_ids.get(chain_id, [])[:20]:
                finding_update.edge_updates.append(
                    _edge(finding_node.node_id, step_id, EdgeType.DERIVED_FROM, ts, source="enhanced_report")
                )

    _safe_apply(store, finding_update, conflicts)


# ── public entry ─────────────────────────────────────────────────────────────


def build_graph_store(
    store: AttackGraphStore,
    run: dict[str, Any],
    run_dir: Path,
    conflicts: list[GraphMergeConflict] | None = None,
) -> tuple[AttackGraphStore, list[GraphNode]]:
    """Populate ``store`` from ``run`` + its on-disk artifacts.

    The store must be created with ``scope = scope_for_run(run_id)``.
    Returns ``(store, conflicts)`` where conflicts are any GraphMergeEngine
    rejections observed during ingestion.
    """
    conflicts = conflicts if conflicts is not None else []
    ingest_run_metadata(store, run, conflicts)
    ingest_audit(store, run_dir, conflicts)
    ingest_report(store, run_dir, conflicts)
    return store, conflicts
