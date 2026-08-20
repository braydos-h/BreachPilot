"""Flow B adapters: FindingVerifier -> graph/evidence wiring (defect C5).

Makes finding validation reachable (reproduction steps derived from evidence
refs) and links findings into the target graph.
"""

from __future__ import annotations

import json
from typing import Any

from finding_verifier import FindingVerifier
from target_graph import TargetGraph


def _json_load(raw: Any, default: Any) -> Any:
    if isinstance(raw, (list, dict)):
        return raw
    if isinstance(raw, str) and raw:
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return default
    return default


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _find_or_add(target_graph: TargetGraph, node_type: str, value: str) -> str:
    """Resolve an existing node id by exact value match, else create the node."""
    nodes = target_graph.query_graph(node_type=node_type, value_pattern=value, limit=500).get("nodes", [])
    existing = next((n for n in nodes if n.get("value") == value), None)
    return existing["id"] if existing else target_graph.add_node(node_type, value)


class FindingAdapter:
    """Thin wiring that makes finding validation reachable and graph-linked."""

    @staticmethod
    def ensure_reproduction_steps(
        finding_row: dict[str, Any],
        evidence_refs: list[str] | None = None,
    ) -> list[str]:
        """Derive reproduction steps from evidence refs when none are stored.

        Accepts either a ``_row_to_finding`` dict or a raw DB row.
        """
        existing = _json_load(finding_row.get("reproduction_steps_json"), [])
        if not existing:
            existing = _json_load(finding_row.get("reproduction_steps"), [])
        if existing:
            return existing
        refs = evidence_refs
        if refs is None:
            refs = _json_load(finding_row.get("evidence_refs_json"), [])
        if not refs:
            refs = _json_load(finding_row.get("evidence_refs"), [])
        return [f"Reproduce via evidence: {ref}" for ref in refs]

    @staticmethod
    def dedupe_findings(
        verifier: FindingVerifier,
        target: str,
        vuln_class: str,
        candidate_rows: list[dict[str, Any]] | None = None,
    ) -> str | None:
        """Return the id of an existing finding on the same (affected_asset, vuln_class)."""
        rows = candidate_rows if candidate_rows is not None else verifier.list_all()
        for row in rows:
            if row.get("affected_asset") == target and row.get("vuln_class") == vuln_class:
                return row.get("finding_id")
        return None

    @staticmethod
    def link_to_graph(
        verifier: FindingVerifier,
        target_graph: TargetGraph,
        finding_row: dict[str, Any],
        node_map: dict[str, str],
    ) -> str | None:
        """Link a finding into the graph: finding node + asset/evidence edges.

        Returns the finding node id, or None if the row has no finding id.
        Node/edge ids are resolved: existing nodes are matched by value, and
        ``node_map`` (value -> node id) overrides lookups.
        """
        finding_id = finding_row.get("finding_id")
        if not finding_id:
            return None
        title = finding_row.get("title") or finding_id
        finding_node_id = _find_or_add(target_graph, "finding", title)
        for asset in _as_list(finding_row.get("affected_asset")):
            asset_node_id = node_map.get(asset) or _find_or_add(target_graph, "asset", asset)
            if asset_node_id:
                # "affects" is not in target_graph.EDGE_TYPES; "related_to" is the
                # closest valid relation (add_edge validates and would raise).
                target_graph.add_edge(finding_node_id, asset_node_id, "related_to")
        for ref in _as_list(finding_row.get("evidence_refs")):
            ev_node_id = node_map.get(ref) or _find_or_add(target_graph, "evidence", ref)
            if ev_node_id:
                target_graph.add_edge(finding_node_id, ev_node_id, "produced_evidence")
        return finding_node_id
