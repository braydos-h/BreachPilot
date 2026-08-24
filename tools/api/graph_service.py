"""AttackGraph explorer service: builds + caches a per-run graph.

Wraps ``tools/intelligence/graph`` (AttackGraphStore / GraphTraversal /
GraphMergeEngine) and the ``graph_builder`` ingestion. One store per run,
rebuilt lazily when the run's artifact fingerprint changes (audit + enhanced
report mtimes/sizes + run updated_at). All query surfaces are bounded and
scope-isolated (scope = run id).

Read-only: never touches a target, never mutates run artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.api.graph_builder import build_graph_store, scope_for_run
from tools.intelligence.graph.merge import GraphMergeConflict
from tools.intelligence.graph.store import AttackGraphStore
from tools.intelligence.graph.types import GraphNode, NodeStatus, NodeType

_CACHE_MAX = 8
_GRAPH_LIMIT_MAX = 500
_NEIGHBOR_MAX_NODES = 200
_NEIGHBOR_MAX_HOPS = 4
_PATH_MAX_LENGTH = 8
_PATH_MAX_PATHS = 8


@dataclass
class _Store:
    store: AttackGraphStore
    conflicts: list[GraphMergeConflict]
    fingerprint: tuple[Any, ...]
    built_at: str


class AttackGraphService:
    """Per-run AttackGraph v2 access with lazy rebuild + bounded queries."""

    def __init__(self, persistence: Any, reports_dir: Path | None = None) -> None:
        self._persistence = persistence
        inherited = getattr(persistence, "reports_dir", None)
        self._reports_dir = Path(reports_dir) if reports_dir else (Path(inherited) if inherited else Path("reports"))
        self._cache: dict[str, _Store] = {}

    # ── entry lifecycle ───────────────────────────────────────────────────

    def _fingerprint(self, run: dict[str, Any], run_dir: Path) -> tuple[Any, ...]:
        def _stat(rel: str) -> tuple[Any, ...]:
            path = run_dir / rel
            try:
                st = path.stat()
                return (path.name, st.st_size, int(st.st_mtime))
            except OSError:
                return (rel, -1, -1)

        return (
            str(run.get("id") or ""),
            str(run.get("updated_at") or ""),
            _state_audit(run_dir),
            _state_enhanced(run_dir),
        )

    def _entry(self, run: dict[str, Any]) -> _Store:
        """Return the cached store for ``run``, rebuilding when artifacts change."""
        run_id = str(run.get("id") or "")
        run_dir = self._run_dir(run_id)
        fingerprint = self._fingerprint(run, run_dir)
        entry = self._cache.get(run_id)
        if entry is not None and entry.fingerprint == fingerprint:
            return entry

        # Evict LRU (dict preserves insertion order; re-insert moves to end).
        if run_id in self._cache:
            self._cache.pop(run_id)
        while len(self._cache) >= _CACHE_MAX:
            oldest = next(iter(self._cache))
            try:
                self._cache[oldest].store.close()
            except Exception:
                pass
            self._cache.pop(oldest)

        from datetime import datetime, timezone

        store = AttackGraphStore(":memory:", scope=scope_for_run(run_id))
        conflicts: list[GraphMergeConflict] = []
        build_graph_store(store, run, run_dir, conflicts)
        entry = _Store(
            store=store,
            conflicts=conflicts,
            fingerprint=fingerprint,
            built_at=datetime.now(timezone.utc).isoformat(),
        )
        self._cache[run_id] = entry
        return entry

    def _run_dir(self, run_id: str) -> Path:
        base = self._reports_dir.resolve()
        candidate = (base / run_id).resolve()
        if base not in candidate.parents and candidate != base:
            raise ValueError(f"Invalid run id: {run_id}")
        return candidate

    def get_store(self, run: dict[str, Any]) -> AttackGraphStore:
        return self._entry(run).store

    def close(self) -> None:
        for entry in self._cache.values():
            try:
                entry.store.close()
            except Exception:
                pass
        self._cache.clear()

    # ── graph data ────────────────────────────────────────────────────────

    def graph(
        self,
        run: dict[str, Any],
        *,
        node_types: list[str] | None = None,
        statuses: list[str] | None = None,
        search: str = "",
        limit: int = 300,
    ) -> dict[str, Any]:
        """Bounded, filtered graph (nodes + edges whose endpoints are included)."""
        store = self._entry(run).store
        scope = store.scope
        limit = max(1, min(int(limit), _GRAPH_LIMIT_MAX))

        types = _parse_enums(node_types, NodeType) if node_types else None
        status_list = _parse_enums(statuses, NodeStatus) if statuses else None

        nodes, truncated = _query_nodes(store, scope, types, status_list, search.strip(), limit)
        ids = {n.node_id for n in nodes}
        edges = [
            e for e in store.query_edges(scope=scope, limit=2000) if e.source_node_id in ids and e.target_node_id in ids
        ]
        total = store.summary()["total_nodes"]

        return {
            "run_id": str(run.get("id") or ""),
            "scope": scope,
            "nodes": [n.to_dict() for n in nodes],
            "edges": [e.to_dict() for e in edges],
            "total_nodes": total,
            "truncated": truncated,
        }

    def summary(self, run: dict[str, Any]) -> dict[str, Any]:
        store = self._entry(run).store
        summary = store.summary()
        nodes = store.to_graph_nodes()
        edges = store.to_graph_edges()

        by_type = summary["nodes"]
        status_counts: dict[str, int] = {}
        for n in nodes:
            status_counts[n.status.value] = status_counts.get(n.status.value, 0) + 1

        degree: dict[str, int] = {}
        for e in edges:
            degree[e.source_node_id] = degree.get(e.source_node_id, 0) + 1
            degree[e.target_node_id] = degree.get(e.target_node_id, 0) + 1
        highest = None
        if degree:
            top_id = max(degree, key=lambda k: degree[k])
            top_node = next((n for n in nodes if n.node_id == top_id), None)
            if top_node is not None:
                highest = {
                    "node_id": top_id,
                    "value": top_node.value,
                    "node_type": top_node.node_type.value,
                    "degree": degree[top_id],
                }

        return {
            "run_id": str(run.get("id") or ""),
            "summary": summary,
            "stats": {
                "hosts": by_type.get("host", 0),
                "domains": by_type.get("domain", 0),
                "ips": by_type.get("ip", 0),
                "services": by_type.get("service", 0),
                "findings": by_type.get("finding", 0),
                "hypotheses": by_type.get("hypothesis", 0),
                "evidence": by_type.get("evidence", 0),
                "observations": by_type.get("observation", 0),
                "vulnerability_candidates": by_type.get("vulnerability_candidate", 0),
                "confirmed": status_counts.get("confirmed", 0),
                "likely": status_counts.get("likely", 0),
                "refuted": status_counts.get("refuted", 0),
                "highest_degree_node": highest,
                "conflict_count": len(self._entry(run).conflicts),
            },
        }

    def conflicts(self, run: dict[str, Any]) -> list[dict[str, Any]]:
        """Merge-engine conflicts observed during ingestion, enriched for the UI."""
        entry = self._entry(run)
        store = entry.store
        out: list[dict[str, Any]] = []
        for c in entry.conflicts:
            out.append(
                {
                    "node_value": c.node_value,
                    "reason": c.reason,
                    "existing_confidence": c.existing_confidence,
                    "proposed_confidence": c.proposed_confidence,
                    "node_id": _resolve_conflict_node_id(store, c.node_value),
                    "scope": store.scope,
                    "built_at": entry.built_at,
                }
            )
        return out

    def node(self, run: dict[str, Any], node_id: str) -> dict[str, Any] | None:
        """Node details + a bounded set of connected edges + neighbors."""
        entry = self._entry(run)
        store = entry.store
        node = store.get_node(node_id)
        if node is None or node.scope != store.scope:
            return None
        edges = [e for e in store.to_graph_edges() if e.source_node_id == node_id or e.target_node_id == node_id][:100]
        neighbor_ids = {e.target_node_id if e.source_node_id == node_id else e.source_node_id for e in edges}
        neighbors = [n.to_dict() for n in store.to_graph_nodes() if n.node_id in neighbor_ids and n.node_id != node_id][
            :100
        ]
        return {
            "node": node.to_dict(),
            "edges": [e.to_dict() for e in edges],
            "neighbors": neighbors,
        }

    def neighbors(
        self,
        run: dict[str, Any],
        node_id: str,
        *,
        max_hops: int = 1,
        max_nodes: int = 50,
    ) -> dict[str, Any]:
        """Bounded BFS neighborhood including the start node."""
        entry = self._entry(run)
        store = entry.store
        start = store.get_node(node_id)
        if start is None or start.scope != store.scope:
            return {"start_node": None, "nodes": [], "edges": []}
        results = store.neighbors(
            node_id,
            max_hops=max(1, min(int(max_hops), _NEIGHBOR_MAX_HOPS)),
            max_nodes=max(1, min(int(max_nodes), _NEIGHBOR_MAX_NODES)),
            scope=store.scope,
        )
        nodes: dict[str, dict[str, Any]] = {start.node_id: start.to_dict()}
        edges: dict[str, dict[str, Any]] = {}
        for n, e, dist in results:
            nodes.setdefault(n.node_id, n.to_dict())
            edges[e.edge_id] = e.to_dict()
        return {
            "run_id": str(run.get("id") or ""),
            "start_node": start.to_dict(),
            "nodes": list(nodes.values()),
            "edges": list(edges.values()),
        }

    def paths(
        self,
        run: dict[str, Any],
        start_id: str,
        end_id: str,
        *,
        max_length: int = 4,
        max_paths: int = 5,
    ) -> dict[str, Any]:
        """Bounded simple paths between two nodes."""
        entry = self._entry(run)
        store = entry.store
        start = store.get_node(start_id)
        end = store.get_node(end_id)
        if start is None or end is None or start.scope != store.scope or end.scope != store.scope:
            return {"run_id": str(run.get("id") or ""), "paths": []}
        found = store.paths(
            start_id,
            end_id,
            max_length=max(1, min(int(max_length), _PATH_MAX_LENGTH)),
            max_paths=max(1, min(int(max_paths), _PATH_MAX_PATHS)),
            scope=store.scope,
        )
        paths: list[list[dict[str, Any]]] = []
        for path in found:
            steps = []
            for n, e, dist in path:
                steps.append({"distance": dist, "node": n.to_dict(), "edge": e.to_dict()})
            paths.append(steps)
        return {"run_id": str(run.get("id") or ""), "paths": paths}


# ── helpers ──────────────────────────────────────────────────────────────────


def _parse_enums(values: list[str], enum_cls) -> list[Any] | None:
    """Map strings to enum members, ignoring invalid values (never raise)."""
    out = []
    for v in values:
        try:
            out.append(enum_cls(v))
        except (ValueError, TypeError):
            continue
    return out or None


def _query_nodes(
    store: AttackGraphStore,
    scope: str,
    types: list[Any] | None,
    statuses: list[Any] | None,
    search: str,
    limit: int,
) -> tuple[list[GraphNode], bool]:
    """Bounded node query across type/status combos, returning (nodes, truncated)."""
    combos: list[tuple[Any | None, Any | None]]
    if types and statuses:
        combos = [(t, s) for t in types for s in statuses]
    elif types:
        combos = [(t, None) for t in types]
    elif statuses:
        combos = [(None, s) for s in statuses]
    else:
        combos = [(None, None)]

    gathered: dict[str, GraphNode] = {}
    for node_type, status in combos:
        if len(gathered) >= limit:
            break
        remaining = limit + 1 - len(gathered)
        rows = store.query_nodes(
            scope=scope,
            node_type=node_type,
            status=status,
            value_substring=search or None,
            limit=max(remaining, 1),
        )
        for n in rows:
            if len(gathered) >= limit + 1:
                break
            gathered[n.node_id] = n
    nodes = list(gathered.values())[:limit]
    truncated = len(gathered) > limit
    return nodes, truncated


def _state_audit(run_dir: Path) -> tuple[Any, ...]:
    for rel in ("exploit_audit.jsonl", "exploit_workspace/exploit_audit.jsonl"):
        path = run_dir / rel
        try:
            st = path.stat()
            return (rel, st.st_size, int(st.st_mtime))
        except OSError:
            continue
    return ("exploit_audit.jsonl", -1, 0)


def _state_enhanced(run_dir: Path) -> tuple[Any, ...]:
    path = run_dir / "enhanced" / "enhanced_report.json"
    try:
        st = path.stat()
        return ("enhanced_report.json", st.st_size, int(st.st_mtime))
    except OSError:
        return ("enhanced_report.json", -1, 0)


def _resolve_conflict_node_id(store: AttackGraphStore, value: str) -> str:
    for n in store.to_graph_nodes():
        if n.value == value:
            return n.node_id
    return ""
