"""SQLite-backed persistent store for AttackGraph v2.

Implements dedup (UNIQUE(scope, node_type, value)), endpoint validation on
edge upsert, bounded BFS/DFS traversal, and merge semantics for node and
edge updates. stdlib + sqlite3 only.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

from tools.intelligence.graph.types import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeStatus,
    NodeType,
)

# Node types whose value is case-folded so "EXAMPLE.COM" and "example.com"
# collide into the same node. IP/host/domain-ish names are case-insensitive.
_CASE_FOLD_TYPES = frozenset({NodeType.IP, NodeType.HOST, NodeType.DOMAIN, NodeType.ASSET, NodeType.ENDPOINT})

_SCHEMA_VERSION = "1"

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS agv2_nodes (
    node_id TEXT PRIMARY KEY,
    node_type TEXT,
    value TEXT,
    scope TEXT,
    properties TEXT,
    confidence REAL,
    status TEXT,
    first_seen TEXT,
    last_seen TEXT,
    evidence_refs TEXT,
    observation_count INTEGER,
    contradiction_count INTEGER,
    source TEXT,
    UNIQUE(scope, node_type, value)
);
CREATE TABLE IF NOT EXISTS agv2_edges (
    edge_id TEXT PRIMARY KEY,
    source_node_id TEXT,
    target_node_id TEXT,
    edge_type TEXT,
    scope TEXT,
    properties TEXT,
    confidence REAL,
    source TEXT,
    first_seen TEXT,
    last_seen TEXT,
    evidence_refs TEXT,
    observation_count INTEGER,
    contradiction_count INTEGER
);
CREATE TABLE IF NOT EXISTS agv2_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE INDEX IF NOT EXISTS idx_agv2_edges_source ON agv2_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_agv2_edges_target ON agv2_edges(target_node_id);
CREATE INDEX IF NOT EXISTS idx_agv2_nodes_type ON agv2_nodes(node_type);
"""


def _new_id() -> str:
    """Short unique id: uuid4 hex, 12 chars."""
    return uuid.uuid4().hex[:12]


def _merge_refs(new_refs: tuple[str, ...], old_refs: tuple[str, ...]) -> tuple[str, ...]:
    """Order-preserving union of evidence refs (new refs appended after old)."""
    seen: set[str] = set()
    out: list[str] = []
    for ref in tuple(old_refs) + tuple(new_refs):
        if ref not in seen:
            seen.add(ref)
            out.append(ref)
    return tuple(out)


def _sql_merge_refs(old: Any, new: Any) -> str:
    """SQLite scalar function: order-preserving refs union over '|' strings.

    Same function the Python merge uses, so native UPSERT stays byte-identical.
    """
    old_refs = tuple(r for r in str(old or "").split("|") if r)
    new_refs = tuple(r for r in str(new or "").split("|") if r)
    return "|".join(_merge_refs(new_refs, old_refs))


def _sql_merge_props(old: Any, new: Any) -> str:
    """SQLite scalar function: shallow JSON merge (``{**old, **new}``), sorted keys."""
    try:
        old_obj = json.loads(old) if isinstance(old, str) and old else {}
    except json.JSONDecodeError:
        old_obj = {}
    try:
        new_obj = json.loads(new) if isinstance(new, str) and new else {}
    except json.JSONDecodeError:
        new_obj = {}
    if not isinstance(old_obj, dict):
        old_obj = {}
    if not isinstance(new_obj, dict):
        new_obj = {}
    return json.dumps({**old_obj, **new_obj}, sort_keys=True)


def _sqlite_supports_upsert() -> bool:
    """UPSERT + RETURNING need SQLite 3.35+ (2021; every CPython 3.11+ bundle)."""
    try:
        major, minor, *_ = (int(p) for p in sqlite3.sqlite_version.split("."))
        return (major, minor) >= (3, 35)
    except (ValueError, AttributeError):
        return False


class AttackGraphStore:
    """SQLite-backed graph store with typed node/edge upserts and traversal."""

    def __init__(self, db_path: str | Path, scope: str = ""):
        self.db_path = str(db_path)
        self.scope = scope
        # ponytail: one global lock; per-connection locks if write concurrency
        # ever matters. Held per public method so read+write pairs stay atomic.
        # RLock: transaction() nests inside upsert_* bulk paths.
        self._lock = threading.RLock()
        self._txn_depth = 0
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        # P2-03: Python-identical merge helpers callable from UPSERT SQL.
        self._conn.create_function("_py_merge_refs", 2, _sql_merge_refs)
        self._conn.create_function("_py_merge_props", 2, _sql_merge_props)
        with self._lock:
            self._conn.executescript(_CREATE_SQL)
            # P2-03: edge dedup key needs a real UNIQUE index (CREATE TABLE
            # never had one). Older DBs with duplicate edges keep the SELECT
            # path: the index build fails and _edges_upsert_ok stays False.
            self._edges_upsert_ok = True
            try:
                self._conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_agv2_edges_dedup "
                    "ON agv2_edges(source_node_id, target_node_id, edge_type, scope)"
                )
            except sqlite3.OperationalError:
                self._edges_upsert_ok = False
            self._nodes_upsert_ok = _sqlite_supports_upsert() and self._has_unique_node_key()
            self._conn.execute(
                "INSERT OR REPLACE INTO agv2_meta(key, value) VALUES (?, ?)",
                ("agv2_schema_version", _SCHEMA_VERSION),
            )
            self._conn.commit()

    def _has_unique_node_key(self) -> bool:
        """True when a UNIQUE index covers (scope, node_type, value).

        Fresh DBs get it from CREATE TABLE; older files predate the clause
        and keep the SELECT fallback (P2-03 constraint).
        """
        try:
            for row in self._conn.execute("PRAGMA index_list(agv2_nodes)").fetchall():
                if not row["unique"]:
                    continue
                cols = [r["name"] for r in self._conn.execute(f"PRAGMA index_info({row['name']})").fetchall()]
                if cols == ["scope", "node_type", "value"]:
                    return True
        except sqlite3.Error:
            pass
        return False

    @contextlib.contextmanager
    def transaction(self):  # type: ignore[no-untyped-def]
        """Single BEGIN/COMMIT block for bulk ingests (P2-02).

        Re-entrant (counter, not double-BEGIN): nested ``transaction()``
        joins the outer one. Rollback on exception leaves no half-merged
        graph. One lock hold for the whole batch is fine at this scale.
        """
        with self._lock:
            self._txn_depth += 1
        try:
            yield self
        except BaseException:
            with self._lock:
                self._txn_depth -= 1
                if self._txn_depth <= 0:
                    self._txn_depth = 0
                    self._conn.rollback()
            raise
        else:
            with self._lock:
                self._txn_depth -= 1
                if self._txn_depth <= 0:
                    self._txn_depth = 0
                    self._conn.commit()

    def _commit_or_defer(self) -> None:
        """Commit unless inside :meth:`transaction` (then the block commits once)."""
        if self._txn_depth <= 0:
            self._conn.commit()

    # -- value normalization -------------------------------------------------

    def _norm_value(self, node: GraphNode) -> str:
        """Normalized value: case-folded for IP/host-ish types, else as-is."""
        value = node.value.strip()
        if node.node_type in _CASE_FOLD_TYPES:
            return value.lower()
        return value

    # -- private row <-> model -----------------------------------------------

    def _node_from_row(self, row: sqlite3.Row) -> GraphNode:
        return GraphNode(
            node_id=row["node_id"],
            node_type=NodeType(row["node_type"]),
            value=row["value"],
            scope=row["scope"],
            properties=json.loads(row["properties"]),
            confidence=row["confidence"],
            status=NodeStatus(row["status"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            evidence_refs=tuple(row["evidence_refs"].split("|")) if row["evidence_refs"] else (),
            observation_count=row["observation_count"],
            contradiction_count=row["contradiction_count"],
            source=row["source"],
        )

    def _edge_from_row(self, row: sqlite3.Row) -> GraphEdge:
        return GraphEdge(
            edge_id=row["edge_id"],
            source_node_id=row["source_node_id"],
            target_node_id=row["target_node_id"],
            edge_type=EdgeType(row["edge_type"]),
            scope=row["scope"],
            properties=json.loads(row["properties"]),
            confidence=row["confidence"],
            source=row["source"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            evidence_refs=tuple(row["evidence_refs"].split("|")) if row["evidence_refs"] else (),
            observation_count=row["observation_count"],
            contradiction_count=row["contradiction_count"],
        )

    def _node_to_row(self, node: GraphNode) -> tuple[Any, ...]:
        return (
            node.node_id,
            node.node_type.value,
            self._norm_value(node),
            node.scope,
            json.dumps(node.properties, sort_keys=True),
            node.confidence,
            node.status.value,
            node.first_seen,
            node.last_seen,
            "|".join(node.evidence_refs),
            node.observation_count,
            node.contradiction_count,
            node.source,
        )

    def _edge_to_row(self, edge: GraphEdge) -> tuple[Any, ...]:
        return (
            edge.edge_id,
            edge.source_node_id,
            edge.target_node_id,
            edge.edge_type.value,
            edge.scope,
            json.dumps(edge.properties, sort_keys=True),
            edge.confidence,
            edge.source,
            edge.first_seen,
            edge.last_seen,
            "|".join(edge.evidence_refs),
            edge.observation_count,
            edge.contradiction_count,
        )

    # -- node upsert ---------------------------------------------------------

    _NODE_UPSERT_SQL = (
        "INSERT INTO agv2_nodes (node_id, node_type, value, scope, properties, confidence, status, "
        "first_seen, last_seen, evidence_refs, observation_count, contradiction_count, source) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(scope, node_type, value) DO UPDATE SET "
        "properties=_py_merge_props(agv2_nodes.properties, excluded.properties), "
        "confidence=max(agv2_nodes.confidence, excluded.confidence), "
        "status=excluded.status, "
        "first_seen=agv2_nodes.first_seen, "
        "last_seen=max(agv2_nodes.last_seen, excluded.last_seen), "
        "evidence_refs=_py_merge_refs(agv2_nodes.evidence_refs, excluded.evidence_refs), "
        "observation_count=agv2_nodes.observation_count + excluded.observation_count, "
        "contradiction_count=agv2_nodes.contradiction_count + "
        "(agv2_nodes.status='confirmed' AND excluded.status='refuted'), "
        "source=CASE WHEN excluded.source != '' THEN excluded.source ELSE agv2_nodes.source END "
        "RETURNING node_id"
    )

    def upsert_node(self, node: GraphNode) -> str:
        """Insert or merge ``node`` by UNIQUE(scope, type, value); returns node_id.

        Merge semantics: confidence takes the max, observation_count sums,
        evidence_refs union (order-preserving), last_seen takes the max.
        A proposal that REFUTEs a CONFIRMED node bumps contradiction_count
        (a heuristic: the contradiction needs a separate merge-conflict
        decision upstream; here we just count it).
        """
        with self._lock:
            return self._upsert_node_locked(node)

    def _upsert_node_locked(self, node: GraphNode) -> str:
        if self._nodes_upsert_ok:
            try:
                return self._upsert_node_native(node)
            except sqlite3.OperationalError:
                # UNIQUE key missing on older DBs: permanent SELECT fallback.
                self._nodes_upsert_ok = False
        return self._upsert_node_select(node)

    def _upsert_node_native(self, node: GraphNode) -> str:
        """One-statement UPSERT; merges computed in SQL (Python-identical fns)."""
        node = self._dedupe_node_id(node)
        row = self._conn.execute(self._NODE_UPSERT_SQL, self._node_to_row(node)).fetchone()
        self._commit_or_defer()
        return row["node_id"]

    def _upsert_node_select(self, node: GraphNode) -> str:
        """Legacy SELECT→INSERT/UPDATE path (older DBs without the UNIQUE key)."""
        norm_value = self._norm_value(node)
        row = self._conn.execute(
            "SELECT * FROM agv2_nodes WHERE scope=? AND node_type=? AND value=?",
            (node.scope, node.node_type.value, norm_value),
        ).fetchone()
        if row is None:
            node = self._dedupe_node_id(node)
            self._conn.execute(
                "INSERT INTO agv2_nodes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                self._node_to_row(node),
            )
            self._commit_or_defer()
            return node.node_id

        node_id = row["node_id"]
        merged_props = {**json.loads(row["properties"]), **node.properties}
        merged_refs = _merge_refs(
            node.evidence_refs, tuple(row["evidence_refs"].split("|")) if row["evidence_refs"] else ()
        )
        is_contradiction = int(row["status"] == NodeStatus.CONFIRMED.value and node.status == NodeStatus.REFUTED)
        self._conn.execute(
            "UPDATE agv2_nodes SET node_type=?, value=?, scope=?, properties=?, "
            "confidence=?, status=?, first_seen=?, last_seen=?, evidence_refs=?, "
            "observation_count=?, contradiction_count=?, source=? WHERE node_id=?",
            (
                node.node_type.value,
                norm_value,
                node.scope,
                json.dumps(merged_props, sort_keys=True),
                max(row["confidence"], node.confidence),
                node.status.value,
                row["first_seen"],
                max(row["last_seen"], node.last_seen),
                "|".join(merged_refs),
                row["observation_count"] + node.observation_count,
                row["contradiction_count"] + is_contradiction,
                node.source or row["source"],
                node_id,
            ),
        )
        self._commit_or_defer()
        return node_id

    def upsert_nodes(self, nodes: list[GraphNode]) -> list[str]:
        """Bulk node upsert: one transaction, O(1) commits (P2-02)."""
        with self._lock, self.transaction():
            return [self._upsert_node_locked(node) for node in nodes]

    def get_node(self, node_id: str) -> GraphNode | None:
        """Fetch a node by id, or None."""
        with self._lock:
            row = self._conn.execute("SELECT * FROM agv2_nodes WHERE node_id=?", (node_id,)).fetchone()
            return self._node_from_row(row) if row else None

    def get_node_by_value(self, node_type: NodeType, value: str, scope: str = "") -> GraphNode | None:
        """Fetch a node by (scope, type, value) using the same normalization."""
        norm = value.strip().lower() if node_type in _CASE_FOLD_TYPES else value.strip()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM agv2_nodes WHERE scope=? AND node_type=? AND value=?",
                (scope, node_type.value, norm),
            ).fetchone()
            return self._node_from_row(row) if row else None

    # -- edge API -------------------------------------------------------------

    _EDGE_UPSERT_SQL = (
        "INSERT INTO agv2_edges (edge_id, source_node_id, target_node_id, edge_type, scope, properties, "
        "confidence, source, first_seen, last_seen, evidence_refs, observation_count, contradiction_count) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(source_node_id, target_node_id, edge_type, scope) DO UPDATE SET "
        "properties=_py_merge_props(agv2_edges.properties, excluded.properties), "
        "confidence=max(agv2_edges.confidence, excluded.confidence), "
        "source=CASE WHEN excluded.source != '' THEN excluded.source ELSE agv2_edges.source END, "
        "first_seen=agv2_edges.first_seen, "
        "last_seen=max(agv2_edges.last_seen, excluded.last_seen), "
        "evidence_refs=_py_merge_refs(agv2_edges.evidence_refs, excluded.evidence_refs), "
        "observation_count=agv2_edges.observation_count + excluded.observation_count, "
        "contradiction_count=agv2_edges.contradiction_count + excluded.contradiction_count "
        "RETURNING edge_id"
    )

    def upsert_edge(self, edge: GraphEdge) -> str:
        """Insert or merge ``edge``; raises ValueError if an endpoint is missing.

        Dedup key: (source_node_id, target_node_id, edge_type, scope).
        Merge keeps max confidence, max last_seen, sums observation_count,
        unions evidence refs, and keeps the newer source.
        """
        with self._lock:
            return self._upsert_edge_locked(edge)

    def _upsert_edge_locked(self, edge: GraphEdge, known_ids: set[str] | None = None) -> str:
        if known_ids is None:
            for node_id in (edge.source_node_id, edge.target_node_id):
                exists = self._conn.execute("SELECT 1 FROM agv2_nodes WHERE node_id=?", (node_id,)).fetchone()
                if exists is None:
                    raise ValueError(f"edge references missing node: {node_id}")
        elif edge.source_node_id not in known_ids or edge.target_node_id not in known_ids:
            raise ValueError(
                f"edge references missing node: {edge.source_node_id} -> {edge.target_node_id}",
            )
        if self._edges_upsert_ok:
            try:
                return self._upsert_edge_native(edge)
            except sqlite3.OperationalError:
                self._edges_upsert_ok = False
        return self._upsert_edge_select(edge)

    def _upsert_edge_native(self, edge: GraphEdge) -> str:
        """One-statement edge UPSERT (requires the dedup UNIQUE index)."""
        row = self._conn.execute(self._EDGE_UPSERT_SQL, self._edge_to_row(edge)).fetchone()
        self._commit_or_defer()
        return row["edge_id"]

    def _upsert_edge_select(self, edge: GraphEdge) -> str:
        """Legacy SELECT→INSERT/UPDATE edge path (DBs without the dedup index)."""
        row = self._conn.execute(
            "SELECT * FROM agv2_edges WHERE source_node_id=? AND target_node_id=? AND edge_type=? AND scope=?",
            (edge.source_node_id, edge.target_node_id, edge.edge_type.value, edge.scope),
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO agv2_edges VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                self._edge_to_row(edge),
            )
            self._commit_or_defer()
            return edge.edge_id

        merged_props = {**json.loads(row["properties"]), **edge.properties}
        merged_refs = _merge_refs(
            edge.evidence_refs, tuple(row["evidence_refs"].split("|")) if row["evidence_refs"] else ()
        )
        self._conn.execute(
            "UPDATE agv2_edges SET properties=?, confidence=?, source=?, "
            "first_seen=?, last_seen=?, evidence_refs=?, observation_count=?, "
            "contradiction_count=? WHERE edge_id=?",
            (
                json.dumps(merged_props, sort_keys=True),
                max(row["confidence"], edge.confidence),
                edge.source or row["source"],
                row["first_seen"],
                max(row["last_seen"], edge.last_seen),
                "|".join(merged_refs),
                row["observation_count"] + edge.observation_count,
                row["contradiction_count"] + edge.contradiction_count,
                row["edge_id"],
            ),
        )
        self._commit_or_defer()
        return row["edge_id"]

    def upsert_edges(self, edges: list[GraphEdge]) -> list[str]:
        """Bulk edge upsert: one transaction, preloaded endpoint set (P2-02)."""
        with self._lock, self.transaction():
            known_ids = {row[0] for row in self._conn.execute("SELECT node_id FROM agv2_nodes").fetchall()}
            return [self._upsert_edge_locked(edge, known_ids) for edge in edges]

    def delete_node(self, node_id: str) -> None:
        """Delete ``node_id`` and every edge touching it (manual two-statement cascade)."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM agv2_edges WHERE source_node_id=? OR target_node_id=?",
                (node_id, node_id),
            )
            self._conn.execute("DELETE FROM agv2_nodes WHERE node_id=?", (node_id,))
            self._commit_or_defer()

    # -- queries ----------------------------------------------------------------

    def query_nodes(
        self,
        scope: str = "",
        node_type: NodeType | None = None,
        status: NodeStatus | None = None,
        value_substring: str | None = None,
        limit: int = 200,
    ) -> list[GraphNode]:
        """Nodes filtered by scope/type/status/value substring, bounded by ``limit``."""
        sql = "SELECT * FROM agv2_nodes WHERE scope=?"
        params: list[Any] = [scope]
        if node_type is not None:
            sql += " AND node_type=?"
            params.append(node_type.value)
        if status is not None:
            sql += " AND status=?"
            params.append(status.value)
        if value_substring is not None:
            sql += " AND value LIKE ?"
            params.append(f"%{value_substring}%")
        sql += " LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [self._node_from_row(r) for r in rows]

    def query_edges(
        self,
        scope: str = "",
        edge_type: EdgeType | None = None,
        source_id: str | None = None,
        target_id: str | None = None,
        limit: int = 200,
    ) -> list[GraphEdge]:
        """Edges filtered by scope/edge_type/source/target, bounded by ``limit``."""
        sql = "SELECT * FROM agv2_edges WHERE scope=?"
        params: list[Any] = [scope]
        if edge_type is not None:
            sql += " AND edge_type=?"
            params.append(edge_type.value)
        if source_id is not None:
            sql += " AND source_node_id=?"
            params.append(source_id)
        if target_id is not None:
            sql += " AND target_node_id=?"
            params.append(target_id)
        sql += " LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [self._edge_from_row(r) for r in rows]

    def neighbors(
        self,
        node_id: str,
        relation: EdgeType | None = None,
        max_hops: int = 1,
        max_nodes: int = 50,
        scope: str = "",
    ) -> list[tuple[GraphNode, GraphEdge, int]]:
        """Bounded BFS from ``node_id``; returns (node, edge, distance) tuples.

        Hop 1 runs as a single SQL join; deeper hops expand in Python but stay
        bounded by ``max_nodes`` collected nodes (and max_nodes results).
        """
        with self._lock:
            start = self._conn.execute("SELECT 1 FROM agv2_nodes WHERE node_id=?", (node_id,)).fetchone()
            if start is None:
                return []

            if max_hops <= 1:
                sql = (
                    "SELECT e.edge_id AS e_id, n.*, e.* FROM agv2_edges e "
                    "JOIN agv2_nodes n ON n.node_id = e.target_node_id "
                    "WHERE e.source_node_id=?"
                )
                params: list[Any] = [node_id]
                if relation is not None:
                    sql += " AND e.edge_type=?"
                    params.append(relation.value)
                if scope:
                    sql += " AND e.scope=? AND n.scope=?"
                    params.extend([scope, scope])
                sql += " LIMIT ?"
                params.append(max_nodes)
                rows = self._conn.execute(sql, params).fetchall()
                return [(self._node_from_row(r), self._edge_from_row(r), 1) for r in rows]

            out: list[tuple[GraphNode, GraphEdge, int]] = []
            frontier: list[str] = [node_id]
            seen: set[str] = {node_id}
            for dist in range(1, max_hops + 1):
                if not frontier or len(out) >= max_nodes:
                    break
                placeholders = ",".join("?" * len(frontier))
                sql = (
                    "SELECT e.edge_id AS eid, n.source AS nsource, n.node_id AS nid, "
                    "e.*, n.* FROM agv2_edges e JOIN agv2_nodes n "
                    f"ON n.node_id = e.target_node_id WHERE e.source_node_id IN ({placeholders})"
                )
                params = list(frontier)
                if relation is not None:
                    sql += " AND e.edge_type=?"
                    params.append(relation.value)
                if scope:
                    sql += " AND e.scope=? AND n.scope=?"
                    params.extend([scope, scope])
                nxt_frontier: list[str] = []
                for r in self._conn.execute(sql, params).fetchall():
                    nxt_id = r["nid"]
                    if nxt_id in seen:
                        continue
                    seen.add(nxt_id)
                    out.append((self._node_from_row(r), self._edge_from_row(r), dist))
                    nxt_frontier.append(nxt_id)
                    if len(out) >= max_nodes:
                        break
                frontier = nxt_frontier
            return out

    def paths(
        self,
        a_id: str,
        b_id: str,
        max_length: int = 4,
        max_paths: int = 10,
        scope: str = "",
    ) -> list[list[tuple[GraphNode, GraphEdge, int]]]:
        """Simple paths from ``a_id`` to ``b_id``, bounded by both limits.

        Iterative DFS in Python; scope filters the loaded graph.
        """
        with self._lock:
            for nid in (a_id, b_id):
                if self._conn.execute("SELECT 1 FROM agv2_nodes WHERE node_id=?", (nid,)).fetchone() is None:
                    return []
            node_sql = "SELECT * FROM agv2_nodes" + (" WHERE scope=?" if scope else "")
            node_params: list[Any] = [scope] if scope else []
            nodes = {r["node_id"]: self._node_from_row(r) for r in self._conn.execute(node_sql, node_params).fetchall()}
            edge_sql = "SELECT * FROM agv2_edges" + (" WHERE scope=?" if scope else "")
            edge_params: list[Any] = [scope] if scope else []
            edges = [self._edge_from_row(r) for r in self._conn.execute(edge_sql, edge_params).fetchall()]

            outgoing: dict[str, list[GraphEdge]] = {}
            for e in edges:
                outgoing.setdefault(e.source_node_id, []).append(e)

            results: list[list[tuple[GraphNode, GraphEdge, int]]] = []
            visited = {a_id}

            def walk(current: str, dist: int, acc: list[tuple[GraphNode, GraphEdge, int]]) -> None:
                if len(results) >= max_paths or dist >= max_length:
                    return
                for e in outgoing.get(current, []):
                    target = e.target_node_id
                    if target in visited or target not in nodes:
                        continue
                    visited.add(target)
                    acc.append((nodes[target], e, dist + 1))
                    if target == b_id:
                        results.append(list(acc))
                    else:
                        walk(target, dist + 1, acc)
                    acc.pop()
                    visited.discard(target)
                    if len(results) >= max_paths:
                        return

            walk(a_id, 0, [])
            return results

    # -- summary / export --------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """Counts of nodes by type, edges by type, and totals."""
        with self._lock:
            nodes = self._conn.execute("SELECT node_type, COUNT(*) AS c FROM agv2_nodes GROUP BY node_type").fetchall()
            edges = self._conn.execute("SELECT edge_type, COUNT(*) AS c FROM agv2_edges GROUP BY edge_type").fetchall()
            total_nodes = sum(r["c"] for r in nodes)
            total_edges = sum(r["c"] for r in edges)
            return {
                "nodes": {r["node_type"]: r["c"] for r in nodes},
                "edges": {r["edge_type"]: r["c"] for r in edges},
                "total_nodes": total_nodes,
                "total_edges": total_edges,
            }

    def to_graph_nodes(self) -> list[GraphNode]:
        """All nodes, for GraphTraversal."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM agv2_nodes").fetchall()
            return [self._node_from_row(r) for r in rows]

    def to_graph_edges(self) -> list[GraphEdge]:
        """All edges, for GraphTraversal."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM agv2_edges").fetchall()
            return [self._edge_from_row(r) for r in rows]

    # -- private helpers ------------------------------------------------------------

    def _dedupe_node_id(self, node: GraphNode) -> GraphNode:
        """Re-key ``node`` with an unused node_id (callers may collide on PK)."""
        if self._conn.execute("SELECT 1 FROM agv2_nodes WHERE node_id=?", (node.node_id,)).fetchone() is None:
            return node
        return replace(node, node_id=_new_id())

    def get_meta(self, key: str) -> str | None:
        """Read a metadata value (P2-04 offset persistence)."""
        with self._lock:
            try:
                row = self._conn.execute("SELECT value FROM agv2_meta WHERE key=?", (key,)).fetchone()
            except sqlite3.Error:
                return None
            return str(row["value"]) if row else None

    def set_meta(self, key: str, value: str) -> None:
        """Write a metadata value (P2-04 offset persistence)."""
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO agv2_meta(key, value) VALUES (?, ?)", (key, value))
            self._commit_or_defer()

    def close(self) -> None:
        """Close the underlying connection."""
        with self._lock:
            self._conn.close()
