"""Target Graph — models the attack surface as a structured graph.

Node types:
  program, asset, host, domain, ip, service, web_app, api, endpoint,
  parameter, identity, role, session, object, permission_boundary,
  technology, evidence, finding

Edge types:
  owns, exposes, resolves_to, serves, requires_auth, accepts_parameter,
  returns_object, belongs_to_user, accessible_by, tested_by,
  produced_evidence, indicates, blocked_by_scope, related_to

Backed by SQLite graph_nodes / graph_edges tables via DatabaseManager.
"""

from __future__ import annotations

import json
from typing import Any

from db import DatabaseManager, _new_id, _now_iso

# ── Valid node and edge types ──────────────────────────────────────────────

NODE_TYPES = frozenset({
    "program", "asset", "host", "domain", "ip", "service", "web_app",
    "api", "endpoint", "parameter", "identity", "role", "session",
    "object", "permission_boundary", "technology", "evidence", "finding",
})

EDGE_TYPES = frozenset({
    "owns", "exposes", "resolves_to", "serves", "requires_auth",
    "accepts_parameter", "returns_object", "belongs_to_user",
    "accessible_by", "tested_by", "produced_evidence", "indicates",
    "blocked_by_scope", "related_to",
})


class TargetGraph:
    """Persistent graph store for modeling the attack surface."""

    def __init__(self, db: DatabaseManager, mission_id: str) -> None:
        self._db = db
        self._mission_id = mission_id

    # ── Node CRUD ─────────────────────────────────────────────────────

    def add_node(
        self,
        node_type: str,
        value: str,
        metadata: dict[str, Any] | None = None,
        node_id: str = "",
    ) -> str:
        if node_type not in NODE_TYPES:
            raise ValueError(
                f"Invalid node type '{node_type}'. Valid types: {sorted(NODE_TYPES)}."
            )
        nid = node_id or _new_id("GN")
        with self._db.connection(write=True) as conn:
            conn.execute(
                """INSERT INTO graph_nodes(id, mission_id, type, value, metadata_json, created_at)
                VALUES(?,?,?,?,?,?)""",
                (nid, self._mission_id, node_type, value, json.dumps(metadata or {}), _now_iso()),
            )
        return nid

    def add_edge(
        self,
        from_node: str,
        to_node: str,
        relation: str,
        metadata: dict[str, Any] | None = None,
        edge_id: str = "",
    ) -> str:
        if relation not in EDGE_TYPES:
            raise ValueError(
                f"Invalid edge relation '{relation}'. Valid relations: {sorted(EDGE_TYPES)}."
            )
        eid = edge_id or _new_id("GE")
        with self._db.connection(write=True) as conn:
            for node_id in (from_node, to_node):
                if conn.execute(
                    "SELECT 1 FROM graph_nodes WHERE id=? AND mission_id=?", (node_id, self._mission_id)
                ).fetchone() is None:
                    raise ValueError(
                        "add_edge endpoints must be existing node ids; "
                        "use add_edge_by_value for value-based wiring"
                    )
            conn.execute(
                """INSERT INTO graph_edges(id, mission_id, from_node_id, to_node_id, relation, metadata_json, created_at)
                VALUES(?,?,?,?,?,?,?)""",
                (eid, self._mission_id, from_node, to_node, relation, json.dumps(metadata or {}), _now_iso()),
            )
        return eid

    # ── Queries ────────────────────────────────────────────────────────

    def query_graph(
        self,
        node_type: str | None = None,
        value_pattern: str | None = None,
        relation: str | None = None,
        limit: int = 100,
    ) -> dict[str, list[dict[str, Any]]]:
        """Query nodes with optional filters. Returns {nodes: [...], edges: [...]}."""
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []

        nquery = "SELECT * FROM graph_nodes WHERE mission_id=?"
        nparams: list[Any] = [self._mission_id]
        if node_type:
            nquery += " AND type=?"
            nparams.append(node_type)
        if value_pattern:
            nquery += " AND value LIKE ?"
            nparams.append(f"%{value_pattern}%")
        nquery += " LIMIT ?"
        nparams.append(limit)

        equery = "SELECT * FROM graph_edges WHERE mission_id=?"
        eparams: list[Any] = [self._mission_id]
        if relation:
            equery += " AND relation=?"
            eparams.append(relation)
        equery += " LIMIT ?"
        eparams.append(limit)

        with self._db.connection() as conn:
            for row in conn.execute(nquery, nparams).fetchall():
                nodes.append(_row_to_node(dict(row)))
            for row in conn.execute(equery, eparams).fetchall():
                edges.append(_row_to_edge(dict(row)))

        return {"nodes": nodes, "edges": edges}

    def find_untested_assets(self) -> list[str]:
        """Return assets that exist in the graph but have no 'tested_by' edge."""
        with self._db.connection() as conn:
            cur = conn.execute(
                """SELECT gn.id, gn.value FROM graph_nodes gn
                WHERE gn.mission_id=? AND gn.type IN ('host','ip','domain','web_app','api')
                AND gn.id NOT IN (
                    SELECT from_node_id FROM graph_edges WHERE relation='tested_by' AND mission_id=?
                )
                ORDER BY gn.created_at""",
                (self._mission_id, self._mission_id),
            )
            return [f"{row['value']} ({row['id'][:12]})" for row in cur.fetchall()]

    def find_permission_boundaries(self) -> list[dict[str, str]]:
        """Return nodes of type permission_boundary."""
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT id, value FROM graph_nodes WHERE mission_id=? AND type='permission_boundary'",
                (self._mission_id,),
            )
            return [{"node_id": row["id"], "boundary": row["value"]} for row in cur.fetchall()]

    def find_object_id_candidates(self) -> list[dict[str, str]]:
        """Return endpoints/parameters that might carry object IDs."""
        with self._db.connection() as conn:
            cur = conn.execute(
                """SELECT id, value FROM graph_nodes WHERE mission_id=?
                AND type IN ('endpoint','parameter')
                AND (value LIKE '%id%' OR value LIKE '%uuid%' OR value LIKE '%object%'
                     OR value LIKE '%user%' OR value LIKE '%order%' OR value LIKE '%account%')""",
                (self._mission_id,),
            )
            return [{"node_id": row["id"], "value": row["value"]} for row in cur.fetchall()]

    def summarize_graph(self) -> str:
        """Produce a text summary of the graph for LLM context."""
        with self._db.connection() as conn:
            node_cur = conn.execute(
                "SELECT type, COUNT(*) as cnt FROM graph_nodes WHERE mission_id=? GROUP BY type ORDER BY cnt DESC",
                (self._mission_id,),
            )
            node_summary = [f"  {row['type']}: {row['cnt']}" for row in node_cur.fetchall()]

            edge_cur = conn.execute(
                "SELECT relation, COUNT(*) as cnt FROM graph_edges WHERE mission_id=? GROUP BY relation ORDER BY cnt DESC",
                (self._mission_id,),
            )
            edge_summary = [f"  {row['relation']}: {row['cnt']}" for row in edge_cur.fetchall()]

        lines = [
            "=== Target Graph Summary ===",
            f"Mission: {self._mission_id}",
            "",
            "Nodes by type:",
        ]
        lines.extend(node_summary or ["  (empty)"])
        lines.append("")
        lines.append("Edges by relation:")
        lines.extend(edge_summary or ["  (empty)"])

        return "\n".join(lines)


# ── Helpers ─────────────────────────────────────────────────────────────────


def _row_to_node(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": data.get("id", ""),
        "mission_id": data.get("mission_id", ""),
        "type": data.get("type", ""),
        "value": data.get("value", ""),
        "metadata": _json_load(data.get("metadata_json", "{}")),
        "created_at": data.get("created_at", ""),
    }


def _row_to_edge(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": data.get("id", ""),
        "mission_id": data.get("mission_id", ""),
        "from_node_id": data.get("from_node_id", ""),
        "to_node_id": data.get("to_node_id", ""),
        "relation": data.get("relation", ""),
        "metadata": _json_load(data.get("metadata_json", "{}")),
        "created_at": data.get("created_at", ""),
    }


def _json_load(raw: Any, default: Any = None) -> Any:
    if isinstance(raw, (list, dict)):
        return raw
    if isinstance(raw, str) and raw:
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            pass
    if default is None:
        return {}
    return default
