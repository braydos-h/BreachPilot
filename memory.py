"""Persistent memory manager for the authorized security research agent.

Memory types:
- working: short current-state summary
- episodic: what happened and what was observed
- semantic: reusable research patterns/lessons
- target: hosts, endpoints, parameters, auth states, objects
- hypothesis: open hypotheses to investigate
- dead_end: things that didn't work
- finding_note: notes attached to specific findings

Backed by SQLite via the DatabaseManager.
"""

from __future__ import annotations

import json
from typing import Any

from db import DatabaseManager, _new_id, _now_iso


from tools.semantic_memory import SemanticMemoryManager


VALID_MEMORY_TYPES = frozenset({
    "working",
    "episodic",
    "semantic",
    "target",
    "hypothesis",
    "dead_end",
    "finding_note",
})

_MEMORY_TYPE_ALIASES = {
    "recon": "target",
    "service_recon": "target",
    "service_enumeration": "target",
    "vuln": "hypothesis",
    "vuln_research": "hypothesis",
    "vulnerability_research": "hypothesis",
    "exploit": "episodic",
    "exploitation": "episodic",
    "exploit_success": "episodic",
    "post_exploit": "episodic",
    "post_exploitation": "episodic",
    "reflection": "semantic",
    "learning": "semantic",
    "critic": "working",
    "exploit_failure": "dead_end",
    "failure": "dead_end",
}


class MemoryManager:
    """CRUD interface for persistent research memory."""

    def __init__(
        self,
        db: DatabaseManager,
        mission_id: str,
        semantic_memory: SemanticMemoryManager | None = None,
    ) -> None:
        self._db = db
        self._mission_id = mission_id
        self._semantic = semantic_memory

    # ── Core operations ────────────────────────────────────────────────

    def remember(
        self,
        target: str,
        fact: str,
        memory_type: str = "target",
        tags: list[str] | None = None,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        memory_id = _new_id("MEM")
        original_memory_type = str(memory_type or "target").strip()
        normalized_memory_type = _normalize_memory_type(original_memory_type)
        normalized_metadata = dict(metadata or {})
        normalized_tags = [tags] if isinstance(tags, str) else list(tags or [])
        if normalized_memory_type != original_memory_type:
            normalized_metadata.setdefault("original_memory_type", original_memory_type)
            if original_memory_type and original_memory_type not in normalized_tags:
                normalized_tags.append(original_memory_type)
        with self._db.connection(write=True) as conn:
            conn.execute(
                """INSERT INTO memories(id, mission_id, memory_type, target, fact, tags_json, confidence, metadata_json, created_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    memory_id,
                    self._mission_id,
                    normalized_memory_type,
                    target,
                    fact,
                    json.dumps(normalized_tags),
                    confidence,
                    json.dumps(normalized_metadata),
                    _now_iso(),
                ),
            )
        # Optionally store embedding for semantic retrieval
        if self._semantic is not None:
            self._semantic.store_embedding(
                source_table="memories",
                source_id=memory_id,
                text=fact,
                mission_id=self._mission_id,
            )
        return memory_id

    def retrieve(
        self,
        target: str = "",
        memory_type: str | None = None,
        tags: list[str] | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM memories WHERE mission_id=?"
        params: list[Any] = [self._mission_id]

        if target:
            query += " AND target=?"
            params.append(target)
        if memory_type:
            query += " AND memory_type=?"
            params.append(memory_type)
        if tags:
            for tag in tags:
                # Escape LIKE wildcards so tags containing % or _ match literally
                escaped = tag.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                query += " AND tags_json LIKE ? ESCAPE '\\'"
                params.append(f'%"{escaped}"%')

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._db.connection() as conn:
            cur = conn.execute(query, params)
            rows = cur.fetchall()
        return [_row_to_memory(dict(r)) for r in rows]

    def retrieve_relevant(
        self,
        target: str,
        current_task_id: str = "",
        limit: int = 10,
        context: str = "",
    ) -> list[dict[str, Any]]:
        """Get memories relevant to the current context — same target + recent entries.
        Falls back to semantic search if exact match yields few results.

        ``context`` (Tier 1.1): a free-text description of what the agent is doing
        right now (service, phase, objective, …). When present, the semantic fallback
        embeds the *context*, not the bare ``target`` IP — a bare IP embeds to a
        near-meaningless vector, which defeated cross-mission recall entirely.
        """
        exact = self.retrieve(target=target, limit=limit)
        if len(exact) >= limit // 2 or self._semantic is None:
            return exact

        # Semantic fallback: find similar memories across missions. Embed the
        # context (not the bare IP) so the vector actually reflects the work.
        similar = self._semantic.find_similar(
            text=(context or target),
            source_table="memories",
            top_k=limit - len(exact),
        )
        similar_ids = [s["source_id"] for s in similar]
        if not similar_ids:
            return exact

        # Fetch the actual memory rows for similar IDs
        placeholders = ",".join("?" for _ in similar_ids)
        with self._db.connection() as conn:
            cur = conn.execute(
                f"SELECT * FROM memories WHERE id IN ({placeholders})",
                similar_ids,
            )
            semantic_rows = [_row_to_memory(dict(r)) for r in cur.fetchall()]

        # Merge and deduplicate
        seen = {m["id"] for m in exact}
        merged = list(exact)
        for row in semantic_rows:
            if row["id"] not in seen:
                merged.append(row)
                seen.add(row["id"])
        return merged[:limit]

    def mark_dead_end(self, target: str, reason: str, metadata: dict[str, Any] | None = None) -> str:
        return self.remember(
            target=target,
            fact=reason,
            memory_type="dead_end",
            tags=["dead_end"],
            confidence=1.0,
            metadata=metadata,
        )

    # ── Summarization helpers ──────────────────────────────────────────

    def summarize_target(self, target: str) -> str:
        """Return a compact summary of everything known about a target."""
        memories = self.retrieve(target=target, limit=50)

        if not memories:
            return f"No stored memory for target '{target}'."

        ep_count = sum(1 for m in memories if m.get("memory_type") == "episodic")
        srv_count = sum(1 for m in memories if m.get("memory_type") == "target")
        hyp_count = sum(1 for m in memories if m.get("memory_type") == "hypothesis")
        dead_count = sum(1 for m in memories if m.get("memory_type") == "dead_end")

        lines = [
            f"=== Target Summary: {target} ===",
            f"Total memories: {len(memories)}",
            f"Episodic (actions): {ep_count}",
            f"Target facts: {srv_count}",
            f"Open hypotheses: {hyp_count}",
            f"Dead ends: {dead_count}",
            "",
            "Recent memories:",
        ]
        for m in memories[:10]:
            lines.append(f"  [{m.get('memory_type','?')}] {m.get('fact','')[:120]}")

        return "\n".join(lines)

    def get_open_hypotheses(self, target: str) -> list[str]:
        results = self.retrieve(target=target, memory_type="hypothesis")
        return [r.get("fact", "") for r in results]


# ── Helpers ─────────────────────────────────────────────────────────────────


def _row_to_memory(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": data.get("id", ""),
        "mission_id": data.get("mission_id", ""),
        "memory_type": data.get("memory_type", ""),
        "target": data.get("target", ""),
        "fact": data.get("fact", ""),
        "tags": _json_load(data.get("tags_json", "[]")),
        "confidence": float(data.get("confidence", 0.0)),
        "metadata": _json_load(data.get("metadata_json", "{}")),
        "created_at": data.get("created_at", ""),
    }


def _normalize_memory_type(memory_type: str) -> str:
    value = (memory_type or "target").strip().lower()
    if value in VALID_MEMORY_TYPES:
        return value
    return _MEMORY_TYPE_ALIASES.get(value, "working")


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
