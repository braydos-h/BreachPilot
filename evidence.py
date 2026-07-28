"""Evidence store for authorized security research.

Every meaningful observation saves:
- raw output (compressed/truncated if needed)
- summarized output
- timestamp
- tool used
- task id
- target
- request/response metadata where applicable
- SHA256 hash for integrity verification

Evidence is stored on the filesystem with metadata in SQLite.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from db import DatabaseManager, _new_id, _now_iso


_EVIDENCE_SUBDIRS = {
    "raw_output": "raw_output",
    "http_response": "http_responses",
    "http_request": "http_responses",
    "screenshot": "screenshots",
    "note": "notes",
    "diff": "notes",
    "file": "artifacts",
    "structured_json": "artifacts",
}


class EvidenceStore:
    """Persistent evidence management backed by filesystem + SQLite."""

    def __init__(
        self,
        db: DatabaseManager,
        mission_id: str,
        workspace: Path,
    ) -> None:
        self._db = db
        self._mission_id = mission_id
        self._workspace = workspace
        self._workspace.mkdir(parents=True, exist_ok=True)

    # ── Primary API ────────────────────────────────────────────────────

    def save(
        self,
        evidence_type: str,
        content: str | bytes,
        metadata: dict[str, Any] | None = None,
        task_id: str = "",
        finding_id: str = "",
        target: str = "",
    ) -> str:
        """Persist evidence and return its evidence_id.

        Args:
            evidence_type: One of raw_output, http_response, screenshot, note, diff, file, http_request, structured_json
            content: Raw content (str or bytes). Large content is truncated to 1MB.
            metadata: Optional structured metadata (headers, request info, etc.)
            task_id: Associated task (optional)
            finding_id: Associated finding (optional)
            target: Target asset string

        Returns:
            evidence_id (e.g. E-00001-ABCD1234)
        """
        subdir = _EVIDENCE_SUBDIRS.get(evidence_type, "raw_output")
        evidence_id = _new_id("E")

        # Hash
        content_bytes = content.encode("utf-8") if isinstance(content, str) else content
        content_hash = hashlib.sha256(content_bytes).hexdigest()

        # Truncate large content
        max_bytes = 1_000_000  # 1MB cap
        if len(content_bytes) > max_bytes:
            content_bytes = content_bytes[:max_bytes]
            content_truncated = True
        else:
            content_truncated = False

        # Write file
        evidence_dir = self._workspace / "evidence" / subdir
        evidence_dir.mkdir(parents=True, exist_ok=True)
        ext = _extension_for_type(evidence_type)
        filename = f"{evidence_id}{ext}"
        filepath = evidence_dir / filename
        filepath.write_bytes(content_bytes)

        # Summary snippet
        snippet = _snippet(content_bytes, evidence_type, 300)

        meta = metadata or {}
        meta["content_truncated"] = content_truncated
        meta["original_size"] = len(content) if isinstance(content, str) else len(content)

        with self._db.connection(write=True) as conn:
            conn.execute(
                """INSERT INTO evidence(
                    id, mission_id, task_id, finding_id, type, path, summary, hash, metadata_json, created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    evidence_id,
                    self._mission_id,
                    task_id or None,
                    finding_id or None,
                    evidence_type,
                    str(filepath.relative_to(self._workspace)),
                    snippet,
                    content_hash,
                    json.dumps(meta),
                    _now_iso(),
                ),
            )
        return evidence_id

    def get(self, evidence_id: str) -> dict[str, Any] | None:
        """Retrieve evidence metadata + content."""
        with self._db.connection() as conn:
            cur = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,))
            row = cur.fetchone()
            if not row:
                return None
            data = dict(row)
        result = _row_to_evidence(data)
        # Attach content if file exists
        filepath = self._workspace / data.get("path", "")
        if filepath.exists():
            raw = filepath.read_bytes()
            # Binary types (screenshot, file) get base64-encoded; text types get decoded
            if data.get("type") in ("screenshot", "file"):
                result["content"] = base64.b64encode(raw).decode("ascii")
                result["_binary"] = True
            else:
                result["content"] = raw.decode("utf-8", errors="replace")
        return result

    def compare(self, evidence_id_a: str, evidence_id_b: str) -> dict[str, Any]:
        """Compare two evidence items. Returns diff metadata (basic)."""
        a = self.get(evidence_id_a)
        b = self.get(evidence_id_b)
        if not a or not b:
            return {"comparable": False, "reason": "one or both evidence items not found."}
        same_hash = a.get("hash") == b.get("hash")
        return {
            "comparable": True,
            "same_hash": same_hash,
            "a_summary": a.get("summary", "")[:200],
            "b_summary": b.get("summary", "")[:200],
            "a_type": a.get("type", ""),
            "b_type": b.get("type", ""),
        }

    def list_for_task(self, task_id: str) -> list[dict[str, Any]]:
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT * FROM evidence WHERE task_id=? ORDER BY created_at",
                (task_id,),
            )
            rows = cur.fetchall()
        return [_row_to_evidence(dict(r)) for r in rows]

    def list_for_finding(self, finding_id: str) -> list[dict[str, Any]]:
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT * FROM evidence WHERE finding_id=? ORDER BY created_at",
                (finding_id,),
            )
            rows = cur.fetchall()
        return [_row_to_evidence(dict(r)) for r in rows]

    def list_for_mission(self, limit: int = 50, evidence_type: str = "") -> list[dict[str, Any]]:
        with self._db.connection() as conn:
            if evidence_type:
                cur = conn.execute(
                    "SELECT * FROM evidence WHERE mission_id=? AND type=? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (self._mission_id, evidence_type, limit),
                )
            else:
                cur = conn.execute(
                    "SELECT * FROM evidence WHERE mission_id=? ORDER BY created_at DESC LIMIT ?",
                    (self._mission_id, limit),
                )
            rows = cur.fetchall()
        return [_row_to_evidence(dict(r)) for r in rows]


# ── Helpers ─────────────────────────────────────────────────────────────────


def _extension_for_type(evidence_type: str) -> str:
    mapping = {
        "raw_output": ".txt",
        "http_response": ".txt",
        "http_request": ".txt",
        "screenshot": ".png",
        "note": ".md",
        "diff": ".diff",
        "file": ".bin",
        "structured_json": ".json",
    }
    return mapping.get(evidence_type, ".txt")


def _snippet(content: bytes, evidence_type: str, max_len: int) -> str:
    text = content.decode("utf-8", errors="replace")
    clean = " ".join(text.split())[:max_len]
    return clean


def _row_to_evidence(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_id": data.get("id", ""),
        "mission_id": data.get("mission_id", ""),
        "task_id": data.get("task_id", ""),
        "finding_id": data.get("finding_id", ""),
        "type": data.get("type", ""),
        "path": data.get("path", ""),
        "summary": data.get("summary", ""),
        "hash": data.get("hash", ""),
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


# ── Flow A <-> Flow B evidence bridge ───────────────────────────────────────
#
# Phase 1.3 of the self-verification core. Flow A (the exploit engine) writes
# its artifact stream to ``exploit_workspace/<ip>/exploit_audit.jsonl`` -- a
# tamper-evident append-only log of ExploitRecord + MCP-tool rows (see
# tools/mcp_shared._audit_log and tools/exploit_agent/policy.ExploitRecord).
# Flow B (the legacy research loop) persists evidence through EvidenceStore.
#
# The bridge lets Flow A's audit entries be promoted into the shared
# EvidenceStore so downstream verification / reporting / findings flows that
# already read from EvidenceStore can see them. It is purely additive: the
# existing Flow B write path (tool_router -> EvidenceStore.save) is untouched,
# and the bridge functions only read the audit JSONL -- they never mutate it.


def _audit_row_kind(row: dict[str, Any]) -> str:
    """Classify an audit JSONL row as ``"mcp"``, ``"flow_a"``, or ``"unknown"``.

    Distinguishing keys (per the grounding contract):
    * MCP-tool rows carry ``tool_name`` + ``args``.
    * Flow A ExploitRecord rows carry ``action`` + ``full_args`` + ``hash``.
    """
    if "tool_name" in row and "args" in row:
        return "mcp"
    if "action" in row and "full_args" in row:
        return "flow_a"
    return "unknown"


def _audit_hash_of(row: dict[str, Any]) -> str:
    """Pick the strongest available integrity tag from an audit row."""
    for key in ("hash", "code_sha256", "prev_hash"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def promote_exploit_audit(
    evidence_store: "EvidenceStore",
    audit_path: "Path",
    mission_id: str,
    target_ip: str,
) -> list[str]:
    """Promote ``exploit_audit.jsonl`` entries into the shared EvidenceStore.

    Reads the JSONL audit log at ``audit_path`` and writes one
    ``structured_json`` evidence row per entry, tagged with the audit hash so
    downstream consumers can join back to the original record. Rows that fail
    to parse or are missing a usable payload are skipped (never raise).

    Args:
        evidence_store: The ``EvidenceStore`` to write into (its bound
            ``mission_id`` is used for the DB row; ``mission_id`` here is
            stamped into metadata for traceability).
        audit_path: Path to ``exploit_audit.jsonl``.
        mission_id: Mission id to record in evidence metadata.
        target_ip: The target IP the audit entries belong to.

    Returns:
        The list of evidence ids created (one per successfully promoted row).
    """
    if evidence_store is None:
        return []
    audit_path = Path(audit_path) if not isinstance(audit_path, Path) else audit_path
    if not audit_path.exists():
        return []

    created: list[str] = []
    with audit_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(row, dict):
                continue
            kind = _audit_row_kind(row)
            if kind == "unknown":
                continue
            try:
                eid = _promote_one_row(evidence_store, row, kind, mission_id, target_ip)
            except Exception:
                # Never let a single bad row abort promotion of the rest.
                continue
            if eid:
                created.append(eid)
    return created


def _promote_one_row(
    evidence_store: "EvidenceStore",
    row: dict[str, Any],
    kind: str,
    mission_id: str,
    target_ip: str,
) -> str:
    """Write a single audit row into the evidence store as structured_json."""
    audit_hash = _audit_hash_of(row)
    # Use the row verbatim as the evidence payload so nothing is lost, then
    # stamp the join keys into metadata.
    content = json.dumps(row, default=str, indent=2)
    metadata: dict[str, Any] = {
        "source": "exploit_audit",
        "audit_kind": kind,
        "audit_hash": audit_hash,
        "mission_id": mission_id,
        "target_ip": target_ip,
        "row_timestamp": row.get("timestamp", ""),
        "row_status": row.get("status", ""),
        "row_attempt_id": row.get("attempt_id", ""),
        # Carry the Flow A action / MCP tool_name as the action label so
        # report generators can group evidence by tool without re-parsing.
        "action": row.get("action") or row.get("tool_name") or "",
    }
    # NOTE: ``task_id`` is intentionally left empty -- the evidence table's
    # task_id FK targets the ``tasks`` table, but audit ``attempt_id`` values
    # are Flow A attempt ids, not Flow B task ids. The attempt id is preserved
    # in ``metadata["row_attempt_id"]`` for traceability instead.
    return evidence_store.save(
        evidence_type="structured_json",
        content=content,
        metadata=metadata,
        task_id="",
        target=target_ip,
    )


def record_run_output(
    evidence_store: "EvidenceStore",
    mission_id: str,
    target_ip: str,
    action: str,
    output_text: str,
    *,
    audit_hash: str = "",
) -> str:
    """Convenience wrapper: persist a single run output as raw evidence.

    Useful for callers that have a tool result in hand (e.g. the PoE verifier)
    and want a single evidence row without reading the full audit JSONL. The
    optional ``audit_hash`` ties the row back to its originating audit entry.

    Args:
        evidence_store: The ``EvidenceStore`` to write into.
        mission_id: Mission id to record in evidence metadata.
        target_ip: Target asset the output was collected from.
        action: Tool / action label that produced the output.
        output_text: The raw output text to persist.
        audit_hash: Optional integrity tag from the originating audit row.

    Returns:
        The evidence id, or ``""`` if the store is missing or the output empty.
    """
    if evidence_store is None or not output_text:
        return ""
    metadata: dict[str, Any] = {
        "source": "run_output",
        "mission_id": mission_id,
        "target_ip": target_ip,
        "action": action,
        "audit_hash": audit_hash,
    }
    return evidence_store.save(
        evidence_type="raw_output",
        content=output_text,
        metadata=metadata,
        target=target_ip,
    )
