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
