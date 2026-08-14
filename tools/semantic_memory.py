"""Semantic Memory Manager — embedding-based retrieval for the research agent.

Uses Ollama's /api/embeddings endpoint to generate embeddings and stores them
in SQLite. Similarity search is done in Python with numpy cosine similarity.
"""

from __future__ import annotations

import json
import logging
import math
import os
from typing import Any

import numpy as np

from db import DatabaseManager, _new_id, _now_iso

_logger = logging.getLogger(__name__)


class SemanticMemoryManager:
    """Generates, stores, and retrieves embeddings via Ollama + SQLite."""

    def __init__(
        self,
        db: DatabaseManager,
        ollama_host: str = "https://api.ollama.com",
        embedding_model: str = "nomic-embed-text",
    ) -> None:
        self._db = db
        self._ollama_host = ollama_host.rstrip("/")
        self._embedding_model = embedding_model

    # ── Embedding generation ──────────────────────────────────────────

    def embed(self, text: str) -> list[float] | None:
        """Public single-text embedding accessor.

        Returns the embedding vector for ``text``, or ``None`` on any failure
        (Ollama unreachable, network error, non-finite response). Same contract
        as the internal generator; exposed so the runtime-skill semantic ranker
        (``tools/skill_embeddings.py``) and other consumers can embed without
        reaching into a private method.
        """
        return self._generate_embedding(text)

    def _generate_embedding(self, text: str) -> list[float] | None:
        """Call Ollama /api/embeddings to get a vector for the given text.

        Returns ``None`` on any failure (Ollama unreachable, network error, or a
        response with no ``embedding`` list). Failures are logged at WARNING so
        a down Ollama does not silently degrade cross-mission learning to a
        no-op — this matches the boot ``[WARN]`` visibility convention. Every
        caller (``store_embedding``/``store_lesson``/``find_similar``/
        ``find_similar_lessons``) already handles ``None`` gracefully.
        """
        try:
            import urllib.error
            import urllib.request

            payload = json.dumps({
                "model": self._embedding_model,
                "prompt": text,
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{self._ollama_host}/api/embeddings",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # ponytail: cloud embed host needs the bearer token; local daemon
            # ignores it. Send unconditionally — one code path for both.
            _api_key = (os.environ.get("OLLAMA_API_KEY", "") or "").strip()
            if _api_key:
                req.add_header("Authorization", f"Bearer {_api_key}")

            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                embedding = data.get("embedding")
                if isinstance(embedding, list):
                    vec = [float(v) for v in embedding]
                    # NaN/inf guard: a malformed Ollama response could hand back
                    # non-finite floats that would poison cosine similarity
                    # (dot/norm become NaN, silently corrupting recall). Treat
                    # this like any other generation failure and return None —
                    # callers already handle that contract.
                    if any(not math.isfinite(v) for v in vec):
                        _logger.warning(
                            "semantic embedding failed: Ollama %s returned non-finite values",
                            self._ollama_host,
                        )
                        return None
                    return vec
                _logger.warning(
                    "semantic embedding failed: Ollama %s returned no 'embedding' list",
                    self._ollama_host,
                )
        except Exception as exc:
            _logger.warning(
                "semantic embedding failed for host %s: %s",
                self._ollama_host,
                exc,
            )
        return None

    # ── Storage ─────────────────────────────────────────────────────────

    def store_embedding(
        self,
        source_table: str,
        source_id: str,
        text: str,
        mission_id: str = "",
    ) -> str | None:
        """Generate and store an embedding for the given text."""
        embedding = self._generate_embedding(text)
        if embedding is None:
            return None

        eid = _new_id("EMB")
        with self._db.connection(write=True) as conn:
            conn.execute(
                """INSERT INTO embeddings(id, mission_id, source_table, source_id, embedding_json, created_at)
                   VALUES(?,?,?,?,?,?)""",
                (eid, mission_id, source_table, source_id, json.dumps(embedding), _now_iso()),
            )
        return eid

    def store_lesson(
        self,
        target_signature: str,
        action_type: str,
        outcome: str,
        text: str,
        metadata: dict[str, Any] | None = None,
        confidence: float = 0.5,
    ) -> str | None:
        """Store a learned lesson with its embedding for cross-mission retrieval.

        The audit flagged that the lesson ``text`` (the ``why it failed`` /
        ``why it worked`` explanation) was embedded for similarity search but
        never persisted -- retrieval returned labels + metadata but NOT the
        text, so the model never saw the lesson. The ``text`` column is now
        populated (migration v5 adds it to existing DBs).
        """
        embedding = self._generate_embedding(text)
        if embedding is None:
            return None

        lid = _new_id("LSN")
        pattern_hash = f"{target_signature}:{action_type}:{outcome}"
        with self._db.connection(write=True) as conn:
            conn.execute(
                """INSERT INTO lessons(id, pattern_hash, target_signature, action_type, outcome, confidence, embedding_json, metadata_json, text, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    lid,
                    pattern_hash,
                    target_signature,
                    action_type,
                    outcome,
                    confidence,
                    json.dumps(embedding),
                    json.dumps(metadata or {}),
                    str(text or "")[:8000],
                    _now_iso(),
                ),
            )
        return lid

    # ── Retrieval ───────────────────────────────────────────────────────

    def find_similar(
        self,
        text: str,
        source_table: str | None = None,
        top_k: int = 5,
        mission_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Find the top-k most similar stored embeddings to the query text."""
        query_emb = self._generate_embedding(text)
        if query_emb is None:
            return []

        query_vec = np.array(query_emb, dtype=np.float32)

        # Tier 1.1: skip zero-length embeddings. ``record_outcome`` (ExperienceStore)
        # writes lessons rows with embedding_json='[]' to track Bayesian outcomes;
        #those rows have no vector and would tie at cosine 0.0, polluting recall.
        # The same guard on the embeddings table is defensive (store_embedding only
        # ever writes a real vector or skips, but never trust that across flows).
        # ponytail: LIMIT avoids loading the entire embeddings table into memory
        # just to score and sort. top_k*10 gives enough candidates for a good top-k
        # after cosine similarity ranking; if the table is smaller, LIMIT is a no-op.
        sql = (
            "SELECT id, mission_id, source_table, source_id, embedding_json "
            "FROM embeddings WHERE embedding_json != '[]'"
        )
        params: list[Any] = []
        if source_table:
            sql += " AND source_table = ?"
            params.append(source_table)
        if mission_id:
            sql += " AND mission_id = ?"
            params.append(mission_id)
        sql += " LIMIT ?"
        params.append(max(top_k * 10, 100))

        candidates: list[dict[str, Any]] = []
        with self._db.connection() as conn:
            cur = conn.execute(sql, params)
            for row in cur.fetchall():
                row_id = row["id"]
                # Guard the per-row parse + vector build + similarity computation.
                # A corrupt embedding_json (truncated, non-JSON, wrong dtype) or a
                # dimension mismatch against the query must not crash the whole
                # recall — skip the offending row and warn, mirroring the failure
                # contract callers already expect (None/[]) for bad embeddings.
                try:
                    emb = json.loads(row["embedding_json"])
                    vec = np.array(emb, dtype=np.float32)
                    sim = self._cosine_similarity(query_vec, vec)
                except (TypeError, json.JSONDecodeError, ValueError) as exc:
                    _logger.warning(
                        "find_similar: skipping embeddings row %s: %s",
                        row_id,
                        exc,
                    )
                    continue
                candidates.append({
                    "id": row_id,
                    "mission_id": row["mission_id"],
                    "source_table": row["source_table"],
                    "source_id": row["source_id"],
                    "similarity": float(sim),
                })

        candidates.sort(key=lambda x: x["similarity"], reverse=True)
        return candidates[:top_k]

    def find_similar_lessons(
        self,
        text: str,
        action_type: str | None = None,
        outcome: str | None = None,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Find top-k lessons similar to the query text, optionally filtered."""
        query_emb = self._generate_embedding(text)
        if query_emb is None:
            return []

        query_vec = np.array(query_emb, dtype=np.float32)

        # Tier 1.1: skip zero-length embeddings. ``record_outcome`` writes
        # embedding_json='[]' (it has no text to embed); without this filter those
        # rows would load as np.array([]), score cosine 0.0, and tie at the bottom
        # of every recall — defeating the whole point of wiring find_similar_lessons.
        sql = (
            "SELECT id, pattern_hash, target_signature, action_type, outcome, "
            "confidence, embedding_json, metadata_json, text "
            "FROM lessons WHERE embedding_json != '[]'"
        )
        params: list[Any] = []
        if action_type:
            sql += " AND action_type = ?"
            params.append(action_type)
        if outcome:
            sql += " AND outcome = ?"
            params.append(outcome)
        sql += " LIMIT ?"
        params.append(max(top_k * 10, 100))

        candidates: list[dict[str, Any]] = []
        with self._db.connection() as conn:
            cur = conn.execute(sql, params)
            for row in cur.fetchall():
                row_id = row["id"]
                # Guard the per-row parse + vector build + similarity computation
                # (same rationale as find_similar): corrupt embedding_json or a
                # dimension mismatch must skip the row, not crash recall. The
                # metadata_json parse is guarded too; on its failure we skip the
                # row (consistent with the embedding case) rather than emit a
                # half-formed candidate.
                try:
                    emb = json.loads(row["embedding_json"])
                    vec = np.array(emb, dtype=np.float32)
                    sim = self._cosine_similarity(query_vec, vec)
                except (TypeError, json.JSONDecodeError, ValueError) as exc:
                    _logger.warning(
                        "find_similar_lessons: skipping lessons row %s: %s",
                        row_id,
                        exc,
                    )
                    continue
                try:
                    metadata = json.loads(row["metadata_json"])
                except (TypeError, json.JSONDecodeError, ValueError) as exc:
                    _logger.warning(
                        "find_similar_lessons: skipping lessons row %s with corrupt metadata_json: %s",
                        row_id,
                        exc,
                    )
                    continue
                candidates.append({
                    "id": row_id,
                    "pattern_hash": row["pattern_hash"],
                    "target_signature": row["target_signature"],
                    "action_type": row["action_type"],
                    "outcome": row["outcome"],
                    "confidence": row["confidence"],
                    "similarity": float(sim),
                    "metadata": metadata,
                    # The lesson text (the "why" explanation). The audit flagged
                    # this was embedded for similarity but never returned, so the
                    # model never saw the lesson. Now persisted in the text column
                    # (migration v5) and selected here.
                    "text": str(row["text"] or "") if "text" in row.keys() else "",
                })

        candidates.sort(key=lambda x: x["similarity"], reverse=True)
        return candidates[:top_k]

    # ── Summarization ─────────────────────────────────────────────────

    def summarize_episodes(
        self,
        memory_type: str,
        mission_id: str,
        client: Any | None = None,
        model: str = "",
    ) -> str:
        """Use an LLM to distill episodic memories into semantic lessons.

        Returns ``""`` on failure (no memories, no client, or LLM error) so the
        caller's ``if not summary`` check falls through to the factual fallback.
        The previous error return ``"Summarization failed: {exc}"`` was
        indistinguishable from a real summary and got embedded as a "lesson"
        and retrieved later -- a real error-as-lesson bug.
        """
        memories: list[str] = []
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT fact FROM memories WHERE mission_id = ? AND memory_type = ? ORDER BY created_at DESC LIMIT 50",
                (mission_id, memory_type),
            )
            for row in cur.fetchall():
                memories.append(row["fact"])

        if not memories or not client:
            return ""

        trunc_marker = " [truncated] - only the 30 most recent observations were shown." if len(memories) > 30 else ""
        prompt = (
            "Summarize the following research observations into concise, reusable security patterns. "
            "Focus on what worked, what failed, and why.\n\n"
            + "\n".join(f"- {m}" for m in memories[:30])
            + trunc_marker
            + "\n\nReturn a JSON object only (no markdown fences):\n"
            "{\n"
            "  \"lessons\": [{\"pattern\": \"...\", \"worked_or_failed\": \"worked|failed\", \"why\": \"...\"}],\n"
            "  \"contradictions\": [\"observation pairs that conflict\"]\n"
            "}\n"
            "If no reusable pattern emerges, return {\"lessons\": [], \"contradictions\": []}."
        )
        messages = [
            {"role": "system", "content": "You are a security research summarizer. Return only valid JSON."},
            {"role": "user", "content": prompt},
        ]
        try:
            response = client.chat(model, messages=messages, stream=False)
            return response.get("message", {}).get("content", "")
        except Exception:
            # Return empty string (not an error message) so the caller's
            # ``if not summary`` falls to the factual fallback instead of
            # embedding the error text as a retrieved "lesson".
            return ""

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
        """Compute cosine similarity between two vectors.

        Defensive guards return 0.0 for: shape mismatch (different embedding
        dimensions across rows), non-finite (NaN/inf) inputs, and a non-finite
        result. 0.0 is the neutral "no information" score the caller already
        treats as a non-match, so a bad row degrades recall gracefully rather
        than crashing the whole similarity scan.
        """
        if a.shape != b.shape:
            return 0.0
        if not (np.isfinite(a).all() and np.isfinite(b).all()):
            return 0.0
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        sim = float(np.dot(a, b) / (norm_a * norm_b))
        if not np.isfinite(sim):
            return 0.0
        return sim
