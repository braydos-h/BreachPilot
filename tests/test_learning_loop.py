"""Tests for the closed learning loop.

Covers:
  * ``SemanticMemoryManager.store_lesson`` persists the lesson text (audit:
    it embedded the text for similarity but never stored it -- retrieval
    returned labels/metadata but NOT the ``why`` explanation).
  * ``get_default_db()`` initializes the schema on a fresh install (audit:
    fresh Flow A installs hit ``no such table: lessons``).
  * The DB migration v5 adds the ``text`` column to existing lessons tables.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


def test_get_default_db_ensures_schema(tmp_path, monkeypatch):
    """A fresh default DB must have the lessons table (audit: fresh install
    hit ``no such table: lessons`` because Flow A never called ensure_schema)."""
    import db as _db

    # Point the default DB at a temp workspace so we don't touch the real one.
    monkeypatch.setenv("RESEARCH_WORKSPACE", str(tmp_path / "ws"))
    _db.reset_default()
    try:
        from db import get_default_db

        gdb = get_default_db()
        with gdb.connection() as conn:
            # The lessons table must exist.
            row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='lessons'").fetchone()
            assert row is not None
            assert row["name"] == "lessons"
            # The text column must exist (DDL on fresh create).
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(lessons)").fetchall()}
            assert "text" in cols
    finally:
        _db.reset_default()


def test_store_lesson_persists_text(tmp_path, monkeypatch):
    """store_lesson must persist the lesson text so retrieval can return it."""
    import db as _db

    monkeypatch.setenv("RESEARCH_WORKSPACE", str(tmp_path / "ws"))
    _db.reset_default()
    try:
        from db import get_default_db
        from tools.semantic_memory import SemanticMemoryManager

        gdb = get_default_db()
        # Stub the embedder so we don't need a running Ollama.
        mgr = SemanticMemoryManager(gdb, embedding_model="nomic-embed-text")
        mgr._generate_embedding = MagicMock(return_value=[0.1, 0.2, 0.3])

        lid = mgr.store_lesson(
            target_signature="ssh:8.5p1:linux",
            action_type="SSHBruteForce:parameter_tweak",
            outcome="failure",
            text="SSH brute force failed: root login disabled by PermitRootLogin no",
            metadata={"reason": "PermitRootLogin"},
        )
        assert lid is not None

        with gdb.connection() as conn:
            row = conn.execute("SELECT text FROM lessons WHERE id=?", (lid,)).fetchone()
            assert row is not None
            assert "PermitRootLogin" in row["text"]
    finally:
        _db.reset_default()


@pytest.mark.asyncio
async def test_find_similar_lessons_returns_text(tmp_path, monkeypatch):
    """find_similar_lessons must return the lesson text, not just labels."""
    import db as _db

    monkeypatch.setenv("RESEARCH_WORKSPACE", str(tmp_path / "ws"))
    _db.reset_default()
    try:
        from db import get_default_db
        from tools.semantic_memory import SemanticMemoryManager

        gdb = get_default_db()
        mgr = SemanticMemoryManager(gdb, embedding_model="nomic-embed-text")
        mgr._generate_embedding = MagicMock(return_value=[0.1, 0.2, 0.3])

        mgr.store_lesson(
            "ssh:8.5:linux",
            "SSHBruteForce",
            "failure",
            "Root login disabled; pivot to key-based auth brute instead.",
        )
        results = mgr.find_similar_lessons("ssh brute force", top_k=1)
        assert len(results) == 1
        assert "Root login disabled" in results[0]["text"]
    finally:
        _db.reset_default()


def test_migration_v5_adds_text_column_to_existing_db(tmp_path, monkeypatch):
    """An existing DB (created pre-v5) must get the text column via migration."""
    import db as _db

    monkeypatch.setenv("RESEARCH_WORKSPACE", str(tmp_path / "ws"))
    _db.reset_default()
    try:
        from db import DatabaseManager

        # Create a DB with the OLD schema (no text column).
        db_path = tmp_path / "ws" / "research.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        import sqlite3

        conn = sqlite3.connect(str(db_path))
        conn.executescript("""
            CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT);
            INSERT INTO schema_migrations VALUES (4, '2024-01-01');
            CREATE TABLE lessons (
                id TEXT PRIMARY KEY,
                pattern_hash TEXT NOT NULL DEFAULT '',
                target_signature TEXT NOT NULL DEFAULT '',
                action_type TEXT NOT NULL DEFAULT '',
                outcome TEXT NOT NULL DEFAULT '' CHECK(outcome IN ('success','failure','partial','unknown')),
                confidence REAL NOT NULL DEFAULT 0.0,
                embedding_json TEXT NOT NULL DEFAULT '[]',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
        """)
        conn.commit()
        conn.close()

        # Now open it via DatabaseManager -- the v5 migration should add text.
        dm = DatabaseManager(db_path)
        with dm.connection(write=True) as conn:
            dm.ensure_schema(conn)
        with dm.connection() as conn:
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(lessons)").fetchall()}
            assert "text" in cols
    finally:
        _db.reset_default()
