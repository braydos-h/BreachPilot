"""Tests for embedding-based runtime skill matching (Tier 2.2)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.skill_embeddings import (
    SkillEmbedder,
    _cosine,
    get_shared_skill_embedder,
    reset_shared_skill_embedder,
    reset_warn_flag,
    semantic_rank,
)
from tools.skill_registry import load_skill_registry
from tools.skill_selector import select_runtime_skills


def _write_skill(root: Path, name: str, tags: list[str], desc: str = "") -> None:
    d = root / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        f"description: {desc or name}\n"
        "tags:\n" + "".join(f"- {t}\n" for t in tags) + "---\n# Skill\n\n## Workflow\nAuthorized use only.",
        encoding="utf-8",
    )


def _registry(tmp_path: Path):
    _write_skill(tmp_path, "alpha-skill", ["nmap", "reconnaissance", "network-security"], "alpha recon methodology")
    _write_skill(tmp_path, "beta-skill", ["api", "web", "owasp"], "beta web api methodology")
    return load_skill_registry([tmp_path], base_dir=tmp_path)


class _FakeSM:
    """Fake semantic memory: maps a substring in the text to a fixed vector."""

    def __init__(self, mapping: dict[str, list[float]]) -> None:
        self._m = mapping
        self.calls = 0

    def embed(self, text: str) -> list[float] | None:
        self.calls += 1
        t = text.lower()
        for key, vec in self._m.items():
            if key in t:
                return list(vec)
        return None


class _BrokenSM:
    def embed(self, text: str) -> list[float] | None:
        raise RuntimeError("Ollama unreachable")


@pytest.fixture(autouse=True)
def _reset_embed_state():
    reset_warn_flag()
    reset_shared_skill_embedder()
    yield
    reset_warn_flag()
    reset_shared_skill_embedder()


# ── cosine / embedder unit tests ─────────────────────────────────────────


def test_cosine_identical_vectors_is_one():
    assert _cosine([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)


def test_cosine_orthogonal_is_zero():
    assert _cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)


def test_skill_embedder_available_and_caching():
    sm = _FakeSM({"alpha": [1.0, 0.0]})
    emb = SkillEmbedder(sm)
    assert emb.available()
    v1 = emb.embed_text("alpha recon")
    v2 = emb.embed_text("alpha recon")
    assert v1 == v2 == [1.0, 0.0]
    # Cached: the second call must not hit the underlying sm again.
    assert sm.calls == 1


def test_skill_embedder_unavailable_wrapping_none():
    emb = SkillEmbedder(None)
    assert not emb.available()
    assert emb.embed_text("anything") is None


def test_shared_embedder_honors_skills_semantic_model(monkeypatch):
    import db
    import tools.semantic_memory as semantic_memory
    from tools.providers.embeddings import OllamaEmbeddingProvider

    captured: dict[str, object] = {}

    class _CapturingManager:
        def __init__(self, _db, *, embedding_provider):
            captured["provider"] = embedding_provider

        def embed(self, _text: str) -> list[float]:
            return [1.0, 0.0]

    monkeypatch.setattr(db, "get_default_db", lambda: object())
    monkeypatch.setattr(semantic_memory, "SemanticMemoryManager", _CapturingManager)

    embedder = get_shared_skill_embedder(
        {
            "memory": {"semantic_enabled": True, "embedding_model": "memory-default"},
            "skills": {"semantic_model": "skill-specific-model"},
            # Legacy backcompat: an untouched embeddings block inherits the
            # ollama embed host (local embeddings stay local).
            "ollama": {"host": "http://embedder.test:11434", "embed_host": "http://embedder.test:11434"},
        }
    )

    assert embedder.available()
    provider = captured["provider"]
    assert isinstance(provider, OllamaEmbeddingProvider)
    # skills.semantic_model wins over memory.embedding_model for skill search.
    assert provider._model == "skill-specific-model"
    assert provider._model != "memory-default"
    assert provider._host == "http://embedder.test:11434"


# ── semantic_rank ────────────────────────────────────────────────────────


def test_semantic_rank_orders_by_cosine(tmp_path: Path):
    registry = _registry(tmp_path)
    sm = _FakeSM({"alpha": [1.0, 0.0], "beta": [0.0, 1.0]})
    emb = SkillEmbedder(sm)
    ranked = semantic_rank("alpha", registry, emb, top_k=10)
    names = [s.name for s, _ in ranked]
    assert names == ["alpha-skill"]  # beta is orthogonal (sim 0) -> excluded


def test_semantic_rank_filters_weak_similarity(tmp_path: Path):
    registry = _registry(tmp_path)
    sm = _FakeSM(
        {
            "query": [1.0, 0.0],
            "alpha": [0.2, 0.979795897],
            "beta": [0.0, 1.0],
        }
    )
    emb = SkillEmbedder(sm)

    ranked = semantic_rank(
        "query",
        registry,
        emb,
        top_k=10,
        min_similarity=0.35,
    )

    assert ranked == []


def test_semantic_rank_empty_when_no_embedder(tmp_path: Path, capsys):
    registry = _registry(tmp_path)
    ranked = semantic_rank("alpha", registry, None, top_k=10)
    assert ranked == []
    out = capsys.readouterr().out
    assert "embeddings unavailable" in out


def test_semantic_rank_empty_when_embed_raises(tmp_path: Path, capsys):
    registry = _registry(tmp_path)
    emb = SkillEmbedder(_BrokenSM())
    # available() is True (sm is not None) but every embed raises -> None.
    ranked = semantic_rank("alpha", registry, emb, top_k=10)
    assert ranked == []
    out = capsys.readouterr().out
    assert "embeddings unavailable" in out


def test_semantic_rank_warns_once(tmp_path: Path, capsys):
    registry = _registry(tmp_path)
    semantic_rank("alpha", registry, None, top_k=10)
    semantic_rank("alpha", registry, None, top_k=10)
    out = capsys.readouterr().out
    assert out.count("embeddings unavailable") == 1


# ── selector integration ─────────────────────────────────────────────────


def test_selector_semantic_path_adds_signal(tmp_path: Path):
    registry = _registry(tmp_path)
    sm = _FakeSM({"alpha": [1.0, 0.0], "beta": [0.0, 1.0]})
    embedder = SkillEmbedder(sm)
    sel = select_runtime_skills(
        registry,
        config={
            "skills": {
                "enabled": True,
                "default_enabled": [],
                "max_active_skills": 6,
                "min_contextual_skills": 0,
                "default_skill_weight": 5,
                "context_skill_weight": 10,
                "semantic_matching": True,
                "semantic_skill_weight": 16,
            }
        },
        goal_name="alpha",
        goal_description="alpha recon",
        mode="recon",
        skill_embedder=embedder,
    )
    alpha = next(a for a in sel.activations if a.name == "alpha-skill")
    assert any(sig.startswith("semantic:") for sig in alpha.signals)


def test_selector_semantic_path_gated_by_config(tmp_path: Path):
    registry = _registry(tmp_path)
    sm = _FakeSM({"alpha": [1.0, 0.0], "beta": [0.0, 1.0]})
    embedder = SkillEmbedder(sm)
    sel = select_runtime_skills(
        registry,
        config={
            "skills": {
                "enabled": True,
                "default_enabled": [],
                "max_active_skills": 6,
                "min_contextual_skills": 0,
                "default_skill_weight": 5,
                "context_skill_weight": 10,
                "semantic_matching": False,  # off -> no semantic term
                "semantic_skill_weight": 16,
            }
        },
        goal_name="alpha",
        goal_description="alpha recon",
        mode="recon",
        skill_embedder=embedder,
    )
    for a in sel.activations:
        assert not any(sig.startswith("semantic:") for sig in a.signals)


def test_semantic_off_falls_back_to_tags(tmp_path: Path):
    """The deterministic regression: with no embedder, tag matching must still
    select the contextually relevant skill (recon goal -> alpha-skill)."""
    registry = _registry(tmp_path)
    sel = select_runtime_skills(
        registry,
        config={
            "skills": {
                "enabled": True,
                "default_enabled": [],
                "max_active_skills": 6,
                "min_contextual_skills": 1,
                "default_skill_weight": 5,
                "context_skill_weight": 10,
                "semantic_matching": True,  # on, but no embedder -> fallback
                "semantic_skill_weight": 16,
            }
        },
        goal_name="recon",
        goal_description="recon",
        mode="recon",
        skill_embedder=None,
    )
    names = {a.name for a in sel.activations}
    assert "alpha-skill" in names  # tag match (recon -> reconnaissance/nmap)
    for a in sel.activations:
        assert not any(sig.startswith("semantic:") for sig in a.signals)


def test_semantic_fallback_when_ollama_unreachable(tmp_path: Path, capsys):
    """When the embedder's underlying Ollama is down, semantic_rank returns []
    and the selector still selects via tag matching (with the one-shot warn)."""
    registry = _registry(tmp_path)
    embedder = SkillEmbedder(_BrokenSM())
    sel = select_runtime_skills(
        registry,
        config={
            "skills": {
                "enabled": True,
                "default_enabled": [],
                "max_active_skills": 6,
                "min_contextual_skills": 1,
                "default_skill_weight": 5,
                "context_skill_weight": 10,
                "semantic_matching": True,
                "semantic_skill_weight": 16,
            }
        },
        goal_name="recon",
        goal_description="recon",
        mode="recon",
        skill_embedder=embedder,
    )
    names = {a.name for a in sel.activations}
    assert "alpha-skill" in names  # tag fallback worked
    for a in sel.activations:
        assert not any(sig.startswith("semantic:") for sig in a.signals)
    assert "embeddings unavailable" in capsys.readouterr().out
