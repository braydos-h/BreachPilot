"""Tests for the embedding provider abstraction (``tools/providers/embeddings.py``).

Covered:
* ``build_embedding_provider`` dispatch: ``none``, ``ollama`` (config applied),
  unknown ids degrade to ``none`` (warn, never crash), and the missing-key
  default stays Ollama (backwards compat);
* ``NullEmbeddingProvider`` makes ZERO network calls and reads no API-key env
  vars;
* ``OllamaEmbeddingProvider`` builds the ``/api/embeddings`` POST with the
  bearer header, degrades to ``None`` on network errors / missing embedding /
  non-finite vectors (never raises), and never logs the key;
* ``embeddings_disabled`` semantics;
* semantic memory with the ``none`` provider stores nothing and requests
  nothing (keyword fallback contract).
"""

from __future__ import annotations

import json
import os
from typing import Any

import pytest

from db import DatabaseManager
from tools.providers import embeddings as emb_mod
from tools.providers.embeddings import (
    NullEmbeddingProvider,
    OllamaEmbeddingProvider,
    build_embedding_provider,
    embeddings_disabled,
)

# ── build_embedding_provider dispatch ───────────────────────────────────


def test_none_provider_selection():
    provider = build_embedding_provider({"embeddings": {"provider": "none"}})
    assert isinstance(provider, NullEmbeddingProvider)


def test_ollama_provider_selection_applies_config():
    provider = build_embedding_provider(
        {
            "embeddings": {
                "provider": "ollama",
                "host": "http://embed-host:11434",
                "model": "my-embed-model",
                "api_key_env": "MY_EMBED_KEY",
                "timeout_seconds": 7,
            }
        }
    )
    assert isinstance(provider, OllamaEmbeddingProvider)
    assert provider._host == "http://embed-host:11434"
    assert provider._model == "my-embed-model"
    assert provider._api_key_env == "MY_EMBED_KEY"
    assert provider._timeout == 7


def test_missing_provider_defaults_to_ollama():
    provider = build_embedding_provider({})
    assert isinstance(provider, OllamaEmbeddingProvider)
    assert provider._host == "http://localhost:11434"


def test_unknown_provider_degrades_to_none(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MYSTERY_KEY", "")  # no crash either way
    provider = build_embedding_provider({"embeddings": {"provider": "mystery"}})
    assert isinstance(provider, NullEmbeddingProvider)


# ── NullEmbeddingProvider: zero network, zero env reads ─────────────────


def test_null_provider_makes_no_network_calls(monkeypatch: pytest.MonkeyPatch):
    import urllib.request

    def _forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("NullEmbeddingProvider must never touch the network")

    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    provider = build_embedding_provider({"embeddings": {"provider": "none"}})
    assert provider.embed("anything") is None
    assert provider.embed("") is None


def test_null_provider_reads_no_api_key_env(monkeypatch: pytest.MonkeyPatch):
    """Building + calling the null provider must not look up any key env var."""
    import urllib.request

    def _forbidden_urlopen(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("null provider must not perform HTTP")

    monkeypatch.setattr(urllib.request, "urlopen", _forbidden_urlopen)
    # Poison os.environ.get for the duration: the null provider must never
    # consult the environment for any key (api_key_env lookups are forbidden).
    monkeypatch.setattr(
        os.environ,
        "get",
        lambda key, default=None: (_ for _ in ()).throw(AssertionError(f"env read of {key}")),
    )
    provider = build_embedding_provider({"embeddings": {"provider": "none"}})
    assert provider.name == "none"
    assert provider.embed("x") is None  # never consulted the environment


def test_embeddings_disabled_semantics():
    assert embeddings_disabled(NullEmbeddingProvider()) is True
    assert embeddings_disabled(OllamaEmbeddingProvider()) is False


# ── OllamaEmbeddingProvider: request construction + degradation ─────────


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


def _capture_urlopen(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]) -> dict[str, Any]:
    import urllib.request

    captured: dict[str, Any] = {}

    def fake_urlopen(req: Any, *args: Any, **kwargs: Any) -> _FakeResponse:
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        captured["data"] = json.loads(req.data.decode("utf-8"))
        return _FakeResponse(payload)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return captured


def test_ollama_provider_posts_embeddings(monkeypatch: pytest.MonkeyPatch):
    captured = _capture_urlopen(monkeypatch, {"embedding": [0.25, 0.5, 0.75]})
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    provider = OllamaEmbeddingProvider(host="http://embed-host:11434", model="my-model")
    vec = provider.embed("what is open on port 22")
    assert vec == [0.25, 0.5, 0.75]
    assert captured["url"] == "http://embed-host:11434/api/embeddings"
    assert captured["method"] == "POST"
    assert captured["data"] == {"model": "my-model", "prompt": "what is open on port 22"}


def test_ollama_provider_sends_bearer_when_key_present(monkeypatch: pytest.MonkeyPatch):
    captured = _capture_urlopen(monkeypatch, {"embedding": [1.0]})
    monkeypatch.setenv("OLLAMA_API_KEY", "secret-key")
    provider = OllamaEmbeddingProvider(api_key_env="OLLAMA_API_KEY")
    assert provider.embed("x") == [1.0]
    assert captured["headers"]["authorization"] == "Bearer secret-key"


def test_ollama_provider_no_bearer_without_key(monkeypatch: pytest.MonkeyPatch):
    captured = _capture_urlopen(monkeypatch, {"embedding": [1.0]})
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    provider = OllamaEmbeddingProvider()
    provider._api_key = ""
    assert provider.embed("x") == [1.0]
    assert "authorization" not in captured["headers"]


def test_ollama_provider_degrades_on_network_error(monkeypatch: pytest.MonkeyPatch):
    import urllib.request

    def _boom(*args: Any, **kwargs: Any) -> Any:
        raise OSError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    provider = OllamaEmbeddingProvider()
    assert provider.embed("x") is None  # never raises


def test_ollama_provider_degrades_on_missing_embedding(monkeypatch: pytest.MonkeyPatch):
    _capture_urlopen(monkeypatch, {"unexpected": "shape"})
    provider = OllamaEmbeddingProvider()
    assert provider.embed("x") is None


def test_ollama_provider_degrades_on_non_finite_values(monkeypatch: pytest.MonkeyPatch):
    _capture_urlopen(monkeypatch, {"embedding": [0.1, float("nan")]})
    provider = OllamaEmbeddingProvider()
    assert provider.embed("x") is None


def test_ollama_provider_error_log_never_contains_key(monkeypatch: pytest.MonkeyPatch, caplog):
    import urllib.request

    monkeypatch.setenv("OLLAMA_API_KEY", "super-secret-key-value")
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(OSError("refused")))

    class _LeakyProvider(OllamaEmbeddingProvider):
        pass

    provider = _LeakyProvider()
    with caplog.at_level("WARNING"):
        assert provider.embed("x") is None
    assert all("super-secret-key-value" not in str(rec.message) for rec in caplog.records)


# ── Semantic memory with the "none" provider (null degrade) ─────────────


@pytest.fixture
def temp_db(tmp_path):
    db = DatabaseManager(tmp_path / "research.db")
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    return db


def test_semantic_memory_none_provider_zero_network(temp_db, monkeypatch: pytest.MonkeyPatch):
    import urllib.request

    from tools.providers.embeddings import NullEmbeddingProvider
    from tools.semantic_memory import SemanticMemoryManager

    def _forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("embeddings.provider: none must never reach any endpoint")

    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)
    mgr = SemanticMemoryManager(temp_db, embedding_provider=NullEmbeddingProvider())
    assert mgr.embed("anything") is None
    assert mgr.store_embedding("memories", "MEM-001", "fact", mission_id="M-001") is None
    assert mgr.find_similar("query", source_table="memories", top_k=5, mission_id="M-001") == []


def test_semantic_memory_accepts_custom_provider(temp_db):
    from tools.semantic_memory import SemanticMemoryManager

    class _StaticProvider:
        name = "static"

        def embed(self, text: str) -> list[float] | None:
            return [0.5, 0.5, 0.5]

    mgr = SemanticMemoryManager(temp_db, embedding_provider=_StaticProvider())
    eid = mgr.store_embedding("memories", "MEM-002", "test", mission_id="M-001")
    assert eid and eid.startswith("EMB-")
    similar = mgr.find_similar("test", source_table="memories", top_k=1, mission_id="M-001")
    assert similar and similar[0]["source_id"] == "MEM-002"
