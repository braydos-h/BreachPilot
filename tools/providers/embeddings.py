"""Embedding provider abstraction — decoupled from Ollama.

Semantic memory and skill embeddings consume embeddings through this
layer instead of calling Ollama's raw ``/api/embeddings`` endpoint.
Two built-ins:

- ``ollama`` — legacy behavior: local Ollama embeddings (``embed_host``);
  owns the raw HTTP call and the ``OLLAMA_API_KEY`` bearer moved out of
  ``tools/semantic_memory.py``.
- ``none`` — embeddings disabled. Degrades cleanly: semantic memory falls
  back to keyword storage, skills to deterministic matching, and NO
  request (not even a health probe) is made to any endpoint.

``embeddings.provider: none`` must therefore produce ZERO Ollama
requests and no ``OLLAMA_API_KEY`` lookup anywhere.
"""

from __future__ import annotations

import logging
import math
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class EmbeddingProvider(Protocol):
    """Minimal embedding contract: ``embed(text) -> vector or None``."""

    name: str

    def embed(self, text: str) -> list[float] | None: ...


class NullEmbeddingProvider:
    """Embeddings disabled — never touches the network or reads API keys."""

    name = "none"

    def embed(self, text: str) -> list[float] | None:
        return None


class OllamaEmbeddingProvider:
    """Ollama ``/api/embeddings`` adapter (all Ollama embedding behavior)."""

    name = "ollama"

    def __init__(
        self,
        host: str = "http://localhost:11434",
        model: str = "nomic-embed-text",
        api_key_env: str = "OLLAMA_API_KEY",
        timeout_seconds: float = 30,
    ) -> None:
        import os

        self._host = str(host or "http://localhost:11434").rstrip("/")
        self._model = model
        self._api_key_env = api_key_env
        self._timeout = timeout_seconds
        self._api_key = (os.environ.get(api_key_env, "") or "").strip()

    def embed(self, text: str) -> list[float] | None:
        """POST {host}/api/embeddings. ``None`` on any failure (caller contract)."""
        import json
        import urllib.error
        import urllib.request

        try:
            payload = json.dumps(
                {
                    "model": self._model,
                    "prompt": text,
                }
            ).encode("utf-8")

            req = urllib.request.Request(
                f"{self._host}/api/embeddings",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # ponytail: cloud embed host needs the bearer token; local daemon
            # ignores it. Send unconditionally — one code path for both.
            if self._api_key:
                req.add_header("Authorization", f"Bearer {self._api_key}")

            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                embedding = data.get("embedding")
                if isinstance(embedding, list):
                    vec = [float(v) for v in embedding]
                    # NaN/inf guard: a malformed response could hand back
                    # non-finite floats that would poison cosine similarity
                    # (dot/norm become NaN, silently corrupting recall). Treat
                    # this like any other generation failure and return None —
                    # callers already handle that contract.
                    if any(not math.isfinite(v) for v in vec):
                        logger.warning(
                            "semantic embedding failed: provider %s returned non-finite values",
                            self._host,
                        )
                        return None
                    return vec
                logger.warning(
                    "semantic embedding failed: %s returned no 'embedding' list",
                    self._host,
                )
        except Exception as exc:
            logger.warning(
                "semantic embedding failed for host %s: %s",
                self._host,
                exc,
            )
        return None


def build_embedding_provider(config: dict[str, Any] | None = None) -> EmbeddingProvider:
    """Build the embedding provider named by ``embeddings.provider``.

    Unknown provider ids degrade to ``none`` (warn, never crash — embeddings
    are an optimization, never on the critical path). ``none`` returns a
    provider with zero side effects.
    """
    from tools.config_manager import get_embeddings_config

    cfg = get_embeddings_config(config)
    provider = str(cfg.get("provider") or "ollama").strip().lower()
    if provider in ("none", "null", "disabled", ""):
        return NullEmbeddingProvider()
    if provider == "ollama":
        return OllamaEmbeddingProvider(
            host=str(cfg.get("host") or "http://localhost:11434"),
            model=str(cfg.get("model") or "nomic-embed-text"),
            api_key_env=str(cfg.get("api_key_env") or "OLLAMA_API_KEY"),
            timeout_seconds=cfg.get("timeout_seconds", 30),
        )
    logger.warning(
        "Unknown embeddings.provider %r — disabling embeddings (registered: none, ollama).",
        provider,
    )
    return NullEmbeddingProvider()


def embeddings_disabled(provider: Any) -> bool:
    """True when the provider can never produce a vector (``none`` selected)."""
    return isinstance(provider, NullEmbeddingProvider)
