"""Regression tests for two model-router boot failures.

1. ``ModelRouter.get_client`` raises ``KeyError`` when a caller passes a
   concrete model id (e.g. ``"glm-5.2:cloud"`` from ``config.ollama.model``)
   instead of its alias. A stray ``--model glm-5.2:cloud`` used to hard-fail
   the whole boot with "Model alias 'glm-5.2:cloud' not registered.".
2. ``_build_model_client`` printed the "Local Ollama unreachable — falling
   back to Ollama Cloud" INFO line once per registered alias (5x by default),
   spamming the boot banner. It must now dedupe per host like the WARNING.
"""

from __future__ import annotations

from typing import Any

import pytest

import tools.model_router as mr
from tools.model_router import ModelClient, ModelRouter


class TestGetClientResolvesModelId:
    def _router_with_glm(self) -> ModelRouter:
        r = ModelRouter()
        r.register("glm", ModelClient(name="glm-5.2:cloud", chat=lambda *a, **k: {}, stream=lambda *a, **k: {}, model_id="glm-5.2:cloud"))
        return r

    def test_alias_passes_through(self) -> None:
        r = self._router_with_glm()
        assert r.get_client("glm").model_id == "glm-5.2:cloud"

    def test_model_id_resolves_to_registered_alias(self) -> None:
        r = self._router_with_glm()
        # The bug: passing the concrete model id raised KeyError.
        assert r.get_client("glm-5.2:cloud").model_id == "glm-5.2:cloud"

    def test_unknown_id_still_raises(self) -> None:
        r = self._router_with_glm()
        with pytest.raises(KeyError):
            r.get_client("does-not-exist")


class TestCloudFallbackInfoDeduped:
    def test_info_printed_once_per_host_across_many_builds(self, monkeypatch, capsys) -> None:
        mr._OLLAMA_UNREACHABLE_WARNED.clear()
        mr._OLLAMA_CLOUD_FALLBACK_ANNOUNCED.clear()
        monkeypatch.setattr(mr.os, "environ", {"OLLAMA_API_KEY": "sk-test"})
        monkeypatch.setattr(mr.time, "sleep", lambda *_: None)

        class _Client:
            def __init__(self, host=None, **kwargs):
                self.host = host

            def list(self):  # noqa: A003
                if self.host == "http://h":
                    raise RuntimeError("connection refused")
                return []  # cloud reachable

            def chat(self, *a, **k):
                return {"message": {"content": "x"}}

        monkeypatch.setattr(mr, "OllamaClient", _Client)
        # Simulate build_router registering 5 aliases against the same host.
        for alias in ("a", "b", "c", "d", "e"):
            mr._build_model_client("m", host="http://h", alias=alias)

        out = capsys.readouterr().out
        assert out.count("falling back to Ollama Cloud") == 1

    def test_info_printed_once_even_if_cloud_also_unreachable(self, monkeypatch, capsys) -> None:
        """When both local and cloud are down, the WARNING is deduped; the
        INFO path is never reached, so it must not print either."""
        mr._OLLAMA_UNREACHABLE_WARNED.clear()
        mr._OLLAMA_CLOUD_FALLBACK_ANNOUNCED.clear()
        monkeypatch.setattr(mr.os, "environ", {"OLLAMA_API_KEY": "sk-test"})
        monkeypatch.setattr(mr.time, "sleep", lambda *_: None)

        class _Client:
            def __init__(self, host=None, **kwargs):
                self.host = host

            def list(self):  # noqa: A003
                raise RuntimeError("down")

            def chat(self, *a, **k):
                return {"message": {"content": "x"}}

        monkeypatch.setattr(mr, "OllamaClient", _Client)
        for alias in ("a", "b", "c"):
            mr._build_model_client("m", host="http://h", alias=alias)

        out = capsys.readouterr().out
        assert "falling back to Ollama Cloud" not in out
        assert out.count("[WARNING] Ollama server at http://h appears unreachable") == 1