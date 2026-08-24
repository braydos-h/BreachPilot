"""Regression tests for two model-router boot failures.

1. ``ModelRouter.get_client`` raises ``KeyError`` when a caller passes a
   concrete model id (e.g. ``"glm-5.2:cloud"`` from ``config.ollama.model``)
   instead of its alias. A stray ``--model glm-5.2:cloud`` used to hard-fail
   the whole boot with "Model alias 'glm-5.2:cloud' not registered.".
2. ``_build_model_client`` is cloud-only: no reachability probe, no
   localâ†’cloud fallback, no per-alias INFO/WARNING spam. Registering many
   aliases must not call ``list()`` or print any fallback/warning lines.
"""

from __future__ import annotations

import pytest

from tools.model_router import ModelClient, ModelRouter


class TestGetClientResolvesModelId:
    def _router_with_glm(self) -> ModelRouter:
        r = ModelRouter()
        r.register(
            "glm",
            ModelClient(
                name="glm-5.2:cloud", chat=lambda *a, **k: {}, stream=lambda *a, **k: {}, model_id="glm-5.2:cloud"
            ),
        )
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


class TestBuildNoProbeSpam:
    """Cloud-only: ``_build_model_client`` no longer probes the host, so
    registering many aliases must not call ``list()`` or print any
    fallback/warning lines. (Guards against regressing back to the per-alias
    probe + announce path that spammed the boot banner.)"""

    def test_no_probe_or_info_across_many_builds(self, monkeypatch, capsys) -> None:
        import tools.model_router as mr

        class _Client:
            def __init__(self, host=None, **kwargs):
                self.host = host

            def list(self):  # pragma: no cover - must not be called
                raise AssertionError("list() probe must not run in cloud-only mode")

            def chat(self, *a, **k):
                return {"message": {"content": "x"}}

        monkeypatch.setattr(mr, "OllamaClient", _Client)
        for alias in ("a", "b", "c", "d", "e"):
            mr._build_model_client("m", host="http://h", alias=alias)

        out = capsys.readouterr().out
        assert "falling back to Ollama Cloud" not in out
        assert "[WARNING]" not in out
