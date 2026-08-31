"""No-Ollama regression tests — the "Ollama is optional" acceptance gate.

The provider architecture's core promise: an install WITHOUT the ``ollama``
Python package (and with zero Ollama endpoints/traffic) can still run the
engine on another provider. These tests enforce:

* with ``ollama`` imports blocked, ``tools.model_router`` imports, the
  opencode_go router builds, the exploit agent imports, the session titler
  degrades, and the doctor runs the non-Ollama provider path;
* selecting the Ollama provider without the SDK raises ACTIONABLE
  ``ProviderMissingDependencyError`` (names the extra / alternative);
* doctor with a non-Ollama active provider performs ZERO Ollama probes
  (no /api/tags, no cloud-model pings);
* the session titler has a single generic non-Ollama path that works while
  ``session_titler.OllamaClient`` is absent;
* a source-scan guard: the ollama SDK is imported ONLY inside
  ``tools/providers/ollama_provider.py`` (+ web_researcher's degrade-graceful
  research provider) — new generic ``import ollama`` fails CI.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tools.providers.types import chat_response

REPO_ROOT = Path(__file__).resolve().parents[1]


# ── 1. Engine works with the ollama package entirely blocked ────────────

_BLOCKED_IMPORT_BOOTSTRAP = """
import builtins, sys
_real = builtins.__import__
def _blocked(name, *args, **kwargs):
    if name == "ollama" or name.startswith("ollama."):
        raise ImportError("ollama blocked by test_no_ollama_regression")
    return _real(name, *args, **kwargs)
builtins.__import__ = _blocked
sys.modules.pop("ollama", None)
"""


def _run_without_ollama(body: str, cap_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    script = _BLOCKED_IMPORT_BOOTSTRAP + "\n" + body + '\nprint("SUBPROCESS_OK")\n'
    proc = subprocess.run(  # noqa: S603 -- fixed argv, test-controlled script
        [sys.executable, "-c", script],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
        env=cap_env,
    )
    return proc


def test_engine_importable_and_opencode_go_router_without_ollama():
    body = """
import tools.model_router as mr

router = mr.build_router(
    provider="opencode_go",
    config={
        "models": {"provider": "opencode_go"},
        "providers": {"opencode_go": {"default_model": "muse-spark-1.2-contributor"}},
    },
)
client = router.get_client("muse-spark-1.2-contributor")
assert client.model_id == "muse-spark-1.2-contributor", client.model_id
assert callable(client.chat) and callable(client.stream)

import tools.exploit_agent  # noqa: F401
import tools.autonomous_orchestrator  # noqa: F401
import tools.run_service.service  # noqa: F401

from tools.providers.registry import _LazyDefaultRegistry, PROVIDERS
_LazyDefaultRegistry._ensure()
assert "opencode_go" in PROVIDERS.ids()
"""
    proc = _run_without_ollama(body)
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert "SUBPROCESS_OK" in proc.stdout


def test_missing_ollama_sdk_error_is_actionable():
    """Selecting ollama without the SDK raises the actionable
    ProviderMissingDependencyError — naming the extra and the alternative."""
    body = """
from tools.providers.ollama_provider import _MISSING_DEP_MSG
from tools.providers.types import ProviderMissingDependencyError
import tools.model_router as mr

for build in (
    lambda: mr.build_router(provider="ollama", config={"models": {"provider": "ollama"}, "ollama": {"host": "http://127.0.0.1:1"}}),
    lambda: mr._build_model_client("glm-5.2:cloud", host="http://127.0.0.1:1"),
):
    try:
        build()
    except ProviderMissingDependencyError as exc:
        assert "optional Ollama" in str(exc) or "Ollama dependency" in str(exc)
        assert "models.provider" in str(exc) and "ollama" in str(exc)
    else:
        raise SystemExit("expected ProviderMissingDependencyError")

assert _MISSING_DEP_MSG
"""
    proc = _run_without_ollama(body)
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert "SUBPROCESS_OK" in proc.stdout


def test_doctor_no_ollama_probes_with_non_ollama_provider():
    """Doctor with a non-Ollama active provider performs ZERO Ollama probes."""
    import tools.doctor as doctor_mod

    def _forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Ollama doctor probe ran for a non-ollama provider")

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(doctor_mod, "_check_ollama", _forbidden)
        monkeypatch.setattr(doctor_mod, "_check_models", _forbidden)
        checks = doctor_mod._check_ai_providers({"models": {"provider": "opencode_go"}})
        assert checks and all(isinstance(c, dict) and c.get("name") for c in checks)
    finally:
        monkeypatch.undo()


# ── 2. Session titler: single generic path without Ollama ───────────────


def _fake_generic_client(monkeypatch: pytest.MonkeyPatch, content: str) -> dict[str, Any]:
    """Point session_titler's generic path at a stub model client."""
    import tools.model_router as mr

    calls: dict[str, Any] = {}

    class _Stub:
        def chat(self, **kwargs: Any) -> dict[str, Any]:
            calls.update(kwargs)
            return chat_response("muse-spark-1.2-contributor", content)

    def fake_build(config: Any, model_id: str, request_timeout_seconds: float | None = None):
        calls["model_id"] = model_id
        return _Stub()

    monkeypatch.setattr(mr, "build_model_client_for_provider", fake_build)
    return calls


def test_session_titler_generic_path_without_ollama(monkeypatch: pytest.MonkeyPatch):
    from tools.api import session_titler

    calls = _fake_generic_client(monkeypatch, "Exploiting Jenkins console")
    title = session_titler.generate_session_title_sync(
        {"goal": "test"},
        {"target_ip": "10.0.0.50"},
        config={"models": {"provider": "opencode_go"}},
    )
    assert title == "Exploiting Jenkins console"
    assert calls["model_id"] == "muse-spark-1.2-contributor"


def test_session_titler_ollama_path_degrades_when_sdk_missing(monkeypatch: pytest.MonkeyPatch):
    """Ollama-active titler with no SDK: best-effort empty string, no raise."""
    from tools.api import session_titler

    monkeypatch.setattr(session_titler, "OllamaClient", None)
    title = session_titler.generate_session_title_sync(
        {"goal": "test"},
        {"target_ip": "10.0.0.50"},
        host="http://127.0.0.1:1",
        config=None,
    )
    assert title == ""


def test_titler_module_importable_without_ollama_sdk():
    body = """
from tools.api import session_titler
assert session_titler.OllamaClient is None
assert callable(session_titler.generate_session_title_sync)
title = session_titler.generate_session_title_sync({"goal": "t"}, {"target_ip": "10.0.0.50"}, host="http://127.0.0.1:1")
assert title == ""
"""
    proc = _run_without_ollama(body)
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert "SUBPROCESS_OK" in proc.stdout


# ── 3. Source-scan guard: the Ollama SDK stays isolated ─────────────────

_IMPORT_OLLAMA_RE = re.compile(
    r"^\s*(?:import\s+ollama\b|from\s+ollama\b|import_module\(\s*['\"]ollama)",
    re.MULTILINE,
)

# web_researcher's research provider dynamically imports ollama and degrades
# gracefully when absent — a separate seam by design (see its _ollama_module).
_ALLOWED_OLLAMA_IMPORTERS = {"tools/providers/ollama_provider.py", "tools/web_researcher.py"}


def test_ollama_sdk_import_is_isolated_to_its_provider():
    """The ONLY tools/ modules allowed to import the ollama SDK are its
    provider adapter (+ the degrade-graceful research provider). A new
    generic ``import ollama`` anywhere else fails this guard."""
    offenders: list[str] = []
    for path in (REPO_ROOT / "tools").rglob("*.py"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in _ALLOWED_OLLAMA_IMPORTERS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:  # pragma: no cover - unreadable file is not an importer
            continue
        if _IMPORT_OLLAMA_RE.search(text):
            offenders.append(rel)
    assert offenders == [], (
        "Generic ollama SDK imports found — isolate them in tools/providers/ollama_provider.py: " + ", ".join(offenders)
    )


# ── 4. Embeddings stay decoupled from the chat provider ─────────────────


def test_embeddings_provider_none_requires_no_ollama():
    """With ``embeddings.provider: none`` the embedding layer imports, builds
    a null provider, and produces no vector — with the ollama package blocked."""
    body = """
from tools.providers.embeddings import NullEmbeddingProvider, build_embedding_provider

provider = build_embedding_provider({"embeddings": {"provider": "none"}})
assert isinstance(provider, NullEmbeddingProvider), type(provider)
assert provider.embed("hello") is None

import tools.semantic_memory  # noqa: F401 - must import without ollama too
import tools.skill_embeddings  # noqa: F401
"""
    proc = _run_without_ollama(body)
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert "SUBPROCESS_OK" in proc.stdout
