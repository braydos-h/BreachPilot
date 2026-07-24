"""Regression tests for ``--doctor`` / ``--self-test`` environment checks.

These tests exercise the *real* ``_check_config`` and ``_check_models`` (the
existing ``test_self_test.py`` patches every check out, which is precisely why
two long-standing bugs hid):

1. ``_check_config`` constructed ``ConfigValidator(data)`` with a *dict*, but
   ``ConfigValidator.__init__`` does ``Path(config_path)`` -- ``Path({...})``
   raises ``TypeError``. The old code swallowed that in a bare ``except`` and
   fell back to ``ok = isinstance(data, dict)``, so **any parseable YAML --
   even a structurally broken one -- reported ok=True** (false green).

2. ``_check_models`` compared the registry *alias keys* ("kimi") against the
   untagged base model names from ``/api/tags`` ("kimi-k2.6"). An alias never
   equals a base name, so **every configured model was reported missing**
   (false negative) -- masking the real state of the Ollama registry.

The fixes: ``_check_config`` now uses ``ConfigValidator(path).load_and_validate()``
and reports ``result.is_valid``; ``_check_models`` now takes registry *values*
(actual model specs) and matches on either the full ``name:tag`` or the
untagged base. Call sites in both ``doctor.py`` and ``self_test.py`` pass
``models_cfg.values()``.
"""
from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ─────────────────────────────────────────────────────────────────


def _write_config(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


class _FakeResp:
    """Stand-in for the urllib response context manager used by _check_models."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_FakeResp":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


def _fake_urlopen(payload: dict[str, Any]):
    """Return a callable matching ``urllib.request.urlopen(url, timeout=...)``."""
    return MagicMock(return_value=_FakeResp(payload))


# ── _check_config ───────────────────────────────────────────────────────────


def test_check_config_missing_file(tmp_path: Path):
    from tools.doctor import _check_config

    result = _check_config(tmp_path / "does_not_exist.yaml")
    assert result["ok"] is False
    assert result["error"] == "missing"


def test_check_config_valid_yaml_passes(tmp_path: Path):
    from tools.doctor import _check_config

    path = _write_config(tmp_path / "config.yaml", """
ollama:
  host: http://localhost:11434
  model: kimi-k2.6:cloud
models:
  registry:
    kimi: kimi-k2.6:cloud
  default_alias: kimi
mcp:
  default_transport: stdio
  http_port: 8001
exploit:
  permission: read_only
""")
    result = _check_config(path)
    assert result["ok"] is True, result
    assert result["errors"] == []


def test_check_config_detects_real_error(tmp_path: Path):
    """Regression: a structurally broken config must NOT pass as ok.

    ``ollama`` is a string, not a mapping -> ConfigValidator reports an error.
    The old code's ``except`` fallback returned ``ok = isinstance(data, dict)``
    = True here, so this test would FAIL against the pre-fix implementation.
    """
    from tools.doctor import _check_config

    path = _write_config(tmp_path / "config.yaml", """
ollama: not-a-mapping
models:
  registry:
    kimi: kimi-k2.6:cloud
mcp:
  http_port: 8001
exploit:
  permission: read_only
""")
    result = _check_config(path)
    assert result["ok"] is False
    assert any("ollama" in e and "mapping" in e for e in result["errors"])


def test_check_config_unknown_keys_are_advisory_not_errors(tmp_path: Path):
    """Unknown top-level keys are warnings, not failures."""
    from tools.doctor import _check_config

    path = _write_config(tmp_path / "config.yaml", """
ollama:
  host: http://localhost:11434
models:
  registry:
    kimi: kimi-k2.6:cloud
mcp:
  http_port: 8001
exploit:
  permission: read_only
experimental_plugin:
  enabled: true
""")
    result = _check_config(path)
    assert result["ok"] is True
    assert "experimental_plugin" in result["unknown_keys"]
    assert result["errors"] == []


def test_check_config_malformed_yaml_fails(tmp_path: Path):
    from tools.doctor import _check_config

    path = _write_config(tmp_path / "config.yaml", "  : : : not valid yaml: [")
    result = _check_config(path)
    assert result["ok"] is False
    assert "error" in result


def test_check_config_non_mapping_root_fails(tmp_path: Path):
    from tools.doctor import _check_config

    path = _write_config(tmp_path / "config.yaml", "- a\n- b\n- c\n")
    result = _check_config(path)
    assert result["ok"] is False
    assert "mapping" in result["error"]


# ── _check_models ───────────────────────────────────────────────────────────


def test_check_models_matches_by_value_full(tmp_path: Path):
    """Regression: a registry *value* present as a full name:tag is not missing.

    Old code compared the alias "kimi" against the base "kimi-k2.6" -> always
    missing. With the value "kimi-k2.6:cloud" and /api/tags reporting the same
    full name, it must now be present.
    """
    from tools.doctor import _check_models

    payload = {"models": [{"name": "kimi-k2.6:cloud"}, {"name": "nomic-embed-text:latest"}]}
    with patch("tools.doctor.urllib.request.urlopen", _fake_urlopen(payload)):
        result = _check_models("http://localhost:11434", ["kimi-k2.6:cloud"])
    assert result["ok"] is True
    assert result["missing"] == []


def test_check_models_matches_by_base(tmp_path: Path):
    """A spec with no tag matches Ollama's tagged model by base name."""
    from tools.doctor import _check_models

    payload = {"models": [{"name": "kimi-k2.6:cloud"}]}
    with patch("tools.doctor.urllib.request.urlopen", _fake_urlopen(payload)):
        result = _check_models("http://localhost:11434", ["kimi-k2.6"])
    assert result["ok"] is True
    assert result["missing"] == []


def test_check_models_reports_missing(tmp_path: Path):
    from tools.doctor import _check_models

    payload = {"models": [{"name": "kimi-k2.6:cloud"}]}
    with patch("tools.doctor.urllib.request.urlopen", _fake_urlopen(payload)):
        result = _check_models("http://localhost:11434", ["kimi-k2.6:cloud", "ghost-model:latest"])
    assert result["ok"] is False
    assert result["missing"] == ["ghost-model:latest"]


def test_check_models_empty_registry_is_ok(tmp_path: Path):
    from tools.doctor import _check_models

    payload = {"models": []}
    with patch("tools.doctor.urllib.request.urlopen", _fake_urlopen(payload)):
        result = _check_models("http://localhost:11434", [])
    assert result["ok"] is True
    assert result["missing"] == []


def test_check_models_alias_is_not_a_match(tmp_path: Path):
    """Documents WHY call sites pass values, not aliases: an alias never matches."""
    from tools.doctor import _check_models

    payload = {"models": [{"name": "kimi-k2.6:cloud"}]}
    with patch("tools.doctor.urllib.request.urlopen", _fake_urlopen(payload)):
        result = _check_models("http://localhost:11434", ["kimi"])
    assert result["ok"] is False
    assert result["missing"] == ["kimi"]


def test_check_models_unreachable_ollama():
    from tools.doctor import _check_models

    with patch("tools.doctor.urllib.request.urlopen",
               MagicMock(side_effect=urllib.error.URLError("conn refused"))):
        result = _check_models("http://localhost:11434", ["kimi-k2.6:cloud"])
    assert result["ok"] is False
    assert "error" in result


# ── Call-site wiring ─────────────────────────────────────────────────────────


def test_run_doctor_passes_registry_values_to_check_models(tmp_path: Path):
    """run_doctor must pass models.registry *values* (specs), not alias keys."""
    from tools import doctor

    config_path = _write_config(tmp_path / "config.yaml", """
ollama:
  host: http://localhost:11434
models:
  registry:
    kimi: kimi-k2.6:cloud
    deepseek: deepseek-v4-pro:cloud
  default_alias: kimi
mcp:
  http_port: 8001
exploit:
  permission: read_only
research:
  workspace_dir: research_workspace
""")
    captured: dict[str, Any] = {}

    real_check_models = doctor._check_models

    def _spy(host, configured, timeout=3.0):
        captured["configured"] = list(configured)
        return real_check_models(host, configured, timeout)

    payload = {"models": [{"name": "kimi-k2.6:cloud"}, {"name": "deepseek-v4-pro:cloud"}]}
    with patch("tools.doctor._check_models", _spy), \
         patch("tools.doctor._check_python", return_value={"name": "python_version", "ok": True}), \
         patch("tools.doctor._check_imports", return_value={"name": "python_imports", "ok": True}), \
         patch("tools.doctor._check_nmap", return_value={"name": "nmap_binary", "ok": True}), \
         patch("tools.doctor._check_workspace", return_value={"name": "workspace_writable", "ok": True}), \
         patch("tools.doctor._check_ollama", return_value={"name": "ollama_reachable", "ok": True}), \
         patch("tools.doctor.urllib.request.urlopen", _fake_urlopen(payload)), \
         patch("tools.doctor._check_port", return_value={"name": "port_free", "ok": True}):
        rc = doctor.run_doctor(config_path)

    assert rc == 0
    # Values (specs), not alias keys ("kimi"/"deepseek").
    assert sorted(captured["configured"]) == ["deepseek-v4-pro:cloud", "kimi-k2.6:cloud"]


# ── Linux-support regressions ───────────────────────────────────────────────


def test_check_nmap_honors_configured_path(monkeypatch):
    """_check_nmap must honor config.yaml's nmap.path override, not just the
    literal "nmap" on PATH (CLAUDE.md says nmap can be "set in config.yaml")."""
    from tools import doctor

    # The configured name is resolved via shutil.which; the default "nmap"
    # need not be on PATH as long as the configured path is resolvable.
    monkeypatch.setattr(doctor.shutil, "which", lambda b: f"/usr/bin/{b}")
    res = doctor._check_nmap({"nmap": {"path": "nmap-custom"}})
    assert res["ok"] is True
    assert res["path"] == "/usr/bin/nmap-custom"

    # Not found -> clear error + install/config hint.
    monkeypatch.setattr(doctor.shutil, "which", lambda b: None)
    res = doctor._check_nmap({"nmap": {"path": "nmap"}})
    assert res["ok"] is False
    assert "nmap.path" in res["hint"]


def test_check_nmap_default_when_no_config(monkeypatch):
    from tools import doctor
    monkeypatch.setattr(doctor.shutil, "which", lambda b: "/usr/bin/nmap" if b == "nmap" else None)
    res = doctor._check_nmap(None)
    assert res["ok"] is True
    assert res["path"] == "/usr/bin/nmap"


def test_check_optional_tools_is_informational(monkeypatch):
    """Optional-tools check must NEVER fail the doctor (a non-Kali Debian/Ubuntu
    host is still runnable in read_only). It reports present/missing as info."""
    from tools import doctor

    def fake_which(b: str):
        return "/usr/bin/" + b if b in ("tmux", "nmap") else None

    monkeypatch.setattr(doctor.shutil, "which", fake_which)
    res = doctor._check_optional_tools({"exploit": {"searchsploit_path": "searchsploit"}})
    assert res["ok"] is True  # informational only
    assert "tmux" in res["present"]
    assert "searchsploit" in res["missing"]


def test_check_linux_privilege_non_root_off_windows(monkeypatch):
    """On non-Windows, non-root, sudo off: ok=True (informational) with a note
    pointing at nmap.sudo. Must not fail the doctor."""
    from tools import doctor

    monkeypatch.setattr(doctor.os, "name", "posix")
    monkeypatch.setattr(doctor.os, "geteuid", lambda: 1000)
    doctor._DOCTOR_NMAP_CFG.clear()
    doctor._DOCTOR_NMAP_CFG["sudo"] = False
    res = doctor._check_linux_privilege()
    assert res["ok"] is True
    assert "1000" in res["value"]
    assert "nmap.sudo" in res["note"]


def test_check_linux_privilege_windows_is_na(monkeypatch):
    from tools import doctor
    monkeypatch.setattr(doctor.os, "name", "nt")
    res = doctor._check_linux_privilege()
    assert res["ok"] is True
    assert "Windows" in res["value"]
