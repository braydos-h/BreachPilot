"""Regression tests for the Linux-support pass.

Covers three fixes:

1. ``sanitize_output`` must NOT run the Windows cp1252 round-trip on non-Windows
   hosts -- it mangles valid UTF-8 (em-dashes, accents, CJK, box-drawing) into
   ``?`` on Linux/macOS terminals. The round-trip is now gated to ``os.name ==
   "nt"``.

2. ``_resolve_attacker_os`` must distinguish Darwin/macOS from Linux instead of
   dumping Macs into the "Kali Linux" system-prompt branch, and must canonicalize
   explicit aliases (kali->Linux, macOS->Darwin, ...).

3. ``mcp_server._downgrade_unprivileged_args`` must strip root-requiring nmap
   flags (``-O``/``-sS``/...) and replace SYN with ``-sT`` so a non-root Linux
   user gets a working connect-scan instead of a permission error.
"""

from __future__ import annotations

import os

# ── sanitize_output / _resolve_attacker_os (no third-party deps) ───────────


def test_sanitize_output_keeps_utf8_on_linux(monkeypatch):
    from tools import exploit_agent

    monkeypatch.setattr(exploit_agent.os, "name", "posix")
    out = exploit_agent.sanitize_output("em-dash — café 日本 ▒ box─draw")
    assert "—" in out
    assert "café" in out
    assert "日本" in out
    assert "box─draw" in out


def test_sanitize_output_cp1252_only_on_windows(monkeypatch):
    from tools import exploit_agent

    # On Windows the cp1252 round-trip replaces chars outside cp1252 (e.g. the
    # U+2500 box-drawing glyph and CJK) with '?'.
    monkeypatch.setattr(exploit_agent.os, "name", "nt")
    out = exploit_agent.sanitize_output("日本 box─draw")
    assert "日本" not in out  # mangled to '?'
    assert "?" in out


def test_resolve_attacker_os_auto(monkeypatch):
    from tools import exploit_agent

    monkeypatch.setattr(exploit_agent._platform, "system", lambda: "Linux")
    assert exploit_agent._resolve_attacker_os("auto") == "Linux"

    monkeypatch.setattr(exploit_agent._platform, "system", lambda: "Darwin")
    assert exploit_agent._resolve_attacker_os("auto") == "Darwin"

    monkeypatch.setattr(exploit_agent._platform, "system", lambda: "Windows")
    assert exploit_agent._resolve_attacker_os("auto") == "Windows"


def test_resolve_attacker_os_explicit_aliases():
    from tools import exploit_agent

    assert exploit_agent._resolve_attacker_os("Windows") == "Windows"
    assert exploit_agent._resolve_attacker_os("win32") == "Windows"
    assert exploit_agent._resolve_attacker_os("Darwin") == "Darwin"
    assert exploit_agent._resolve_attacker_os("macOS") == "Darwin"
    assert exploit_agent._resolve_attacker_os("osx") == "Darwin"
    assert exploit_agent._resolve_attacker_os("Linux") == "Linux"
    assert exploit_agent._resolve_attacker_os("kali") == "Linux"
    assert exploit_agent._resolve_attacker_os("posix") == "Linux"
    assert exploit_agent._resolve_attacker_os(None) in {"Linux", "Darwin", "Windows"}


# ── nmap unprivileged downgrade (requires the MCP SDK to import mcp_server) ──

pytest_present = True
try:
    import pytest  # noqa: F401
except Exception:  # pragma: no cover
    pytest_present = False

try:
    import mcp_server  # noqa: F401

    _MCP_IMPORTABLE = True
except Exception:
    _MCP_IMPORTABLE = False


if pytest_present and _MCP_IMPORTABLE:
    import pytest

    @pytest.mark.skipif(os.name == "nt", reason="POSIX nmap privilege semantics")
    def test_downgrade_strips_o_and_keeps_rest():
        from mcp_server import _downgrade_unprivileged_args

        args, note = _downgrade_unprivileged_args(["-sV", "-sC", "-O", "-T4", "10.0.0.5"])
        assert "-O" not in args
        assert "-sV" in args and "-sC" in args and "-T4" in args and "10.0.0.5" in args
        assert note  # surfaced to operator
        assert "root" in note

    @pytest.mark.skipif(os.name == "nt", reason="POSIX nmap privilege semantics")
    def test_downgrade_replaces_syn_with_connect():
        from mcp_server import _downgrade_unprivileged_args

        args, note = _downgrade_unprivileged_args(["-sS", "-p-", "10.0.0.5"])
        assert "-sS" not in args
        assert "-sT" in args  # SYN -> connect scan
        assert "-p-" in args and "10.0.0.5" in args
        assert "-sT" in note

    @pytest.mark.skipif(os.name == "nt", reason="POSIX nmap privilege semantics")
    def test_downgrade_noop_when_no_root_flags():
        from mcp_server import _downgrade_unprivileged_args

        args, note = _downgrade_unprivileged_args(["-sn", "10.0.0.5"])
        assert args == ["-sn", "10.0.0.5"]
        assert note == ""
else:  # pragma: no cover - exercised only on hosts without the MCP SDK

    def test_mcp_nmap_helpers_skipped_without_sdk():
        # Keep the file importable/collectible even where the MCP SDK isn't
        # installed (e.g. a CI box without `requirements.txt` installed).
        assert not _MCP_IMPORTABLE
