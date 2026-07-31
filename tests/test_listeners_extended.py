"""Phase 3 — extended C2 listener types (tls / dns / https-beacon / socks_pivot).

The new ``ListenerHelper`` methods probe optional Kali binaries via
``shutil.which`` and fall back to stdlib tools (socat/openssl) or a clean
``False`` when nothing is available — never raise. ``PersistentSessionManager.
start_listener`` routes the new types; the ``start_listener`` MCP tool config-
gates them (default OFF) and allowlist-gates the ``socks_pivot`` upstream (the
allowlist is the pivot lock). No live network: ``shutil.which`` and
``subprocess.Popen`` are monkeypatched.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from tools.persistent_session_manager import ListenerHelper, PersistentSessionManager


# ── ListenerHelper: clean-fail when the binary is absent ─────────────────────

def test_start_dns_clean_fail_without_binary(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("tools.persistent_session_manager.shutil.which", lambda b: None)
    lh = ListenerHelper(tmp_path)
    ok, pid = lh.start_dns("dns1", 53)
    assert ok is False and pid is None


def test_start_tls_clean_fail_without_openssl_or_socat(monkeypatch, tmp_path: Path) -> None:
    # _tls_cert returns None (no openssl), and start_tls then needs openssl/socat.
    monkeypatch.setattr("tools.persistent_session_manager.shutil.which", lambda b: None)
    lh = ListenerHelper(tmp_path)
    ok, pid = lh.start_tls("tls1", 8443)
    assert ok is False and pid is None


def test_start_https_beacon_clean_fail_without_socat(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("tools.persistent_session_manager.shutil.which", lambda b: None)
    lh = ListenerHelper(tmp_path)
    ok, pid = lh.start_https_beacon("beacon1", 443)
    assert ok is False and pid is None


def test_start_socks_pivot_clean_fail_without_tools(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("tools.persistent_session_manager.shutil.which", lambda b: None)
    lh = ListenerHelper(tmp_path)
    ok, pid = lh.start_socks_pivot("pivot1", 1080, upstream_host="10.0.0.1", upstream_port=445)
    assert ok is False and pid is None


# ── TLS cert generation ─────────────────────────────────────────────────────

def test_tls_cert_generated_via_openssl(monkeypatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    def fake_which(b):
        return "/usr/bin/openssl" if b == "openssl" else None
    def fake_run(argv, **kw):
        calls.append(list(argv))
        # The argv contains -keyout <path> and -out <path>; create both.
        keyout = argv[argv.index("-keyout") + 1]
        out = argv[argv.index("-out") + 1]
        Path(out).write_text("CERT", encoding="utf-8")
        Path(keyout).write_text("KEY", encoding="utf-8")
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")
    monkeypatch.setattr("tools.persistent_session_manager.shutil.which", fake_which)
    monkeypatch.setattr("tools.persistent_session_manager.subprocess.run", fake_run)
    lh = ListenerHelper(tmp_path)
    ck = lh._tls_cert(8443)
    assert ck is not None
    cert, key = ck
    assert cert.exists() and key.exists()
    assert any("req" in c for c in calls)


def test_tls_cert_reused_if_present(monkeypatch, tmp_path: Path) -> None:
    # Pre-create the cert+key files; _tls_cert should reuse them and NOT run openssl.
    (tmp_path / "tls_listener_8443.crt").write_text("CERT", encoding="utf-8")
    (tmp_path / "tls_listener_8443.key").write_text("KEY", encoding="utf-8")
    ran: list[Any] = []
    monkeypatch.setattr("tools.persistent_session_manager.subprocess.run", lambda *a, **k: ran.append(a))
    lh = ListenerHelper(tmp_path)
    ck = lh._tls_cert(8443)
    assert ck is not None and ck[0].exists()
    assert ran == []  # no openssl invocation


# ── start_tls / start_https_beacon / start_socks_pivot success paths ─────────

class _FakeProc:
    def __init__(self) -> None:
        self.pid = 4242
        self._poll = None
    def poll(self):
        return self._poll


def _patch_listener_helper(monkeypatch, *, which_map: dict[str, str] | None = None,
                           cert_ok: bool = True):
    which_map = which_map or {}
    monkeypatch.setattr("tools.persistent_session_manager.shutil.which", lambda b: which_map.get(b))
    fake_proc = _FakeProc()
    def fake_popen(argv, **kw):
        fake_proc._argv = list(argv)
        return fake_proc
    monkeypatch.setattr("tools.persistent_session_manager.subprocess.Popen", fake_popen)
    if cert_ok:
        def fake_cert(self, port):
            p = self.workspace / f"tls_listener_{port}.crt"
            k = self.workspace / f"tls_listener_{port}.key"
            p.write_text("CERT", encoding="utf-8")
            k.write_text("KEY", encoding="utf-8")
            return p, k
        monkeypatch.setattr(ListenerHelper, "_tls_cert", fake_cert)
    return fake_proc


def test_start_tls_success_with_openssl(monkeypatch, tmp_path: Path) -> None:
    proc = _patch_listener_helper(monkeypatch, which_map={"openssl": "/usr/bin/openssl"})
    lh = ListenerHelper(tmp_path)
    ok, pid = lh.start_tls("tls1", 8443)
    assert ok is True and pid == 4242
    assert proc._argv[0] == "openssl" and "s_server" in proc._argv


def test_start_tls_success_with_socat_fallback(monkeypatch, tmp_path: Path) -> None:
    proc = _patch_listener_helper(monkeypatch, which_map={"socat": "/usr/bin/socat"})
    lh = ListenerHelper(tmp_path)
    ok, pid = lh.start_tls("tls1", 8443)
    assert ok is True
    assert proc._argv[0] == "socat" and any("OPENSSL-LISTEN" in a for a in proc._argv)


def test_start_https_beacon_success(monkeypatch, tmp_path: Path) -> None:
    proc = _patch_listener_helper(monkeypatch, which_map={"socat": "/usr/bin/socat"})
    lh = ListenerHelper(tmp_path)
    ok, pid = lh.start_https_beacon("beacon1", 443)
    assert ok is True
    assert proc._argv[0] == "socat" and any("SYSTEM:cat" in a for a in proc._argv)


def test_start_socks_pivot_chisel(monkeypatch, tmp_path: Path) -> None:
    proc = _patch_listener_helper(monkeypatch, which_map={"chisel": "/usr/bin/chisel"})
    lh = ListenerHelper(tmp_path)
    ok, pid = lh.start_socks_pivot("pivot1", 1080)
    assert ok is True
    assert proc._argv[0] == "chisel" and "server" in proc._argv


def test_start_socks_pivot_socat_fallback_with_upstream(monkeypatch, tmp_path: Path) -> None:
    proc = _patch_listener_helper(monkeypatch, which_map={"socat": "/usr/bin/socat"})
    lh = ListenerHelper(tmp_path)
    ok, pid = lh.start_socks_pivot("pivot1", 1080, upstream_host="10.0.0.1", upstream_port=445)
    assert ok is True
    assert any("TCP:10.0.0.1:445" in a for a in proc._argv)


def test_start_socks_pivot_socat_no_upstream_fails(monkeypatch, tmp_path: Path) -> None:
    # socat present but no upstream host -> cannot build a forward -> fail.
    _patch_listener_helper(monkeypatch, which_map={"socat": "/usr/bin/socat"})
    lh = ListenerHelper(tmp_path)
    ok, pid = lh.start_socks_pivot("pivot1", 1080)  # no upstream
    assert ok is False


# ── PersistentSessionManager.start_listener routing ─────────────────────────

def test_psm_start_listener_routes_tls(monkeypatch, tmp_path: Path) -> None:
    _patch_listener_helper(monkeypatch, which_map={"openssl": "/usr/bin/openssl"})
    mgr = PersistentSessionManager(tmp_path)
    res = mgr.start_listener("tlsA", 8443, listener_type="tls")
    assert res["success"] is True
    assert res["listener_type"] == "tls"
    assert res["pid"] == 4242


def test_psm_start_listener_unknown_type(monkeypatch, tmp_path: Path) -> None:
    _patch_listener_helper(monkeypatch, which_map={})
    mgr = PersistentSessionManager(tmp_path)
    res = mgr.start_listener("x", 1234, listener_type="nope")
    assert res["success"] is False
    assert "Unknown listener_type" in res["error"]


# ── MCP start_listener: config-off guard + allowlist gate ────────────────────

def _make_server(tmp_path: Path, *, require_allowlist: bool = False, allowed: list[str] | None = None,
                 listeners: dict[str, bool] | None = None):
    from mcp_exploit_server import create_mcp_server
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.cve_lookup import NVDClient, CVESearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {
        "exploit": {
            "require_explicit_allowlist": require_allowlist,
            "allowed_targets": allowed or [],
            "listeners": listeners or {"tls": False, "dns": False, "https_beacon": False, "socks_pivot": False},
        }
    }
    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        config,
    )


def _text(result) -> str:
    content = result[0] if isinstance(result, (list, tuple)) else result
    if hasattr(content, "content"):
        content = content.content
    return "".join(getattr(c, "text", str(c)) for c in content)


@pytest.mark.asyncio
async def test_start_listener_tls_config_off(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("start_listener", {"name": "t", "port": 8443, "listener_type": "tls"}))
    assert "BLOCKED" in text and "listeners.tls" in text


@pytest.mark.asyncio
async def test_start_listener_dns_config_off(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("start_listener", {"name": "d", "port": 53, "listener_type": "dns"}))
    assert "BLOCKED" in text and "listeners.dns" in text


@pytest.mark.asyncio
async def test_start_listener_socks_pivot_offlist_upstream_blocked(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=True, allowed=["10.0.0.1"],
                       listeners={"tls": False, "dns": False, "https_beacon": False, "socks_pivot": True})
    text = _text(await mcp.call_tool("start_listener", {
        "name": "p", "port": 1080, "listener_type": "socks_pivot",
        "upstream_host": "10.0.0.99", "upstream_port": 445,
    }))
    assert "BLOCKED" in text and "10.0.0.99" in text


@pytest.mark.asyncio
async def test_start_listener_legacy_netcat_ungated_by_new_config(tmp_path: Path) -> None:
    """Legacy netcat/socat/http types are NOT gated by the new listeners config
    block (default OFF) — pre-existing behavior is unchanged."""
    mcp = _make_server(tmp_path)  # all listeners flags False
    # Should NOT return a config-off BLOCKED for netcat (it will fail to start
    # because nc isn't present in the test env, but that's a LISTENER_FAILED,
    # not a BLOCKED: listeners.* disabled).
    text = _text(await mcp.call_tool("start_listener", {"name": "nc1", "port": 4444, "listener_type": "netcat"}))
    assert "listeners." not in text
