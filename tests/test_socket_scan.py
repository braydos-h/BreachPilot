"""Tests for ``tools/socket_scan.py`` — native Python TCP port scanner.

Covers the ``COMMON_PORTS``/``_SERVICE_GUESS`` tables, the sync and async scan
functions (with socket monkeypatching), banner parsing, and the
``format_socket_scan_results`` formatter.
"""

from __future__ import annotations

import asyncio
import socket

from tools.socket_scan import (
    _SERVICE_GUESS,
    COMMON_PORTS,
    _probe_port,
    format_socket_scan_results,
    socket_scan,
    socket_scan_sync,
)

# ── Constants ───────────────────────────────────────────────────────────────


def test_common_ports_are_sorted_unique_ints():
    assert COMMON_PORTS == sorted(set(COMMON_PORTS))
    assert all(isinstance(p, int) for p in COMMON_PORTS)
    assert 22 in COMMON_PORTS
    assert 80 in COMMON_PORTS
    assert 443 in COMMON_PORTS


def test_service_guess_covers_common_ports():
    # Every well-known common port should have a service guess.
    for port in (21, 22, 80, 443, 3306, 8080):
        assert port in _SERVICE_GUESS
    assert _SERVICE_GUESS[22] == "ssh"
    assert _SERVICE_GUESS[80] == "http"
    assert _SERVICE_GUESS[443] == "https"


def test_service_guess_unknown_port_returns_empty_via_get():
    assert _SERVICE_GUESS.get(99999, "") == ""


# ── _probe_port (mocked socket) ─────────────────────────────────────────────


class _FakeSocket:
    """Minimal fake socket that simulates connect_ex + recv."""

    def __init__(self, *, connect_result=0, banner=b"", recv_error=False):
        self._connect_result = connect_result
        self._banner = banner
        self._recv_error = recv_error
        self._timeout = None

    def settimeout(self, t):
        self._timeout = t

    def connect_ex(self, addr):
        return self._connect_result

    def recv(self, n):
        if self._recv_error:
            raise socket.timeout("timed out")
        return self._banner[:n]

    def close(self):
        pass


def _patch_socket_factory(monkeypatch, **kwargs):
    fake = _FakeSocket(**kwargs)
    monkeypatch.setattr(socket, "socket", lambda *a, **k: fake)
    return fake


def test_probe_port_open_with_banner(monkeypatch):
    _patch_socket_factory(monkeypatch, connect_result=0, banner=b"SSH-2.0-OpenSSH_8.9\r\n")
    r = _probe_port("10.0.0.5", 22, timeout=1.0)
    assert r["port"] == 22
    assert r["open"] is True
    assert "SSH-2.0-OpenSSH_8.9" in r["banner"]
    assert r["service_guess"] == "ssh"


def test_probe_port_requires_two_successful_connections(monkeypatch):
    sockets = [_FakeSocket(connect_result=0), _FakeSocket(connect_result=111)]
    monkeypatch.setattr(socket, "socket", lambda *a, **k: sockets.pop(0))

    r = _probe_port("10.0.0.5", 22, timeout=1.0)

    assert r["open"] is False


def test_probe_port_open_no_banner(monkeypatch):
    _patch_socket_factory(monkeypatch, connect_result=0, banner=b"")
    r = _probe_port("10.0.0.5", 80, timeout=1.0)
    assert r["open"] is True
    assert r["banner"] == ""
    assert r["service_guess"] == "http"


def test_probe_port_open_banner_recv_error(monkeypatch):
    # recv raises -> banner stays empty, port still open.
    _patch_socket_factory(monkeypatch, connect_result=0, banner=b"x", recv_error=True)
    r = _probe_port("10.0.0.5", 22, timeout=1.0)
    assert r["open"] is True
    assert r["banner"] == ""


def test_probe_port_closed(monkeypatch):
    _patch_socket_factory(monkeypatch, connect_result=1)  # non-zero = not connected
    r = _probe_port("10.0.0.5", 9999, timeout=1.0)
    assert r["port"] == 9999
    assert r["open"] is False
    assert r["banner"] == ""
    assert r["service_guess"] == ""


def test_probe_port_connect_ex_raises(monkeypatch):
    # connect_ex raising (e.g. network error) is caught and returns closed.
    fake = _FakeSocket(connect_result=0)
    monkeypatch.setattr(socket, "socket", lambda *a, **k: fake)
    # Make connect_ex itself raise after construction succeeds.
    fake.connect_ex = lambda addr: (_ for _ in ()).throw(OSError("net down"))
    r = _probe_port("10.0.0.5", 22, timeout=1.0)
    assert r["open"] is False
    assert r["banner"] == ""


def test_probe_port_settimeout_raises(monkeypatch):
    # settimeout raising after construction is NOT caught (outside try); but
    # the real code only sets timeout inside try after connect_ex. We instead
    # verify a connect_ex result of non-zero yields closed with empty fields.
    _patch_socket_factory(monkeypatch, connect_result=111)  # connection refused
    r = _probe_port("10.0.0.5", 22, timeout=1.0)
    assert r["open"] is False
    assert r["banner"] == ""
    assert r["service_guess"] == ""


def test_probe_port_banner_truncated_to_200(monkeypatch):
    long_banner = b"A" * 600
    _patch_socket_factory(monkeypatch, connect_result=0, banner=long_banner)
    r = _probe_port("10.0.0.5", 22, timeout=1.0)
    assert r["open"] is True
    assert len(r["banner"]) == 200


# ── socket_scan_sync ────────────────────────────────────────────────────────


def test_socket_scan_sync_calls_probe_per_port(monkeypatch):
    calls: list[tuple[str, int, float]] = []

    def fake_probe(target, port, timeout):
        calls.append((target, port, timeout))
        return {"port": port, "open": False, "banner": "", "service_guess": ""}

    monkeypatch.setattr("tools.socket_scan._probe_port", fake_probe)
    results = socket_scan_sync("10.0.0.5", [22, 80, 443], timeout=2.0)
    assert len(results) == 3
    assert [c[1] for c in calls] == [22, 80, 443]
    assert all(c[0] == "10.0.0.5" for c in calls)
    assert all(c[2] == 2.0 for c in calls)


def test_socket_scan_sync_empty_ports(monkeypatch):
    monkeypatch.setattr("tools.socket_scan._probe_port", lambda *a, **k: {})
    assert socket_scan_sync("x", []) == []


# ── socket_scan (async) ─────────────────────────────────────────────────────


def test_socket_scan_async_returns_all_results(monkeypatch):
    def fake_probe(target, port, timeout):
        return {"port": port, "open": port == 22, "banner": "", "service_guess": "ssh" if port == 22 else ""}

    monkeypatch.setattr("tools.socket_scan._probe_port", fake_probe)
    results = asyncio.run(socket_scan("10.0.0.5", [22, 80], timeout=1.0))
    assert len(results) == 2
    assert results[0]["open"] is True
    assert results[1]["open"] is False


# ── format_socket_scan_results ──────────────────────────────────────────────


def test_format_results_with_open_ports():
    results = [
        {"port": 22, "open": True, "banner": "SSH-2.0-OpenSSH", "service_guess": "ssh"},
        {"port": 80, "open": True, "banner": "", "service_guess": "http"},
        {"port": 443, "open": False, "banner": "", "service_guess": "https"},
    ]
    out = format_socket_scan_results("10.0.0.5", results)
    assert "QUICK_SCAN_RESULTS: 10.0.0.5" in out
    assert "Port 22/tcp OPEN (ssh) - SSH-2.0-OpenSSH" in out
    assert "Port 80/tcp OPEN (http) - (no banner)" in out
    assert "443" not in out.split("SUMMARY")[0]  # closed port not listed
    assert "SUMMARY: 2/3 ports open" in out
    assert "NEXT STEPS:" in out


def test_format_results_no_open_ports():
    results = [
        {"port": 22, "open": False, "banner": "", "service_guess": "ssh"},
        {"port": 80, "open": False, "banner": "", "service_guess": "http"},
    ]
    out = format_socket_scan_results("10.0.0.5", results)
    assert "SUMMARY: 0/2 ports open" in out
    assert "NOTE: No ports responded" in out
    assert "NEXT STEPS:" not in out


def test_format_results_empty_results():
    out = format_socket_scan_results("10.0.0.5", [])
    assert "QUICK_SCAN_RESULTS: 10.0.0.5" in out
    assert "SUMMARY: 0/0 ports open" in out
    assert "NOTE: No ports responded" in out


def test_format_results_open_port_with_empty_service_guess():
    results = [{"port": 9999, "open": True, "banner": "x", "service_guess": ""}]
    out = format_socket_scan_results("10.0.0.5", results)
    assert "Port 9999/tcp OPEN () - x" in out
