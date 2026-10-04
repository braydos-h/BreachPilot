"""Regression coverage for DNS-pinned, host-side recon MCP tools.

All name resolution and network sinks are replaced with local fakes; these
tests never open sockets or invoke scanner binaries.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest


def _text(result) -> str:
    if isinstance(result, str):
        return result
    content = getattr(result, "content", None)
    if content is not None:
        return "\n".join(str(getattr(item, "text", item)) for item in content)
    return str(result)


def _clear_allowlist_env(monkeypatch) -> None:
    for key in (
        "EXPLOIT_TARGET",
        "EXPLOIT_TARGET_IP",
        "EXPLOIT_TARGET_DOMAIN",
        "EXPLOIT_DISCOVERED_TARGETS",
        "EXPLOIT_ALLOWED_TARGETS",
    ):
        monkeypatch.delenv(key, raising=False)


def _make_server(tmp_path: Path, allowed_targets: list[str]):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        {
            "exploit": {
                "require_explicit_allowlist": True,
                "allowed_targets": allowed_targets,
            },
            "skills": {"enabled": False},
            "multi_model": {"enabled": False},
        },
    )


@pytest.mark.asyncio
async def test_recon_mcp_tools_use_one_pinned_address_for_host_io(tmp_path: Path, monkeypatch):
    """Every host-side recon sink receives the same single resolved address."""
    import tools.mcp_tools.recon as recon_module
    import tools.socket_scan as socket_scan

    target = "recon-pin.example.com"
    pinned_ip = "93.184.216.34"
    resolve_calls: list[str] = []
    sinks: dict[str, list[str] | str] = {}

    def fake_resolve(host: str, **_kwargs):
        resolve_calls.append(host)
        return pinned_ip, host

    class FakeSocket:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, _timeout):
            pass

        def connect_ex(self, address):
            sinks.setdefault("socket_connect_ex", []).append(address[0])
            return 1

        def connect(self, address):
            sinks.setdefault("socket_connect", []).append(address[0])

        def sendall(self, _data):
            pass

        def recv(self, _size):
            return b""

    def fake_ping(command, **_kwargs):
        sinks["ping"] = command[-1]
        return SimpleNamespace(stdout="", stderr="", returncode=1)

    def fake_socket_scan(host, _ports):
        sinks["quick_scan"] = host
        return []

    class FakePipeline:
        def __init__(self, *_args, **_kwargs):
            pass

        async def recon_host(self, host):
            sinks["full_recon"] = host
            return recon_module.HostReconResult(target_ip=host)

        async def recon_udp(self, host, *, top_ports):
            sinks["udp_recon"] = host
            return recon_module.HostReconResult(target_ip=host)

    def fake_osint(host, *, hostname):
        sinks["osint"] = host
        sinks["osint_hostname"] = hostname
        return {"target_ip": host, "hostname": hostname}

    _clear_allowlist_env(monkeypatch)
    mcp = _make_server(tmp_path, [target])
    monkeypatch.setattr(recon_module, "resolve_target_bounded", fake_resolve)
    monkeypatch.setattr(recon_module.subprocess, "run", fake_ping)
    monkeypatch.setattr(recon_module.socket, "socket", FakeSocket)
    monkeypatch.setattr(socket_scan, "socket_scan_sync", fake_socket_scan)
    monkeypatch.setattr(recon_module, "ReconPipeline", FakePipeline)
    monkeypatch.setattr("tools.recon_osint.run_osint", fake_osint)

    await mcp.call_tool("check_os", {"target_ip": target})
    await mcp.call_tool("quick_scan", {"target_ip": target, "ports": "80"})
    await mcp.call_tool("run_full_recon", {"target_ip": target})
    await mcp.call_tool("get_service_fingerprint", {"target_ip": target, "port": 48191})
    await mcp.call_tool("run_udp_recon", {"target_ip": target, "top_ports": 10})
    await mcp.call_tool("run_osint_recon", {"target_ip": target})

    assert resolve_calls == [target] * 6
    assert sinks["ping"] == pinned_ip
    assert sinks["quick_scan"] == pinned_ip
    assert sinks["full_recon"] == pinned_ip
    assert sinks["udp_recon"] == pinned_ip
    assert sinks["osint"] == pinned_ip
    assert sinks["osint_hostname"] == target
    assert set(sinks["socket_connect_ex"]) == {pinned_ip}
    assert set(sinks["socket_connect"]) == {pinned_ip}


@pytest.mark.asyncio
async def test_hostname_resolving_to_unscoped_private_address_is_blocked(tmp_path: Path, monkeypatch):
    """An allowed FQDN cannot redirect host recon into an unlisted private IP."""
    import tools.mcp_tools.recon as recon_module
    import tools.socket_scan as socket_scan

    target = "private-answer.example.com"
    sink_calls: list[str] = []
    _clear_allowlist_env(monkeypatch)
    mcp = _make_server(tmp_path, [target])
    monkeypatch.setattr(recon_module, "resolve_target_bounded", lambda _host: ("10.0.0.9", target))
    monkeypatch.setattr(socket_scan, "socket_scan_sync", lambda host, _ports: sink_calls.append(host) or [])

    text = _text(await mcp.call_tool("quick_scan", {"target_ip": target, "ports": "80"}))

    assert "BLOCKED" in text
    assert "non-public address 10.0.0.9" in text
    assert sink_calls == []


@pytest.mark.asyncio
async def test_recon_first_pinned_private_ip_is_blocked_without_independent_scope(tmp_path: Path, monkeypatch):
    """An IP-oriented tool cannot lose the domain provenance of its run target."""
    import tools.mcp_tools.recon as recon_module
    import tools.socket_scan as socket_scan

    target = "private-answer.example.com"
    pinned_ip = "10.0.0.9"
    sink_calls: list[str] = []
    _clear_allowlist_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET", pinned_ip)
    monkeypatch.setenv("EXPLOIT_TARGET_IP", pinned_ip)
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", target)
    mcp = _make_server(tmp_path, [target])
    monkeypatch.setattr(recon_module, "resolve_target_bounded", lambda _host: (_ for _ in ()).throw(AssertionError()))
    monkeypatch.setattr(socket_scan, "socket_scan_sync", lambda host, _ports: sink_calls.append(host) or [])

    text = _text(await mcp.call_tool("quick_scan", {"target_ip": pinned_ip, "ports": "80"}))

    assert "BLOCKED" in text
    assert "non-public address 10.0.0.9" in text
    assert sink_calls == []


@pytest.mark.asyncio
async def test_dns_timeout_fails_closed_before_recon_io(tmp_path: Path, monkeypatch):
    """A bounded resolver timeout cannot fall back to hostname-based scanning."""
    import tools.mcp_tools.recon as recon_module
    import tools.socket_scan as socket_scan

    target = "slow-dns.example.com"
    sink_calls: list[str] = []
    _clear_allowlist_env(monkeypatch)
    mcp = _make_server(tmp_path, [target])

    def timed_out(_host: str):
        raise TimeoutError("resolver timed out")

    monkeypatch.setattr(recon_module, "resolve_target_bounded", timed_out)
    monkeypatch.setattr(socket_scan, "socket_scan_sync", lambda host, _ports: sink_calls.append(host) or [])

    text = _text(await mcp.call_tool("quick_scan", {"target_ip": target, "ports": "80"}))

    assert "BLOCKED: target resolution failed: resolver timed out" in text
    assert sink_calls == []


@pytest.mark.parametrize("target", ["169.254.169.254", "::ffff:169.254.169.254"])
def test_metadata_destination_is_blocked_even_when_explicitly_allowlisted(monkeypatch, target: str):
    """Explicit scope cannot override the sandbox's metadata/link-local deny set."""
    import tools.mcp_tools.recon as recon_module

    _clear_allowlist_env(monkeypatch)
    monkeypatch.setattr(recon_module, "resolve_target_bounded", lambda host: (host, None))

    address, error = recon_module._resolve_recon_target(
        target,
        {"exploit": {"allowed_targets": [target]}},
    )

    assert address is None
    assert error == "target resolves to a blocked metadata or link-local address"


def test_explicit_private_ip_scope_allows_private_dns_answer(monkeypatch):
    """An operator can authorize an internal lab target by IP or CIDR."""
    import tools.mcp_tools.recon as recon_module

    _clear_allowlist_env(monkeypatch)
    target = "lab-host.example.com"
    monkeypatch.setattr(recon_module, "resolve_target_bounded", lambda _host: ("10.20.0.8", target))

    address, error = recon_module._resolve_recon_target(
        target,
        {"exploit": {"allowed_targets": [target, "10.20.0.0/24"]}},
    )

    assert address == "10.20.0.8"
    assert error is None


def test_domain_nat64_private_answer_requires_its_embedded_ip_in_scope(monkeypatch):
    """A global-looking NAT64 address cannot hide an unscoped RFC1918 target."""
    import tools.mcp_tools.recon as recon_module

    _clear_allowlist_env(monkeypatch)
    target = "translated.example.com"
    monkeypatch.setattr(recon_module, "resolve_target_bounded", lambda _host: ("64:ff9b::a00:1", target))

    address, error = recon_module._resolve_recon_target(target, {"exploit": {"allowed_targets": [target]}})

    assert address is None
    assert error == "domain resolves to non-public address 10.0.0.1, which is not separately allowlisted"


def test_run_context_domain_rejects_implicit_private_ip_without_separate_scope(monkeypatch):
    """The run's derived IP cannot authorize a private answer by itself."""
    import tools.mcp_tools.recon as recon_module

    target = "session-pin.example.com"
    pinned_ip = "10.20.0.8"
    _clear_allowlist_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", target)
    monkeypatch.setenv("EXPLOIT_TARGET_IP", pinned_ip)
    monkeypatch.setenv("EXPLOIT_TARGET", pinned_ip)

    def unexpected_resolution(_host: str):
        raise AssertionError("run-session target must not be resolved a second time")

    monkeypatch.setattr(recon_module, "resolve_target_bounded", unexpected_resolution)

    address, error = recon_module._resolve_recon_target(
        target,
        {"exploit": {"allowed_targets": [target]}},
    )

    assert address is None
    assert error == f"domain resolves to non-public address {pinned_ip}, which is not separately allowlisted"


def test_run_context_domain_can_use_explicit_private_ip_override(monkeypatch):
    import tools.mcp_tools.recon as recon_module

    target = "session-pin.example.com"
    pinned_ip = "10.20.0.8"
    _clear_allowlist_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", target)
    monkeypatch.setenv("EXPLOIT_TARGET_IP", pinned_ip)
    monkeypatch.setenv("EXPLOIT_TARGET", pinned_ip)
    monkeypatch.setenv("EXPLOIT_ALLOWED_TARGETS", "10.20.0.0/24")
    monkeypatch.setattr(recon_module, "resolve_target_bounded", lambda _host: (_ for _ in ()).throw(AssertionError()))

    address, error = recon_module._resolve_recon_target(
        target,
        {"exploit": {"allowed_targets": [target]}},
    )

    assert address == pinned_ip
    assert error is None
