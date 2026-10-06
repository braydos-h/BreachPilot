"""Regression coverage for DNS-pinned, worker-contained recon MCP tools.

All name resolution and worker execution are replaced with local fakes; these
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
async def test_target_active_recon_uses_pinned_worker_argv_and_osint_is_passive(tmp_path: Path, monkeypatch):
    """Active tools pass the pinned IP to the worker and preserve hostname scope."""
    import tools.mcp_tools.recon as recon_module

    target = "recon-pin.example.com"
    pinned_ip = "93.184.216.34"
    resolve_calls: list[str] = []
    worker_calls: list[tuple[list[str], dict]] = []
    osint_calls: list[tuple[str, str]] = []
    nmap_xml = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="93.184.216.34" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.1 Linux"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.57"/></port>
<port protocol="tcp" portid="443"><state state="closed"/></port></ports></host></nmaprun>"""

    def fake_resolve(host: str, **_kwargs):
        resolve_calls.append(host)
        return pinned_ip, host

    def fake_worker(_ctx, argv, **kwargs):
        worker_calls.append((argv, kwargs))
        return True, SimpleNamespace(
            stdout=nmap_xml,
            stderr="",
            exit_code=0,
            duration_seconds=0.25,
            timed_out=False,
            status="completed",
        )

    def fake_osint(host, *, hostname):
        osint_calls.append((host, hostname))
        return {"target_ip": host, "hostname": hostname}

    _clear_allowlist_env(monkeypatch)
    mcp = _make_server(tmp_path, [target])
    monkeypatch.setattr(recon_module, "resolve_target_bounded", fake_resolve)
    monkeypatch.setattr(recon_module, "run_argv_in_sandbox", fake_worker)
    monkeypatch.setattr("tools.recon_osint.run_osint", fake_osint)

    os_text = _text(await mcp.call_tool("check_os", {"target_ip": target}))
    quick_text = _text(await mcp.call_tool("quick_scan", {"target_ip": target, "ports": "80,443"}))
    full_text = _text(await mcp.call_tool("run_full_recon", {"target_ip": target}))
    fingerprint = _text(await mcp.call_tool("get_service_fingerprint", {"target_ip": target, "port": 443}))
    udp_text = _text(await mcp.call_tool("run_udp_recon", {"target_ip": target, "top_ports": 10}))
    osint_text = _text(await mcp.call_tool("run_osint_recon", {"target_ip": target}))

    assert resolve_calls == [target] * 6
    assert [kwargs["tool_name"] for _argv, kwargs in worker_calls] == [
        "check_os",
        "quick_scan",
        "run_full_recon",
        "get_service_fingerprint",
    ]
    for argv, kwargs in worker_calls:
        assert argv[-1] == pinned_ip
        assert target not in argv
        assert kwargs["target_ip"] == target
        assert kwargs["targets"] == [target]
    assert "OS_VERDICT: LINUX" in os_text
    assert "TTL: N/A" in os_text
    assert "Port 80/tcp OPEN" in quick_text
    assert "sandbox worker" in quick_text
    assert "SCAN_TOOL: nmap-worker" in full_text
    assert "secondary service-specific enumeration was not run" in full_text
    assert "STATE: not reported open" in fingerprint
    assert "SANDBOX_UNSUPPORTED" in udp_text
    assert "EXECUTED: nowhere" in udp_text
    assert osint_calls == [(pinned_ip, target)]
    assert "OSINT: completed" in osint_text


@pytest.mark.asyncio
async def test_shared_campaign_recon_adapter_fails_closed_without_worker(monkeypatch):
    import tools.mcp_tools.recon as recon_module

    _clear_allowlist_env(monkeypatch)
    result, error = await recon_module.sandbox_recon_host(
        SimpleNamespace(sandbox=None),
        "192.0.2.10",
        {},
    )

    assert result is None
    assert error is not None and "sandbox" in error.lower()


@pytest.mark.asyncio
async def test_hostname_resolving_to_unscoped_private_address_is_blocked(tmp_path: Path, monkeypatch):
    """An allowed FQDN cannot redirect worker recon into an unlisted private IP."""
    import tools.mcp_tools.recon as recon_module

    target = "private-answer.example.com"
    worker_calls: list[str] = []
    _clear_allowlist_env(monkeypatch)
    mcp = _make_server(tmp_path, [target])
    monkeypatch.setattr(recon_module, "resolve_target_bounded", lambda _host: ("10.0.0.9", target))
    monkeypatch.setattr(recon_module, "run_argv_in_sandbox", lambda *_args, **_kwargs: worker_calls.append("called"))

    text = _text(await mcp.call_tool("quick_scan", {"target_ip": target, "ports": "80"}))

    assert "BLOCKED" in text
    assert "non-public address 10.0.0.9" in text
    assert worker_calls == []


@pytest.mark.asyncio
async def test_recon_first_pinned_private_ip_is_blocked_without_independent_scope(tmp_path: Path, monkeypatch):
    """An IP-oriented tool cannot lose the domain provenance of its run target."""
    import tools.mcp_tools.recon as recon_module

    target = "private-answer.example.com"
    pinned_ip = "10.0.0.9"
    worker_calls: list[str] = []
    _clear_allowlist_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET", pinned_ip)
    monkeypatch.setenv("EXPLOIT_TARGET_IP", pinned_ip)
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", target)
    mcp = _make_server(tmp_path, [target])
    monkeypatch.setattr(recon_module, "resolve_target_bounded", lambda _host: (_ for _ in ()).throw(AssertionError()))
    monkeypatch.setattr(recon_module, "run_argv_in_sandbox", lambda *_args, **_kwargs: worker_calls.append("called"))

    text = _text(await mcp.call_tool("quick_scan", {"target_ip": pinned_ip, "ports": "80"}))

    assert "BLOCKED" in text
    assert "non-public address 10.0.0.9" in text
    assert worker_calls == []


@pytest.mark.asyncio
async def test_equivalent_ipv6_spelling_preserves_private_domain_provenance(tmp_path: Path, monkeypatch):
    """A differently formatted pinned IP cannot shed its domain scope check."""
    import tools.mcp_tools.recon as recon_module

    target = "private-ipv6.example.com"
    pinned_ip = "fd00::1"
    equivalent_ip = "fd00:0000:0000:0000:0000:0000:0000:0001"
    worker_calls: list[str] = []
    _clear_allowlist_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET", pinned_ip)
    monkeypatch.setenv("EXPLOIT_TARGET_IP", pinned_ip)
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", target)
    mcp = _make_server(tmp_path, [target])
    monkeypatch.setattr(
        recon_module,
        "resolve_target_bounded",
        lambda _host: (_ for _ in ()).throw(AssertionError("pinned domain must not be resolved again")),
    )
    monkeypatch.setattr(recon_module, "run_argv_in_sandbox", lambda *_args, **_kwargs: worker_calls.append("called"))

    text = _text(await mcp.call_tool("quick_scan", {"target_ip": equivalent_ip, "ports": "80"}))

    assert "BLOCKED" in text
    assert "non-public address fd00::1" in text
    assert worker_calls == []


@pytest.mark.asyncio
async def test_dns_timeout_fails_closed_before_recon_io(tmp_path: Path, monkeypatch):
    """A bounded resolver timeout cannot fall back to hostname-based worker scanning."""
    import tools.mcp_tools.recon as recon_module

    target = "slow-dns.example.com"
    worker_calls: list[str] = []
    _clear_allowlist_env(monkeypatch)
    mcp = _make_server(tmp_path, [target])

    def timed_out(_host: str):
        raise TimeoutError("resolver timed out")

    monkeypatch.setattr(recon_module, "resolve_target_bounded", timed_out)
    monkeypatch.setattr(recon_module, "run_argv_in_sandbox", lambda *_args, **_kwargs: worker_calls.append("called"))

    text = _text(await mcp.call_tool("quick_scan", {"target_ip": target, "ports": "80"}))

    assert "BLOCKED: target resolution failed: resolver timed out" in text
    assert worker_calls == []


@pytest.mark.asyncio
async def test_sandbox_failure_blocks_without_host_fallback(tmp_path: Path, monkeypatch):
    """A missing worker yields a SANDBOX block and never reports scan output."""
    import tools.mcp_tools.recon as recon_module
    from tools.sandbox.exceptions import SandboxUnavailableError

    target = "93.184.216.34"
    _clear_allowlist_env(monkeypatch)
    mcp = _make_server(tmp_path, [target])
    monkeypatch.setattr(recon_module, "resolve_target_bounded", lambda host: (host, None))
    calls: list[tuple[list[str], dict]] = []

    def missing_worker(_ctx, argv, **kwargs):
        calls.append((argv, kwargs))
        raise SandboxUnavailableError("fake missing worker")

    monkeypatch.setattr(recon_module, "run_argv_in_sandbox", missing_worker)
    text = _text(await mcp.call_tool("quick_scan", {"target_ip": target, "ports": "80"}))

    assert "SANDBOX_UNAVAILABLE" in text
    assert "EXECUTED: nowhere" in text
    assert "QUICK_SCAN_RESULTS" not in text
    assert len(calls) == 1
    assert calls[0][0][-1] == target


@pytest.mark.asyncio
async def test_quick_scan_rejects_invalid_ports_before_worker(tmp_path: Path, monkeypatch):
    """Port parsing never turns malformed input into an Nmap argument."""
    import tools.mcp_tools.recon as recon_module

    target = "93.184.216.34"
    _clear_allowlist_env(monkeypatch)
    mcp = _make_server(tmp_path, [target])
    calls: list[str] = []
    monkeypatch.setattr(recon_module, "run_argv_in_sandbox", lambda *_args, **_kwargs: calls.append("called"))

    text = _text(await mcp.call_tool("quick_scan", {"target_ip": target, "ports": "80,80;evil"}))

    assert "BLOCKED" in text
    assert "decimal TCP port numbers" in text
    assert calls == []


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
