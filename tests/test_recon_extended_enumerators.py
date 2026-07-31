"""Phase 2 — extended depth recon enumerators (7 additive, gated, injectable).

Each enumerator is gated by its own ``ReconConfig`` flag (default OFF) and
all network/subprocess I/O is injectable (``fetch_fn``/``run_fn``), so no
live network is touched. They write into ``result.extended`` and never raise
out of the enumerator. The dispatch in ``SecondaryEnumerator.enumerate_host``
only appends a coroutine when its flag is True.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tools.recon_pipeline import (
    HostReconResult,
    ReconConfig,
    SecondaryEnumerator,
    ServiceInfo,
)


def _result(ip: str = "10.0.0.50", hostname: str = "host.example.com") -> HostReconResult:
    return HostReconResult(
        target_ip=ip,
        hostname=hostname,
        services=[ServiceInfo(port=80, protocol="tcp", service="http", version="", banner="")],
    )


# ── flags gate dispatch ──────────────────────────────────────────────────────

def test_extended_flags_default_off_in_recon_config() -> None:
    cfg = ReconConfig()
    for f in ("subdomain_enum", "vhost_discovery", "waf_fingerprint", "asn_whois",
              "cloud_metadata_probe", "snmp_enum", "dns_zone_transfer"):
        assert getattr(cfg, f) is False


def test_extended_flags_read_from_config() -> None:
    cfg = ReconConfig.from_config({"recon": {"subdomain_enum": True, "snmp_enum": True}})
    assert cfg.subdomain_enum is True
    assert cfg.snmp_enum is True
    assert cfg.vhost_discovery is False


def test_extended_field_roundtrips() -> None:
    r = _result()
    r.extended = {"subdomains": ["a.example.com"]}
    d = r.to_dict()
    assert d["extended"] == {"subdomains": ["a.example.com"]}
    r2 = HostReconResult.from_dict(d)
    assert r2.extended == {"subdomains": ["a.example.com"]}


# ── subdomain_enum ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_subdomain_enum_parses_crtsh() -> None:
    def fake_fetch(url, **kw):
        body = json.dumps([
            {"name_value": "a.example.com\nb.example.com"},
            {"name_value": "*.c.example.com"},
            {"name_value": "other.com"},
        ])
        return 200, {"content-type": "json"}, body

    enum = SecondaryEnumerator(ReconConfig(subdomain_enum=True))
    r = await enum._enumerate_subdomains(_result(), [], fetch_fn=fake_fetch)
    subs = r.extended["subdomains"]["subdomains"]
    assert "a.example.com" in subs and "b.example.com" in subs and "c.example.com" in subs
    assert "other.com" not in subs
    assert r.extended["subdomains"]["count"] == 3
    assert any(e.startswith("crt.sh:") for e in r.evidence_refs)


@pytest.mark.asyncio
async def test_subdomain_enum_no_domain_skips() -> None:
    enum = SecondaryEnumerator(ReconConfig(subdomain_enum=True))
    r = HostReconResult(target_ip="10.0.0.50", hostname="")
    out = await enum._enumerate_subdomains(r, [], fetch_fn=lambda *a, **k: (0, {}, ""))
    assert out.extended["subdomains"]["enabled"] is False


@pytest.mark.asyncio
async def test_subdomain_enum_failure_is_swallowed() -> None:
    def boom(url, **kw):
        raise RuntimeError("net down")
    enum = SecondaryEnumerator(ReconConfig(subdomain_enum=True))
    r = await enum._enumerate_subdomains(_result(), [], fetch_fn=boom)
    assert any("subdomain_enum failed" in w for w in r.warnings)


# ── vhost_discovery ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vhost_discovery_detects_diverging_response() -> None:
    base_body = "x" * 500
    calls = {"n": 0}

    def fake_fetch(url, **kw):
        host = (kw.get("headers") or {}).get("Host", "")
        calls["n"] += 1
        # admin vhost returns a different status+length
        if host == "admin.example.com":
            return 200, {}, "y" * 200
        return 200, {}, base_body

    base = _result()
    enum = SecondaryEnumerator(ReconConfig(vhost_discovery=True))
    r = await enum._enumerate_vhosts(base, base.services, fetch_fn=fake_fetch)
    vhosts = r.extended["vhosts"]["vhosts"]
    assert any(v["vhost"] == "admin.example.com" for v in vhosts)


# ── waf_fingerprint ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_waf_fingerprint_detects_cloudflare() -> None:
    def fake_fetch(url, **kw):
        return 200, {"server": "cloudflare", "cf-ray": "abc123", "content-type": "text/html"}, "<html>"
    base = _result()
    enum = SecondaryEnumerator(ReconConfig(waf_fingerprint=True))
    r = await enum._enumerate_waf(base, base.services, fetch_fn=fake_fetch)
    detected = r.extended["waf"]["detected"]
    assert any(d["waf"] == "Cloudflare" for d in detected)


# ── asn_whois (RDAP) ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_asn_whois_parses_rdap() -> None:
    def fake_fetch(url, **kw):
        body = json.dumps({
            "name": "EXAMPLE-CORP",
            "cidr0_cidrs": [{"v4prefix": "10.0.0.0", "length": 24}],
            "entities": [{"vcardArray": ["vcard", [["fn", {}, "text", "Example Org"]]]}],
        })
        return 200, {}, body

    enum = SecondaryEnumerator(ReconConfig(asn_whois=True))
    r = await enum._enumerate_asn_whois(_result(), [], fetch_fn=fake_fetch)
    info = r.extended["asn"]
    assert info["network_name"] == "EXAMPLE-CORP"
    assert info["org"] == "Example Org"
    assert info["cidr"] == "10.0.0.0"


@pytest.mark.asyncio
async def test_asn_whois_failure_is_swallowed() -> None:
    def boom(url, **kw):
        raise RuntimeError("rdap down")
    enum = SecondaryEnumerator(ReconConfig(asn_whois=True))
    r = await enum._enumerate_asn_whois(_result(), [], fetch_fn=boom)
    assert any("asn_whois failed" in w for w in r.warnings)


# ── cloud_metadata_probe ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cloud_metadata_probe_records_imdsv1() -> None:
    def fake_fetch(url, **kw):
        if "api/token" in url:
            return 200, {}, "TOKEN"
        if "meta-data" in url:
            return 200, {}, "instance-id\nami-id"
        return 0, {}, ""
    enum = SecondaryEnumerator(ReconConfig(cloud_metadata_probe=True))
    r = await enum._enumerate_cloud_metadata(_result(), [], fetch_fn=fake_fetch)
    info = r.extended["cloud_metadata"]
    assert info["imdsv1_reachable"] is True
    assert info["imdsv2_reachable"] is True


@pytest.mark.asyncio
async def test_cloud_metadata_probe_unreachable() -> None:
    def fake_fetch(url, **kw):
        return 0, {}, ""
    enum = SecondaryEnumerator(ReconConfig(cloud_metadata_probe=True))
    r = await enum._enumerate_cloud_metadata(_result(), [], fetch_fn=fake_fetch)
    info = r.extended["cloud_metadata"]
    assert info["imdsv1_reachable"] is False
    assert info["imdsv2_reachable"] is False


# ── snmp_enum ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_snmp_enum_parses_sysdescr() -> None:
    def fake_run(argv, **kw):
        return subprocess.CompletedProcess(
            args=argv, returncode=0,
            stdout="SNMPv2-MIB::sysDescr.0 = STRING: Linux 5.15.0-25-generic #25-Ubuntu",
            stderr="",
        )
    enum = SecondaryEnumerator(ReconConfig(snmp_enum=True))
    r = await enum._enumerate_snmp(_result(), [], run_fn=fake_run)
    info = r.extended["snmp"]
    assert "Linux 5.15.0-25-generic" in info["sysDescr"]
    assert r.os_family == "linux"
    assert r.os_name  # populated from sysDescr
    assert any(e.startswith("snmpwalk:") for e in r.evidence_refs)


@pytest.mark.asyncio
async def test_snmp_enum_failure_swallowed() -> None:
    def boom(argv, **kw):
        raise RuntimeError("snmp down")
    enum = SecondaryEnumerator(ReconConfig(snmp_enum=True))
    r = await enum._enumerate_snmp(_result(), [], run_fn=boom)
    assert any("snmp_enum failed" in w for w in r.warnings)


# ── dns_zone_transfer ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dns_zone_transfer_parses_records() -> None:
    def fake_run(argv, **kw):
        return subprocess.CompletedProcess(
            args=argv, returncode=0,
            stdout="; <<>> DiG 9.18 <<>> axfr @10.0.0.50 example.com\n"
                   "example.com.\t3600\tIN\tSOA\tns1.example.com. hostmaster.example.com. 1 2 3 4 5\n"
                   "www.example.com.\t3600\tIN\tA\t10.0.0.50\n"
                   "; Transfer complete.",
            stderr="",
        )
    enum = SecondaryEnumerator(ReconConfig(dns_zone_transfer=True))
    r = await enum._enumerate_dns_zone_transfer(_result(), [], run_fn=fake_run)
    info = r.extended["dns_zone"]
    assert info["record_count"] == 2
    assert any("www.example.com" in rec for rec in info["records"])


@pytest.mark.asyncio
async def test_dns_zone_transfer_refused_is_safe() -> None:
    def fake_run(argv, **kw):
        return subprocess.CompletedProcess(args=argv, returncode=1, stdout="; Transfer failed.", stderr="")
    enum = SecondaryEnumerator(ReconConfig(dns_zone_transfer=True))
    r = await enum._enumerate_dns_zone_transfer(_result(), [], run_fn=fake_run)
    info = r.extended["dns_zone"]
    assert info["record_count"] == 0
    assert "note" in info


# ── dispatch: flags actually gate ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enumerate_host_runs_extended_when_flagged(monkeypatch) -> None:
    """With subdomain_enum ON, enumerate_host dispatches the subdomain
    coroutine (mocked crt.sh). With it OFF, no subdomain key appears.
    Sibling heavy coroutines (http/osint/spider) are stubbed to no-ops so the
    test never touches live subprocess/DNS."""
    crt_body = json.dumps([{"name_value": "a.example.com"}])

    def fake_fetch(url, **kw):
        if "crt.sh" in url:
            return 200, {}, crt_body
        return 0, {}, ""

    async def _noop(self, result, services=None, **kw):
        return result

    monkeypatch.setattr(SecondaryEnumerator, "_stdlib_fetch", staticmethod(fake_fetch))
    # Stub the heavy sibling enumerators so only the gated subdomain coroutine runs.
    for sib in ("_enumerate_http", "_enumerate_osint", "_enumerate_web_spider"):
        monkeypatch.setattr(SecondaryEnumerator, sib, _noop, raising=False)

    cfg_on = ReconConfig(extended_enumerators=True, subdomain_enum=True)
    r_on = await SecondaryEnumerator(cfg_on).enumerate_host(_result())
    assert "subdomains" in r_on.extended
    assert "a.example.com" in r_on.extended["subdomains"]["subdomains"]

    cfg_off = ReconConfig(extended_enumerators=True, subdomain_enum=False)
    r_off = await SecondaryEnumerator(cfg_off).enumerate_host(_result())
    assert "subdomains" not in r_off.extended