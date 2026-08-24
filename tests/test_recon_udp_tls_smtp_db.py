"""Phase 3 Round 2 — UDP / TLS / SMTP / DB recon + new HostReconResult fields.

Mocks ``tools.recon_pipeline.run_command`` and ``ToolAvailability.check`` per
the established pattern in ``tests/test_recon_pipeline.py``. No real network.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tools.recon_pipeline import (
    HostReconResult,
    PrimaryReconScanner,
    ReconConfig,
    SecondaryEnumerator,
    ServiceInfo,
)


@pytest.fixture
def recon_config() -> ReconConfig:
    return ReconConfig(
        nmap_path="nmap",
        timeout_seconds=60,
        max_retries=1,
        extended_enumerators=True,
    )


# ── UDP scan ───────────────────────────────────────────────────────────────

class TestUdpRecon:
    @pytest.mark.asyncio
    async def test_recon_udp_populates_udp_ports(self, recon_config: ReconConfig) -> None:
        """recon_udp parses nmap UDP output into udp_ports + udp ServiceInfo."""
        udp_xml = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/>
    <ports>
      <port protocol="udp" portid="53"><state state="open"/>
        <service name="domain" product="ISC BIND"/>
      </port>
      <port protocol="udp" portid="161"><state state="open|filtered"/>
        <service name="snmp"/>
      </port>
      <port protocol="udp" portid="137"><state state="closed"/>
        <service name="netbios-ns"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        with patch("tools.recon_pipeline.ToolAvailability.check", return_value=True):
            with patch("tools.recon_pipeline.run_command") as mock_run:
                mock_run.return_value = (True, udp_xml, "", 1.0)
                scanner = PrimaryReconScanner(recon_config)
                result = await scanner.recon_udp("10.0.0.50", top_ports=100)

        assert 53 in result.udp_ports
        assert 161 in result.udp_ports
        # closed ports must be skipped
        assert 137 not in result.udp_ports
        udp_svcs = [s for s in result.services if s.protocol == "udp"]
        assert any(s.port == 53 and s.service == "domain" for s in udp_svcs)
        assert any(s.port == 161 for s in udp_svcs)

    @pytest.mark.asyncio
    async def test_recon_udp_no_nmap_returns_error(self, recon_config: ReconConfig) -> None:
        """When nmap is unavailable, recon_udp returns an error result (no crash)."""
        with patch("tools.recon_pipeline.ToolAvailability.check", return_value=False):
            scanner = PrimaryReconScanner(recon_config)
            result = await scanner.recon_udp("10.0.0.50")
        assert result.udp_ports == []
        assert any("nmap" in e.lower() for e in result.errors)

    @pytest.mark.asyncio
    async def test_recon_udp_failure_is_tolerated(self, recon_config: ReconConfig) -> None:
        """A failed nmap UDP run returns a result with an error, not an exception."""
        with patch("tools.recon_pipeline.ToolAvailability.check", return_value=True):
            with patch("tools.recon_pipeline.run_command") as mock_run:
                mock_run.return_value = (False, "", "requires root", 1.0)
                scanner = PrimaryReconScanner(recon_config)
                result = await scanner.recon_udp("10.0.0.50")
        assert result.udp_ports == []
        assert len(result.errors) > 0


# ── TLS enumeration ────────────────────────────────────────────────────────

class TestTlsEnumeration:
    @pytest.mark.asyncio
    async def test_enumerate_tls_populates_ssl_info(self, recon_config: ReconConfig) -> None:
        """_enumerate_tls parses nmap ssl-cert output into svc.ssl_info."""
        nmap_ssl_output = (
            "Nmap scan report for 10.0.0.50\n"
            "Host is up.\n"
            "PORT    STATE SERVICE\n"
            "443/tcp open  https\n"
            "\n"
            "ssl-cert:\n"
            "  Subject: CN=www.example.com\n"
            "  Issuer: CN=Example CA\n"
            "  Public Key type: rsa\n"
            "  Subject Alternative Name: DNS:www.example.com,DNS:example.com\n"
            "  Not valid before: 2024-01-01T00:00:00\n"
            "  Not valid after:  2025-01-01T00:00:00\n"
        )
        with patch("tools.recon_pipeline.ToolAvailability.check", return_value=True):
            with patch("tools.recon_pipeline.run_command") as mock_run:
                mock_run.return_value = (True, nmap_ssl_output, "", 1.0)
                enumerator = SecondaryEnumerator(recon_config)
                result = HostReconResult(
                    target_ip="10.0.0.50",
                    services=[ServiceInfo(port=443, service="https")],
                )
                updated = await enumerator._enumerate_tls(result, result.services)

        svc = updated.services[0]
        assert svc.ssl_info
        assert "example" in svc.ssl_info.get("subject", "").lower()
        assert svc.ssl_info.get("issuer")
        # SAN should include at least one DNS entry.
        assert isinstance(svc.ssl_info.get("san"), list)
        assert any("example.com" in s for s in svc.ssl_info["san"])


# ── SMTP enumeration ───────────────────────────────────────────────────────

class TestSmtpEnumeration:
    @pytest.mark.asyncio
    async def test_enumerate_smtp_populates_smtp_info(self, recon_config: ReconConfig) -> None:
        """_enumerate_smtp parses an EHLO banner into svc.smtp_info."""
        banner = (
            "220 mail.example.com ESMTP Postfix\n"
            "250-mail.example.com\n"
            "250-PIPELINING\n"
            "250-SIZE 10240000\n"
            "250-STARTTLS\n"
            "250-AUTH PLAIN LOGIN\n"
            "250-ENHANCEDSTATUSCODES\n"
            "250-8BITMIME\n"
        )
        with patch("tools.recon_pipeline.ToolAvailability.check", return_value=True):
            with patch("tools.recon_pipeline.run_command") as mock_run:
                mock_run.return_value = (True, banner, "", 1.0)
                enumerator = SecondaryEnumerator(recon_config)
                result = HostReconResult(
                    target_ip="10.0.0.50",
                    services=[ServiceInfo(port=25, service="smtp")],
                )
                updated = await enumerator._enumerate_smtp(result, result.services)

        svc = updated.services[0]
        assert svc.smtp_info
        assert svc.smtp_info.get("supports_starttls") is True
        assert "PLAIN" in svc.smtp_info.get("auth_methods", [])
        assert "LOGIN" in svc.smtp_info.get("auth_methods", [])


# ── DB enumeration ─────────────────────────────────────────────────────────

class TestDbEnumeration:
    @pytest.mark.asyncio
    async def test_enumerate_db_detects_mysql(self, recon_config: ReconConfig) -> None:
        """_enumerate_db parses a MySQL banner into svc.db_info with db_type=mysql."""
        banner = (
            "Nmap scan report for 10.0.0.50\n"
            "PORT     STATE SERVICE\n"
            "3306/tcp open  mysql\n"
            "banner: 5.7.40-log MySQL Community Server\n"
        )
        with patch("tools.recon_pipeline.ToolAvailability.check", return_value=True):
            with patch("tools.recon_pipeline.run_command") as mock_run:
                mock_run.return_value = (True, banner, "", 1.0)
                enumerator = SecondaryEnumerator(recon_config)
                result = HostReconResult(
                    target_ip="10.0.0.50",
                    services=[ServiceInfo(port=3306, service="mysql")],
                )
                updated = await enumerator._enumerate_db(result, result.services)

        svc = updated.services[0]
        assert svc.db_info
        assert svc.db_info.get("db_type") == "mysql"
        assert svc.db_info.get("version")


# ── HostReconResult / ServiceInfo new-field round-trip ─────────────────────

class TestNewFieldsRoundTrip:
    def test_service_info_round_trips_smtp_db_info(self) -> None:
        svc = ServiceInfo(
            port=25,
            service="smtp",
            smtp_info={"supports_starttls": True, "auth_methods": ["PLAIN"]},
            db_info={"db_type": "unknown"},
        )
        d = svc.to_dict()
        assert d["smtp_info"]["supports_starttls"] is True
        assert d["db_info"]["db_type"] == "unknown"
        rebuilt = ServiceInfo.from_dict(d)
        assert rebuilt.smtp_info == svc.smtp_info
        assert rebuilt.db_info == svc.db_info

    def test_host_result_round_trips_new_fields(self) -> None:
        result = HostReconResult(
            target_ip="10.0.0.50",
            udp_ports=[53, 161],
            spider_results=[{"target_ip": "10.0.0.50", "urls_visited": ["/"]}],
            osint={"target_ip": "10.0.0.50", "ipv6_addresses": ["2001:db8::1"]},
            ipv6_addresses=["2001:db8::1"],
        )
        d = result.to_dict()
        assert d["udp_ports"] == [53, 161]
        assert d["ipv6_addresses"] == ["2001:db8::1"]
        assert d["osint"]["ipv6_addresses"] == ["2001:db8::1"]
        assert len(d["spider_results"]) == 1
        rebuilt = HostReconResult.from_dict(d)
        assert rebuilt.udp_ports == [53, 161]
        assert rebuilt.ipv6_addresses == ["2001:db8::1"]
        assert rebuilt.osint["ipv6_addresses"] == ["2001:db8::1"]
        assert len(rebuilt.spider_results) == 1

    def test_from_dict_tolerates_missing_new_keys(self) -> None:
        """Old recon_result.json / attack_states.json without the new keys
        must still load (tolerant from_dict — old-file compat)."""
        old = {
            "target_ip": "10.0.0.50",
            "os_family": "Linux",
            "open_ports": [22, 80],
            "services": [{"port": 22, "service": "ssh"}],
        }
        result = HostReconResult.from_dict(old)
        assert result.target_ip == "10.0.0.50"
        assert result.open_ports == [22, 80]
        assert result.udp_ports == []
        assert result.spider_results == []
        assert result.osint == {}
        assert result.ipv6_addresses == []
        # ServiceInfo.from_dict tolerant of missing smtp_info/db_info too.
        svc = result.services[0]
        assert svc.smtp_info == {}
        assert svc.db_info == {}
