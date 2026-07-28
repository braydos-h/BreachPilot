"""Phase 3 Round 2 — web spider + passive OSINT enumerators.

Mocks ``tools.recon_enrichers.http_spider`` and ``tools.recon_osint.run_osint``
so no network is touched. The enumerators are exercised through
``SecondaryEnumerator`` with ``extended_enumerators=True``.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch

from tools.recon_pipeline import (
    HostReconResult,
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


class TestWebSpiderEnumerator:
    @pytest.mark.asyncio
    async def test_enumerate_web_spider_appends_result(
        self, recon_config: ReconConfig
    ) -> None:
        """_enumerate_web_spider appends the http_spider result dict to
        result.spider_results."""
        canned = {
            "target_ip": "10.0.0.50",
            "port": 80,
            "urls_visited": ["/", "/about"],
            "links": ["/login"],
            "forms": 1,
            "status_codes": {"/": 200, "/about": 200},
            "technologies": ["Apache/2.4.41"],
        }
        with patch("tools.recon_enrichers.http_spider", return_value=canned) as mock_spider:
            enumerator = SecondaryEnumerator(recon_config)
            result = HostReconResult(
                target_ip="10.0.0.50",
                services=[ServiceInfo(port=80, service="http")],
            )
            updated = await enumerator._enumerate_web_spider(result, result.services)

        assert mock_spider.called
        # Called with the single target IP, the http port, scheme http.
        args, kwargs = mock_spider.call_args
        assert args[0] == "10.0.0.50"
        assert args[1] == 80
        assert kwargs.get("scheme") == "http"
        assert len(updated.spider_results) == 1
        assert updated.spider_results[0] == canned
        assert "spider:80" in updated.evidence_refs

    @pytest.mark.asyncio
    async def test_enumerate_web_spider_https_scheme(
        self, recon_config: ReconConfig
    ) -> None:
        """https service / 443 port -> scheme=https."""
        canned = {"target_ip": "10.0.0.50", "port": 443, "urls_visited": ["/"]}
        with patch("tools.recon_enrichers.http_spider", return_value=canned) as mock_spider:
            enumerator = SecondaryEnumerator(recon_config)
            result = HostReconResult(
                target_ip="10.0.0.50",
                services=[ServiceInfo(port=443, service="https")],
            )
            await enumerator._enumerate_web_spider(result, result.services)
        _, kwargs = mock_spider.call_args
        assert kwargs.get("scheme") == "https"

    @pytest.mark.asyncio
    async def test_enumerate_web_spider_swallows_exception(
        self, recon_config: ReconConfig
    ) -> None:
        """A spider exception must not crash the pipeline."""
        with patch("tools.recon_enrichers.http_spider", side_effect=RuntimeError("boom")):
            enumerator = SecondaryEnumerator(recon_config)
            result = HostReconResult(
                target_ip="10.0.0.50",
                services=[ServiceInfo(port=80, service="http")],
            )
            updated = await enumerator._enumerate_web_spider(result, result.services)
        assert updated.spider_results == []
        assert any("spider" in w.lower() for w in updated.warnings)


class TestOsintEnumerator:
    @pytest.mark.asyncio
    async def test_enumerate_osint_populates_osint_and_ipv6(
        self, recon_config: ReconConfig
    ) -> None:
        """_enumerate_osint stores run_osint dict in result.osint and copies
        ipv6_addresses into result.ipv6_addresses."""
        canned = {
            "target_ip": "10.0.0.50",
            "hostname": "host.example.com",
            "ipv6_addresses": ["2001:db8::1", "2001:db8::2"],
            "reverse_dns": "host.example.com",
            "cert_transparency": {"domain": "host.example.com", "certs": [], "count": 0},
            "shodan": {"enabled": False, "note": "no key"},
        }
        with patch("tools.recon_osint.run_osint", return_value=canned) as mock_osint:
            enumerator = SecondaryEnumerator(recon_config)
            result = HostReconResult(target_ip="10.0.0.50", hostname="host.example.com")
            updated = await enumerator._enumerate_osint(result, [])

        assert mock_osint.called
        assert updated.osint == canned
        assert updated.ipv6_addresses == ["2001:db8::1", "2001:db8::2"]

    @pytest.mark.asyncio
    async def test_enumerate_osint_swallows_failure(
        self, recon_config: ReconConfig
    ) -> None:
        """An OSINT failure must never break the pipeline — osint stays {}."""
        with patch("tools.recon_osint.run_osint", side_effect=RuntimeError("dns down")):
            enumerator = SecondaryEnumerator(recon_config)
            result = HostReconResult(target_ip="10.0.0.50")
            updated = await enumerator._enumerate_osint(result, [])
        assert updated.osint == {}
        assert updated.ipv6_addresses == []
        assert any("osint" in w.lower() for w in updated.warnings)

    @pytest.mark.asyncio
    async def test_enumerate_osint_empty_ipv6_is_safe(
        self, recon_config: ReconConfig
    ) -> None:
        """run_osint returning no ipv6 must leave ipv6_addresses as [] (no crash)."""
        canned = {
            "target_ip": "10.0.0.50",
            "ipv6_addresses": [],
            "reverse_dns": "",
            "cert_transparency": {"count": 0},
            "shodan": {"enabled": False},
        }
        with patch("tools.recon_osint.run_osint", return_value=canned):
            enumerator = SecondaryEnumerator(recon_config)
            result = HostReconResult(target_ip="10.0.0.50")
            updated = await enumerator._enumerate_osint(result, [])
        assert updated.osint == canned
        assert updated.ipv6_addresses == []