"""Regression tests for version-aware CVE correlation in recon-first mode."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tools.recon_assessment_cli import _cve_query_from_banner, run_recon_assessment


def test_openssh_banner_uses_server_not_protocol_version() -> None:
    assert _cve_query_from_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13") == (
        "OpenSSH",
        "9.6p1",
    )


def test_missing_banner_does_not_create_a_generic_service_query() -> None:
    assert _cve_query_from_banner("") is None
    assert _cve_query_from_banner("SSH-2.0") is None


class _Session:
    def __init__(self, scan_result: str) -> None:
        self.scan_result = scan_result
        self.calls: list[tuple[str, dict[str, str]]] = []

    async def call_tool(self, name: str, arguments: dict[str, str]):
        self.calls.append((name, arguments))
        text = {
            "check_os": "OS_CHECK_RESULTS:\nOS_VERDICT: LINUX",
            "quick_scan": self.scan_result,
            "search_cve_intel": "No CVEs found in NVD for this query.",
        }[name]
        return SimpleNamespace(content=[SimpleNamespace(text=text)])


@pytest.mark.asyncio
async def test_no_banner_skips_generic_ssh_cve_lookup(tmp_path) -> None:
    session = _Session("QUICK_SCAN_RESULTS: 10.0.0.50\nPort 22/tcp OPEN (ssh) - (no banner)")

    assessment = await run_recon_assessment(
        session=session,
        target_ip="10.0.0.50",
        reports_dir=tmp_path,
    )

    assert not any(name == "search_cve_intel" for name, _ in session.calls)
    assert assessment.cve_findings == []


@pytest.mark.asyncio
async def test_openssh_lookup_uses_product_and_version(tmp_path) -> None:
    session = _Session("QUICK_SCAN_RESULTS: 10.0.0.50\nPort 22/tcp OPEN (ssh) - SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")

    await run_recon_assessment(session=session, target_ip="10.0.0.50", reports_dir=tmp_path)

    assert ("search_cve_intel", {"query": "OpenSSH 9.6p1"}) in session.calls
