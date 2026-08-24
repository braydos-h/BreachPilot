"""Tests for the broadened service-banner parsing.

Regression: the loop's service-ingestion block only ran for ``check_os``,
``run_exploit_terminal``, ``nmap_scan``, and ``run_nmap`` -- so services
discovered by ``quick_scan``, ``run_full_recon``, and
``get_service_fingerprint`` never updated plan/session state. Also
``parse_service_banners`` only recognized the ``check_os``/nmap format
(``Port 22/tcp: open - OpenSSH_8.5p1``), missing the ``quick_scan`` format
(``Port 22/tcp OPEN (ssh) - banner``) that ``socket_scan`` emits. These
tests pin the broadened coverage + the merged, deduplicated records.
"""

from __future__ import annotations

from tools.validation_utils import parse_service_banners


def test_quick_scan_format_is_parsed():
    sample = (
        "QUICK_SCAN_RESULTS: 10.0.0.5\n"
        "SUMMARY: 2/2 ports open\n"
        "  Port 22/tcp OPEN (ssh) - SSH-2.0-OpenSSH_8.5p1\n"
        "  Port 80/tcp OPEN (http) - Apache/2.4.41\n"
    )
    records = parse_service_banners(sample)
    ports = {r["port"] for r in records}
    assert 22 in ports
    assert 80 in ports
    ssh = [r for r in records if r["port"] == 22][0]
    assert ssh["service"] == "ssh"
    assert "OpenSSH" in ssh["raw_banner"] or ssh["raw_banner"]


def test_quick_scan_no_banner_marker_handled():
    sample = "  Port 445/tcp OPEN (microsoft-ds) - (no banner)\n"
    records = parse_service_banners(sample)
    assert len(records) == 1
    assert records[0]["port"] == 445
    assert records[0]["service"] == "microsoft-ds"
    assert records[0]["raw_banner"] == ""


def test_check_os_and_quick_scan_formats_merge_without_duplicates():
    """A result block carrying BOTH formats must not double-count a port."""
    sample = (
        "TARGET: 10.0.0.5\nOS_VERDICT: LINUX\n"
        "  Port 22/tcp: open - OpenSSH_8.5p1\n"
        "  Port 22/tcp OPEN (ssh) - SSH-2.0-OpenSSH_8.5p1\n"
        "  Port 80/tcp OPEN (http) - Apache/2.4.41\n"
    )
    records = parse_service_banners(sample)
    # Port 22 appears in both formats but must be counted once.
    ssh_records = [r for r in records if r["port"] == 22]
    assert len(ssh_records) == 1
    assert ssh_records[0]["product"] == "OpenSSH"
    # Port 80 only in quick_scan format -- still captured.
    http_records = [r for r in records if r["port"] == 80]
    assert len(http_records) == 1


def test_empty_input_still_returns_empty():
    assert parse_service_banners("") == []


def test_os_verdict_carries_into_quick_scan_records():
    sample = "TARGET: 10.0.0.5\nOS_VERDICT: LINUX\n  Port 22/tcp OPEN (ssh) - SSH-2.0-OpenSSH_8.5p1\n"
    records = parse_service_banners(sample)
    assert records[0]["os_guess"] == "LINUX"
