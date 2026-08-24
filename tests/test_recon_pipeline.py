"""Tests for recon_pipeline.py — comprehensive coverage of reconnaissance pipeline.

Tests:
- Tool availability checking
- Command execution with retries
- Nmap XML parsing
- RustScan output parsing
- Masscan output parsing
- Service enumeration
- Attack surface summary generation
- Full pipeline integration
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.recon_pipeline import (
    HostReconResult,
    PrimaryReconScanner,
    ReconConfig,
    ReconPipeline,
    SecondaryEnumerator,
    ServiceInfo,
    ToolAvailability,
    run_command,
)

# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def recon_config() -> ReconConfig:
    return ReconConfig(
        nmap_path="nmap",
        rustscan_path="rustscan",
        masscan_path="masscan",
        timeout_seconds=60,
        max_retries=1,
        fallback_enabled=True,
        parallel_secondary=False,  # Disable for predictable tests
    )


@pytest.fixture
def sample_nmap_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sS -sV -O -Pn -T4 --script=vuln,default -p- -oX - 10.0.0.50"
         start="1234567890" version="7.94" xmloutputversion="1.05">
  <host><status state="up" reason="syn-ack"/>
    <address addr="10.0.0.50" addrtype="ipv4"/>
    <hostnames><hostname name="test.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.5p1" extrainfo="Ubuntu">
          <cpe>cpe:/a:openssh:openssh:8.5p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="Apache" version="2.4.41">
          <cpe>cpe:/a:apache:http_server:2.4.41</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="443"><state state="open"/>
        <service name="https" product="Apache" version="2.4.41">
          <cpe>cpe:/a:apache:http_server:2.4.41</cpe>
        </service>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4" accuracy="95">
        <osclass osfamily="Linux" vendor="Linux"/>
      </osmatch>
    </os>
  </host>
</nmaprun>"""


@pytest.fixture
def sample_rustscan_output() -> str:
    return """Open 10.0.0.50:22
Open 10.0.0.50:80
Open 10.0.0.50:443
Done."""


@pytest.fixture
def sample_masscan_output() -> str:
    return """[
{ "ip": "10.0.0.50", "ports": [ { "port": 22, "proto": "tcp", "status": "open" } ] },
{ "ip": "10.0.0.50", "ports": [ { "port": 80, "proto": "tcp", "status": "open" } ] }
]"""


# ── Tool Availability Tests ──────────────────────────────────────────────────


class TestToolAvailability:
    def test_check_available_tool(self) -> None:
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            assert ToolAvailability.check("nmap") is True

    def test_check_unavailable_tool(self) -> None:
        with patch("shutil.which", return_value=None):
            assert ToolAvailability.check("nonexistent_tool") is False

    def test_cache_works(self) -> None:
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            ToolAvailability.reset()
            result1 = ToolAvailability.check("nmap")
            result2 = ToolAvailability.check("nmap")
            assert result1 == result2


# ── Command Execution Tests ──────────────────────────────────────────────────


class TestRunCommand:
    @pytest.mark.asyncio
    async def test_successful_command(self) -> None:
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate.return_value = (b"stdout content", b"")
            mock_exec.return_value = mock_proc

            success, stdout, stderr, elapsed = await run_command(
                ["echo", "hello"],
                timeout=10,
                max_retries=0,
            )
            assert success is True
            assert stdout == "stdout content"
            assert elapsed > 0

    @pytest.mark.asyncio
    async def test_failed_command(self) -> None:
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 1
            mock_proc.communicate.return_value = (b"", b"error message")
            mock_exec.return_value = mock_proc

            success, stdout, stderr, elapsed = await run_command(
                ["false"],
                timeout=10,
                max_retries=0,
            )
            assert success is False
            assert "error message" in stderr

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_proc.returncode = None
            mock_exec.return_value = mock_proc

            success, stdout, stderr, elapsed = await run_command(
                ["sleep", "100"],
                timeout=1,
                max_retries=0,
            )
            assert success is False
            assert "Timeout" in stderr

    @pytest.mark.asyncio
    async def test_retry_success(self) -> None:
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc_fail = AsyncMock()
            mock_proc_fail.returncode = 1
            mock_proc_fail.communicate.return_value = (b"", b"temp error")

            mock_proc_success = AsyncMock()
            mock_proc_success.returncode = 0
            mock_proc_success.communicate.return_value = (b"success", b"")

            mock_exec.side_effect = [mock_proc_fail, mock_proc_success]

            success, stdout, stderr, elapsed = await run_command(
                ["test"],
                timeout=10,
                max_retries=1,
                retry_delay=0.1,
            )
            assert success is True
            assert stdout == "success"

    @pytest.mark.asyncio
    async def test_windows_access_violation_not_retried(self) -> None:
        """0xC0000005 (nmap crash on Windows) is deterministic, not transient.
        run_command must return immediately without sleeping/retrying -- the
        log showed it retried 2x with 5s/7.5s sleeps before falling through."""
        with (
            patch("asyncio.create_subprocess_exec") as mock_exec,
            patch("asyncio.sleep", new=AsyncMock()) as mock_sleep,
        ):
            mock_proc = AsyncMock()
            mock_proc.returncode = 3221225477  # 0xC0000005
            mock_proc.communicate.return_value = (b"", b"access violation")
            mock_exec.return_value = mock_proc

            success, stdout, stderr, elapsed = await run_command(
                ["nmap", "-sS", "10.0.0.50"],
                timeout=10,
                max_retries=2,
                retry_delay=5.0,
            )
            assert success is False
            assert elapsed > 0
            # Only one subprocess attempt -- no retry.
            assert mock_exec.call_count == 1
            # No retry sleep happened.
            mock_sleep.assert_not_called()

    @pytest.mark.asyncio
    async def test_command_not_found_exit_not_retried(self) -> None:
        """Exit 127 / 9009 (command not found) is deterministic -- no retry."""
        for code in (127, 9009):
            with (
                patch("asyncio.create_subprocess_exec") as mock_exec,
                patch("asyncio.sleep", new=AsyncMock()) as mock_sleep,
            ):
                mock_proc = AsyncMock()
                mock_proc.returncode = code
                mock_proc.communicate.return_value = (b"", b"not found")
                mock_exec.return_value = mock_proc

                success, _stdout, _stderr, _elapsed = await run_command(
                    ["nonexistent-tool"],
                    timeout=10,
                    max_retries=2,
                    retry_delay=0.1,
                )
                assert success is False
                assert mock_exec.call_count == 1
                mock_sleep.assert_not_called()


# ── Nmap XML Parsing Tests ─────────────────────────────────────────────────


class TestNmapParsing:
    def test_parse_nmap_xml(self, sample_nmap_xml: str) -> None:
        scanner = PrimaryReconScanner(ReconConfig())
        result = HostReconResult(target_ip="10.0.0.50")
        parsed = scanner._parse_nmap_xml(sample_nmap_xml, result)

        assert parsed.hostname == "test.local"
        assert parsed.os_name == "Linux 5.4"
        assert parsed.os_family == "Linux"
        assert parsed.os_accuracy == 95
        assert len(parsed.open_ports) == 3
        assert 22 in parsed.open_ports
        assert 80 in parsed.open_ports
        assert 443 in parsed.open_ports

    def test_parse_services(self, sample_nmap_xml: str) -> None:
        scanner = PrimaryReconScanner(ReconConfig())
        result = HostReconResult(target_ip="10.0.0.50")
        parsed = scanner._parse_nmap_xml(sample_nmap_xml, result)

        ssh_service = parsed.get_services_by_port(22)
        assert len(ssh_service) == 1
        assert ssh_service[0].service == "ssh"
        assert ssh_service[0].version == "OpenSSH 8.5p1"
        assert "cpe:/a:openssh:openssh:8.5p1" in ssh_service[0].cpe

    def test_parse_grepable_output(self) -> None:
        scanner = PrimaryReconScanner(ReconConfig())
        result = HostReconResult(target_ip="10.0.0.50")
        output = "22/tcp open ssh\n80/tcp open http\n443/tcp open https"
        parsed = scanner._parse_nmap_grepable(output, result)

        assert len(parsed.open_ports) == 3
        assert parsed.open_ports == [22, 80, 443]

    def test_ttl_to_os_family(self) -> None:
        scanner = PrimaryReconScanner(ReconConfig())
        assert scanner._ttl_to_os_family(64) == "Linux/Unix"
        assert scanner._ttl_to_os_family(128) == "Windows"
        assert scanner._ttl_to_os_family(255) == "Cisco/Network"
        assert scanner._ttl_to_os_family(0) == "Unknown"


# ── RustScan Parsing Tests ─────────────────────────────────────────────────


class TestRustScanParsing:
    def test_extract_ports(self, sample_rustscan_output: str) -> None:
        scanner = PrimaryReconScanner(ReconConfig())
        ports = scanner._extract_ports_from_rustscan(sample_rustscan_output)
        assert ports == [22, 80, 443]

    def test_extract_ports_empty(self) -> None:
        scanner = PrimaryReconScanner(ReconConfig())
        ports = scanner._extract_ports_from_rustscan("")
        assert ports == []

    def test_extract_ports_alternative_format(self) -> None:
        scanner = PrimaryReconScanner(ReconConfig())
        output = "22 -> Open\n80 -> Open\n443 -> Closed"
        ports = scanner._extract_ports_from_rustscan(output)
        assert ports == [22, 80]


# ── Masscan Parsing Tests ──────────────────────────────────────────────────


class TestMasscanParsing:
    def test_extract_ports_json(self, sample_masscan_output: str) -> None:
        scanner = PrimaryReconScanner(ReconConfig())
        ports = scanner._extract_ports_from_masscan(sample_masscan_output)
        assert ports == [22, 80]

    def test_extract_ports_fallback_regex(self) -> None:
        scanner = PrimaryReconScanner(ReconConfig())
        output = '{"port": 22, "proto": "tcp"}\n{"port": 443, "proto": "tcp"}'
        ports = scanner._extract_ports_from_masscan(output)
        assert ports == [22, 443]

    def test_extract_ports_invalid_json(self) -> None:
        scanner = PrimaryReconScanner(ReconConfig())
        ports = scanner._extract_ports_from_masscan("invalid json")
        assert ports == []


# ── HostReconResult Tests ──────────────────────────────────────────────────


class TestHostReconResult:
    def test_get_services_by_name(self) -> None:
        result = HostReconResult(
            target_ip="10.0.0.50",
            services=[
                ServiceInfo(port=22, service="ssh"),
                ServiceInfo(port=80, service="http"),
                ServiceInfo(port=443, service="https"),
            ],
        )
        ssh_services = result.get_services_by_name("ssh")
        assert len(ssh_services) == 1
        assert ssh_services[0].port == 22

    def test_get_services_by_port(self) -> None:
        result = HostReconResult(
            target_ip="10.0.0.50",
            services=[
                ServiceInfo(port=22, service="ssh"),
                ServiceInfo(port=80, service="http"),
            ],
        )
        services = result.get_services_by_port(80)
        assert len(services) == 1
        assert services[0].service == "http"

    def test_has_service(self) -> None:
        result = HostReconResult(
            target_ip="10.0.0.50",
            services=[ServiceInfo(port=22, service="ssh")],
        )
        assert result.has_service("ssh") is True
        assert result.has_service("ftp") is False

    def test_has_port(self) -> None:
        result = HostReconResult(
            target_ip="10.0.0.50",
            open_ports=[22, 80, 443],
        )
        assert result.has_port(80) is True
        assert result.has_port(9999) is False

    def test_to_dict(self) -> None:
        result = HostReconResult(
            target_ip="10.0.0.50",
            services=[ServiceInfo(port=22, service="ssh")],
            open_ports=[22],
        )
        d = result.to_dict()
        assert d["target_ip"] == "10.0.0.50"
        assert d["open_ports"] == [22]
        assert len(d["services"]) == 1


# ── Secondary Enumeration Tests ────────────────────────────────────────────


class TestSecondaryEnumeration:
    @pytest.mark.asyncio
    async def test_enumerate_http(self, recon_config: ReconConfig) -> None:
        with patch("tools.recon_pipeline.run_command") as mock_run:
            mock_run.return_value = (True, "Server: Apache/2.4.41", "", 1.0)

            enumerator = SecondaryEnumerator(recon_config)
            result = HostReconResult(
                target_ip="10.0.0.50",
                services=[ServiceInfo(port=80, service="http")],
            )
            updated = await enumerator._enumerate_http(result, result.services)
            assert len(updated.services) >= 1

    @pytest.mark.asyncio
    async def test_enumerate_ssh(self, recon_config: ReconConfig) -> None:
        with patch("tools.recon_pipeline.run_command") as mock_run:
            mock_run.return_value = (True, "arcfour", "", 1.0)

            enumerator = SecondaryEnumerator(recon_config)
            result = HostReconResult(
                target_ip="10.0.0.50",
                services=[ServiceInfo(port=22, service="ssh", version="OpenSSH 8.5p1")],
            )
            updated = await enumerator._enumerate_ssh(result, result.services)
            assert len(updated.warnings) > 0
            assert any("weak" in w.lower() for w in updated.warnings)

    @pytest.mark.asyncio
    async def test_enumerate_smb(self, recon_config: ReconConfig) -> None:
        with patch("tools.recon_pipeline.run_command") as mock_run:
            mock_run.return_value = (True, "Sharename\n| test_share\n|", "", 1.0)

            enumerator = SecondaryEnumerator(recon_config)
            result = HostReconResult(
                target_ip="10.0.0.50",
                services=[ServiceInfo(port=445, service="microsoft-ds")],
            )
            updated = await enumerator._enumerate_smb(result, result.services)
            assert len(updated.evidence_refs) > 0


# ── Pipeline Integration Tests ───────────────────────────────────────────────


class TestReconPipeline:
    @pytest.mark.asyncio
    async def test_recon_host(self, recon_config: ReconConfig, sample_nmap_xml: str) -> None:
        with patch("tools.recon_pipeline.ToolAvailability.check", return_value=True):
            with patch("tools.recon_pipeline.run_command") as mock_run:
                mock_run.return_value = (True, sample_nmap_xml, "", 5.0)

                pipeline = ReconPipeline(recon_config)
                result = await pipeline.recon_host("10.0.0.50")

                assert result.target_ip == "10.0.0.50"
                assert len(result.open_ports) > 0
                assert result.scan_duration > 0

    @pytest.mark.asyncio
    async def test_recon_host_no_ports(self, recon_config: ReconConfig) -> None:
        # Patch the native socket-scan fallback too, otherwise a test run on a
        # machine that can actually reach 10.0.0.50 would find real open ports
        # and break the "no ports" assertion. The fallback is real network I/O
        # the test never intended to exercise.
        async def _no_open_ports(_target: str, _ports):
            return []

        with (
            patch("tools.recon_pipeline.ToolAvailability.check", return_value=True),
            patch("tools.recon_pipeline.run_command") as mock_run,
            patch("tools.socket_scan.socket_scan", side_effect=_no_open_ports),
        ):
            mock_run.return_value = (True, "", "", 1.0)

            pipeline = ReconPipeline(recon_config)
            result = await pipeline.recon_host("10.0.0.50")

            assert len(result.open_ports) == 0
            assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_recon_hosts_parallel(self, recon_config: ReconConfig, sample_nmap_xml: str) -> None:
        with patch("tools.recon_pipeline.ToolAvailability.check", return_value=True):
            with patch("tools.recon_pipeline.run_command") as mock_run:
                mock_run.return_value = (True, sample_nmap_xml, "", 5.0)

                pipeline = ReconPipeline(recon_config)
                results = await pipeline.recon_hosts(["10.0.0.50", "10.0.0.51"])

                assert len(results) == 2
                for r in results:
                    if not isinstance(r, Exception):
                        assert len(r.open_ports) > 0

    def test_attack_surface_summary(self, recon_config: ReconConfig) -> None:
        result = HostReconResult(
            target_ip="10.0.0.50",
            os_family="Linux",
            services=[
                ServiceInfo(port=22, service="ssh", version="OpenSSH 8.5p1"),
                ServiceInfo(port=80, service="http"),
                ServiceInfo(port=445, service="microsoft-ds"),
            ],
            open_ports=[22, 80, 445],
        )
        pipeline = ReconPipeline(recon_config)
        summary = pipeline.get_attack_surface_summary(result)

        assert summary["target_ip"] == "10.0.0.50"
        assert summary["os_family"] == "Linux"
        assert summary["total_open_ports"] == 3
        assert len(summary["high_value_targets"]) > 0
        assert len(summary["web_targets"]) > 0
        assert len(summary["credential_targets"]) > 0
        assert len(summary["lateral_movement_targets"]) > 0
        assert "recommended_attack_modules" in summary


# ── Config Tests ─────────────────────────────────────────────────────────────


class TestReconConfig:
    def test_default_config(self) -> None:
        config = ReconConfig()
        assert config.nmap_path == "nmap"
        assert config.timeout_seconds == 300
        assert config.max_retries == 2
        assert config.fallback_enabled is True

    def test_custom_config(self) -> None:
        config = ReconConfig(
            nmap_path="/usr/local/bin/nmap",
            timeout_seconds=120,
            aggression_level="stealth",
        )
        assert config.nmap_path == "/usr/local/bin/nmap"
        assert config.timeout_seconds == 120
        assert config.aggression_level == "stealth"


# ── Regression Tests (H7/H10/M12-M15) ───────────────────────────────────────


class TestRegressions:
    """Regression coverage for bugs fixed in the lazy-canyon fix pass."""

    @pytest.mark.asyncio
    async def test_enumerate_host_does_not_duplicate_evidence(self) -> None:
        """H10: the shared result is mutated in place; merging it back into
        itself must not duplicate evidence/warnings/errors."""
        config = ReconConfig(max_concurrent_secondary=3)
        enumerator = SecondaryEnumerator(config)

        async def fake_http(result: HostReconResult, services: list) -> HostReconResult:
            result.evidence_refs.append("nikto:80")
            result.warnings.append("warn-1")
            result.errors.append("err-1")
            return result

        enumerator._enumerate_http = fake_http  # type: ignore[assignment]
        result = HostReconResult(
            target_ip="10.0.0.50",
            services=[ServiceInfo(port=80, service="http")],
        )
        out = await enumerator.enumerate_host(result)
        # With the old self-merge block, each list would be doubled because
        # the shared result was extended with itself. They must stay singular.
        assert out.evidence_refs == ["nikto:80"]
        assert out.warnings == ["warn-1"]
        assert out.errors == ["err-1"]

    @pytest.mark.asyncio
    async def test_enumerate_host_bounds_concurrency(self) -> None:
        """M12: coroutines are gathered through a semaphore wrapper so at most
        ``max_concurrent_secondary`` run at once (pre-creating Tasks would have
        started them immediately, defeating the limit)."""
        config = ReconConfig(max_concurrent_secondary=2)
        enumerator = SecondaryEnumerator(config)

        current = 0
        peak = 0

        async def fake_enum(result: HostReconResult, services: list) -> HostReconResult:
            nonlocal current, peak
            current += 1
            peak = max(peak, current)
            await asyncio.sleep(0.2)
            current -= 1
            return result

        for name in (
            "_enumerate_http",
            "_enumerate_ssh",
            "_enumerate_smb",
            "_enumerate_ldap",
            "_enumerate_ftp",
            "_enumerate_redis",
            "_enumerate_elasticsearch",
            "_enumerate_docker_k8s",
            "_enumerate_rdp",
        ):
            setattr(enumerator, name, fake_enum)

        result = HostReconResult(
            target_ip="10.0.0.50",
            services=[
                ServiceInfo(port=80, service="http"),
                ServiceInfo(port=22, service="ssh"),
                ServiceInfo(port=445, service="microsoft-ds"),
                ServiceInfo(port=389, service="ldap"),
                ServiceInfo(port=21, service="ftp"),
                ServiceInfo(port=6379, service="redis"),
            ],
        )
        await enumerator.enumerate_host(result)
        assert peak <= 2
        # Six branches are dispatched, so the limit of 2 should be saturated.
        assert peak == 2

    @pytest.mark.asyncio
    async def test_run_command_kills_process_on_timeout(self) -> None:
        """M15: on timeout run_command must kill the subprocess (group) and
        must start it with start_new_session=True."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = None
            mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_exec.return_value = mock_proc

            with patch("tools.recon_pipeline._kill_process", new=AsyncMock()) as mock_kill:
                success, _stdout, stderr, _elapsed = await run_command(
                    ["sleep", "100"],
                    timeout=1,
                    max_retries=0,
                )
                assert success is False
                assert "Timeout" in stderr
                mock_kill.assert_awaited()

            # The subprocess must be started in its own session/process-group.
            assert mock_exec.call_args.kwargs.get("start_new_session") is True

    @pytest.mark.asyncio
    async def test_run_command_kills_process_on_exception(self) -> None:
        """M15: the generic except-Exception branch also kills the process
        before recording the error."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = None
            # communicate raises a non-timeout error -> generic except branch.
            mock_proc.communicate = AsyncMock(side_effect=RuntimeError("boom"))
            mock_exec.return_value = mock_proc

            with patch("tools.recon_pipeline._kill_process", new=AsyncMock()) as mock_kill:
                success, _stdout, stderr, _elapsed = await run_command(
                    ["sleep", "100"],
                    timeout=10,
                    max_retries=0,
                )
                assert success is False
                assert "boom" in stderr
                mock_kill.assert_awaited()

    def test_kill_process_uses_process_group_on_posix(self) -> None:
        """M15: _kill_process targets the process group via os.killpg when
        available (POSIX), falling back to proc.kill() otherwise."""
        from types import SimpleNamespace

        from tools.recon_pipeline import _kill_process

        # POSIX path: os.killpg present -> killpg used, proc.kill not called.
        mock_killpg = MagicMock()
        fake_os_posix = SimpleNamespace(killpg=mock_killpg, getpgid=lambda pid: 1234)
        fake_signal = SimpleNamespace(SIGKILL=9)
        with patch("tools.recon_pipeline.os", fake_os_posix), patch("tools.recon_pipeline.signal", fake_signal):
            mock_proc = MagicMock()
            mock_proc.pid = 99
            mock_proc.wait = AsyncMock()
            asyncio.run(_kill_process(mock_proc))
            mock_killpg.assert_called_once_with(1234, 9)
            mock_proc.kill.assert_not_called()

        # Windows path: os has no killpg attribute -> fallback to proc.kill().
        fake_os_win = SimpleNamespace(getpgid=lambda pid: 1234)
        with patch("tools.recon_pipeline.os", fake_os_win):
            mock_proc = MagicMock()
            mock_proc.pid = 99
            mock_proc.kill = MagicMock(return_value=None)
            mock_proc.wait = AsyncMock()
            asyncio.run(_kill_process(mock_proc))
            mock_proc.kill.assert_called_once()

    def test_map_openssh_cves_matches_space_separator(self) -> None:
        """M14: the OpenSSH version regex must accept a whitespace separator
        between 'openssh' and the version number."""
        enumerator = SecondaryEnumerator(ReconConfig())
        cves = enumerator._map_openssh_cves("openssh 8.5p1")
        assert len(cves) > 0
        assert "CVE-2024-6387 (regreSSHion)" in cves

    def test_map_openssh_cves_matches_slash_separator(self) -> None:
        """M14: the existing slash/underscore/dash separators still match."""
        enumerator = SecondaryEnumerator(ReconConfig())
        cves = enumerator._map_openssh_cves("openssh-8.5p1")
        assert "CVE-2024-6387 (regreSSHion)" in cves

    def test_technologies_round_trip(self) -> None:
        """M13: technologies survives to_dict/from_dict."""
        svc = ServiceInfo(
            port=80,
            service="http",
            technologies=["Server: Apache/2.4.41", "X-Powered-By: PHP/7.4"],
        )
        d = svc.to_dict()
        assert d["technologies"] == ["Server: Apache/2.4.41", "X-Powered-By: PHP/7.4"]
        restored = ServiceInfo.from_dict(d)
        assert restored.technologies == ["Server: Apache/2.4.41", "X-Powered-By: PHP/7.4"]

    def test_technologies_defaults_empty(self) -> None:
        """M13: technologies defaults to an empty list and is tolerant of
        missing keys in older serialized state."""
        svc = ServiceInfo(port=80, service="http")
        assert svc.technologies == []
        restored = ServiceInfo.from_dict({"port": 80, "service": "http"})
        assert restored.technologies == []

    @pytest.mark.asyncio
    async def test_enumerate_http_sets_technologies(self, recon_config: ReconConfig) -> None:
        """M13: _enumerate_http stores fingerprinted technologies on
        svc.technologies instead of the old non-existent new_technologies."""
        with patch("tools.recon_pipeline.ToolAvailability.check", return_value=True):
            with patch("tools.recon_pipeline.run_command") as mock_run:
                mock_run.return_value = (True, "Server: Apache/2.4.41", "", 1.0)
                enumerator = SecondaryEnumerator(recon_config)
                result = HostReconResult(
                    target_ip="10.0.0.50",
                    services=[ServiceInfo(port=80, service="http")],
                )
                await enumerator._enumerate_http(result, result.services)
                assert result.services[0].technologies
                assert any("Apache" in t for t in result.services[0].technologies)

    @pytest.mark.asyncio
    async def test_enumerate_redis_rejects_invalid_target(self) -> None:
        """H7: _enumerate_redis refuses non-IPv4 targets and skips spawning any
        subprocess (defense-in-depth against shell injection)."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            enumerator = SecondaryEnumerator(ReconConfig())
            result = HostReconResult(
                target_ip="10.0.0.50; rm -rf /",
                services=[ServiceInfo(port=6379, service="redis")],
            )
            out = await enumerator._enumerate_redis(result, result.services)
            # No subprocess spawned, no evidence recorded.
            mock_exec.assert_not_called()
            assert out.evidence_refs == []

    @pytest.mark.asyncio
    async def test_enumerate_redis_no_shell_injection(self) -> None:
        """H7: _enumerate_redis talks to nc via an argv list (no bash -c) and
        writes INFO to stdin."""
        with patch("tools.recon_pipeline.ToolAvailability.check", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_proc = AsyncMock()
                mock_proc.returncode = 0
                mock_proc.communicate = AsyncMock(return_value=(b"redis_version:7.0.0\r\n", b""))
                mock_exec.return_value = mock_proc

                enumerator = SecondaryEnumerator(ReconConfig())
                result = HostReconResult(
                    target_ip="10.0.0.50",
                    services=[ServiceInfo(port=6379, service="redis")],
                )
                out = await enumerator._enumerate_redis(result, result.services)

                # Invoked as an argv list with nc first (no bash -c wrapper).
                args, kwargs = mock_exec.call_args
                assert args[0] == "nc"
                assert "bash" not in args and "-c" not in args
                assert list(args[1:]) == ["-w", "3", "10.0.0.50", "6379"]
                assert kwargs.get("stdin") is asyncio.subprocess.PIPE
                # INFO command sent via stdin, not shell echo.
                mock_proc.communicate.assert_awaited()
                communicated_kwargs = mock_proc.communicate.call_args.kwargs
                assert communicated_kwargs.get("input") == b"INFO\n"
                assert "redis_info:6379" in out.evidence_refs
