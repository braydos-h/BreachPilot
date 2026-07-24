"""Tests for attack_modules.py — comprehensive coverage of all attack modules.

Tests:
- Module registration and discovery
- Applicability scoring
- Module execution (mocked)
- Script generation
- CVE mapping
- Service-specific modules
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from tools.attack_modules import (
    AttackModule,
    ModuleContext,
    list_modules,
    find_modules,
    get_module,
    Log4jRCE,
    SMBGhost,
    EternalBlue,
    BasicAuthBuster,
    APIFuzzer,
    RDPBlueKeep,
    SSHBruteForce,
    RegreSSHion,
    OpenSSHCVECheck,
    SMBRelay,
    SMBNullSession,
    WebShellUpload,
    SQLInjection,
    XSSScanner,
    CredentialSpray,
    LinuxPrivescCheck,
    WindowsPrivescCheck,
    SUIDEnumeration,
    KernelExploitCheck,
    ContainerBreakout,
    FTPAnonymous,
    RedisExploit,
    ElasticsearchExploit,
    LDAPAnonymous,
    RDPExploit,
    DeserializeAttack,
)


# ── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def ctx_http() -> ModuleContext:
    return ModuleContext(
        target_ip="10.0.0.50",
        target_os="Linux",
        services=[{"service": "http", "port": "80/tcp"}],
        cves=["CVE-2021-44228"],
    )


@pytest.fixture
def ctx_ssh() -> ModuleContext:
    return ModuleContext(
        target_ip="10.0.0.50",
        target_os="Linux",
        services=[{"service": "ssh", "port": "22/tcp"}],
        cves=["CVE-2024-6387"],
    )


@pytest.fixture
def ctx_smb() -> ModuleContext:
    return ModuleContext(
        target_ip="10.0.0.50",
        target_os="Windows",
        services=[{"service": "microsoft-ds", "port": "445/tcp"}],
        cves=["CVE-2020-0796"],
    )


@pytest.fixture
def ctx_multi() -> ModuleContext:
    return ModuleContext(
        target_ip="10.0.0.50",
        target_os="Linux",
        services=[
            {"service": "http", "port": "80/tcp"},
            {"service": "ssh", "port": "22/tcp"},
            {"service": "smb", "port": "445/tcp"},
        ],
        cves=["CVE-2021-44228", "CVE-2024-6387"],
    )


# ── Registry Tests ─────────────────────────────────────────────────────────

class TestModuleRegistry:
    def test_list_modules_returns_all(self) -> None:
        modules = list_modules()
        assert len(modules) >= 6
        names = [m.name for m in modules]
        assert "Log4jRCE" in names
        assert "SSHBruteForce" in names
        assert "SMBRelay" in names

    def test_get_module_found(self) -> None:
        mod = get_module("Log4jRCE")
        assert mod is not None
        assert mod.name == "Log4jRCE"

    def test_get_module_not_found(self) -> None:
        mod = get_module("NonExistent")
        assert mod is None

    def test_get_module_case_insensitive(self) -> None:
        mod = get_module("log4jrce")
        assert mod is not None
        assert mod.name == "Log4jRCE"


# ── Applicability Tests ────────────────────────────────────────────────────

class TestApplicability:
    def test_log4j_high_score_with_http(self, ctx_http: ModuleContext) -> None:
        mod = Log4jRCE()
        score = mod.applicability(ctx_http)
        assert score >= 70  # 30 for service + 40 for CVE

    def test_log4j_zero_without_http(self, ctx_ssh: ModuleContext) -> None:
        mod = Log4jRCE()
        score = mod.applicability(ctx_ssh)
        assert score == 0

    def test_ssh_brute_force_with_ssh(self, ctx_ssh: ModuleContext) -> None:
        mod = SSHBruteForce()
        score = mod.applicability(ctx_ssh)
        assert score >= 30

    def test_smb_ghost_with_smb(self, ctx_smb: ModuleContext) -> None:
        mod = SMBGhost()
        score = mod.applicability(ctx_smb)
        assert score >= 70  # 30 for service + 40 for CVE

    def test_find_modules_sorted(self, ctx_multi: ModuleContext) -> None:
        scored = find_modules(ctx_multi)
        assert len(scored) > 0
        # Should be sorted by score descending
        scores = [s for s, _ in scored]
        assert scores == sorted(scores, reverse=True)

    def test_find_modules_filters_zero(self, ctx_ssh: ModuleContext) -> None:
        scored = find_modules(ctx_ssh)
        # Log4j should not appear for SSH-only target
        names = [m.name for _, m in scored]
        assert "Log4jRCE" not in names


# ── Module Execution Tests ─────────────────────────────────────────────────

class TestModuleExecution:
    def test_log4j_rce_run(self, ctx_http: ModuleContext) -> None:
        mod = Log4jRCE()
        result = mod.run(ctx_http)
        assert result["status"] == "script_generated"
        assert "script" in result
        assert ctx_http.target_ip in result["script"]

    def test_ssh_brute_force_run(self, ctx_ssh: ModuleContext) -> None:
        mod = SSHBruteForce()
        result = mod.run(ctx_ssh)
        assert result["status"] == "script_generated"
        assert "hydra" in result["suggested_command"]
        assert ctx_ssh.target_ip in result["script"]

    def test_regreSSHion_run(self, ctx_ssh: ModuleContext) -> None:
        mod = RegreSSHion()
        result = mod.run(ctx_ssh)
        assert result["status"] == "info"
        assert "CVE-2024-6387" in result["note"]

    def test_smb_relay_run(self, ctx_smb: ModuleContext) -> None:
        mod = SMBRelay()
        result = mod.run(ctx_smb)
        assert result["status"] == "info"
        assert "ntlmrelayx" in result["suggested_command"]

    def test_smb_null_session_run(self, ctx_smb: ModuleContext) -> None:
        mod = SMBNullSession()
        result = mod.run(ctx_smb)
        assert result["status"] == "script_generated"
        assert "smbclient" in result["script"]

    def test_webshell_upload_run(self, ctx_http: ModuleContext) -> None:
        mod = WebShellUpload()
        result = mod.run(ctx_http)
        assert result["status"] == "script_generated"
        assert "shell.php" in result["script"]

    def test_sql_injection_run(self, ctx_http: ModuleContext) -> None:
        mod = SQLInjection()
        result = mod.run(ctx_http)
        assert result["status"] == "info"
        assert "sqlmap" in result["suggested_command"]

    def test_xss_scanner_run(self, ctx_http: ModuleContext) -> None:
        mod = XSSScanner()
        result = mod.run(ctx_http)
        assert result["status"] == "script_generated"
        assert "alert" in result["script"]

    def test_linux_privesc_run(self, ctx_ssh: ModuleContext) -> None:
        mod = LinuxPrivescCheck()
        result = mod.run(ctx_ssh)
        assert result["status"] == "script_generated"
        assert "suid" in result["script"].lower()

    def test_container_breakout_run(self, ctx_ssh: ModuleContext) -> None:
        mod = ContainerBreakout()
        result = mod.run(ctx_ssh)
        assert result["status"] == "script_generated"
        assert "docker" in result["script"].lower()

    def test_ftp_anonymous_run(self) -> None:
        ctx = ModuleContext(target_ip="10.0.0.50", services=[{"service": "ftp", "port": "21/tcp"}])
        mod = FTPAnonymous()
        result = mod.run(ctx)
        assert result["status"] == "info"
        assert "anonymous" in result["suggested_command"]

    def test_redis_exploit_run(self) -> None:
        ctx = ModuleContext(target_ip="10.0.0.50", services=[{"service": "redis", "port": "6379/tcp"}])
        mod = RedisExploit()
        result = mod.run(ctx)
        assert result["status"] == "info"
        assert "redis-cli" in result["suggested_command"]

    def test_ldap_anonymous_run(self) -> None:
        ctx = ModuleContext(target_ip="10.0.0.50", services=[{"service": "ldap", "port": "389/tcp"}])
        mod = LDAPAnonymous()
        result = mod.run(ctx)
        assert result["status"] == "info"
        assert "ldapsearch" in result["suggested_command"]


# ── CVE Mapping Tests ──────────────────────────────────────────────────────

class TestCVEMapping:
    def test_openssh_cve_check_maps_cves(self, ctx_ssh: ModuleContext) -> None:
        mod = OpenSSHCVECheck()
        # Manually set version in services
        ctx_ssh.services = [{"service": "ssh", "port": "22/tcp", "version": "OpenSSH 8.5p1"}]
        result = mod.run(ctx_ssh)
        assert result["status"] == "info"
        assert len(result["cves"]) > 0
        cve_ids = [c["cve"] for c in result["cves"]]
        assert "CVE-2024-6387 (regreSSHion)" in cve_ids or any("CVE-2024-6387" in c for c in cve_ids)

    def test_openssh_cve_check_no_version(self) -> None:
        ctx = ModuleContext(target_ip="10.0.0.50", services=[{"service": "ssh", "port": "22/tcp"}])
        mod = OpenSSHCVECheck()
        result = mod.run(ctx)
        assert result["status"] == "info"
        assert len(result["cves"]) == 0

    def test_openssh_cve_check_old_version(self) -> None:
        ctx = ModuleContext(
            target_ip="10.0.0.50",
            services=[{"service": "ssh", "port": "22/tcp", "version": "OpenSSH 7.2p2"}],
        )
        mod = OpenSSHCVECheck()
        result = mod.run(ctx)
        assert len(result["cves"]) > 0


# ── Script Generation Tests ────────────────────────────────────────────────

class TestScriptGeneration:
    def test_scripts_contain_target_ip(self, ctx_multi: ModuleContext) -> None:
        for mod in list_modules():
            if hasattr(mod, "generate_python_script"):
                script = mod.generate_python_script(ctx_multi)
                if script:
                    assert ctx_multi.target_ip in script

    def test_scripts_are_valid_python(self, ctx_multi: ModuleContext) -> None:
        import ast
        for mod in list_modules():
            if hasattr(mod, "generate_python_script"):
                script = mod.generate_python_script(ctx_multi)
                if script:
                    try:
                        ast.parse(script)
                    except SyntaxError as e:
                        pytest.fail(f"{mod.name} generated invalid Python: {e}")


# ── Edge Cases ─────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_context(self) -> None:
        ctx = ModuleContext(target_ip="10.0.0.50")
        mod = Log4jRCE()
        score = mod.applicability(ctx)
        assert score == 0

    def test_module_to_json(self, ctx_http: ModuleContext) -> None:
        mod = Log4jRCE()
        json_data = mod.to_json()
        assert json_data["name"] == "Log4jRCE"
        assert "http" in json_data["target_services"]

    def test_unknown_service_no_crash(self) -> None:
        ctx = ModuleContext(
            target_ip="10.0.0.50",
            services=[{"service": "unknown-service", "port": "9999/tcp"}],
        )
        for mod in list_modules():
            score = mod.applicability(ctx)
            assert 0 <= score <= 100

    def test_multiple_services_high_score(self, ctx_multi: ModuleContext) -> None:
        mod = Log4jRCE()
        score = mod.applicability(ctx_multi)
        assert score >= 30  # At least HTTP match

        mod2 = SSHBruteForce()
        score2 = mod2.applicability(ctx_multi)
        assert score2 >= 30  # At least SSH match


# ── Regression: PHP gadget brace bug (M28) ─────────────────────────────────

class TestPhpGadgetBraces:
    """M28: the generated DeserializeAttack script embeds a nested f-string for
    generate_php_gadget. The outer f-string must render an *inner* f-string that
    evaluates len(class_name)/class_name and emits a literal {}. Previously the
    brace counts were wrong so the inner f-string emitted literal
    '{{len(class_name)}}' instead of the evaluated value.
    """

    @staticmethod
    def _extract_gadget_func(script: str):
        """Pull just the generate_php_gadget function out of the generated
        script and exec it in an isolated namespace (avoids the module-level
        network/probe code at the bottom of the generated script)."""
        import ast
        tree = ast.parse(script)
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "generate_php_gadget":
                ns: dict = {}
                exec(compile(ast.Module([node], type_ignores=[]), "<gadget>", "exec"), ns)
                return ns["generate_php_gadget"]
        raise AssertionError("generate_php_gadget not found in generated script")

    def test_generate_php_gadget_splobjectstorage(self, ctx_http: ModuleContext) -> None:
        script = DeserializeAttack().generate_python_script(ctx_http)
        gadget_fn = self._extract_gadget_func(script)
        # M28: previously the f-string over-escaped the expression placeholders,
        # producing literal '{{len(class_name)}}' instead of evaluating them.
        # PHP serialization uses the string length: len("SplObjectStorage") == 16.
        assert gadget_fn("SplObjectStorage") == 'O:16:"SplObjectStorage":0:{}'

    def test_generate_php_gadget_default_arg(self, ctx_http: ModuleContext) -> None:
        script = DeserializeAttack().generate_python_script(ctx_http)
        gadget_fn = self._extract_gadget_func(script)
        assert gadget_fn() == 'O:16:"SplObjectStorage":0:{}'

    def test_generate_php_gadget_custom_class(self, ctx_http: ModuleContext) -> None:
        script = DeserializeAttack().generate_python_script(ctx_http)
        gadget_fn = self._extract_gadget_func(script)
        assert gadget_fn("stdClass") == 'O:8:"stdClass":0:{}'

    def test_generate_php_gadget_no_literal_braces(self, ctx_http: ModuleContext) -> None:
        # The bug symptom: literal '{{len(class_name)}}' / '{class_name}' in output.
        script = DeserializeAttack().generate_python_script(ctx_http)
        gadget_fn = self._extract_gadget_func(script)
        out = gadget_fn("SplObjectStorage")
        assert "{len(class_name)}" not in out
        assert "{class_name}" not in out
        assert out.endswith(":0:{}")


# ── Regression: ContainerBreakout guarded cgroup read (M29) ─────────────────

class TestContainerBreakoutCgroupGuard:
    def test_cgroup_open_is_guarded(self, ctx_ssh: ModuleContext) -> None:
        # M29: the generated script must not call open("/proc/1/cgroup")
        # unguarded; it must wrap the read in try/except OSError.
        mod = ContainerBreakout()
        result = mod.run(ctx_ssh)
        script = result["script"]
        assert 'open("/proc/1/cgroup")' in script
        assert "except OSError" in script
        # Ensure the unguarded form is gone.
        assert '"docker" in open("/proc/1/cgroup"' not in script


# ── Regression: PersistentSessionManager stop fallback (M27) ───────────────
# Lives in test_attack_modules.py because that is the sole owned test file;
# the fixtures under test are in tools/persistent_session_manager.py.

class TestPersistentSessionStopFallback:
    def _manager_with_recorded_session(self, tmp_path, session_type, name="sess"):
        from tools.persistent_session_manager import PersistentSessionManager, SessionInfo
        mgr = PersistentSessionManager(tmp_path)
        info = SessionInfo(
            name=name,
            session_type=session_type,
            command="probe",
            pid=4242,
            workspace=tmp_path,
        )
        mgr._register(info)
        mgr._processes.track(name, 4242)
        return mgr, name

    def test_stop_background_job_falls_back_to_kill_pid(self, tmp_path) -> None:
        # M27: helper.stop returns False (handle lost) but a PID is recorded;
        # manager must fall back to ProcessTracker.kill_pid and report success.
        mgr, name = self._manager_with_recorded_session(tmp_path, "background", name="job")
        mgr._jobs.stop = MagicMock(return_value=False)  # type: ignore[assignment]
        mgr._processes.kill_pid = MagicMock(return_value=True)  # type: ignore[assignment]

        result = mgr.stop_background_job(name)
        assert result["success"] is True
        mgr._processes.kill_pid.assert_called_once_with(4242)
        # On success the session is unregistered.
        assert name not in mgr._sessions

    def test_stop_background_job_failed_stop_keeps_pid(self, tmp_path) -> None:
        # M27: when both helper.stop and kill_pid fail, the recorded PID must
        # NOT be destroyed (so a later retry can still find it).
        mgr, name = self._manager_with_recorded_session(tmp_path, "background", name="job")
        mgr._jobs.stop = MagicMock(return_value=False)  # type: ignore[assignment]
        mgr._processes.kill_pid = MagicMock(return_value=False)  # type: ignore[assignment]

        result = mgr.stop_background_job(name)
        assert result["success"] is False
        # Session + tracked PID preserved for retry.
        assert name in mgr._sessions
        assert mgr._sessions[name].pid == 4242
        assert name in mgr._processes._tracked

    def test_stop_listener_falls_back_to_kill_pid(self, tmp_path) -> None:
        mgr, name = self._manager_with_recorded_session(tmp_path, "listener", name="lst")
        mgr._listeners.stop = MagicMock(return_value=False)  # type: ignore[assignment]
        mgr._processes.kill_pid = MagicMock(return_value=True)  # type: ignore[assignment]

        result = mgr.stop_listener(name)
        assert result["success"] is True
        mgr._processes.kill_pid.assert_called_once_with(4242)
        assert name not in mgr._sessions

    def test_stop_listener_failed_stop_keeps_pid(self, tmp_path) -> None:
        mgr, name = self._manager_with_recorded_session(tmp_path, "listener", name="lst")
        mgr._listeners.stop = MagicMock(return_value=False)  # type: ignore[assignment]
        mgr._processes.kill_pid = MagicMock(return_value=False)  # type: ignore[assignment]

        result = mgr.stop_listener(name)
        assert result["success"] is False
        assert name in mgr._sessions
        assert mgr._sessions[name].pid == 4242
        assert name in mgr._processes._tracked
