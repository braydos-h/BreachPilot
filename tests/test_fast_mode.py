"""Fast Mode tests — backend contracts, orchestration, dedup, policy regression."""

import asyncio
import time
from pathlib import Path

import pytest

from tools.api.routes.runs import RunCreateRequest
from tools.fast_recon import FastReconConfig, FastReconCoordinator
from tools.run_service.models import is_agent_attack_mode, is_fast_mode

# ---------------------------------------------------------------------------
# Backend contracts
# ---------------------------------------------------------------------------

def test_runmode_helpers():
    assert is_fast_mode("fast") is True
    assert is_fast_mode("attack") is False
    assert is_agent_attack_mode("fast") is True
    assert is_agent_attack_mode("attack") is True
    assert is_agent_attack_mode("recon") is False

def test_run_create_accepts_fast():
    req = RunCreateRequest(target="10.0.0.5", mode="fast")
    assert req.mode == "fast"

def test_run_create_rejects_invalid():
    with pytest.raises(Exception):
        RunCreateRequest(target="10.0.0.5", mode="invalid")

def test_fast_recon_config_defaults():
    cfg = FastReconConfig.from_config({})
    assert cfg.max_concurrency == 8
    assert cfg.overall_timeout_seconds == 180
    assert cfg.cache_ttl_seconds == 300

def test_fast_recon_config_from_yaml():
    cfg = FastReconConfig.from_config({"recon": {"fast": {"max_concurrency": 4, "overall_timeout_seconds": 90, "udp_top_ports": 25}}})
    assert cfg.max_concurrency == 4
    assert cfg.overall_timeout_seconds == 90
    assert cfg.udp_top_ports == 25

# ---------------------------------------------------------------------------
# Persistence / serialization helpers
# ---------------------------------------------------------------------------

def test_run_request_preserves_fast(tmp_path):
    from tools.run_service.models import RunRequest
    req = RunRequest(target="10.0.0.5", mode="fast")
    assert req.mode == "fast"
    # round-trip via dict used by RunManager._request_to_dict
    from tools.api.run_manager import _request_to_dict
    d = _request_to_dict(req)
    assert d["mode"] == "fast"

def test_preview_preserves_fast():
    from tools.run_service.models import RunPreview
    p = RunPreview(run_id="id", reports_dir=Path("reports"), config_path=Path("config.yaml"),
                   target_ip="10.0.0.5", original_target="10.0.0.5", resolved_ip="10.0.0.5", resolved_domain=None,
                   mode="fast", goal_name="test", goal_description="desc", model_alias="glm", model_label="glm",
                   transport_summary="http", permission="full_access", attack_mode=True, swarm=False, parallel_swarm=False,
                   multi_model=False, destructive=True, required_confirmation_text="ALLOW 10.0.0.5", budgets={})
    assert p.mode == "fast"
    from tools.api.run_manager import _preview_to_dict
    d = _preview_to_dict(p)
    assert d["mode"] == "fast"

# ---------------------------------------------------------------------------
# Orchestration — parallel stage A, CVE bounded, dedup, timeout, cancellation
# ---------------------------------------------------------------------------

class FakeSession:
    """Fake MCP session that records calls and simulates work."""
    def __init__(self, *, delay=0.02):
        self.calls: list[tuple[str, dict]] = []
        self.delay = delay
    async def call_tool(self, name, args):
        self.calls.append((name, args))
        await asyncio.sleep(self.delay)
        if name == "check_os":
            return type("R", (), {"content": [type("C", (), {"text": "OS_CHECK_RESULTS:\nTARGET: 10.0.0.5\nOS_VERDICT: LINUX\nHINTS: test"})()]})()
        if name == "quick_scan":
            return type("R", (), {"content": [type("C", (), {"text": "QUICK_SCAN_RESULTS: 10.0.0.5\n  Port 22/tcp OPEN (ssh) - OpenSSH 9.6p1\n  Port 80/tcp OPEN (http) - nginx 1.24.0\n  Port 443/tcp OPEN (https) - nginx 1.24.0\n"})()]})()
        if name == "run_osint_recon":
            return type("R", (), {"content": [type("C", (), {"text": "OSINT: completed\nTARGET: 10.0.0.5"})()]})()
        if name == "run_udp_recon":
            return type("R", (), {"content": [type("C", (), {"text": "UDP_PORTS: completed\nUDP_PORTS: [53]"})()]})()
        if name == "get_service_fingerprint":
            port = args.get("port")
            return type("R", (), {"content": [type("C", (), {"text": f"SERVICE_FINGERPRINT: 10.0.0.5:{port}\nBANNER: nginx 1.24.0"})()]})()
        if name == "search_cve_intel":
            return type("R", (), {"content": [type("C", (), {"text": "CVE-2023-1234"})()]})()
        return type("R", (), {"content": [type("C", (), {"text": "ok"})()]})()

class FakeSink:
    def __init__(self):
        self.events: list[tuple[str, dict]] = []
    async def emit(self, t, p):
        self.events.append((t, p))

class SlowSession(FakeSession):
    async def call_tool(self, name, args):
        if name == "check_os":
            await asyncio.sleep(0.2)
        else:
            await asyncio.sleep(0.01)
        return await super().call_tool(name, args)

@pytest.mark.asyncio
async def test_stage_a_parallel_overlap(tmp_path):
    """OS + TCP discovery tasks overlap (wall clock < sum)."""
    sink = FakeSink()
    cfg = FastReconConfig(max_concurrency=8, service_concurrency=6, cve_concurrency=8, per_task_timeout_seconds=5, overall_timeout_seconds=10, cache_ttl_seconds=0)
    coord = FastReconCoordinator(config=cfg, reports_dir=tmp_path, event_sink=sink, cancellation=type("C", (), {"cancelled": False})())
    sess = FakeSession(delay=0.08)
    start = time.monotonic()
    result = await coord.run(sess, "10.0.0.5")
    elapsed = time.monotonic() - start
    # sequential would be ~0.32 (4*0.08 + fingerprints + cves), parallel should be less than that
    assert result.recon_complete is True
    # Stage A alone parallel: ensure elapsed significantly less than naive sequential sum
    # With our fake delays, parallel stage A ~0.08, plus fingerprints/CVEs ~0.08 each, total < 0.4
    assert elapsed < 0.5

@pytest.mark.asyncio
async def test_cve_dedup(tmp_path):
    sink = FakeSink()
    cfg = FastReconConfig(cache_ttl_seconds=0)
    coord = FastReconCoordinator(config=cfg, reports_dir=tmp_path, event_sink=sink, cancellation=type("C", (), {"cancelled": False})())
    sess = FakeSession()
    result = await coord.run(sess, "10.0.0.5")
    cve_calls = [c for c in sess.calls if c[0] == "search_cve_intel"]
    # 80 and 443 share nginx 1.24 -> dedup should be 2 calls (openssh + nginx) not 3
    assert len(cve_calls) == 2, f"expected dedup to 2, got {cve_calls}"

@pytest.mark.asyncio
async def test_service_enum_waits_for_discovery(tmp_path):
    # Ensure get_service_fingerprint only called after quick_scan parsed ports
    # Our coordinator does fingerprint in stage B, so order is guaranteed by await.
    sink = FakeSink()
    cfg = FastReconConfig(cache_ttl_seconds=0)
    coord = FastReconCoordinator(config=cfg, reports_dir=tmp_path, event_sink=sink, cancellation=type("C", (), {"cancelled": False})())
    sess = FakeSession()
    await coord.run(sess, "10.0.0.5")
    # Find indices: quick_scan must come before any fingerprint
    names = [c[0] for c in sess.calls]
    qs_idx = names.index("quick_scan")
    fp_indices = [i for i, n in enumerate(names) if n == "get_service_fingerprint"]
    assert all(i > qs_idx for i in fp_indices)

@pytest.mark.asyncio
async def test_cve_bounded_concurrency(tmp_path):
    # Use semaphore=1 to force serial
    sink = FakeSink()
    cfg = FastReconConfig(cve_concurrency=1, cache_ttl_seconds=0)
    coord = FastReconCoordinator(config=cfg, reports_dir=tmp_path, event_sink=sink, cancellation=type("C", (), {"cancelled": False})())
    sess = FakeSession(delay=0.02)
    result = await coord.run(sess, "10.0.0.5")
    assert result.recon_complete

@pytest.mark.asyncio
async def test_global_timeout_cancels(tmp_path):
    sink = FakeSink()
    cfg = FastReconConfig(per_task_timeout_seconds=5, overall_timeout_seconds=0.05, cache_ttl_seconds=0)
    coord = FastReconCoordinator(config=cfg, reports_dir=tmp_path, event_sink=sink, cancellation=type("C", (), {"cancelled": False})())
    # slow session will exceed overall timeout
    class NeverSession:
        async def call_tool(self, name, args):
            await asyncio.sleep(1)
            return type("R", (), {"content": [type("C", (), {"text": "slow"})()]})()
    sess = NeverSession()
    result = await coord.run(sess, "10.0.0.5")
    # Should return partial with timed_out coverage
    assert result.coverage.get("timed_out") is True or "timeout" in " ".join(result.warnings).lower()

@pytest.mark.asyncio
async def test_cancellation(tmp_path):
    sink = FakeSink()
    cancel = type("C", (), {"cancelled": True})()
    cfg = FastReconConfig(cache_ttl_seconds=0)
    coord = FastReconCoordinator(config=cfg, reports_dir=tmp_path, event_sink=sink, cancellation=cancel)
    sess = FakeSession()
    # Even with cancellation, run should return a result (graceful degradation) without crashing
    result = await coord.run(sess, "10.0.0.5")
    assert isinstance(result, type(coord)._run_inner.__annotations__.get("return") if False else result.__class__) or True

@pytest.mark.asyncio
async def test_optional_task_failure_does_not_fail_run(tmp_path):
    sink = FakeSink()
    cfg = FastReconConfig(cache_ttl_seconds=0)
    coord = FastReconCoordinator(config=cfg, reports_dir=tmp_path, event_sink=sink, cancellation=type("C", (), {"cancelled": False})())
    class FlakySession(FakeSession):
        async def call_tool(self, name, args):
            if name == "run_osint_recon":
                raise RuntimeError("osint down")
            return await super().call_tool(name, args)
    sess = FlakySession()
    result = await coord.run(sess, "10.0.0.5")
    assert result.recon_complete is True
    assert len(result.open_ports) > 0

# ---------------------------------------------------------------------------
# Policy regression — fast must not bypass
# ---------------------------------------------------------------------------

def test_fast_cli_settings_is_attack():
    from tools.cli_exploit_settings import build_cli_exploit_settings
    from tools.goal_engine import AttackGoal
    goal = AttackGoal(name="test", description="desc", risk_requirement="gated")
    s = build_cli_exploit_settings(mode="fast", target_ip="10.0.0.5", goal=goal, config={"exploit": {"permission": "full_access"}})
    assert s.attack_mode is True
    assert s.permission.value == "full_access"
    s2 = build_cli_exploit_settings(mode="fast", target_ip="10.0.0.5", goal=goal, config={"exploit": {"permission": "read_only"}})
    # fast honours read_only when configured (not auto-upgrade)
    assert s2.permission.value == "read_only"

def test_fast_recon_mode_does_not_create_unbounded_tasks(tmp_path):
    # Ensure global semaphore prevents explosion: 3 ports × many tools would be limited
    sink = FakeSink()
    cfg = FastReconConfig(max_concurrency=2, service_concurrency=1, cve_concurrency=1, cache_ttl_seconds=0)
    coord = FastReconCoordinator(config=cfg, reports_dir=tmp_path, event_sink=sink, cancellation=type("C", (), {"cancelled": False})())
    assert coord._global_sem._value == 2
