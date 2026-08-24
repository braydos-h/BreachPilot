from __future__ import annotations

from pathlib import Path

from tools.attack_memory import AttackMemoryStore
from tools.attack_planner import AttackPlan, AttackStep
from tools.exploit_agent import (
    ATTACK_MEMORY_MARKER,
    COMPACTED_CONTEXT_MARKER,
    ExploitPermission,
    ExploitPolicy,
    ExploitSettings,
    _build_compacted_messages,
    _build_context_profile,
    _context_compaction_gap,
    _should_compact_context,
)


def _policy(tmp_path: Path, *, attack_mode: bool = True, gap: int = 5) -> ExploitPolicy:
    settings = ExploitSettings(
        enabled=True,
        mode="standalone",
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=attack_mode,
        context_summarize_every=gap,
    )
    return ExploitPolicy(settings, tmp_path)


def _plan() -> AttackPlan:
    plan = AttackPlan(
        target_ip="10.0.0.5",
        target_os="Linux",
        target_cves=["CVE-2026-0001"],
        service_context="22/tcp ssh OpenSSH; 80/tcp http nginx",
        attack_mode=True,
    )
    done = plan.add_step(AttackStep(
        phase="recon",
        tool="run_nmap",
        reason="Identify exposed services",
        target_ip="10.0.0.5",
    ))
    plan.mark_step_done(done, True, "Open ports: 22/tcp ssh, 80/tcp http")
    plan.add_step(AttackStep(
        phase="enumerate",
        tool="http_probe",
        reason="Fingerprint web service",
        target_ip="10.0.0.5",
    ))
    return plan


def test_context_profile_honors_config_window_and_registry_alias(monkeypatch) -> None:
    import tools.config_manager as config_manager

    monkeypatch.setattr(
        config_manager,
        "load_validated_config",
        lambda: {
            "models": {
                "registry": {"glm": "glm-5.2:cloud"},
                "info": {"glm": {"context_window": 488000}},
            }
        },
    )

    profile = _build_context_profile("glm-5.2:cloud")

    assert profile["context_window_tokens"] == 488000
    assert profile["compact_at_tokens"] == int(488000 * (340000 / 976000))
    assert profile["keep_full"] == 20


def test_context_profile_resolves_deepseek_flash_model_id(monkeypatch) -> None:
    import tools.config_manager as config_manager

    monkeypatch.setattr(
        config_manager,
        "load_validated_config",
        lambda: {
            "models": {
                "registry": {"deepseek_flash": "deepseek-v4-flash:cloud"},
                "info": {"deepseek_flash": {"context_window": 1000000}},
            }
        },
    )

    profile = _build_context_profile("deepseek-v4-flash:cloud")

    assert profile["context_window_tokens"] == 1000000
    assert profile["compact_at_tokens"] == 300000
    assert profile["keep_full"] == 20


def test_structured_compaction_keeps_recent_verbatim_and_summarizes_old_tools(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    messages = [
        {"role": "system", "content": "old system"},
        {"role": "user", "content": "Start against 10.0.0.5"},
        {
            "role": "tool",
            "tool_name": "run_nmap",
            "content": (
                "Nmap 7.94 scan initiated\n"
                "PORT STATE SERVICE VERSION\n"
                "22/tcp open ssh OpenSSH 8.9\n"
                "80/tcp open http nginx 1.24\n"
            ),
        },
        {"role": "assistant", "content": "I will probe HTTP next."},
        {"role": "tool", "tool_name": "http_probe", "content": "HTTP/1.1 200 OK\nServer: nginx"},
    ]

    compacted = _build_compacted_messages(
        messages=messages,
        system_prompt="fresh system",
        plan=_plan(),
        policy=policy,
        target_ip="10.0.0.5",
        target_cve="",
        target_os="Linux",
        known_cves=["CVE-2026-0001"],
        service_context="service context",
        attacker_os="Windows",
        keep_full=2,
        output_max_chars=1200,
    )

    assert compacted[0] == {"role": "system", "content": "fresh system"}
    assert COMPACTED_CONTEXT_MARKER in compacted[1]["content"]
    assert "TARGET STATE" in compacted[1]["content"]
    assert "Open ports: 2" in compacted[1]["content"]
    assert "22/tcp" in compacted[1]["content"]
    assert compacted[-2:] == messages[-2:]


def test_repeated_compaction_replaces_prior_summary_and_preserves_failure_reference(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    first = _build_compacted_messages(
        messages=[
            {"role": "system", "content": "old system"},
            {"role": "tool", "tool_name": "run_nmap", "content": "22/tcp open ssh OpenSSH"},
        ],
        system_prompt="fresh system",
        plan=_plan(),
        policy=policy,
        target_ip="10.0.0.5",
        target_cve="",
        target_os="Linux",
        known_cves=[],
        service_context="",
        attacker_os="Windows",
        keep_full=0,
        output_max_chars=1000,
    )
    second = _build_compacted_messages(
        messages=first + [
            {
                "role": "tool",
                "tool_name": "run_exploit_terminal",
                "content": (
                    "ERROR: exploit failed\n"
                    "Evidence saved to C:\\work\\evidence\\attempt-1.txt\n"
                    "EXIT_CODE: 1\n"
                ),
            }
        ],
        system_prompt="fresh system",
        plan=_plan(),
        policy=policy,
        target_ip="10.0.0.5",
        target_cve="",
        target_os="Linux",
        known_cves=[],
        service_context="",
        attacker_os="Windows",
        keep_full=0,
        output_max_chars=1000,
    )

    marker_count = sum(COMPACTED_CONTEXT_MARKER in str(m.get("content", "")) for m in second)
    summary = second[1]["content"]

    assert marker_count == 1
    assert "PREVIOUS COMPACTED STATE" in summary
    assert "run_nmap" in summary
    assert "run_exploit_terminal (failure)" in summary
    assert "Evidence saved to C:\\work\\evidence\\attempt-1.txt" in summary


def test_context_summarize_every_controls_minimum_compaction_gap(tmp_path: Path) -> None:
    policy = _policy(tmp_path, gap=4)
    policy._compact_at_tokens = 100  # type: ignore[attr-defined]
    policy._last_compaction_round = 3  # type: ignore[attr-defined]

    assert _context_compaction_gap(policy) == 4
    assert not _should_compact_context(policy, round_index=6, current_tokens=100)
    assert _should_compact_context(policy, round_index=7, current_tokens=100)


def test_context_compaction_is_disabled_outside_attack_mode(tmp_path: Path) -> None:
    policy = _policy(tmp_path, attack_mode=False, gap=1)
    policy._compact_at_tokens = 1  # type: ignore[attr-defined]
    policy._last_compaction_round = 0  # type: ignore[attr-defined]

    assert not _should_compact_context(policy, round_index=10, current_tokens=1000)


def test_compaction_includes_durable_current_attack_memory(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    memory = AttackMemoryStore(tmp_path, "sess-1", "10.0.0.5")
    memory.capture_tool_result(
        "run_nmap",
        (
            "22/tcp open ssh OpenSSH 8.9\n"
            "username: admin password: exact-secret\n"
            "Evidence saved to C:\\work\\evidence\\attempt-1.txt\n"
        ),
        success=True,
    )
    policy._attack_memory = memory  # type: ignore[attr-defined]
    policy._attack_memory_max_context_chars = 3000  # type: ignore[attr-defined]

    compacted = _build_compacted_messages(
        messages=[
            {"role": "system", "content": "old system"},
            {"role": "tool", "tool_name": "run_nmap", "content": "old verbose output"},
        ],
        system_prompt="fresh system",
        plan=_plan(),
        policy=policy,
        target_ip="10.0.0.5",
        target_cve="",
        target_os="Linux",
        known_cves=[],
        service_context="",
        attacker_os="Windows",
        keep_full=0,
        output_max_chars=1000,
    )

    assert ATTACK_MEMORY_MARKER in compacted[1]["content"]
    assert "password: exact-secret" in compacted[1]["content"]
    assert "C:\\work\\evidence\\attempt-1.txt" in compacted[1]["content"]
    assert "CURRENT ATTACK MEMORY" in compacted[2]["content"]
    assert "22/tcp" in compacted[2]["content"]
