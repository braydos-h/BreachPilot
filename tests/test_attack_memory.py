from __future__ import annotations

from tools.attack_memory import AttackMemoryStore


def test_capture_tool_result_extracts_current_attack_facts(tmp_path):
    store = AttackMemoryStore(tmp_path, "sess-1", "10.0.0.5")
    output = (
        "Nmap 7.94 scan initiated\n"
        "22/tcp open ssh OpenSSH 8.9\n"
        "80/tcp open http nginx 1.24\n"
        "CVE-2026-0001 appears relevant\n"
        "GET /admin HTTP/1.1\n"
        "username: admin password: SuperSecret!\n"
        "[+] Meterpreter session 1 opened\n"
        "Evidence saved to C:\\work\\evidence\\attempt-1.txt\n"
    )

    count = store.capture_tool_result("run_nmap", output, success=True)

    assert count > 0
    categories = {item.category for item in store.list_items()}
    assert {"services", "cves", "endpoints", "credentials", "access", "evidence"} <= categories

    context = store.format_context()
    assert "22/tcp" in context
    assert "CVE-2026-0001" in context
    assert "SuperSecret!" not in context
    assert "[redacted]" in context
    assert "Meterpreter session 1 opened" in context
    assert "C:\\work\\evidence\\attempt-1.txt" in context


def test_capture_tool_result_deduplicates_and_counts_seen_items(tmp_path):
    store = AttackMemoryStore(tmp_path, "sess-1", "10.0.0.5")
    output = "22/tcp open ssh OpenSSH 8.9"

    store.capture_tool_result("run_nmap", output, success=True)
    store.capture_tool_result("run_nmap", output, success=True)

    services = store.list_items(category="services")
    assert len(services) == 1
    assert services[0].seen_count == 2


def test_attack_memory_is_scoped_to_session_and_target(tmp_path):
    first = AttackMemoryStore(tmp_path, "sess-1", "10.0.0.5")
    first.capture_tool_result("check_os", "Target OS identified as Linux: 10.0.0.5", success=True)

    same_file_other_session = AttackMemoryStore(tmp_path, "sess-2", "10.0.0.5")
    same_file_other_target = AttackMemoryStore(tmp_path, "sess-1", "10.0.0.6")

    assert first.list_items(category="os")
    assert same_file_other_session.list_items() == []
    assert same_file_other_target.list_items() == []
