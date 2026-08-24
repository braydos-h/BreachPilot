"""Tests for ``observer.py`` — heuristic tool-output parsing into Observations.

Covers ``Observation.to_dict``, the per-tool parsers (nmap/http/cve/os/generic),
``_score_usefulness``, ``_compact_output``, and the ``ObserverAgent.observe``
dispatch including the semantic-memory wiring branch.
"""

from __future__ import annotations

from observer import Observation, ObserverAgent, _compact_output

# ── Observation dataclass ────────────────────────────────────────────────────


def test_observation_defaults():
    obs = Observation()
    assert obs.facts == []
    assert obs.usefulness == 0
    assert obs.confidence == 0.0
    assert obs.hypothesis_evidence == []


def test_observation_to_dict_roundtrip_keys():
    obs = Observation(task_id="T-1", target="10.0.0.5", tool_name="nmap")
    obs.facts.append("port 22 open")
    d = obs.to_dict()
    expected_keys = {
        "task_id",
        "target",
        "tool_name",
        "input_summary",
        "output_summary",
        "facts",
        "new_assets",
        "new_endpoints",
        "new_parameters",
        "new_technologies",
        "new_identities",
        "new_objects",
        "interesting_signals",
        "possible_findings",
        "dead_ends",
        "recommended_followup_tasks",
        "memory_updates",
        "graph_updates",
        "evidence_refs",
        "hypothesis_evidence",
        "confidence",
        "usefulness",
    }
    assert set(d.keys()) == expected_keys
    assert d["task_id"] == "T-1"
    assert d["facts"] == ["port 22 open"]


# ── _compact_output ─────────────────────────────────────────────────────────


def test_compact_output_under_limit():
    assert _compact_output("short") == "short"


def test_compact_output_truncates_with_marker():
    raw = "x" * 600
    out = _compact_output(raw, max_len=100)
    assert out.startswith("x" * 100)
    assert "more chars]" in out


def test_compact_output_strips_whitespace():
    assert _compact_output("  hi  ") == "hi"


# ── ObserverAgent.observe dispatch ──────────────────────────────────────────


def _task(**kw):
    base = {
        "task_id": "T-1",
        "target": "10.0.0.5",
        "phase": "recon",
        "objective": "Scan target",
        "hypothesis": "Services exposed",
    }
    base.update(kw)
    return base


def test_observe_nmap_parses_open_ports():
    agent = ObserverAgent()
    raw = (
        "Nmap scan report for 10.0.0.5\n"
        "22/tcp   open  ssh      OpenSSH 8.9\n"
        "80/tcp   open  http     nginx\n"
        "OS details: Linux 5.15\n"
    )
    obs = agent.observe(_task(), raw, tool_name="run_nmap_basic")
    assert any("22" in f and "open" in f for f in obs.facts)
    assert any("80" in f and "open" in f for f in obs.facts)
    assert any("10.0.0.5:22" in e for e in obs.new_endpoints)
    assert any("10.0.0.5:80" in e for e in obs.new_endpoints)
    assert any("Linux 5.15" in f for f in obs.facts)
    assert any("OS: Linux 5.15" in t for t in obs.new_technologies)
    assert obs.usefulness > 0


def test_observe_nmap_filtered_signal():
    agent = ObserverAgent()
    raw = "PORT   STATE  SERVICE\n443/tcp filtered https\n"
    obs = agent.observe(_task(), raw, tool_name="nmap")
    assert obs.interesting_signals  # filtered triggers a signal


def test_observe_http_status_non_200_is_signal():
    agent = ObserverAgent()
    raw = "HTTP/1.1 403 Forbidden\nServer: nginx/1.25\n"
    obs = agent.observe(_task(), raw, tool_name="http_request")
    assert any("403" in s for s in obs.interesting_signals)
    assert any("nginx" in t.lower() for t in obs.new_technologies)


def test_observe_http_200_is_fact():
    agent = ObserverAgent()
    raw = "HTTP/1.1 200 OK\nServer: Apache/2.4.41\n"
    obs = agent.observe(_task(), raw, tool_name="http_probe")
    assert any("HTTP 200" in f for f in obs.facts)
    assert any("Apache" in t for t in obs.new_technologies)


def test_observe_http_x_powered_by():
    agent = ObserverAgent()
    raw = "HTTP/1.1 200 OK\nX-Powered-By: PHP/8.2\n"
    obs = agent.observe(_task(), raw, tool_name="web_probe")
    assert any("PHP" in t for t in obs.new_technologies)


def test_observe_http_sensitive_file_signals():
    agent = ObserverAgent()
    raw = "HTTP/1.1 200 OK\n.git/config found\n.env exposed\n"
    obs = agent.observe(_task(), raw, tool_name="http_probe")
    assert any(".git" in s for s in obs.interesting_signals)
    assert any(".env" in s for s in obs.interesting_signals)


def test_observe_http_extracts_endpoints_from_request_log():
    agent = ObserverAgent()
    raw = "GET /api/users HTTP/1.1\nPOST /api/login HTTP/1.1\n"
    obs = agent.observe(_task(), raw, tool_name="http_request")
    assert "/api/users" in obs.new_endpoints
    assert "/api/login" in obs.new_endpoints


def test_observe_cve_extracts_cve_ids():
    agent = ObserverAgent()
    raw = "CVE-2021-44228 found with CVSS: 9.8 affecting apache-log4j"
    obs = agent.observe(_task(), raw, tool_name="search_cve")
    assert any("CVE-2021-44228" in f for f in obs.facts)
    assert "CVE-2021-44228" in obs.new_technologies
    assert obs.possible_findings  # high CVSS -> finding
    assert obs.possible_findings[0]["cve"] == "CVE-2021-44228"
    assert obs.possible_findings[0]["cvss"] == 9.8


def test_observe_cve_low_cvss_no_finding():
    agent = ObserverAgent()
    raw = "CVE-2023-0001 CVSS: 3.2"
    obs = agent.observe(_task(), raw, tool_name="cve_lookup")
    assert any("CVE-2023-0001" in f for f in obs.facts)
    assert obs.possible_findings == []


def test_observe_cve_invalid_cvss_ignored():
    agent = ObserverAgent()
    raw = "CVE-2023-0001 CVSS: N/A"
    obs = agent.observe(_task(), raw, tool_name="cve")
    assert obs.possible_findings == []


def test_observe_os_windows():
    agent = ObserverAgent()
    obs = agent.observe(_task(), "Windows Server 2019\nMicrosoft Windows", tool_name="check_os")
    assert any("Windows" in f for f in obs.facts)


def test_observe_os_linux():
    agent = ObserverAgent()
    obs = agent.observe(_task(), "Linux 5.15.0-generic\nUbuntu 22.04", tool_name="check_os")
    assert any("Linux" in f for f in obs.facts)


def test_observe_os_inconclusive():
    agent = ObserverAgent()
    obs = agent.observe(_task(), "unknown system", tool_name="os_detect")
    assert any("inconclusive" in f for f in obs.facts)


def test_observe_generic_error_is_dead_end():
    agent = ObserverAgent()
    obs = agent.observe(_task(), "connection error\noperation failed", tool_name="custom_tool")
    assert obs.dead_ends
    assert "custom_tool" in obs.dead_ends[0]


def test_observe_generic_success_is_signal():
    agent = ObserverAgent()
    obs = agent.observe(_task(), "operation complete\nsuccess", tool_name="custom_tool")
    assert obs.interesting_signals
    assert "completed successfully" in obs.interesting_signals[0]


def test_observe_generic_extracts_first_few_lines_as_facts():
    agent = ObserverAgent()
    raw = "line one\nline two\nline three\nline four"
    obs = agent.observe(_task(), raw, tool_name="unknown_tool")
    # min(3, count of newlines) facts
    assert len(obs.facts) <= 3
    assert "line one" in obs.facts


def test_observe_uses_hypothesis_for_input_summary():
    agent = ObserverAgent()
    obs = agent.observe(_task(hypothesis="SSH may be misconfigured"), "x", tool_name="nmap")
    assert "SSH may be misconfigured" in obs.input_summary


def test_observe_uses_objective_when_no_hypothesis():
    agent = ObserverAgent()
    task = _task()
    task.pop("hypothesis")
    obs = agent.observe(task, "x", tool_name="nmap")
    assert "Scan target" in obs.input_summary


def test_observe_evidence_refs_passed_through():
    agent = ObserverAgent()
    obs = agent.observe(_task(), "ok", tool_name="nmap", evidence_refs=["E-1", "E-2"])
    assert obs.evidence_refs == ["E-1", "E-2"]


def test_observe_evidence_refs_default_empty():
    agent = ObserverAgent()
    obs = agent.observe(_task(), "ok", tool_name="nmap")
    assert obs.evidence_refs == []


# ── _score_usefulness ───────────────────────────────────────────────────────


def test_score_usefulness_empty_is_zero():
    agent = ObserverAgent()
    obs = agent.observe(_task(), "x", tool_name="unknown_tool")
    # generic parser on "x" with no error/success -> no facts, score 0
    assert obs.usefulness == 0


def test_score_usefulness_caps_at_100():
    agent = ObserverAgent()
    raw = "\n".join(f"22/tcp open ssh service{i} OS details: Linux" for i in range(200))
    obs = agent.observe(_task(), raw, tool_name="nmap")
    assert obs.usefulness == 100


def test_score_usefulness_weighting():
    # facts=1, endpoints=1 (x2), tech=1 (x2), signal=1 (x3), finding=1 (x5)
    obs = Observation(
        facts=["f"],
        new_endpoints=["e"],
        new_technologies=["t"],
        interesting_signals=["s"],
        possible_findings=[{"x": 1}],
    )
    score = ObserverAgent._score_usefulness(obs)
    assert score == 1 + 2 + 2 + 3 + 5


# ── semantic memory wiring ──────────────────────────────────────────────────


def test_observe_stores_embedding_when_semantic_wired():
    calls = []

    class FakeSemantic:
        def store_embedding(self, source_table, source_id, text):
            calls.append((source_table, source_id, text))

    agent = ObserverAgent(semantic_memory=FakeSemantic())
    agent.observe(_task(task_id="T-9"), "output", tool_name="nmap")
    assert len(calls) == 1
    assert calls[0][0] == "observations"
    assert calls[0][1] == "T-9"
    assert "nmap" in calls[0][2]


def test_observe_no_semantic_no_embedding_call():
    # Should not raise when semantic_memory is None.
    agent = ObserverAgent(semantic_memory=None)
    obs = agent.observe(_task(), "x", tool_name="nmap")
    assert obs.task_id == "T-1"


def test_observe_task_id_falls_back_to_id_key():
    agent = ObserverAgent()
    task = {"id": "X-1", "target": "10.0.0.5", "objective": "x"}
    obs = agent.observe(task, "ok", tool_name="nmap")
    assert obs.task_id == "X-1"
