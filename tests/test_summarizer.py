"""Tests for ``summarizer.py`` — output compaction for LLM context.

Covers every branch of ``summarize_tool_output`` (nmap/search/http/msf/python/
terminal/generic), the ``_cap`` truncation helper, and ``summarize_observation``.
"""

from __future__ import annotations

import pytest

from summarizer import (
    _cap,
    _summarize_generic,
    _summarize_http,
    _summarize_msf,
    _summarize_nmap,
    _summarize_python,
    _summarize_search,
    _summarize_terminal,
    summarize_observation,
    summarize_tool_output,
)

# ── summarize_tool_output dispatch ──────────────────────────────────────────


@pytest.mark.parametrize(
    "tool_name",
    ["nmap", "run_nmap_scan", "scan_host", "NMAP"],
)
def test_dispatch_nmap(tool_name):
    out = summarize_tool_output("Nmap 7.94\n22/tcp open ssh\n", tool_name)
    assert "Nmap" in out
    assert "22/tcp" in out


@pytest.mark.parametrize(
    "tool_name",
    ["search", "search_exploit_db", "search_cve_intel", "EXPLOIT_DB"],
)
def test_dispatch_search(tool_name):
    out = summarize_tool_output("CVE-2021-44228\nhttps://x\n", tool_name)
    assert "CVE-2021-44228" in out


@pytest.mark.parametrize("tool_name", ["http_request", "curl", "web_probe"])
def test_dispatch_http(tool_name):
    out = summarize_tool_output("HTTP/1.1 200 OK\nServer: nginx\n", tool_name)
    assert "Status: 200" in out
    assert "Server: nginx" in out


@pytest.mark.parametrize("tool_name", ["msf_exploit", "run_msf_module", "msf"])
def test_dispatch_msf(tool_name):
    out = summarize_tool_output("[+] exploit succeeded\nsession opened\n", tool_name)
    assert "exploit succeeded" in out or "session opened" in out


@pytest.mark.parametrize("tool_name", ["python_file", "run_python_file"])
def test_dispatch_python(tool_name):
    out = summarize_tool_output("print('hi')\n# comment\nresult=42\n", tool_name)
    # comments are stripped, code preserved
    assert "print('hi')" in out
    assert "result=42" in out
    assert "# comment" not in out


@pytest.mark.parametrize("tool_name", ["run_exploit_terminal", "terminal"])
def test_dispatch_terminal(tool_name):
    raw = "COMMAND: nmap -sS 10.0.0.1\nEXIT_CODE: 0\noutput line one\n===\nline two"
    out = summarize_tool_output(raw, tool_name)
    assert "Command: nmap -sS 10.0.0.1" in out
    assert "Exit: 0" in out
    assert "===" not in out  # separator lines are filtered


def test_dispatch_generic_fallback():
    out = summarize_tool_output("just\nsome\nlines\n", "unknown_tool")
    assert "just" in out
    assert "some" in out


# ── _summarize_nmap ────────────────────────────────────────────────────────


NMAP_OUTPUT = """Nmap 7.94 scan initiated
Nmap scan report for 10.0.0.5
Host is up (0.01s latency).
22/tcp   open  ssh      OpenSSH 8.9
80/tcp   open  http     nginx 1.25
443/tcp  closed https
OS details: Linux 5.15
Nmap done: 1 IP address (1 host up) scanned in 1.2s
"""


def test_summarize_nmap_extracts_version_ports_os_hosts():
    out = _summarize_nmap(NMAP_OUTPUT, 4000)
    assert "Nmap 7.94" in out
    assert "Open ports:" in out
    assert "22/tcp" in out
    assert "80/tcp" in out
    assert "443/tcp" not in out  # only OPEN ports listed by the port regex
    assert "OS: Linux 5.15" in out
    assert "Hosts up: 1" in out


def test_summarize_nmap_caps_open_ports_list_to_50():
    lines = [f"{p}/tcp open svc{p}" for p in range(1, 100)]
    out = _summarize_nmap("\n".join(lines), 100000)
    # The summary line reports total open ports even though display is capped.
    assert "Open ports: 99" in out


def test_summarize_nmap_empty():
    out = _summarize_nmap("nothing useful here", 4000)
    assert out == ""


# ── _summarize_search ───────────────────────────────────────────────────────


def test_summarize_search_strips_html_and_url_lines():
    raw = "<html>title</html>\nhttp://example.com\nwww.foo.com\nCVE-2021-44228\n"
    out = _summarize_search(raw, 4000)
    assert "CVE-2021-44228" in out
    assert "<html>" not in out
    assert "http://example.com" not in out


def test_summarize_search_caps_entries_to_30():
    raw = "\n".join(f"entry{i}" for i in range(50))
    out = _summarize_search(raw, 100000)
    assert "entry0" in out
    assert "entry29" in out
    assert "entry30" not in out


# ── _summarize_http ────────────────────────────────────────────────────────


def test_summarize_http_status_and_headers():
    raw = (
        "HTTP/1.1 301 Moved\n"
        "Server: Apache/2.4.41\n"
        "Content-Type: text/html\n"
        "Location: https://x.example/\n"
        "Set-Cookie: sid=abc\n"
        "\n"
        "<html>body</html>"
    )
    out = _summarize_http(raw, 4000)
    assert "Status: 301" in out
    assert "Server: Apache/2.4.41" in out
    assert "Content-Type: text/html" in out
    assert "Location:" in out
    assert "Set-Cookie:" in out
    assert "Body:" in out


def test_summarize_http_no_headers():
    out = _summarize_http("just a body", 4000)
    assert "Status" not in out


# ── _summarize_msf ──────────────────────────────────────────────────────────


def test_summarize_msf_keeps_key_lines():
    raw = "[*] starting\n[+] vulnerable\n[-] failed once\n[*] session 1 opened\nrandom noise line\n"
    out = _summarize_msf(raw, 4000)
    assert "[+] vulnerable" in out
    assert "[*] session 1 opened" in out
    assert "random noise line" not in out


def test_summarize_msf_falls_back_when_no_keywords():
    raw = "nothing matched here"
    out = _summarize_msf(raw, 4000)
    assert out.strip() == "nothing matched here"


def test_summarize_msf_caps_to_20_lines():
    raw = "\n".join(f"[+] line{i}" for i in range(40))
    out = _summarize_msf(raw, 100000)
    assert "[+] line0" in out
    assert "[+] line19" in out
    assert "[+] line20" not in out


# ── _summarize_python ───────────────────────────────────────────────────────


def test_summarize_python_strips_comments_and_blanks():
    raw = "#!/usr/bin/python\n\nprint('hi')\nimport os\n# trailing comment\n"
    out = _summarize_python(raw, 4000)
    assert "print('hi')" in out
    assert "import os" in out
    assert "#!/usr/bin/python" not in out
    assert "# trailing comment" not in out


def test_summarize_python_caps_to_30_lines():
    raw = "\n".join(f"line{i}" for i in range(60))
    out = _summarize_python(raw, 100000)
    assert "line0" in out
    assert "line29" in out
    assert "line30" not in out


# ── _summarize_terminal ─────────────────────────────────────────────────────


def test_summarize_terminal_strips_ansi_and_extracts_exit_code():
    raw = "\x1b[31mCOMMAND: ls -la\x1b[0m\nEXIT_CODE: 0\nfile1\nfile2\n===\nfile3"
    out = _summarize_terminal(raw, 4000)
    assert "Command: ls -la" in out
    assert "Exit: 0" in out
    assert "\x1b[" not in out
    assert "===" not in out


def test_summarize_terminal_missing_exit_code_defaults_unknown():
    out = _summarize_terminal("COMMAND: echo hi\nhello", 4000)
    assert "Exit: ?" in out


def test_summarize_terminal_missing_command():
    out = _summarize_terminal("just output\nEXIT_CODE: 1", 4000)
    assert "Command: unknown" in out


# ── _summarize_generic ──────────────────────────────────────────────────────


def test_summarize_generic_strips_ansi_and_caps_lines():
    raw = "\x1b[32mkeep\x1b[0m\n\nskip blank\n" + "\n".join(f"l{i}" for i in range(50))
    out = _summarize_generic(raw, 100000)
    assert "\x1b[" not in out
    assert "keep" in out
    assert "skip blank" in out
    # caps to 40 non-blank lines: keep + skip blank + l0..l37 (38 lines), then trimmed
    assert "l37" in out
    # l40 is well past the 40-line cap, so it must be absent
    assert "l40" not in out


def test_summarize_generic_exactly_40_lines():
    raw = "\n".join(f"l{i}" for i in range(40))
    out = _summarize_generic(raw, 100000)
    assert out.count("\n") == 39  # 40 lines, 39 newlines
    assert "l39" in out


# ── _cap ────────────────────────────────────────────────────────────────────


def test_cap_no_truncation_when_under_limit():
    assert _cap("short", 100) == "short"


def test_cap_truncates_and_appends_marker():
    text = "x" * 200
    out = _cap(text, 50)
    assert out.startswith("x" * 50)
    assert "truncated" in out


def test_cap_exact_length_not_truncated():
    text = "x" * 10
    assert _cap(text, 10) == text


# ── summarize_observation ───────────────────────────────────────────────────


def test_summarize_observation_empty():
    assert summarize_observation({}) == "no notable output"


def test_summarize_observation_counts_fields():
    obs = {
        "facts": ["a", "b"],
        "interesting_signals": ["s"],
        "possible_findings": [{"x": 1}],
        "dead_ends": ["d1", "d2", "d3"],
    }
    out = summarize_observation(obs)
    assert "2 fact(s)" in out
    assert "1 signal(s)" in out
    assert "1 possible finding(s)" in out
    assert "3 dead end(s)" in out
    assert "; " in out


def test_summarize_observation_partial_fields():
    obs = {"facts": ["a"], "interesting_signals": [], "possible_findings": [], "dead_ends": []}
    out = summarize_observation(obs)
    assert out == "1 fact(s)"
