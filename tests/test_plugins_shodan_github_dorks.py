"""Tests for the shodan_recon and github_dorks plugins.

All HTTP is mocked via injectable ``fetch_fn`` callables -- no live network,
no real Shodan/GitHub API calls. The tests cover:
  - Plugin is default-off (manifest ``enabled: false``)
  - Plugin only loads when the API key/token is set (two-gate enablement)
  - MCP tool refuses with ``BLOCKED:`` when the key/token is unset
  - HTTP parsing + structured JSON output
  - Prompt-injection hardening (``_clean`` caps strings at 200 chars)
  - Network errors degrade to ``{"error": ...}`` (never raise)
"""
from __future__ import annotations

# ── shodan_recon ─────────────────────────────────────────────────────────────
from plugins.github_dorks.plugin import (
    _DEFAULT_DORKS,
    GithubDorksPlugin,
    _github_token,
    run_dorks,
)
from plugins.shodan_recon.plugin import (
    ShodanReconPlugin,
    _shodan_api_key,
    shodan_host,
    shodan_search,
)
from plugins.shodan_recon.plugin import (
    _clean as shodan_clean,
)


def test_shodan_plugin_manifest_lab_default_on():
    """Lab build: the plugin ships enabled -- operator opts out via
    plugins.disabled. The two-gate still holds: the MCP tool refuses with
    BLOCKED: when recon.shodan_api_key is unset."""
    p = ShodanReconPlugin()
    assert p.manifest.enabled is True
    assert "mcp_tool" in p.manifest.capabilities


def test_shodan_api_key_reads_recon_block():
    cfg = {"recon": {"shodan_api_key": "TESTKEY"}}
    assert _shodan_api_key(cfg) == "TESTKEY"
    assert _shodan_api_key({}) == ""
    assert _shodan_api_key({"recon": {}}) == ""


def test_shodan_host_no_key_returns_error():
    res = shodan_host("8.8.8.8", "")
    assert res["error"] == "shodan api key missing"


def test_shodan_host_parses_banner():
    fake_payload = {
        "ip_str": "8.8.8.8",
        "ports": [53, 443],
        "hostnames": ["dns.google"],
        "org": "Google",
        "os": "",
        "vulns": ["CVE-2020-1234"],
        "data": [
            {"port": 53, "transport": "udp", "product": "Google DNS", "version": "", "cpe": []},
            {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.18", "cpe": ["cpe:/a:nginx:nginx:1.18"]},
        ],
    }
    res = shodan_host("8.8.8.8", "KEY", fetch_fn=lambda url: fake_payload)
    assert res["ip"] == "8.8.8.8"
    assert res["ports"] == [53, 443]
    assert res["hostnames"] == ["dns.google"]
    assert res["vulns"] == ["CVE-2020-1234"]
    assert len(res["services"]) == 2
    assert res["services"][1]["product"] == "nginx"


def test_shodan_host_network_error_returns_error_dict():
    import urllib.error
    def boom(url):
        raise urllib.error.HTTPError(url, 403, "forbidden", {}, b'{"error":"forbidden"}')
    res = shodan_host("8.8.8.8", "KEY", fetch_fn=boom)
    assert "error" in res
    assert "403" in res["error"]


def test_shodan_search_parses_matches():
    fake_payload = {
        "matches": [
            {"ip_str": "1.2.3.4", "port": 80, "product": "apache", "version": "2.4", "hostnames": [], "vulns": ["CVE-X"]},
        ],
        "total": 1,
    }
    res = shodan_search("apache country:US", "KEY", fetch_fn=lambda url: fake_payload)
    assert res["total"] == 1
    assert res["matches"][0]["ip"] == "1.2.3.4"
    assert res["matches"][0]["vulns"] == ["CVE-X"]


def test_shodan_search_prompt_injection_cap():
    """A >200-char product string is capped by _clean."""
    fake_payload = {
        "matches": [{"ip_str": "1.2.3.4", "port": 80, "product": "X" * 500, "version": "", "hostnames": [], "vulns": []}],
        "total": 1,
    }
    res = shodan_search("q", "KEY", fetch_fn=lambda url: fake_payload)
    assert len(res["matches"][0]["product"]) <= 200


def test_shodan_search_empty_query_rejected():
    res = shodan_search("", "KEY")
    assert res["error"] == "empty query"


def test_shodan_clean_strips_control_chars():
    assert shodan_clean("abc\x00def\t") == "abcdef"
    assert shodan_clean("X" * 500) == "X" * 200


def test_shodan_plugin_registers_factory():
    """register() contributes an MCP tool factory + a config section."""
    from tools.plugins import PluginRegistry
    p = ShodanReconPlugin()
    reg = PluginRegistry()
    p.register(reg)
    assert len(reg.mcp_tool_factories) == 1
    assert "shodan_recon" in reg.config_sections


def test_shodan_mcp_tool_blocks_without_key(monkeypatch):
    """The MCP tool returns a BLOCKED marker when recon.shodan_api_key is unset."""
    from plugins.shodan_recon.plugin import _register_shodan_tools

    class _FakeMcp:
        def __init__(self):
            self.tools = {}
        def tool(self):
            def deco(fn):
                self.tools[fn.__name__] = fn
                return fn
            return deco

    class _FakeCtx:
        def __init__(self, config):
            self.config = config
            self.audit_tool = lambda fn: fn  # passthrough for test

    mcp = _FakeMcp()
    ctx = _FakeCtx({"recon": {"shodan_api_key": ""}})
    _register_shodan_tools(mcp, ctx)
    result = mcp.tools["shodan_host_lookup"]("8.8.8.8")
    assert result.startswith("BLOCKED:")
    assert "shodan_api_key" in result


# ── github_dorks tests ──────────────────────────────────────────────────────


def test_github_dorks_plugin_manifest_lab_default_on():
    """Lab build: the plugin ships enabled -- operator opts out via
    plugins.disabled. Two-gate: MCP tool refuses with BLOCKED: when
    GITHUB_TOKEN is unset."""
    p = GithubDorksPlugin()
    assert p.manifest.enabled is True
    assert "mcp_tool" in p.manifest.capabilities


def test_github_token_reads_cve_lookup_block(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghtest")
    assert _github_token({"cve_lookup": {"github": {"token_env": "GITHUB_TOKEN"}}}) == "ghtest"
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert _github_token({}) == ""


def test_run_dorks_no_token_returns_error(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    res = run_dorks("someorg", "")
    assert res["error"] == "github token missing"


def test_run_dorks_invalid_org_rejected(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghtest")
    # URL-shaped org is rejected (prompt-injection guard).
    res = run_dorks("http://169.254.169.254/", "ghtest")
    assert res["error"].startswith("invalid org name")
    res2 = run_dorks("org; rm -rf /", "ghtest")
    assert res2["error"].startswith("invalid org name")


def test_run_dorks_runs_all_dorks(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghtest")
    def fake_fetch(url, method, headers):
        return {"items": [
            {"repository": {"full_name": "acme/widgets"}, "path": "config/env", "name": "env", "html_url": "https://github.com/acme/widgets/blob/main/config/env", "score": 1.0},
        ], "total_count": 1}
    res = run_dorks("acme", "ghtest", fetch_fn=fake_fetch)
    assert res["org"] == "acme"
    assert len(res["results"]) == len(_DEFAULT_DORKS)
    assert res["results"][0]["matches"][0]["repo"] == "acme/widgets"
    assert res["summary"]["total_dorks"] == len(_DEFAULT_DORKS)
    assert res["summary"]["total_hits"] == len(_DEFAULT_DORKS)


def test_run_dorks_one_dork_failure_doesnt_abort(monkeypatch):
    """A 403 on one dork degrades that one to an error, the rest still run."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghtest")
    call_count = {"n": 0}
    def fake_fetch(url, method, headers):
        call_count["n"] += 1
        if call_count["n"] == 1:
            import urllib.error
            raise urllib.error.HTTPError(url, 403, "rate limit", {}, b'{"message":"rate limit"}')
        return {"items": [], "total_count": 0}
    res = run_dorks("acme", "ghtest", fetch_fn=fake_fetch)
    assert "error" in res["results"][0]
    assert "matches" in res["results"][1]  # second dork still ran


def test_run_dorks_prompt_injection_cap(monkeypatch):
    """A >200-char repo name is capped by _clean."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghtest")
    def fake_fetch(url, method, headers):
        return {"items": [
            {"repository": {"full_name": "X" * 500}, "path": "p", "name": "n", "html_url": "u", "score": 1.0},
        ], "total_count": 1}
    res = run_dorks("acme", "ghtest", fetch_fn=fake_fetch)
    assert len(res["results"][0]["matches"][0]["repo"]) <= 200


def test_github_dorks_plugin_registers_factory():
    from tools.plugins import PluginRegistry
    p = GithubDorksPlugin()
    reg = PluginRegistry()
    p.register(reg)
    assert len(reg.mcp_tool_factories) == 1
    assert "github_dorks" in reg.config_sections


def test_github_dorks_mcp_tool_blocks_without_token(monkeypatch):
    """The MCP tool returns a BLOCKED marker when GITHUB_TOKEN is unset."""
    from plugins.github_dorks.plugin import _register_github_dorks_tools

    class _FakeMcp:
        def __init__(self):
            self.tools = {}
        def tool(self):
            def deco(fn):
                self.tools[fn.__name__] = fn
                return fn
            return deco

    class _FakeCtx:
        def __init__(self, config):
            self.config = config
            self.audit_tool = lambda fn: fn

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    mcp = _FakeMcp()
    ctx = _FakeCtx({})
    _register_github_dorks_tools(mcp, ctx)
    result = mcp.tools["search_github_dorks"]("acme")
    assert result.startswith("BLOCKED:")
    assert "GITHUB_TOKEN" in result
