"""Tests for the cve_to_poc verified PoC resolver (Issue 3)."""

from __future__ import annotations

import io
import json


def _make_search():
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings

    return ExploitSearch(ExploitSearchSettings(enabled=True))


def test_invalid_cve_rejected():
    s = _make_search()
    out = s.cve_to_poc("not-a-cve")
    assert out.startswith("BLOCKED:")
    assert "CVE-YYYY-NNNNN" in out


def test_disabled_returns_blocked():
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings

    s = ExploitSearch(ExploitSearchSettings(enabled=False))
    assert s.cve_to_poc("CVE-2024-6387").startswith("BLOCKED:")


class _FakeResp:
    def __init__(self, payload_bytes: bytes, code: int = 200):
        self._buf = io.BytesIO(payload_bytes)
        self._code = code

    def read(self):
        return self._buf.read()

    def getcode(self):
        return self._code

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_hallucinated_url_is_filtered_to_no_verified_poc(monkeypatch):
    """A 404 GitHub repo URL (the hallucination case) must be filtered out,
    and with no other verified source the result is NO_VERIFIED_POC_FOUND —
    never a guessed URL."""
    s = _make_search()

    # GitHub Search API returns one item whose html_url then 404s on existence
    # check (simulating a fabricated/hallucinated repo that does not exist).
    gh_payload = json.dumps({
        "items": [{"html_url": "https://github.com/zverok/openssh-regreSSHion-exploit",
                   "full_name": "zverok/openssh-regreSSHion-exploit",
                   "stargazers_count": 0, "description": "fake"}]
    }).encode()

    def fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "api.github.com/search" in url:
            return _FakeResp(gh_payload, 200)
        # existence check on the repo URL -> 404
        return _FakeResp(b"", 404)

    # searchsploit not installed -> FileNotFoundError path
    def fake_run(cmd, **kw):
        raise FileNotFoundError("no searchsploit")

    monkeypatch.setattr("tools.exploit_search.urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("tools.exploit_search.subprocess.run", fake_run)

    out = s.cve_to_poc("CVE-2024-6387")
    assert out.startswith("NO_VERIFIED_POC_FOUND")
    assert "zverok" not in out  # the hallucinated repo must NOT appear
    assert "Do NOT guess" in out


def test_verified_github_repo_returned(monkeypatch):
    """A real (200) GitHub repo URL is returned in CVE_TO_POC_RESULTS."""
    s = _make_search()
    gh_payload = json.dumps({
        "items": [{"html_url": "https://github.com/zverok/openssh-regreSSHion-real",
                   "full_name": "zverok/openssh-regreSSHion-real",
                   "stargazers_count": 42, "description": "real PoC"}]
    }).encode()

    def fake_urlopen(req, timeout=None):
        return _FakeResp(gh_payload, 200)  # both search and existence check 200

    def fake_run(cmd, **kw):
        raise FileNotFoundError("no searchsploit")

    monkeypatch.setattr("tools.exploit_search.urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("tools.exploit_search.subprocess.run", fake_run)

    out = s.cve_to_poc("CVE-2024-6387")
    assert out.startswith("CVE_TO_POC_RESULTS:")
    data = json.loads(out.split("CVE_TO_POC_RESULTS:\n", 1)[1])
    assert data[0]["url"] == "https://github.com/zverok/openssh-regreSSHion-real"
    assert data[0]["source"] == "github"
    assert data[0]["stars"] == 42


def test_prompt_forbids_url_guessing():
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(attacker_os="Linux", target_ip="10.0.0.5")
    assert "NEVER fabricate or guess exploit/PoC repository URLs" in prompt
    assert "cve_to_poc" in prompt
    assert "NO_VERIFIED_POC_FOUND" in prompt


def test_mcp_instructions_forbid_url_guessing():
    import inspect

    import mcp_exploit_server

    src = inspect.getsource(mcp_exploit_server)
    assert "cve_to_poc" in src
    assert "NEVER fabricate or guess" in src
    assert "NO_VERIFIED_POC_FOUND" in src
