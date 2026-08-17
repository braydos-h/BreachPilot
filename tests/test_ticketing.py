"""Tests for tools/ticketing.py — remediation ticket generation.

Hermetic: no real network. The HTTP POST is intercepted by monkeypatching
``urllib.request.urlopen``. Asserts a confirmed finding produces a ticket
payload with the right fields, the provider field-mapping is correct, auth
missing is a no-op, and the API-down path retries then drops without raising.
"""
from __future__ import annotations

import json
import urllib.error
from typing import Any
from unittest.mock import patch

from tools.ticketing import build_ticket_payload, create_ticket

# ── build_ticket_payload (pure, no network) ──────────────────────────────────


def _sample_finding() -> dict[str, Any]:
    return {
        "finding_id": "F-001",
        "title": "SMBv1 EternalBlue exposure",
        "affected_asset": "10.0.0.5",
        "vuln_class": "Remote Code Execution",
        "severity": "critical",
        "cvss": {"base_score": 8.8},
        "confidence": 0.95,
        "summary": "SMBv1 is enabled and vulnerable to MS17-010.",
        "reproduction_steps": ["nmap -p 445 --script smb-vuln-ms17-010 10.0.0.5", "observe vuln result"],
        "evidence_refs": ["evidence/nmap.txt"],
        "exploitation_result": "success",
        "remediation": "Apply MS17-010 patch. Disable SMBv1.",
        "references": ["https://cve.mitre.org/CVE-2017-0144"],
    }


def test_build_jira_payload_has_required_fields():
    payload = build_ticket_payload(_sample_finding(), provider="jira", project_key="SEC")
    fields = payload["fields"]
    assert "EternalBlue" in fields["summary"]
    assert fields["project"]["key"] == "SEC"
    assert fields["issuetype"]["name"] == "Bug"
    assert "security" in fields["labels"]
    assert "severity-critical" in fields["labels"]
    assert "MS17-010" in fields["description"]


def test_build_github_payload_has_required_fields():
    payload = build_ticket_payload(_sample_finding(), provider="github")
    assert "EternalBlue" in payload["title"]
    assert "security" in payload["labels"]
    assert "severity:critical" in payload["labels"]
    assert "MS17-010" in payload["body"]


def test_build_payload_unknown_provider_returns_empty():
    payload = build_ticket_payload(_sample_finding(), provider="gitlab")
    assert payload == {}


def test_build_payload_missing_fields_skipped_not_crashed():
    minimal = {"finding_id": "F-002", "title": "X"}
    payload = build_ticket_payload(minimal, provider="jira", project_key="SEC")
    # must not crash; severity falls back to "unknown"
    assert payload["fields"]["summary"] == "X"
    assert "severity-unknown" in payload["fields"]["labels"]


def test_build_payload_title_capped():
    finding = dict(_sample_finding(), title="x" * 500)
    payload = build_ticket_payload(finding, provider="github")
    assert len(payload["title"]) <= 200


def test_build_payload_includes_cvss_when_present():
    payload = build_ticket_payload(_sample_finding(), provider="github")
    assert "8.8" in payload["body"]


def test_build_payload_skips_non_list_repro():
    finding = dict(_sample_finding(), reproduction_steps="not a list")
    payload = build_ticket_payload(finding, provider="github")
    # no crash; body still built
    assert "Summary" in payload["body"]


# ── create_ticket (network mocked) ───────────────────────────────────────────


class _FakeResp:
    def __init__(self, status: int = 201, headers: dict[str, str] | None = None):
        self.status = status
        self._headers = headers or {"Location": "https://jira.example.com/browse/SEC-1"}
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    @property
    def headers(self):
        return self._headers


def test_create_ticket_jira_success(monkeypatch):
    cfg = {"ticketing": {"enabled": True, "provider": "jira", "base_url": "https://jira.example.com", "token_env": "TICKETING_TOKEN", "project_key": "SEC"}}
    monkeypatch.setenv("TICKETING_TOKEN", "secret-token")
    posts: list[Any] = []
    with patch("urllib.request.urlopen", side_effect=lambda req, timeout: (posts.append(req), _FakeResp(201))[1]):
        result = create_ticket(_sample_finding(), cfg)
    assert result["created"] is True
    assert "SEC-1" in result["url"]
    assert len(posts) == 1
    # auth header present
    assert posts[0].headers["Authorization"] == "Bearer secret-token"
    # payload is valid JSON with jira shape
    sent = json.loads(posts[0].data.decode("utf-8"))
    assert sent["fields"]["project"]["key"] == "SEC"


def test_create_ticket_github_success(monkeypatch):
    cfg = {"ticketing": {"enabled": True, "provider": "github", "base_url": "https://api.github.com/repos/owner/repo", "token_env": "GH_TOKEN"}}
    monkeypatch.setenv("GH_TOKEN", "ghp-token")
    posts: list[Any] = []
    with patch("urllib.request.urlopen", side_effect=lambda req, timeout: (posts.append(req), _FakeResp(201, {"Location": "https://api.github.com/repos/owner/repo/issues/1"}))[1]):
        result = create_ticket(_sample_finding(), cfg)
    assert result["created"] is True
    assert len(posts) == 1
    sent = json.loads(posts[0].data.decode("utf-8"))
    assert "title" in sent
    assert "body" in sent


def test_create_ticket_disabled_no_post(monkeypatch):
    cfg = {"ticketing": {"enabled": False, "provider": "jira", "base_url": "https://jira.example.com", "token_env": "TICKETING_TOKEN"}}
    monkeypatch.setenv("TICKETING_TOKEN", "tok")
    posts: list[Any] = []
    with patch("urllib.request.urlopen", side_effect=lambda req, timeout: (posts.append(req), _FakeResp(201))[1]):
        result = create_ticket(_sample_finding(), cfg)
    assert result["created"] is False
    assert result["status"] == "disabled"
    assert posts == []


def test_create_ticket_missing_token_no_post(monkeypatch):
    cfg = {"ticketing": {"enabled": True, "provider": "jira", "base_url": "https://jira.example.com", "token_env": "MISSING_TOKEN"}}
    monkeypatch.delenv("MISSING_TOKEN", raising=False)
    posts: list[Any] = []
    with patch("urllib.request.urlopen", side_effect=lambda req, timeout: (posts.append(req), _FakeResp(201))[1]):
        result = create_ticket(_sample_finding(), cfg)
    assert result["created"] is False
    assert "auth missing" in result["status"]
    assert posts == []


def test_create_ticket_missing_base_url_no_post():
    cfg = {"ticketing": {"enabled": True, "provider": "jira", "base_url": "", "token_env": "TICKETING_TOKEN"}}
    result = create_ticket(_sample_finding(), cfg)
    assert result["created"] is False
    assert "base_url" in result["status"]


def test_create_ticket_unknown_provider_no_post():
    cfg = {"ticketing": {"enabled": True, "provider": "gitlab", "base_url": "https://gitlab.example.com", "token_env": "TICKETING_TOKEN"}}
    result = create_ticket(_sample_finding(), cfg)
    assert result["created"] is False
    assert "unknown provider" in result["status"]


def test_create_ticket_retry_then_drop_does_not_raise(monkeypatch):
    cfg = {"ticketing": {"enabled": True, "provider": "jira", "base_url": "https://jira.example.com", "token_env": "TICKETING_TOKEN", "max_retries": 2, "backoff_seconds": 0.0}}
    monkeypatch.setenv("TICKETING_TOKEN", "tok")
    calls = {"n": 0}
    def fail(req, timeout):
        calls["n"] += 1
        raise urllib.error.URLError("down")
    with patch("urllib.request.urlopen", side_effect=fail):
        result = create_ticket(_sample_finding(), cfg)
    assert result["created"] is False
    assert calls["n"] == 2  # retried up to max_retries


def test_create_ticket_rate_limit_honors_retry_after(monkeypatch):
    cfg = {"ticketing": {"enabled": True, "provider": "jira", "base_url": "https://jira.example.com", "token_env": "TICKETING_TOKEN", "max_retries": 3, "backoff_seconds": 0.0}}
    monkeypatch.setenv("TICKETING_TOKEN", "tok")
    # first call 429 with Retry-After: 0, second call 201
    responses = [
        urllib.error.HTTPError(url="https://jira.example.com", code=429, msg="rate limited", hdrs={"Retry-After": "0"}, fp=None),
        _FakeResp(201),
    ]
    calls = {"n": 0}
    def fake(req, timeout):
        r = responses[calls["n"]]
        calls["n"] += 1
        if isinstance(r, Exception):
            raise r
        return r
    with patch("urllib.request.urlopen", side_effect=fake):
        result = create_ticket(_sample_finding(), cfg)
    assert result["created"] is True
    assert calls["n"] == 2


def test_create_ticket_no_network_in_ci(monkeypatch):
    """The test must not make a real network call."""
    cfg = {"ticketing": {"enabled": True, "provider": "jira", "base_url": "https://jira.example.com", "token_env": "TICKETING_TOKEN"}}
    monkeypatch.setenv("TICKETING_TOKEN", "tok")
    # If urlopen is not mocked, this would try a real DNS lookup. We patch it
    # to fail loudly if called without the patch.
    def fail(*args, **kwargs):
        raise AssertionError("urlopen was called without a mock — real network attempt")
    with patch("urllib.request.urlopen", side_effect=fail):
        # disabled, so no call
        cfg["ticketing"]["enabled"] = False
        result = create_ticket(_sample_finding(), cfg)
    assert result["created"] is False
