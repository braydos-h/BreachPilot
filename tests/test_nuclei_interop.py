"""Tests for Nuclei two-way interop (findings in, templates out).

Covers: JSONL flags on the nuclei path (mocked subprocess only, no live
Nuclei), parse mapping (severity/CVSS/evidence/repro/MITRE), severity->CVSS
fallback, (template-id, host) dedup, template YAML validity, VALID/INVALID
reporting, and BLOCKED paths.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
import yaml

HIGH_EVENT = {
    "template-id": "cve-2021-41773-apache",
    "info": {
        "name": "Apache Path Traversal",
        "severity": "high",
        "reference": ["https://httpd.apache.org/security/"],
        "classification": {"cvss-score": "7.5", "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    },
    "matched-at": "http://10.0.0.50:80/cgi-bin/.%2e/",
    "host": "http://10.0.0.50:80",
    "request": "GET /cgi-bin/.%2e/ HTTP/1.1",
    "response": "HTTP/1.1 200 root:x:0:0",
    "matcher-name": "status",
}

MEDIUM_EVENT = {
    "template-id": "http-missing-security-headers",
    "info": {"name": "Missing Security Headers", "severity": "medium"},
    "matched-at": "http://10.0.0.50:80/",
    "host": "http://10.0.0.50:80",
}


def _make_server(tmp_path: Path, *, require_allowlist: bool = True):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.sandbox.models import SandboxResult
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    class FakeSandbox:
        def __init__(self) -> None:
            self.workspace = tmp_path
            self.cfg = SimpleNamespace(remove_stale_on_startup=False)
            self.calls: list[dict[str, Any]] = []
            self.events: list[dict[str, Any]] = []

        def container_path(self, path: Path) -> str:
            return f"/workspace/{Path(path).relative_to(self.workspace).as_posix()}"

        def execute_argv(self, argv: list[str], **kwargs: Any) -> SandboxResult:
            call = {"argv": list(argv), **kwargs}
            self.calls.append(call)
            if "-o" in argv and kwargs.get("cwd"):
                name = argv[argv.index("-o") + 1]
                relative_cwd = str(kwargs["cwd"]).removeprefix("/workspace/")
                output_path = self.workspace / relative_cwd / name
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text("\n".join(json.dumps(event) for event in self.events), encoding="utf-8")
            return SandboxResult(
                exit_code=0,
                stdout="scan tail\n",
                stderr="",
                timed_out=False,
                duration_seconds=0.1,
                status="completed",
            )

        def __getitem__(self, key: str) -> Any:
            call = self.calls[-1]
            return call["argv"] if key == "argv" else call.get("cwd")

    sandbox = FakeSandbox()

    config: dict[str, Any] = {
        "exploit": {"require_explicit_allowlist": require_allowlist, "allowed_targets": ["10.0.0.50"]}
    }
    with patch("tools.sandbox.resolve_manager_with_fallback", return_value=(sandbox, "")):
        server = create_mcp_server(
            ExploitSearch(ExploitSearchSettings()),
            NVDClient(CVESearchSettings()),
            WebResearcher(WebResearcherSettings()),
            tmp_path,
            config,
        )
    server._test_sandbox = sandbox
    return server


def _text(result) -> str:
    content = result[0] if isinstance(result, (list, tuple)) else result
    if hasattr(content, "content"):
        content = content.content
    parts = []
    for c in content:
        t = getattr(c, "text", None)
        if t is None and isinstance(c, dict):
            t = c.get("text")
        if t is None:
            t = str(c)
        parts.append(t)
    return "".join(parts)


def _attempt_id(text: str) -> str:
    return re.search(r"ATTEMPT_ID: (\S+)", text).group(1)


def _patch_nuclei_run(_monkeypatch, mcp, events: list[dict[str, Any]]):
    """Configure the fake worker response and return its latest invocation."""
    mcp._test_sandbox.events = events
    return mcp._test_sandbox


@pytest.mark.asyncio
async def test_nuclei_tools_are_registered(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    names = {tool.name for tool in await mcp.list_tools()}
    assert "parse_nuclei_results" in names
    assert "generate_nuclei_template" in names


@pytest.mark.asyncio
async def test_nuclei_scan_appends_jsonl_flags(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    captured = _patch_nuclei_run(monkeypatch, mcp, [HIGH_EVENT])

    text = _text(await mcp.call_tool("run_web_scan", {"scanner": "nuclei", "target_ip": "10.0.0.50"}))
    assert "WEB_SCAN_RESULT: completed" in text
    argv = captured["argv"]
    assert "-jsonl" in argv
    assert "-nc" in argv
    assert "-o" in argv
    assert argv[argv.index("-o") + 1] == "nuclei.jsonl"
    # The worker's /workspace cwd maps to this host-side attempt directory.
    assert captured["cwd"] is not None
    attempt_dir = tmp_path / _attempt_id(text)
    assert (attempt_dir / "nuclei.jsonl").is_file()
    assert (attempt_dir / "nuclei.log").is_file()


@pytest.mark.asyncio
async def test_nuclei_scan_honors_operator_json_flags(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    captured = _patch_nuclei_run(monkeypatch, mcp, [HIGH_EVENT])

    await mcp.call_tool(
        "run_web_scan",
        {"scanner": "nuclei", "target_ip": "10.0.0.50", "options": "-jsonl -o custom.json -nc"},
    )
    argv = captured["argv"]
    assert argv.count("-jsonl") == 1
    assert "nuclei.jsonl" not in argv
    assert "custom.json" in argv


@pytest.mark.asyncio
async def test_parse_maps_events_to_findings(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    _patch_nuclei_run(monkeypatch, mcp, [HIGH_EVENT, MEDIUM_EVENT])

    scan = _text(await mcp.call_tool("run_web_scan", {"scanner": "nuclei", "target_ip": "10.0.0.50"}))
    text = _text(await mcp.call_tool("parse_nuclei_results", {"attempt_id": _attempt_id(scan)}))
    assert text.startswith("NUCLEI_FINDINGS: 2 confirmed-candidate")
    assert "cve-2021-41773-apache" in text
    assert "http-missing-security-headers" in text
    assert "T1595" in text  # MITRE fallback for run_web_scan

    saved = tmp_path / _attempt_id(scan) / "nuclei-findings.json"
    records = json.loads(saved.read_text(encoding="utf-8"))
    assert len(records) == 2
    high = next(r for r in records if r["vuln_class"] == "cve-2021-41773-apache")
    assert high["severity"] == "High"
    assert high["cvss"]["base_score"] == 7.5  # from classification.cvss-score
    assert high["cvss"]["vector_string"].startswith("CVSS:3.1")
    assert high["affected_asset"] == "http://10.0.0.50:80/cgi-bin/.%2e/"
    assert any("root:x:0:0" in ref for ref in high["evidence_refs"])
    assert any("cve-2021-41773-apache" in step for step in high["reproduction_steps"])
    assert any("status" in step for step in high["reproduction_steps"])
    assert any("attack.mitre.org" in ref for ref in high["references"])
    assert high["confidence"] == 0.7
    medium = next(r for r in records if r["vuln_class"] == "http-missing-security-headers")
    assert medium["cvss"]["base_score"] == 5.0  # severity-default fallback


@pytest.mark.asyncio
async def test_parse_dedups_by_template_and_host(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    other_host = dict(MEDIUM_EVENT, **{"matched-at": "http://10.0.0.50:8080/", "host": "http://10.0.0.50:8080"})
    _patch_nuclei_run(monkeypatch, mcp, [MEDIUM_EVENT, dict(MEDIUM_EVENT), other_host, {"info": {}}])

    scan = _text(await mcp.call_tool("run_web_scan", {"scanner": "nuclei", "target_ip": "10.0.0.50"}))
    text = _text(await mcp.call_tool("parse_nuclei_results", {"attempt_id": _attempt_id(scan)}))
    # Exact duplicate collapsed, other host kept, template-less event skipped.
    assert text.startswith("NUCLEI_FINDINGS: 2 confirmed-candidate")


@pytest.mark.asyncio
async def test_parse_blocked_and_missing(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    assert _text(await mcp.call_tool("parse_nuclei_results", {"attempt_id": ""})).startswith("BLOCKED:")
    assert _text(await mcp.call_tool("parse_nuclei_results", {"attempt_id": "../evil"})).startswith("BLOCKED:")
    assert _text(await mcp.call_tool("parse_nuclei_results", {"attempt_id": "a/b"})).startswith("BLOCKED:")
    missing = _text(await mcp.call_tool("parse_nuclei_results", {"attempt_id": "no-such-attempt"}))
    assert missing.startswith("NUCLEI_FINDINGS: 0 confirmed-candidate")


@pytest.mark.asyncio
async def test_generate_template_valid_yaml(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    _patch_nuclei_run(monkeypatch, mcp, [HIGH_EVENT])

    scan = _text(await mcp.call_tool("run_web_scan", {"scanner": "nuclei", "target_ip": "10.0.0.50"}))
    aid = _attempt_id(scan)
    parsed = _text(await mcp.call_tool("parse_nuclei_results", {"attempt_id": aid}))
    fid = re.search(r"FINDING: (\S+)", parsed).group(1)

    text = _text(await mcp.call_tool("generate_nuclei_template", {"finding_id": fid}))
    assert text.startswith("NUCLEI_TEMPLATE: VALID")
    assert f"TEMPLATE_ID: {fid}" in text or "TEMPLATE_ID:" in text
    out_path = tmp_path / aid / f"nuclei-template-{fid}.yaml"
    assert out_path.is_file()
    doc = yaml.safe_load(out_path.read_text(encoding="utf-8"))
    assert doc["id"]
    assert doc["info"]["severity"] == "high"
    assert doc["info"]["classification"]
    assert doc["info"]["metadata"]["finding-id"] == fid
    assert isinstance(doc["http"], list) and doc["http"][0]["matchers"]


@pytest.mark.asyncio
async def test_generate_blocked_paths(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=False)
    assert _text(await mcp.call_tool("generate_nuclei_template", {"finding_id": ""})).startswith("BLOCKED:")
    assert _text(await mcp.call_tool("generate_nuclei_template", {"finding_id": "x/y"})).startswith("BLOCKED:")
    unknown = _text(await mcp.call_tool("generate_nuclei_template", {"finding_id": "NUCLEI-nope-unknown"}))
    assert unknown.startswith("BLOCKED:")
    assert "unknown finding_id" in unknown


def test_validate_rejects_invalid_schema_without_host_process(monkeypatch) -> None:
    import tools.mcp_tools.web_scan as ws

    def forbidden(*args, **kwargs):
        raise AssertionError("template validation must not launch a process on the MCP host")

    monkeypatch.setattr(ws, "subprocess", forbidden, raising=False)
    verdict, detail = ws._validate_nuclei_template(
        Path("dummy.yaml"),
        yaml.safe_dump(
            {
                "id": "x",
                "info": {"name": "n", "severity": "high", "description": "d"},
                "http": [{"matchers": []}],
            }
        ),
    )
    assert verdict == "INVALID"
    assert "missing matchers" in detail


def test_prompt_prefers_parse_over_scan_tail() -> None:
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(attacker_os="Linux", target_ip="10.0.0.5")
    assert "parse_nuclei_results" in prompt
    assert "generate_nuclei_template" in prompt
