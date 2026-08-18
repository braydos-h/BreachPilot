"""Phase 3 — MSF recipe catalog, run_recipe dispatch, handler orchestration,
and the msf_run_recipe / msf_start_handler / msf_stop_handler MCP tools.

The bridge methods are exercised with a real ``MetasploitBridge`` whose
``run_exploit``/``run_auxiliary``/``run_post_module``/``run_resource_script``/
``console_command`` are monkeypatched to record calls (no msfconsole, no
tmux). The MCP tools are exercised via ``create_mcp_server`` + ``call_tool``
with ``get_msf_bridge`` patched to return a fake. No live network.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tools.metasploit_bridge import (
    MSF_RECIPES,
    MetasploitBridge,
    get_msf_recipe,
)


# ── catalog ──────────────────────────────────────────────────────────────────

def test_recipes_present() -> None:
    for n in ("smb_version", "bluekeep", "psexec", "cred_gather_win",
              "local_exploit_suggester", "hashdump", "getsystem", "handler"):
        assert n in MSF_RECIPES
        r = MSF_RECIPES[n]
        assert "module" in r and "kind" in r and "description" in r
        assert r["kind"] in ("exploit", "auxiliary", "post", "handler")


def test_get_msf_recipe_returns_copy() -> None:
    r = get_msf_recipe("bluekeep")
    # Phase 2: the recipe module path was a typo (exploit/windows/smb/
    # ms17_010_bluekeep does not exist in msfconsole); the real module is the
    # RDP one.
    assert r and r["module"] == "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"
    r["module"] = "mutated"
    assert MSF_RECIPES["bluekeep"]["module"] == "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"  # copy, not alias


def test_get_msf_recipe_unknown() -> None:
    assert get_msf_recipe("nope") is None
    assert get_msf_recipe("") is None


# ── bridge run_recipe dispatch (fake bridge) ─────────────────────────────────

def _bridge(tmp_path: Path) -> MetasploitBridge:
    return MetasploitBridge(tmp_path)


def test_run_recipe_unknown_returns_error(tmp_path: Path) -> None:
    b = _bridge(tmp_path)
    res = b.run_recipe("does_not_exist", "10.0.0.1")
    assert res["success"] is False
    assert "unknown MSF recipe" in res["error"]


def test_run_recipe_auxiliary_routes_to_run_auxiliary(monkeypatch, tmp_path: Path) -> None:
    b = _bridge(tmp_path)
    captured: dict[str, Any] = {}
    def fake_aux(module, target_ip, options=None, wait_seconds=15.0):
        captured.update(module=module, target_ip=target_ip, options=options)
        return {"success": True, "module": module, "target_ip": target_ip, "output": "ok"}
    monkeypatch.setattr(b, "run_auxiliary", fake_aux)
    res = b.run_recipe("smb_version", "10.0.0.1")
    assert res["success"] is True
    assert captured["module"] == "auxiliary/scanner/smb/smb_version"
    assert captured["target_ip"] == "10.0.0.1"
    assert captured["options"] == {}


def test_run_recipe_post_requires_session(monkeypatch, tmp_path: Path) -> None:
    b = _bridge(tmp_path)
    res = b.run_recipe("hashdump", session_id=0)
    assert res["success"] is False
    assert "session_id" in res["error"]


def test_run_recipe_post_routes_to_run_post_module(monkeypatch, tmp_path: Path) -> None:
    b = _bridge(tmp_path)
    captured: dict[str, Any] = {}
    def fake_post(module, session_id, options=None):
        captured.update(module=module, session_id=session_id, options=options)
        return {"success": True, "module": module, "session_id": session_id, "output": "ok"}
    monkeypatch.setattr(b, "run_post_module", fake_post)
    res = b.run_recipe("local_exploit_suggester", session_id=2)
    assert res["success"] is True
    assert captured["module"] == "post/multi/recon/local_exploit_suggester"
    assert captured["session_id"] == 2


def test_run_recipe_exploit_routes_to_run_exploit(monkeypatch, tmp_path: Path) -> None:
    b = _bridge(tmp_path)
    captured: dict[str, Any] = {}
    def fake_exp(module, target_ip, options=None, payload="", wait_seconds=30.0):
        captured.update(module=module, target_ip=target_ip, payload=payload, options=options)
        return {"success": True, "status": "completed", "output": "ok"}
    monkeypatch.setattr(b, "run_exploit", fake_exp)
    res = b.run_recipe("bluekeep", "10.0.0.1")
    assert res["success"] is True
    assert captured["module"] == "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"
    assert captured["payload"] == "windows/x64/meterpreter/reverse_tcp"


def test_run_recipe_options_override_preset(monkeypatch, tmp_path: Path) -> None:
    b = _bridge(tmp_path)
    captured: dict[str, Any] = {}
    def fake_aux(module, target_ip, options=None, wait_seconds=15.0):
        captured["options"] = options
        return {"success": True, "output": ""}
    monkeypatch.setattr(b, "run_auxiliary", fake_aux)
    b.run_recipe("smb_version", "10.0.0.1", options={"threads": "20"})
    assert captured["options"] == {"threads": "20"}


# ── handler orchestration ────────────────────────────────────────────────────

def test_start_handler_builds_resource_script(monkeypatch, tmp_path: Path) -> None:
    b = _bridge(tmp_path)
    captured: dict[str, Any] = {}
    def fake_rc(script_content):
        captured["script"] = script_content
        return {"success": True, "output": "handler started"}
    monkeypatch.setattr(b, "run_resource_script", fake_rc)
    res = b.start_handler("10.0.0.5", 4444, "windows/meterpreter/reverse_tcp")
    assert res["success"] is True
    script = captured["script"]
    assert "use exploit/multi/handler" in script
    assert "set PAYLOAD windows/meterpreter/reverse_tcp" in script
    assert "set LHOST 10.0.0.5" in script
    assert "set LPORT 4444" in script
    assert "set ExitOnSession false" in script
    assert "exploit -j -z" in script


def test_start_handler_options_extra_set(monkeypatch, tmp_path: Path) -> None:
    b = _bridge(tmp_path)
    captured: dict[str, Any] = {}
    monkeypatch.setattr(b, "run_resource_script", lambda s: captured.__setitem__("script", s) or {"success": True, "output": ""})
    b.start_handler("10.0.0.5", 4444, "windows/meterpreter/reverse_tcp", {"SessionCommunicationTimeout": "300"})
    assert "set SessionCommunicationTimeout 300" in captured["script"]


def test_stop_handler_calls_jobs_kill(monkeypatch, tmp_path: Path) -> None:
    b = _bridge(tmp_path)
    captured: dict[str, Any] = {}
    def fake_cmd(command, wait_seconds=2.0, read_lines=100):
        captured["command"] = command
        return {"success": True, "output": "stopping"}
    monkeypatch.setattr(b, "console_command", fake_cmd)
    res = b.stop_handler()
    assert res["success"] is True
    assert captured["command"] == "jobs -K"


def test_run_recipe_handler_routes_to_start_handler(monkeypatch, tmp_path: Path) -> None:
    b = _bridge(tmp_path)
    captured: dict[str, Any] = {}
    def fake_handler(lhost, lport, payload, options=None):
        captured.update(lhost=lhost, lport=lport, payload=payload)
        return {"success": True, "output": ""}
    monkeypatch.setattr(b, "start_handler", fake_handler)
    res = b.run_recipe("handler", target_ip="10.0.0.5")
    assert res["success"] is True
    assert captured["lhost"] == "10.0.0.5"
    assert captured["payload"] == "windows/meterpreter/reverse_tcp"


# ── MCP tools ────────────────────────────────────────────────────────────────

def _make_server(tmp_path: Path, *, require_allowlist: bool = False,
                 allowed: list[str] | None = None, recipes_enabled: bool = True):
    from mcp_exploit_server import create_mcp_server
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.cve_lookup import NVDClient, CVESearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {
        "exploit": {
            "require_explicit_allowlist": require_allowlist,
            "allowed_targets": allowed or [],
            "msf": {"recipes_enabled": recipes_enabled, "auto_local_exploit_suggester": False},
        }
    }
    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        config,
    )


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


class _FakeBridge:
    """Minimal stand-in for MetasploitBridge for the MCP tools."""
    def __init__(self) -> None:
        self.recipe_calls: list[dict[str, Any]] = []
        self.handler_calls: list[dict[str, Any]] = []
        self.stop_calls = 0
    def run_recipe(self, name, target_ip="", session_id=0, options=None):
        self.recipe_calls.append({"name": name, "target_ip": target_ip, "session_id": session_id, "options": options})
        return {"success": True, "output": f"ran {name}"}
    def start_handler(self, lhost, lport, payload, options=None):
        self.handler_calls.append({"lhost": lhost, "lport": lport, "payload": payload})
        return {"success": True, "output": "handler up"}
    def stop_handler(self):
        self.stop_calls += 1
        return {"success": True, "output": "stopped"}
    def run_post_module(self, module, session_id, options=None):
        return {"success": True, "module": module, "session_id": session_id, "output": "post ok"}


@pytest.mark.asyncio
async def test_msf_run_recipe_config_off(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, recipes_enabled=False)
    text = _text(await mcp.call_tool("msf_run_recipe", {"name": "smb_version", "target_ip": "10.0.0.1"}))
    assert "BLOCKED" in text and "recipes_enabled" in text


@pytest.mark.asyncio
async def test_msf_run_recipe_unknown_name(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("msf_run_recipe", {"name": "nope", "target_ip": "10.0.0.1"}))
    assert "BLOCKED" in text and "unknown MSF recipe" in text


@pytest.mark.asyncio
async def test_msf_run_recipe_offlist_target_blocked(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=True, allowed=["10.0.0.1"])
    text = _text(await mcp.call_tool("msf_run_recipe", {"name": "smb_version", "target_ip": "10.0.0.99"}))
    assert "BLOCKED" in text and "10.0.0.99" in text


@pytest.mark.asyncio
async def test_msf_run_recipe_dispatches(monkeypatch, tmp_path: Path) -> None:
    fake = _FakeBridge()
    monkeypatch.setattr("tools.mcp_tools.metasploit.get_metasploit_bridge", lambda ws: fake)
    mcp = _make_server(tmp_path, require_allowlist=True, allowed=["10.0.0.1"])
    text = _text(await mcp.call_tool("msf_run_recipe", {"name": "smb_version", "target_ip": "10.0.0.1"}))
    assert "MSF_RECIPE_RESULT" in text and "smb_version" in text
    assert fake.recipe_calls and fake.recipe_calls[0]["name"] == "smb_version"


@pytest.mark.asyncio
async def test_msf_start_handler_offlist_lhost_blocked(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=True, allowed=["10.0.0.1"])
    text = _text(await mcp.call_tool("msf_start_handler", {"lhost": "10.0.0.99", "lport": 4444}))
    assert "BLOCKED" in text and "10.0.0.99" in text


@pytest.mark.asyncio
async def test_msf_start_handler_dispatches(monkeypatch, tmp_path: Path) -> None:
    fake = _FakeBridge()
    monkeypatch.setattr("tools.mcp_tools.metasploit.get_metasploit_bridge", lambda ws: fake)
    mcp = _make_server(tmp_path, require_allowlist=True, allowed=["10.0.0.1"])
    text = _text(await mcp.call_tool("msf_start_handler", {"lhost": "10.0.0.1", "lport": 4444,
                                                          "payload": "windows/meterpreter/reverse_tcp"}))
    assert "MSF_HANDLER_STARTED" in text
    assert fake.handler_calls and fake.handler_calls[0]["lhost"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_msf_stop_handler_dispatches(monkeypatch, tmp_path: Path) -> None:
    fake = _FakeBridge()
    monkeypatch.setattr("tools.mcp_tools.metasploit.get_metasploit_bridge", lambda ws: fake)
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("msf_stop_handler", {}))
    assert "MSF_HANDLER_STOPPED" in text
    assert fake.stop_calls == 1


@pytest.mark.asyncio
async def test_msf_post_wrappers_dispatch(monkeypatch, tmp_path: Path) -> None:
    fake = _FakeBridge()
    monkeypatch.setattr("tools.mcp_tools.metasploit.get_metasploit_bridge", lambda ws: fake)
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("msf_post_hashdump", {"session_id": 1}))
    assert "MSF_POST_RESULT" in text and "hashdump" in text
    text = _text(await mcp.call_tool("msf_post_getsystem", {"session_id": 1}))
    assert "MSF_POST_RESULT" in text and "getsystem" in text


@pytest.mark.asyncio
async def test_msf_post_wrappers_require_session(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("msf_post_hashdump", {"session_id": 0}))
    assert "BLOCKED" in text and "session_id" in text


@pytest.mark.asyncio
async def test_msf_post_portfwd_offlist_remote_blocked(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=True, allowed=["10.0.0.1"])
    text = _text(await mcp.call_tool("msf_post_portfwd", {"session_id": 1, "remote_host": "10.0.0.99", "remote_port": 445}))
    assert "BLOCKED" in text and "10.0.0.99" in text


@pytest.mark.asyncio
async def test_msf_post_route_offlist_subnet_blocked(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=True, allowed=["10.0.0.1"])
    text = _text(await mcp.call_tool("msf_post_route", {"session_id": 1, "subnet": "10.99.0.0/24"}))
    assert "BLOCKED" in text and "10.99.0.0" in text


@pytest.mark.asyncio
async def test_msf_post_portfwd_dispatches(monkeypatch, tmp_path: Path) -> None:
    fake = _FakeBridge()
    monkeypatch.setattr("tools.mcp_tools.metasploit.get_metasploit_bridge", lambda ws: fake)
    mcp = _make_server(tmp_path, require_allowlist=True, allowed=["10.0.0.1"])
    text = _text(await mcp.call_tool("msf_post_portfwd", {"session_id": 1, "remote_host": "10.0.0.1", "remote_port": 445, "local_port": 8445}))
    assert "MSF_POST_RESULT" in text
    # The post module runner received the portfwd module + options.
    assert fake.handler_calls == []  # sanity: not routed to handler
