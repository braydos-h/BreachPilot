"""Regression tests for write_python_file's binary=True mode (Gap 1).

The prompt (``tools/exploit_agent/prompt.py`` FILE & KEY HANDLING) tells the agent
that ``write_python_file`` writes bytes verbatim for SSH-key materialization.
Before this fix the tool used ``Path.write_text`` regardless, so a key with
non-UTF-8 bytes was silently corrupted (libcrypto "no start line"). ``binary=True``
base64-decodes the payload and writes raw bytes; the default text path is
byte-identical to the old behavior for Python source.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any

import pytest

# ── Harness (mirrors tests/test_mcp_injection_hardening.py) ─────────────────


def _make_server(tmp_path: Path):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    search = ExploitSearch(ExploitSearchSettings())
    nvd = NVDClient(CVESearchSettings())
    config: dict[str, Any] = {"exploit": {"require_explicit_allowlist": False, "allowed_targets": []}}
    return create_mcp_server(search, nvd, WebResearcher(WebResearcherSettings()), tmp_path, config)


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


# ── Tests ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_write_python_file_text_mode_unchanged(tmp_path: Path) -> None:
    """Default path: Python source written as UTF-8 text, byte-identical to old."""
    mcp = _make_server(tmp_path)
    code = "import os\nprint('ok')\n"
    text = _text(
        await mcp.call_tool(
            "write_python_file",
            {"filename": "exploit.py", "code": code},
        )
    )
    assert "PYTHON_FILE_WRITTEN" in text
    assert "MODE: text" in text
    assert f"SHA256: {hashlib.sha256(code.encode('utf-8')).hexdigest()}" in text
    assert f"SIZE: {len(code)} chars" in text
    # Locate the file via the returned PATH line and confirm byte-exact content.
    path_line = [ln for ln in text.splitlines() if ln.startswith("PATH:")]
    assert path_line, "PATH line missing from result"
    written = Path(path_line[0].split(":", 1)[1].strip())
    assert written.read_text(encoding="utf-8") == code


@pytest.mark.asyncio
async def test_write_python_file_binary_mode_writes_bytes(tmp_path: Path) -> None:
    """binary=True writes raw bytes, including non-UTF-8 bytes, byte-exact."""
    mcp = _make_server(tmp_path)
    # A private key body with a non-UTF-8 byte (0xff) that write_text would mangle.
    raw = b"-----BEGIN OPENSSH PRIVATE KEY-----\n\xff\xfe non-utf8\n-----END-----\n"
    payload_b64 = base64.b64encode(raw).decode("ascii")
    text = _text(
        await mcp.call_tool(
            "write_python_file",
            {"filename": "id_ed25519", "code": payload_b64, "binary": True},
        )
    )
    assert "PYTHON_FILE_WRITTEN" in text
    assert "MODE: binary" in text
    assert f"SHA256: {hashlib.sha256(raw).hexdigest()}" in text
    assert f"SIZE: {len(raw)} bytes" in text
    path_line = [ln for ln in text.splitlines() if ln.startswith("PATH:")]
    written = Path(path_line[0].split(":", 1)[1].strip())
    # Byte-exact: the non-UTF-8 byte survives (write_text would have raised or
    # replaced it).
    assert written.read_bytes() == raw


@pytest.mark.asyncio
async def test_write_python_file_binary_rejects_invalid_base64(tmp_path: Path) -> None:
    """A non-base64 payload under binary=True fails loudly, not silently."""
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "write_python_file",
            {"filename": "bad.bin", "code": "not!!base64!!", "binary": True},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "valid base64" in text


@pytest.mark.asyncio
async def test_write_python_file_binary_absolute_path(tmp_path: Path) -> None:
    """binary=True honors an absolute path (LAB build: unrestricted)."""
    mcp = _make_server(tmp_path)
    target = tmp_path / "nested" / "key.pem"
    raw = b"\x00\x01\x02PEM\x80\x81"
    text = _text(
        await mcp.call_tool(
            "write_python_file",
            {"filename": str(target), "code": base64.b64encode(raw).decode(), "binary": True},
        )
    )
    assert "MODE: binary" in text
    assert target.read_bytes() == raw
