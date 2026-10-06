"""Regression tests for contained write_python_file behavior.

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
import json
from pathlib import Path
from typing import Any

import pytest


def test_workspace_writer_creates_missing_root(tmp_path: Path) -> None:
    from tools.kernel.workspace import write_workspace_file

    root = tmp_path / "new-workspace"

    written = write_workspace_file(root, "payload.bin", b"safe")

    assert written.read_bytes() == b"safe"
    assert written.parent == root


def test_workspace_writer_refuses_symlink_root(tmp_path: Path) -> None:
    from tools.kernel.workspace import write_workspace_file

    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    outside.mkdir()
    workspace.symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError):
        write_workspace_file(workspace, "payload.bin", b"must not escape")
    assert not (outside / "payload.bin").exists()


def test_workspace_writer_refuses_symlink_parent(tmp_path: Path) -> None:
    """A worker-created directory symlink cannot redirect a later host write."""
    from tools.kernel.workspace import write_workspace_file

    root = tmp_path / "workspace"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "attempt").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        write_workspace_file(root, "attempt/payload.bin", b"not written")
    assert not (outside / "payload.bin").exists()


def test_workspace_writer_refuses_symlink_leaf(tmp_path: Path) -> None:
    """An existing worker-controlled leaf cannot redirect host-side writes."""
    from tools.kernel.workspace import write_workspace_file

    root = tmp_path / "workspace"
    attempt = root / "attempt"
    outside = tmp_path / "operator-data.txt"
    attempt.mkdir(parents=True)
    outside.write_text("keep", encoding="utf-8")
    (attempt / "terminal.log").symlink_to(outside)

    with pytest.raises(OSError):
        write_workspace_file(root, "attempt/terminal.log", b"overwrite")
    assert outside.read_text(encoding="utf-8") == "keep"


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
async def test_write_python_file_binary_absolute_path_is_refused(tmp_path: Path) -> None:
    """Agent-provided paths cannot write outside the run workspace."""
    mcp = _make_server(tmp_path)
    target = tmp_path / "nested" / "key.pem"
    raw = b"\x00\x01\x02PEM\x80\x81"
    text = _text(
        await mcp.call_tool(
            "write_python_file",
            {"filename": str(target), "code": base64.b64encode(raw).decode(), "binary": True},
        )
    )
    assert text.startswith("BLOCKED:")
    assert not target.exists()


@pytest.mark.asyncio
async def test_write_python_file_audit_redacts_base64_key_material(tmp_path: Path) -> None:
    """Audit captures a digest and size without persisting source or key bytes."""
    mcp = _make_server(tmp_path)
    raw = b"-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-key-material\n-----END-----\n"
    payload_b64 = base64.b64encode(raw).decode("ascii")
    result = _text(
        await mcp.call_tool(
            "write_python_file",
            {"filename": "id_ed25519", "code": payload_b64, "binary": True},
        )
    )
    assert "PYTHON_FILE_WRITTEN" in result
    audit = (tmp_path / "exploit_audit.jsonl").read_text(encoding="utf-8")
    assert payload_b64 not in audit
    assert raw.decode("ascii") not in audit
    record = next(json.loads(line) for line in audit.splitlines() if '"tool_name": "write_python_file"' in line)
    assert record["args"]["code"] == {
        "redacted": True,
        "chars": len(payload_b64),
        "sha256": hashlib.sha256(payload_b64.encode("utf-8")).hexdigest(),
    }
