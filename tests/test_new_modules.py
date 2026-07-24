"""Quick smoke test for new modules.

Usage (no Ollama required):
    python test_new_modules.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path


def test_model_router():
    # We can't call Ollama without a running server, but we can test the router
    try:
        from tools.model_router import build_router
        router = build_router()
        aliases = {c.name for c in router.clients()}
        assert "kimi-k2.6:cloud" in aliases
        assert "deepseek-v4-pro:cloud" in aliases
        assert "glm-5.2:cloud" in aliases
        print(f"ModelRouter OK: aliases={aliases}")
    except RuntimeError as exc:
        print(f"ModelRouter OK (no ollama installed): {exc}")


def test_main_cli_parse():
    from main import parse_args

    args = parse_args(["--target", "10.0.0.1", "--mode", "attack"])
    assert args.target == "10.0.0.1"
    assert args.mode == "attack"
    print(f"CLI parse OK: target={args.target}, mode={args.mode}")

    args = parse_args(["--self-test"])
    assert args.self_test is True
    print("CLI parse OK: --self-test")

    args = parse_args(["--target", "127.0.0.1", "--mode", "recon", "--ultrathink"])
    assert args.ultrathink is True
    print("CLI parse OK: --ultrathink")


def test_config_defaults():
    import yaml
    cfg = yaml.safe_load(Path("config.yaml").read_text(encoding="utf-8"))
    assert cfg["models"]["registry"]["kimi"] == "kimi-k2.6:cloud"
    assert cfg["models"]["registry"]["deepseek"] == "deepseek-v4-pro:cloud"
    assert cfg["models"]["registry"]["glm"] == "glm-5.2:cloud"
    assert cfg["models"]["default_alias"] == "glm"
    assert cfg["ollama"]["model"] == "glm-5.2:cloud"
    assert "stealth" in cfg
    print("Config defaults OK")


def test_mcp_exploit_server_startup():
    """Smoke test that mcp_exploit_server imports and create_mcp_server is defined."""
    import subprocess
    import sys

    # Verify it compiles
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", "mcp_exploit_server.py"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"mcp_exploit_server.py compile failed: {result.stderr}"

    # Verify it can run --help
    result = subprocess.run(
        [sys.executable, "mcp_exploit_server.py", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"mcp_exploit_server.py --help failed: {result.stderr}"
    assert "MCP server" in result.stdout

    # Verify create_mcp_server is importable
    import mcp_exploit_server as _mcp_mod
    assert hasattr(_mcp_mod, "create_mcp_server"), "create_mcp_server not defined"
    assert callable(_mcp_mod.create_mcp_server), "create_mcp_server not callable"
    print("MCP exploit server startup OK")


if __name__ == "__main__":
    test_model_router()
    test_main_cli_parse()
    test_config_defaults()
    test_mcp_exploit_server_startup()
    print("\nAll smoke tests passed.")
