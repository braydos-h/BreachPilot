"""Contained-process test seams; never launch target tools from the test host."""

from __future__ import annotations

import subprocess
import time
from typing import Any

_ORIGINAL_SUBPROCESS_RUN = subprocess.run


def install_fake_sandbox_tool_runner(monkeypatch: Any, modules: tuple[str, ...]) -> None:
    """Patch MCP tool wrappers to return controlled results without a worker.

    Existing tool contract tests patch either subprocess.run or the server's
    process-group runner. This adapter preserves those assertions while
    production code continues to call the sandbox-only wrapper.
    """
    import importlib

    import mcp_exploit_server

    monkeypatch.setattr("tools.sandbox.resolve_manager_with_fallback", lambda *_args: (None, ""))
    default_pgrp_runner = mcp_exploit_server._run_with_pgrp_timeout

    def fake_run_tool_argv(
        _ctx: Any,
        argv: list[str],
        *,
        timeout: int,
        tool_name: str,
        cwd_host=None,
        env=None,
        max_chars: int = 4000,
        **_kwargs: Any,
    ) -> tuple[str, int | None, str, float]:
        del tool_name
        started = time.monotonic()
        if mcp_exploit_server._run_with_pgrp_timeout is not default_pgrp_runner:
            rc, stdout, stderr = mcp_exploit_server._run_with_pgrp_timeout(
                argv,
                timeout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(cwd_host) if cwd_host else None,
                env=env,
            )
        elif subprocess.run is not _ORIGINAL_SUBPROCESS_RUN:
            proc = subprocess.run(
                argv,
                cwd=str(cwd_host) if cwd_host else None,
                env=env,
                timeout=timeout,
                capture_output=True,
                text=True,
            )
            rc, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        else:
            rc, stdout, stderr = 0, "ok", ""
        output = "\n".join(part for part in (stdout, stderr) if part)
        if max_chars > 0:
            output = output[-max_chars:]
        return ("completed" if rc == 0 else "failed"), rc, output, time.monotonic() - started

    for module_name in modules:
        module = importlib.import_module(module_name)
        monkeypatch.setattr(module, "run_tool_argv_in_sandbox", fake_run_tool_argv)
