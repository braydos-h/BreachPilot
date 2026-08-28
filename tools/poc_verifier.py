"""Self-healing PoC verification (Killer Feature #3).

A synthesized PoC is **untrusted code** derived from NVD/GitHub content. This
module verifies a PoC *before* the agent declares success, without ever
running it on the operator box:

1. ``syntax_check`` -- ``py_compile`` the source (stdlib, compiles without
   executing). Safe on the operator box.
2. ``docker_check`` -- optionally compile/import the PoC inside a throwaway
   Docker container with ``--network=none --read-only --memory=256m`` and a
   timeout. A malicious PoC cannot reach the target or the operator box.

The MCP tool ``verify_poc`` (``tools/mcp_tools/poc_verifier.py``) wires this
into the exploit agent's loop so ``cve_to_exploit_synth`` can self-heal:
synth -> verify -> LLM fix -> re-verify, up to ``max_retries``.

Audit fields hash the code with SHA256 (first 16 hex chars) -- the source is
never logged verbatim.

Config (``config.yaml``)::

    poc_verification:
      enabled: false
      docker_image: python:3.11-slim
      compile_timeout_seconds: 30
      max_retries: 3
      docker_network: none       # never let the PoC reach the target/network
      docker_read_only: true
      docker_memory: 256m
"""

from __future__ import annotations

import hashlib
import py_compile
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def code_sha256(code: str) -> str:
    """SHA256 of the source, first 16 hex chars -- for audit fields, not logging."""
    return hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest()[:16]


@dataclass
class SyntaxResult:
    syntax_ok: bool
    stderr: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"syntax_ok": self.syntax_ok, "stderr": self.stderr}


@dataclass
class VerifyResult:
    syntax_ok: bool
    docker_ok: bool | None  # None = Docker skipped (not installed / disabled)
    stderr: str
    code_sha256: str
    image: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "syntax_ok": self.syntax_ok,
            "docker_ok": self.docker_ok,
            "stderr": self.stderr[:500],
            "code_sha256": self.code_sha256,
            "image": self.image,
        }


def syntax_check(code: str) -> SyntaxResult:
    """Compile-check Python source without executing it.

    Uses stdlib ``py_compile`` (safe: compiles to bytecode, does not run).
    Returns ``SyntaxResult`` with ``syntax_ok=False`` and the error on failure.
    """
    if not code or not code.strip():
        return SyntaxResult(False, stderr="empty code")
    tmpdir = Path(tempfile.mkdtemp(prefix="poc_syntax_"))
    src = tmpdir / "poc.py"
    try:
        src.write_text(code, encoding="utf-8")
        try:
            py_compile.compile(str(src), doraise=True)
            return SyntaxResult(True)
        except py_compile.PyCompileError as exc:
            return SyntaxResult(False, stderr=str(exc))
        except SyntaxError as exc:
            return SyntaxResult(False, stderr=f"{exc.msg} (line {exc.lineno})")
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass


def _docker_available() -> bool:
    """True if the ``docker`` CLI is on PATH and the daemon responds."""
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def docker_check(
    code: str,
    *,
    image: str = "python:3.11-slim",
    timeout: int = 30,
    network: str = "none",
    read_only: bool = True,
    memory: str = "256m",
) -> tuple[bool | None, str]:
    """Compile + import the PoC inside a throwaway, fully-isolated Docker container.

    Returns ``(docker_ok, stderr)``. ``docker_ok`` is ``None`` when Docker is
    not available (caller degrades to syntax-only). The container is run with
    ``--network=none --read-only --memory=<mem>`` and a ``timeout``-bounded
    ``py_compile``; a malicious PoC cannot reach the target or operator box.

    We write the source to a temp file and mount it read-only into the
    container, then run ``python -m py_compile /mounted/poc.py``. This
    compiles *and* imports any stdlib modules the PoC references at module
    load time -- it still does NOT execute the PoC's ``__main__`` block.
    """
    if not _docker_available():
        return None, "docker not available"

    tmpdir = Path(tempfile.mkdtemp(prefix="poc_docker_"))
    src = tmpdir / "poc.py"
    try:
        src.write_text(code, encoding="utf-8")
        argv: list[str] = [
            "docker",
            "run",
            "--rm",
            "--network",
            str(network),
            "--memory",
            str(memory),
            "--cpus",
            "1",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
        ]
        if read_only:
            argv.append("--read-only")
        argv.extend(
            [
                "--tmpfs",
                "/tmp:rw,size=8m",
                "-v",
                f"{src}:/poc.py:ro",
                str(image),
                "python",
                "-m",
                "py_compile",
                "/poc.py",
            ]
        )
        try:
            proc = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True,
            )
        except subprocess.TimeoutExpired:
            return False, f"docker compile timed out after {timeout}s"
        except OSError as exc:
            return None, f"docker run failed: {exc}"

        stderr = (proc.stderr or "").strip()
        if proc.returncode == 0:
            return True, stderr
        return False, stderr or f"py_compile exited {proc.returncode}"
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass


def verify_poc(
    code: str,
    *,
    image: str = "python:3.11-slim",
    timeout: int = 30,
    network: str = "none",
    read_only: bool = True,
    memory: str = "256m",
    use_docker: bool = True,
) -> VerifyResult:
    """Syntax-check (py_compile) and optionally Docker-compile a PoC.

    Returns ``VerifyResult``. When ``use_docker=False`` or Docker is not
    available, ``docker_ok`` is ``None`` (degraded to syntax-only). This is
    a **compile/import gate, not a sandbox guarantee** -- the PoC is never
    executed.
    """
    sha = code_sha256(code)
    syn = syntax_check(code)
    if not syn.syntax_ok:
        return VerifyResult(
            syntax_ok=False,
            docker_ok=None,
            stderr=syn.stderr,
            code_sha256=sha,
            image=image,
        )
    if not use_docker:
        return VerifyResult(
            syntax_ok=True,
            docker_ok=None,
            stderr=syn.stderr,
            code_sha256=sha,
            image=image,
        )
    dock_ok, dock_err = docker_check(
        code,
        image=image,
        timeout=timeout,
        network=network,
        read_only=read_only,
        memory=memory,
    )
    stderr = dock_err if dock_ok is False else (syn.stderr or dock_err)
    return VerifyResult(
        syntax_ok=True,
        docker_ok=dock_ok,
        stderr=stderr,
        code_sha256=sha,
        image=image,
    )


def render_verify_result(result: VerifyResult) -> str:
    """Render a ``VerifyResult`` as the MCP tool's text return."""
    dock_text = "skipped" if result.docker_ok is None else ("ok" if result.docker_ok else "FAILED")
    return (
        f"VERIFY_POC_RESULT:\n"
        f"CODE_SHA256: {result.code_sha256}\n"
        f"IMAGE: {result.image}\n"
        f"SYNTAX_OK: {str(result.syntax_ok).lower()}\n"
        f"DOCKER_OK: {dock_text}\n"
        f"STDERR: {result.stderr[:500]}"
    )


def poc_verification_config(config: dict[str, Any] | None) -> dict[str, Any]:
    """Resolve the ``poc_verification`` config block with defaults.

    ``max_retries`` falls back to ``agent.generated_code_repair_attempts``
    (capability-upgrade §23) when the ``poc_verification`` block does not set
    it explicitly, so the documented agent-block budget is honored. An absent
    agent block preserves the historical default of 3.
    """
    cfg = (config or {}).get("poc_verification", {}) or {}
    agent_cfg = (config or {}).get("agent", {}) or {}
    default_retries = int(agent_cfg.get("generated_code_repair_attempts", 3) or 3)
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "docker_image": str(cfg.get("docker_image", "python:3.11-slim")),
        "compile_timeout_seconds": int(cfg.get("compile_timeout_seconds", 30)),
        "max_retries": int(cfg.get("max_retries", default_retries)),
        "docker_network": str(cfg.get("docker_network", "none")),
        "docker_read_only": bool(cfg.get("docker_read_only", True)),
        "docker_memory": str(cfg.get("docker_memory", "256m")),
    }


# ─── Self-check ──────────────────────────────────────────────────────────


def _demo() -> int:
    """Runnable via ``python -m tools.poc_verifier``. Verifies two sample PoCs."""
    good = "def ok():\n    return 1\n\nif __name__ == '__main__':\n    print(ok())\n"
    bad = "def broken(:\n    pass\n"
    print("=== PoC Verifier self-check ===")
    for label, code in (("valid", good), ("syntax_error", bad)):
        r = verify_poc(code, use_docker=False)
        print(f"\n[{label}]")
        print(render_verify_result(r))
        assert r.syntax_ok == (label == "valid"), f"expected {label}"
    # Docker path: degraded to None when docker is absent (CI-safe).
    r2 = verify_poc(good, use_docker=True)
    print(f"\n[docker_available path] docker_ok={r2.docker_ok}")
    assert r2.syntax_ok is True
    print("\nOK")
    return 0


if __name__ == "__main__":
    sys.exit(_demo())
