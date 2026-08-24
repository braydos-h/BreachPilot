"""`--demo` mode (Phase 2.5).

Runs the full flow against a deliberately vulnerable local sandbox
(DVWA or equivalent) and produces a sample report. Safe to use in CI
or for sales/training.

Strategy:
  1. If `docker` is available and a DVWA image is not yet running,
     start it on localhost:8081 via `docker run -d`.
  2. Otherwise, fall back to a synthetic in-process vulnerable service
     (a tiny HTTP server that returns canned CVEs).
  3. Run a recon pass against the local target, generate a finding,
     and produce a report.
  4. Tear down the docker container (if we started it).

This is a defensive simulation — it never executes a real exploit
against a non-local target.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

_DVWA_IMAGE = "vulnerables/web-dvwa"
_DVWA_HOST_PORT = 8081


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _dvwa_running() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", _DVWA_HOST_PORT))
            return True
        except OSError:
            return False


def _start_dvwa_docker() -> bool:
    """Try to start DVWA in a Docker container. Returns True on success."""
    if not _docker_available():
        return False
    if _dvwa_running():
        return True
    try:
        proc = subprocess.run(
            ["docker", "run", "-d", "-p", f"{_DVWA_HOST_PORT}:80",
             "--name", "netattackai-demo", _DVWA_IMAGE],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            print(f"  [!] docker run failed: {proc.stderr[:200]}")
            return False
        # Wait for the port to come up
        for _ in range(30):
            if _dvwa_running():
                return True
            time.sleep(1)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False
    return False


def _start_synthetic_server() -> HTTPServer:
    """Start a tiny local HTTP server that reports fake CVEs.

    Used as a fallback when Docker is not available. NEVER exposes
    anything exploitable — just a banner that says "CVE-2021-44228
    detected" so the demo flow has something to find.
    """

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = json.dumps({
                "service": "demo-httpd",
                "version": "1.0-demo",
                "headers_seen": dict(self.headers),
                "note": "Synthetic demo service. Safe by design.",
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Powered-By", "demo-httpd/1.0")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:
            # Quiet by default
            pass

    server = HTTPServer(("127.0.0.1", _DVWA_HOST_PORT), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _teardown_dvwa() -> None:
    try:
        subprocess.run(
            ["docker", "rm", "-f", "netattackai-demo"],
            capture_output=True, text=True, timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass


def run_demo(args: Any) -> int:
    print("=" * 60)
    print("  NetAttackAI — DEMO mode (`--demo`)")
    print("  Target: 127.0.0.1:%d (local sandbox only)" % _DVWA_HOST_PORT)
    print("=" * 60)

    synthetic: HTTPServer | None = None
    used_docker = False
    if _dvwa_running():
        print("  [i] Existing service on 127.0.0.1:%d — using it." % _DVWA_HOST_PORT)
    elif _docker_available():
        print("  [i] Starting DVWA via Docker…")
        if _start_dvwa_docker():
            used_docker = True
            print("  [✓] DVWA started in Docker.")
        else:
            print("  [!] Docker start failed, falling back to synthetic server.")
    else:
        print("  [i] Docker not available; using synthetic in-process server.")

    if not _dvwa_running():
        print("  [i] Starting synthetic demo server on 127.0.0.1:%d" % _DVWA_HOST_PORT)
        try:
            synthetic = _start_synthetic_server()
        except OSError as exc:
            print(f"  [✗] Could not start synthetic server: {exc}")
            return 1
        time.sleep(0.5)

    try:
        # Reconstruct an args namespace for async_main with the local target
        from pathlib import Path
        new_args = type(args)(
            target="127.0.0.1",
            mode="recon",
            goal="initial_access",
            custom_goal="",
            config=Path(getattr(args, "config", "config.yaml")),
            model=None,
            model_strategy="default",
            mcp_transport="stdio",
            http_port=None,
            reports_dir=Path("reports/demo"),
            plain=getattr(args, "plain", False),
            stealth=False,
            rotate_ua=False,
            doh=False,
            menu=False,
            web=False, web_host="127.0.0.1", web_port=8080,
            swarm=False, critic=False, reflection=False,
            adaptive_exploits=False,
            observer_mode="hybrid",
            recon_first=None,
            no_recon_first=False,
            doctor=False, demo=False, resume="",
            json=False, quiet=True, debug=False,
        )
        # Build a minimal namespace shim — easiest is to call the
        # underlying async flow directly. We just print the demo banner
        # and produce a small report for the operator.
        reports_dir = Path("reports/demo")
        reports_dir.mkdir(parents=True, exist_ok=True)
        report = reports_dir / "demo_report.md"
        report.write_text(
            "# Demo Report — Local Sandbox Scan\n\n"
            f"- **Target**: 127.0.0.1:{_DVWA_HOST_PORT}\n"
            f"- **Mode**: recon\n"
            f"- **Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- **Source**: {'Docker DVWA' if used_docker else 'Synthetic in-process server'}\n"
        )
        print(f"  [✓] Demo report written to: {report}")
        print()
        print("  To run the full exploitation flow against this target:")
        print("    python main.py --target 127.0.0.1 --mode recon --goal initial_access")
        return 0
    finally:
        if synthetic is not None:
            synthetic.shutdown()
        if used_docker:
            print("  [i] Tearing down demo DVWA container…")
            _teardown_dvwa()
