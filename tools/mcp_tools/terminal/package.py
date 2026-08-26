"""Package management tools for terminal MCP (apt, pip, install_package, etc.)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from tools.exceptions import _EXC_GROUP_CATCH, _log_nested_exceptions
from tools.mcp_tools.registry import ToolContext, _attempt_dir, _run_with_pgrp_timeout
from tools.mcp_tools.terminal.privilege import _require_sudo_or_pivot

__all__ = ["_register_package_tools"]


def _register_package_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    audit_tool = ctx.audit_tool

    @mcp.tool()
    @audit_tool
    def apt_install(packages: str) -> str:
        """Install Kali Linux packages via apt. Provide a space-separated list of package names (e.g., 'nmap hydra gobuster'). Runs 'sudo apt install -y <packages>'. Use this to install missing tools before exploitation."""
        if not packages or not packages.strip():
            return "BLOCKED: no packages specified."
        pkg_list = [
            p.strip() for p in packages.split() if p.strip() and re.fullmatch(r"[a-zA-Z0-9_.+-]{1,60}", p.strip())
        ]
        if not pkg_list:
            return "BLOCKED: invalid package names."
        _pivot = _require_sudo_or_pivot("apt_install", " ".join(pkg_list))
        if _pivot:
            return _pivot
        cmd = f"sudo apt install -y {' '.join(pkg_list)} 2>&1"
        try:
            proc = subprocess.run(
                ["bash", "-c", cmd],
                capture_output=True,
                text=True,
                timeout=300,
            )
            output = (proc.stdout + "\n" + proc.stderr)[-4000:]
            status = "completed" if proc.returncode == 0 else "failed"
            return f"APT_INSTALL_RESULT: {status} (exit_code={proc.returncode})\nPACKAGES: {', '.join(pkg_list)}\nOUTPUT:\n{output}"
        except subprocess.TimeoutExpired:
            return "APT_INSTALL_RESULT: timed_out\nPACKAGES: " + ", ".join(pkg_list)
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            return f"APT_INSTALL_RESULT: error - {exc}"

    @mcp.tool()
    @audit_tool
    def pip_install(packages: str) -> str:
        """Install Python packages via pip. Provide a space-separated list of package names (e.g., 'impacket pwntools requests'). Runs 'pip install <packages>'. Use for Python exploit dependencies."""
        if not packages or not packages.strip():
            return "BLOCKED: no packages specified."
        pkg_list = [
            p.strip() for p in packages.split() if p.strip() and re.fullmatch(r"[a-zA-Z0-9_.\-]{1,60}", p.strip())
        ]
        if not pkg_list:
            return "BLOCKED: invalid package names."
        cmd = f"pip install {' '.join(pkg_list)} 2>&1"
        try:
            proc = subprocess.run(
                ["bash", "-c", cmd],
                capture_output=True,
                text=True,
                timeout=120,
            )
            output = (proc.stdout + "\n" + proc.stderr)[-3000:]
            status = "completed" if proc.returncode == 0 else "failed"
            return f"PIP_INSTALL_RESULT: {status} (exit_code={proc.returncode})\nPACKAGES: {', '.join(pkg_list)}\nOUTPUT:\n{output}"
        except subprocess.TimeoutExpired:
            return "PIP_INSTALL_RESULT: timed_out\nPACKAGES: " + ", ".join(pkg_list)
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            return f"PIP_INSTALL_RESULT: error - {exc}"

    @mcp.tool()
    @audit_tool
    def install_package(manager: str, packages: str) -> str:
        """Install packages using the specified package manager.
        Supported managers: apt, pip, gem, npm, go, cargo, snap.
        Provide a space-separated list of package names.
        Use this to install missing tools or dependencies the AI discovers it needs during an engagement.
        """
        if not manager or not manager.strip():
            return "BLOCKED: manager is required."
        if not packages or not packages.strip():
            return "BLOCKED: no packages specified."

        mgr = manager.strip().lower()
        pkg_list = [p.strip() for p in packages.split() if p.strip()]
        if not pkg_list:
            return "BLOCKED: invalid package names."

        safe_re = re.compile(r"^[A-Za-z0-9_.+\-/@]{1,80}$")
        invalid = [p for p in pkg_list if not safe_re.match(p)]
        if invalid:
            return f"BLOCKED: invalid package names: {', '.join(invalid)}"

        cmd = ""
        timeout = 300
        if mgr == "apt":
            cmd = f"sudo apt install -y {' '.join(pkg_list)} 2>&1"
            timeout = 600
        elif mgr == "pip":
            cmd = f"pip install {' '.join(pkg_list)} 2>&1"
        elif mgr == "gem":
            cmd = f"gem install {' '.join(pkg_list)} 2>&1"
        elif mgr == "npm":
            cmd = f"npm install -g {' '.join(pkg_list)} 2>&1"
        elif mgr == "go":
            cmd = f"go install {' '.join(pkg_list)} 2>&1"
        elif mgr == "cargo":
            cmd = f"cargo install {' '.join(pkg_list)} 2>&1"
        elif mgr == "snap":
            cmd = f"sudo snap install {' '.join(pkg_list)} 2>&1"
            timeout = 600
        else:
            return f"BLOCKED: unsupported manager '{mgr}'. Supported: apt, pip, gem, npm, go, cargo, snap."

        if cmd.startswith("sudo "):
            _pivot = _require_sudo_or_pivot(f"install_package({mgr})", " ".join(pkg_list))
            if _pivot:
                return _pivot

        try:
            proc = subprocess.run(
                ["bash", "-c", cmd],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = (proc.stdout + "\n" + proc.stderr)[-4000:]
            status = "completed" if proc.returncode == 0 else "failed"
            return (
                f"INSTALL_RESULT: {status} (exit_code={proc.returncode})\n"
                f"MANAGER: {mgr}\n"
                f"PACKAGES: {', '.join(pkg_list)}\n"
                f"OUTPUT:\n{output}"
            )
        except subprocess.TimeoutExpired:
            return f"INSTALL_RESULT: timed_out\nMANAGER: {mgr}\nPACKAGES: {', '.join(pkg_list)}"
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            return f"INSTALL_RESULT: error - {exc}"

    @mcp.tool()
    @audit_tool
    def download_and_install(url: str, install_type: str = "auto", target_name: str = "") -> str:
        """Download and install a tool from a URL.
        Supports .deb (auto-installs with dpkg), .tar.gz/.tgz (extracts to /opt or workspace),
        .zip (extracts), and raw binaries (makes executable).
        Use this when a tool isn't in apt repos and must be fetched from GitHub releases or vendor sites.
        """
        if not url or not url.strip():
            return "BLOCKED: url is required."
        url = url.strip()
        if not re.fullmatch(r"https?://[A-Za-z0-9._/\-:@%+?=~&]+", url):
            return "BLOCKED: invalid URL."

        itype = install_type.strip().lower() or "auto"
        if itype == "auto":
            if url.endswith(".deb"):
                itype = "deb"
            elif url.endswith((".tar.gz", ".tgz")):
                itype = "tarball"
            elif url.endswith(".zip"):
                itype = "zip"
            else:
                itype = "binary"

        if itype not in ("deb", "tarball", "zip", "binary"):
            return "BLOCKED: install_type must be auto, deb, tarball, zip, or binary."

        filename = url.split("/")[-1].split("?")[0] or "download"
        if target_name.strip():
            cleaned_name = target_name.strip().replace("\\", "/").split("/")[-1]
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", cleaned_name):
                return f"BLOCKED: target_name must match [A-Za-z0-9._-]{{1,120}} (got {cleaned_name!r})."
            filename = cleaned_name

        attempt_dir, attempt_id = _attempt_dir(workspace)
        download_path = attempt_dir / filename

        try:
            proc = subprocess.run(
                ["curl", "-fsSL", "-o", str(download_path), url],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                return f"DOWNLOAD_RESULT: failed\nURL: {url}\nERROR: curl failed: {proc.stderr[-1000:]}"
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            return f"DOWNLOAD_RESULT: error - {exc}"

        if itype == "deb":
            try:
                rc1, out1, err1 = _run_with_pgrp_timeout(
                    ["sudo", "dpkg", "-i", str(download_path)],
                    300,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                rc2, out2, err2 = _run_with_pgrp_timeout(
                    ["sudo", "apt-get", "install", "-f", "-y"],
                    300,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                output = (out1 + "\n" + err1 + "\n" + out2 + "\n" + err2)[-4000:]
                status = "completed" if rc1 == 0 and rc2 == 0 else "failed"
                return (
                    f"INSTALL_RESULT: {status} (exit_code={rc1}/{rc2})\n"
                    f"TYPE: deb\n"
                    f"URL: {url}\n"
                    f"PATH: {download_path}\n"
                    f"OUTPUT:\n{output}"
                )
            except subprocess.TimeoutExpired:
                return f"INSTALL_RESULT: timed_out\nTYPE: deb\nURL: {url}"
            except _EXC_GROUP_CATCH as exc:
                _log_nested_exceptions(exc)
                return f"INSTALL_RESULT: error - {exc}"

        elif itype in ("tarball", "zip"):
            extract_dir = attempt_dir / (filename.rsplit(".", 1)[0].replace(".tar", ""))
            extract_dir.mkdir(parents=True, exist_ok=True)
            if itype == "tarball":
                extract_argv = ["tar", "-xzf", str(download_path), "-C", str(extract_dir)]
            else:
                extract_argv = ["unzip", "-q", str(download_path), "-d", str(extract_dir)]
            try:
                rc, out, err = _run_with_pgrp_timeout(
                    extract_argv,
                    120,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                output = (out + "\n" + err)[-2000:]
                status = "completed" if rc == 0 else "failed"
                listing = ""
                try:
                    list_proc = subprocess.run(
                        ["ls", "-la", str(extract_dir)],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    listing = list_proc.stdout[:2000]
                except _EXC_GROUP_CATCH:
                    pass
                return (
                    f"INSTALL_RESULT: {status} (exit_code={rc})\n"
                    f"TYPE: {itype}\n"
                    f"URL: {url}\n"
                    f"DOWNLOAD: {download_path}\n"
                    f"EXTRACTED_TO: {extract_dir}\n"
                    f"OUTPUT:\n{output}\n"
                    f"CONTENTS:\n{listing}"
                )
            except subprocess.TimeoutExpired:
                return f"INSTALL_RESULT: timed_out\nTYPE: {itype}\nURL: {url}"
            except _EXC_GROUP_CATCH as exc:
                _log_nested_exceptions(exc)
                return f"INSTALL_RESULT: error - {exc}"

        else:  # binary
            bin_dir = Path("/usr/local/bin")
            target_path = bin_dir / filename
            try:
                shutil.move(str(download_path), str(target_path))
                target_path.chmod(0o755)
                return (
                    f"INSTALL_RESULT: completed\n"
                    f"TYPE: binary\n"
                    f"URL: {url}\n"
                    f"PATH: {target_path}\n"
                    f"NOTE: Made executable at {target_path}"
                )
            except _EXC_GROUP_CATCH:
                download_path.chmod(0o755)
                return (
                    f"INSTALL_RESULT: completed (workspace-only)\n"
                    f"TYPE: binary\n"
                    f"URL: {url}\n"
                    f"PATH: {download_path}\n"
                    f"NOTE: Could not write to /usr/local/bin. Binary is executable in workspace."
                )

    @mcp.tool()
    @audit_tool
    def update_system(upgrade: bool = True) -> str:
        """Update the system's package lists and optionally upgrade all packages.
        Runs 'apt update' and optionally 'apt upgrade -y'.
        Use this to ensure the system has the latest tool versions before starting an engagement.
        """
        try:
            proc = subprocess.run(
                ["bash", "-c", "sudo apt update 2>&1"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            update_output = (proc.stdout + "\n" + proc.stderr)[-2000:]
            update_status = "completed" if proc.returncode == 0 else "failed"
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            return f"UPDATE_RESULT: error during apt update - {exc}"

        if not upgrade:
            return f"UPDATE_RESULT: {update_status} (apt update only)\nOUTPUT:\n{update_output}"

        try:
            proc = subprocess.run(
                ["bash", "-c", "sudo apt upgrade -y 2>&1"],
                capture_output=True,
                text=True,
                timeout=600,
            )
            upgrade_output = (proc.stdout + "\n" + proc.stderr)[-4000:]
            upgrade_status = "completed" if proc.returncode == 0 else "failed"
            return (
                f"UPDATE_RESULT: {update_status} (update) / {upgrade_status} (upgrade)\n"
                f"UPDATE_OUTPUT:\n{update_output}\n"
                f"UPGRADE_OUTPUT:\n{upgrade_output}"
            )
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            return (
                f"UPDATE_RESULT: {update_status} (update) / error (upgrade)\n"
                f"UPDATE_OUTPUT:\n{update_output}\n"
                f"UPGRADE_ERROR: {exc}"
            )
