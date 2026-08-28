"""Terminal MCP tool registration."""
# NetAttackAI by @braydos-h — https://github.com/braydos-h/NetAttackAi

from __future__ import annotations

import platform
import shutil
import subprocess
import sys

from tools.command_analyzer import (
    _endpoint_ips as _cmd_endpoint_ips,
)
from tools.command_analyzer import (
    _extract_destinations as _cmd_extract_destinations,
)
from tools.exceptions import _EXC_GROUP_CATCH, _log_nested_exceptions
from tools.mcp_shared import _allowed_target_list, _is_inside_workspace
from tools.mcp_tools.registry import *
from tools.opsec import OpsecManager


def _opsec_advisory_block(sanitized_command: str, config: Any) -> str:
    """Build an advisory OPSEC feedback block for a command the AI just ran.

    Target-aware (resolves against the runtime ``EXPLOIT_TARGET``): returns ``""``
    when OPSEC is OFF for this target (local/private, or OPSEC disabled). When ON,
    surfaces a live noise score, a suggested quieter rewrite, and the pacing
    posture. ADVISORY ONLY -- the command always executes regardless of this
    block; ``is_quiet_blocked`` and ``noise_budget`` are NOT consulted and stay
    dormant (no attack-path gate is re-added). Best-effort: any OPSEC build error
    degrades to ``""`` and never blocks the result.
    """
    try:
        _target_ip = os.environ.get("EXPLOIT_TARGET", "")
        # ponytail: per-call config read; cache only if profiling shows it matters.
        mgr = OpsecManager.from_config(config or {}).resolve_for_target(_target_ip)
        if not mgr.profile.enabled:
            return ""
        noise = mgr.score_command_noise(sanitized_command)
        alt = mgr.suggest_low_noise_alternative(sanitized_command)
        reasons = ", ".join(noise["reasons"][:3]) or "none"
        alt_line = alt if alt else "no rewrite available"
        if mgr.profile.min_gap_seconds > 0 or mgr.profile.jitter_seconds > 0:
            pacing = f"min_gap={mgr.profile.min_gap_seconds}s jitter={mgr.profile.jitter_seconds}s active"
        else:
            pacing = "off (no min_gap/jitter configured)"
        return (
            f"OPSEC_ADVISORY: (advisory -- does not block; you decide)\n"
            f"- Noise score: {noise['score']} (matched: {reasons})\n"
            f"- Suggested quieter rewrite: {alt_line}\n"
            f"- Pacing posture: {pacing}\n"
        )
    except Exception:
        return ""


def _target_lock_block(command: str, config: Any) -> str | None:
    """Return a block reason if ``command`` touches a host outside the target
    allowlist, else None.

    LAB BUILD: this is the one attack-mode safety kept -- the target-IP lock.
    The policy no longer inspects command content, so the lock is enforced here
    at the tool layer. The allowlist unions the runtime ``--target`` via the
    ``EXPLOIT_TARGET`` env var (see ``mcp_shared._allowed_target_list``); every
    destination endpoint (URL authorities, /dev/tcp hosts, LHOST/RHOST, scanner
    verb targets, bare IPs) must be in that allowlist. Operator-authorized
    callback/C2 hosts are added via ``exploit.allowed_targets`` in config.yaml.
    """
    exploit_cfg = (config or {}).get("exploit", {})
    if not exploit_cfg.get("require_explicit_allowlist", False):
        return None
    allowed_targets = _allowed_target_list(config)
    if not allowed_targets:
        return None
    _dest_tokens: list[str] = []
    for _tok in _cmd_extract_destinations(command):
        if _tok not in _dest_tokens:
            _dest_tokens.append(_tok)
    for _ip in extract_ips_from_command(command):
        if _ip not in _dest_tokens:
            _dest_tokens.append(_ip)
    for _tok in _extract_scanner_targets(command):
        if _tok not in _dest_tokens:
            _dest_tokens.append(_tok)
    for _tok in _dest_tokens:
        _decoded = _cmd_endpoint_ips(_tok)
        _targets = _decoded if _decoded else [_tok]
        for _t in _targets:
            if not is_target_in_allowlist(_t, allowed_targets):
                return (
                    f"Target {_t} is not in the explicit allowlist. "
                    f"Add it to config.yaml exploit.allowed_targets to authorize."
                )
    return None


def _require_sudo_or_pivot(tool_name: str, payload: str) -> str | None:
    """Return a ``BLOCKED:`` pivot message if passwordless sudo is unavailable,
    else None (caller proceeds to spawn the subprocess).

    Gap 3: ``apt_install`` / ``install_package`` (apt branch) / ``run_as_root``
    unconditionally prepend ``sudo`` via ``bash -c`` with no ``-n`` and no
    precheck, so on a sudo-less / password-required operator box the subprocess
    HANGS on an interactive password prompt. The env_probe prompt tells the
    LLM to pivot, but if the LLM ignores it the call still hangs. This helper
    short-circuits BEFORE the subprocess is spawned -- no hang, and the
    ``BLOCKED:`` prefix makes the LLM's existing BLOCKED-result detection
    (``exploit_agent/prompt.py`` RULES) treat it as a hard constraint.

    Never raises: an inability to determine sudo status falls through to the
    legacy spawn path (returns None). On Windows ``_can_passwordless_sudo``
    returns False, so Windows callers get the pivot message instead of a
    bogus ``sudo`` spawn.
    """
    try:
        from tools.env_probe import _can_passwordless_sudo

        if _can_passwordless_sudo():
            return None
    except Exception:
        # Could not determine sudo status -- do not block; let the existing
        # path run and surface whatever it surfaces (legacy behavior).
        return None
    return (
        f"BLOCKED: {tool_name} requires passwordless sudo, which is unavailable "
        f"on this box. PIVOT: call preflight_env_check for a per-tool fallback "
        f"plan, then implement {payload!r} as a workspace Python script via "
        f"write_python_file + run_python_file. Do not retry "
        f"apt_install/install_package/run_as_root -- they will hang or fail opaquely."
    )


def _check_env_default_tools() -> list[str]:
    """Default tool list for ``check_environment`` (Gap 5).

    Derived from the single source of truth ``tools.env_probe.ENV_TOOLS`` plus an
    explicit extras set (secondary scanners / language runtimes / package
    managers worth surfacing that are not in the curated env_probe list), with
    dedup so the agent never sees two different "missing tools" answers from
    ``check_environment`` vs ``preflight_env_check``. ReconConfig's per-tool
    ``*_path`` fields are a separate concern (binary-path overrides) and are
    intentionally not unified here.
    """
    from tools.env_probe import ENV_TOOLS

    _CHECK_ENV_EXTRAS = [
        "masscan",
        "rustscan",
        "feroxbuster",
        "nuclei",
        "metasploit-framework",
        "ldapsearch",
        "aircrack-ng",
        "wireshark",
        "tcpdump",
        "wget",
        "ruby",
        "gem",
        "npm",
        "go",
        "cargo",
        "snap",
    ]
    seen: set[str] = set()
    out: list[str] = []
    for t in list(ENV_TOOLS) + _CHECK_ENV_EXTRAS:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _find_windows_bash(config: Any) -> str | None:
    """Locate a bash binary for ``run_exploit_terminal`` on Windows.

    Unix pipelines (``curl ... | head -100``) fail under cmd.exe because
    head/tail/grep don't exist there; Git Bash provides them. Resolution
    order: the configured ``exploit.shell`` on PATH, then common Git Bash
    install paths. Returns None when no bash is available (cmd.exe fallback).
    """
    _shell = str((config or {}).get("exploit", {}).get("shell", "bash")) or "bash"
    found = shutil.which(_shell)
    if found:
        return found
    if _shell in ("bash", "sh"):
        for _cand in (
            Path(r"C:\Program Files\Git\bin\bash.exe"),
            Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
            Path(r"C:\Program Files (x86)\Git\bin\bash.exe"),
        ):
            if _cand.exists():
                return str(_cand)
    return None


def register_terminal_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @audit_tool
    def run_exploit_terminal(command: str) -> str:
        """Run any shell command in a dedicated visible terminal window. The command executes synchronously; output is captured and RETURNED in the result under an OUTPUT: section. Use for running Kali tools, nmap, curl, netcat, searchsploit, etc. IMPORTANT: for long scans (nmap -sV), redirect output to a file with -oN scan.txt so you can read it later with read_workspace_file."""
        if not command or not command.strip():
            return "BLOCKED: empty command."
        if len(command) > 4000:
            return "BLOCKED: command too long."

        # Ã¢â€â‚¬Ã¢â€â‚¬ Validation: sanitize command and fix malformed IPs Ã¢â€â‚¬Ã¢â€â‚¬
        original_command = command
        preflight = preflight_command_check(command)
        if not preflight["valid"]:
            return (
                f"TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                f"ATTEMPT_ID: preflight\n"
                f"COMMAND_ORIGINAL: {original_command}\n"
                f"COMMAND_SANITIZED: {preflight['sanitized_command']}\n"
                f"BLOCKED_REASON: {preflight['blocked_reason']}"
            )

        sanitized_command = preflight["sanitized_command"]
        corrections = preflight["corrections"]

        # LAB BUILD: the destructive-command block and interpreter -c/find
        # hand-off block were removed -- the AI may do whatever it takes. The
        # one safety kept is the target-IP lock (below), enforced at the tool
        # layer since the policy no longer inspects command content.
        _lock_reason = _target_lock_block(sanitized_command, config)
        if _lock_reason:
            return (
                f"TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                f"ATTEMPT_ID: preflight\n"
                f"COMMAND_ORIGINAL: {original_command}\n"
                f"COMMAND_SANITIZED: {sanitized_command}\n"
                f"BLOCKED_REASON: {_lock_reason}"
            )

        # Ã¢â€â‚¬Ã¢â€â‚¬ Tool preflight (log only; do not block execution) Ã¢â€â‚¬Ã¢â€â‚¬
        missing_tools = preflight["missing_tools"]
        preflight_note = ""
        if missing_tools:
            preflight_note = f"PREFLIGHT_WARNING: Missing tools on PATH: {', '.join(missing_tools)}.\n"
        if corrections:
            preflight_note += f"PREFLIGHT_CORRECTIONS: {json.dumps(corrections)}\n"

        attempt_dir, attempt_id = _attempt_dir(workspace)
        log_path = attempt_dir / "terminal.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        start = time.monotonic()
        is_windows = _platform_system() == "Windows"
        # The header is written by Python, never echoed by the shell wrapper:
        # an ``echo COMMAND: ...`` line lets cmd.exe/bash parse ``|``/``>``/
        # ``&&`` inside the command text -- ``curl ... | head -100`` turns the
        # echo into a pipe (``head`` is not a cmd.exe command, the batch
        # aborts, log comes back empty), and ``echo COMMAND: rm x > f`` would
        # even execute the redirect. The wrapper only runs the command and
        # records its exit code.
        header = f"{'=' * 60}\nCOMMAND: {sanitized_command}\n{'=' * 60}\n"
        log_path.write_text(header, encoding="utf-8", errors="replace")

        # On Windows prefer Git Bash when available so Unix pipelines like
        # ``curl ... | head -100`` actually work (cmd.exe has no head/tail/
        # grep). ``exploit.shell`` config is honored on all platforms.
        _bash_on_windows = _find_windows_bash(config) if is_windows else None
        if is_windows and _bash_on_windows is None:
            # cmd.exe fallback (no bash on the box): the wrapper appends
            # command output to terminal.log itself.
            wrapper = attempt_dir / "run_exploit.cmd"
            wrapper.write_text(
                f"@echo off\r\n"
                f"title AI Exploit Terminal\r\n"
                f'cd /d "{attempt_dir}"\r\n'
                f"{sanitized_command} >> terminal.log 2>&1\r\n"
                f"echo EXIT_CODE: %ERRORLEVEL% >> terminal.log\r\n",
                encoding="ascii",
                errors="replace",
            )
            proc = subprocess.Popen(
                ["cmd.exe", "/c", str(wrapper)],
                cwd=str(attempt_dir),
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        else:
            # Native Linux/macOS, or Windows with Git Bash: run via the shell
            # (default bash) and capture output synchronously. ``exploit.shell``
            # lets an operator point this at zsh/sh/ash when bash isn't the
            # login shell.
            if _bash_on_windows:
                _shell_bin = _bash_on_windows
            else:
                _shell = str((config or {}).get("exploit", {}).get("shell", "bash")) or "bash"
                _shell_bin = shutil.which(_shell) or _shell
            wrapper = attempt_dir / "run_exploit.sh"
            wrapper.write_text(
                f'#!{_shell_bin}\ncd "{attempt_dir}"\n{sanitized_command} 2>&1\necho EXIT_CODE: $?\n',
                encoding="utf-8",
            )
            wrapper.chmod(0o755)
            proc = subprocess.Popen(
                [_shell_bin, str(wrapper)],
                cwd=str(attempt_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        timeout = 300
        # Bug #4: on Linux the child writes to a PIPE. ``proc.wait()`` then
        # ``proc.stdout.read()`` deadlocks once the OS pipe buffer (~64KB)
        # fills — the child blocks writing, we block waiting for it to exit,
        # neither progresses. ``communicate`` drains the pipe concurrently
        # while waiting, so arbitrarily large output completes. The cmd.exe
        # fallback has no PIPE here (output goes to a new console window +
        # terminal.log), so it stays on ``wait()``.
        out_bytes: bytes | str | None = None
        try:
            if is_windows and _bash_on_windows is None:
                exit_code = proc.wait(timeout=timeout)
                status = "completed" if exit_code == 0 else "failed"
            else:
                out_bytes, _ = proc.communicate(timeout=timeout)
                exit_code = proc.returncode
                status = "completed" if exit_code == 0 else "failed"
        except subprocess.TimeoutExpired:
            # M2: kill the whole process group so shell-spawned children die
            # with the parent instead of surviving the kill.
            if is_windows:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            else:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
            # Drain any buffered output after the kill so we don't leak the
            # pipe FD or lose the partial output that was already produced.
            if not (is_windows and _bash_on_windows is None):
                try:
                    out_bytes, _ = proc.communicate(timeout=5)
                except Exception:
                    out_bytes = out_bytes or b""
            exit_code = None
            status = "timed_out"

        elapsed = time.monotonic() - start
        # Read actual command output
        output_tail = ""
        if out_bytes is not None:
            # bash path: output captured via communicate(). Prepend the
            # Python-written header so terminal.log reads the same on both
            # platforms.
            try:
                text = out_bytes.decode("utf-8", errors="replace") if isinstance(out_bytes, bytes) else str(out_bytes)
                log_path.write_text(header + text, encoding="utf-8", errors="replace")
                output_tail = text[-4000:]
            except Exception:
                pass
        elif log_path.exists():
            text = log_path.read_text(encoding="utf-8", errors="replace")
            output_tail = text[-4000:]

        _opsec_advisory = _opsec_advisory_block(sanitized_command, config)

        return (
            f"TERMINAL_RESULT: {status} (exit_code={exit_code}, duration={elapsed:.1f}s)\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"COMMAND_ORIGINAL: {original_command}\n"
            f"COMMAND_SANITIZED: {sanitized_command}\n"
            f"{preflight_note}"
            f"{_opsec_advisory}"
            f"WORKSPACE: {attempt_dir}\n"
            f"OUTPUT:\n{output_tail}"
        )

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
        # Gap 3: short-circuit before spawning sudo on a sudo-less box (would
        # hang on an interactive password prompt). PIVOT to a Python fallback.
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
    def git_clone(repo_url: str, target_dir: str = "") -> str:
        """Clone a Git repository (GitHub exploit/PoC/tool) into the workspace. Provide the full repo URL (e.g., 'https://github.com/user/repo.git'). Optional target_dir for a custom folder name."""
        if not repo_url or not repo_url.strip():
            return "BLOCKED: repo_url is required."
        url = repo_url.strip()
        if not re.fullmatch(r"https?://[a-zA-Z0-9._/\-:@]+\.git", url) and not re.fullmatch(
            r"https?://github\.com/[a-zA-Z0-9._\-/]+", url
        ):
            return "BLOCKED: invalid repo URL. Must be a GitHub/GitLab HTTPS URL."
        # H3: validate target_dir -- a crafted name like ``../evil`` or one
        # containing shell metacharacters could traverse out of the workspace
        # or inject into the previous ``bash -c git clone ...`` string.
        dir_name = target_dir.strip() if target_dir.strip() else url.rstrip("/").split("/")[-1].replace(".git", "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", dir_name):
            return f"BLOCKED: target_dir must match [A-Za-z0-9._-]{{1,80}} (got {dir_name!r})."
        clone_dir = workspace / dir_name
        if not _is_inside_workspace(workspace, clone_dir.resolve()):
            return f"BLOCKED: clone target {clone_dir} escapes the exploit workspace."

        # Gap 4: defense-in-depth existence preflight. cve_to_poc is the upstream
        # gate against hallucinated PoC URLs, but if a URL slips through we
        # surface a warning BEFORE the (slow) clone attempt. We never hard-block:
        # private/auth-gated repos 404 to unauthenticated HEAD, so a 404 here is
        # not proof the URL is fake. The clone proceeds regardless; the warning
        # steers the LLM back to cve_to_poc if the clone then fails. Only http(s)
        # is checked -- ssh:// and git:// clones are unaffected.
        preflight_note = ""
        if url.lower().startswith(("http://", "https://")):
            try:
                from tools.exploit_search import url_exists as _url_exists_check

                _ok, _reason = _url_exists_check(url, timeout=8)
            except Exception:
                _ok, _reason = True, None  # import/probe failure -> don't block
            if not _ok:
                preflight_note = (
                    f"PREFLIGHT_WARNING: URL existence check failed ({_reason}); "
                    f"if this is a private/auth-gated repo the clone may still "
                    f"succeed. If the clone fails, use cve_to_poc instead of "
                    f"guessing URLs.\n"
                )

        # H3: argv list (no shell) so url/dir_name are literal arguments.
        try:
            returncode, out, err = _run_with_pgrp_timeout(
                ["git", "clone", "--", url, str(clone_dir)],
                120,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            output = (out + "\n" + err)[-3000:]
            status = "completed" if returncode == 0 else "failed"
            return (
                f"{preflight_note}GIT_CLONE_RESULT: {status} (exit_code={returncode})\n"
                f"REPO: {url}\nPATH: {clone_dir}\nOUTPUT:\n{output}"
            )
        except subprocess.TimeoutExpired:
            return f"{preflight_note}GIT_CLONE_RESULT: timed_out\nREPO: {url}"
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            return f"{preflight_note}GIT_CLONE_RESULT: error - {exc}"

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
    def run_as_root(command: str) -> str:
        """Run ANY command with sudo (root privileges). Use for commands that require root: tcpdump, iptables, systemctl, writing to /etc, raw socket operations, etc. The command runs synchronously and output is captured."""
        if not command or not command.strip():
            return "BLOCKED: empty command."
        if len(command) > 4000:
            return "BLOCKED: command too long."
        original_command = command
        # LAB BUILD: target-IP lock only (destructive/executable/redirect
        # gates removed -- the AI may do whatever it takes as root). The lock
        # is enforced at the tool layer via the allowlist (runtime --target
        # unioned in via EXPLOIT_TARGET).
        _lock_reason = _target_lock_block(command, config)
        if _lock_reason:
            return f"ROOT_CMD_RESULT: blocked (target lock: {_lock_reason})"
        # Gap 3: short-circuit before spawning sudo on a sudo-less box. The
        # target-IP lock above has already run (and would have blocked an
        # off-target command), so the pivot only fires for in-scope commands
        # that still need root the box cannot provide.
        _pivot = _require_sudo_or_pivot("run_as_root", original_command)
        if _pivot:
            return _pivot
        cmd = f"sudo {command} 2>&1"
        # Note: the @audit_tool decorator already writes started/completed audit
        # records with the (redacted) command arg, so a manual _audit_log here
        # would double-log the RAW command -- a credential leak. Removed.
        try:
            returncode, out, err = _run_with_pgrp_timeout(
                ["bash", "-c", cmd],
                300,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            output = (out + "\n" + err)[-4000:]
            status = "completed" if returncode == 0 else "failed"
            return f"ROOT_CMD_RESULT: {status} (exit_code={returncode})\nCOMMAND: {original_command}\nOUTPUT:\n{output}"
        except subprocess.TimeoutExpired:
            return f"ROOT_CMD_RESULT: timed_out\nCOMMAND: {original_command}"
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            return f"ROOT_CMD_RESULT: error - {exc}"

    @mcp.tool()
    @audit_tool
    def check_environment(tools: str = "") -> str:
        """Check which security testing tools are installed and available on the system.
        Provide a space-separated list of tool names (e.g., 'nmap metasploit-framework hydra gobuster'),
        or leave empty to check a default set of common pentesting tools.
        Returns version info and install status for each tool, plus OS details.
        """
        default_tools = _check_env_default_tools()
        check_list = [t.strip() for t in tools.split() if t.strip()] if tools else default_tools

        result_lines = ["ENVIRONMENT_CHECK:", ""]
        result_lines.append(f"OS: {_platform_system()} {platform.release()} ({platform.machine()})")
        result_lines.append(f"Python: {sys.version.split()[0]}")
        result_lines.append("")

        installed: list[str] = []
        missing: list[str] = []
        for tool in check_list:
            path = shutil.which(tool)
            if path:
                installed.append(tool)
                # Try to get version
                version = "unknown"
                try:
                    proc = subprocess.run(
                        [tool, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if proc.returncode == 0 and proc.stdout:
                        version = proc.stdout.strip().split("\n")[0][:100]
                    else:
                        # Some tools use -version or -V
                        proc2 = subprocess.run(
                            [tool, "-version"],
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        if proc2.returncode == 0 and proc2.stdout:
                            version = proc2.stdout.strip().split("\n")[0][:100]
                except Exception:
                    pass
                result_lines.append(f"  [+] {tool}: {path}  ({version})")
            else:
                missing.append(tool)
                result_lines.append(f"  [-] {tool}: NOT FOUND")

        result_lines.append("")
        result_lines.append(f"SUMMARY: {len(installed)}/{len(check_list)} tools available")
        if missing:
            result_lines.append(f"MISSING: {', '.join(missing)}")
            # Issue 4: sudo-aware hint. On a box without passwordless sudo,
            # apt_install/install_package will fail -- steer the agent to the
            # preflight_env_check tool (which gives a per-tool fallback plan)
            # and to write_python_file Python implementations instead of a
            # dead-end install attempt.
            try:
                from tools.env_probe import _can_passwordless_sudo

                _has_sudo = _can_passwordless_sudo()
            except Exception:
                _has_sudo = True  # unknown; keep the legacy hint
            if _has_sudo:
                result_lines.append(
                    "HINT: Use install_package or apt_install to install missing tools,"
                    " or call preflight_env_check for a per-tool fallback plan."
                )
            else:
                result_lines.append(
                    "HINT: sudo unavailable — apt_install/install_package will fail. "
                    "Call preflight_env_check for a per-tool fallback plan, then pivot to "
                    "write_python_file Python implementations for missing tools."
                )
        return "\n".join(result_lines)

    @mcp.tool()
    @audit_tool
    def preflight_env_check() -> str:
        """Probe installed pentest tools, sudo/pip installability, and the
        recommended fallback (install_via_apt / install_via_pip / write_python_fallback)
        for each MISSING tool. Call once at session start (the system prompt
        already carries the startup probe) or after installing a tool to
        re-probe. Local-only; touches no target."""
        try:
            from tools.env_probe import preflight_env_probe, render_env_context

            rendered = render_env_context(preflight_env_probe())
        except _EXC_GROUP_CATCH as exc:  # pragma: no cover - defensive
            _log_nested_exceptions(exc)
            return f"PREFLIGHT_ENV_CHECK_ERROR: {exc}"
        return rendered or "ENV_OK: all standard pentest tools present."

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

        # Validate package names (basic alphanumeric + common chars)
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

        # Gap 3: the apt and snap branches prepend ``sudo``; on a sudo-less box
        # the subprocess would hang on an interactive password prompt. Short-
        # circuit to a Python-fallback pivot BEFORE spawning. pip/gem/npm/go/
        # cargo do not use sudo and are unaffected.
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

        # H6: validate the filename/target_name immediately. A crafted
        # ``target_name`` like ``../evil`` or one with shell metacharacters could
        # traverse out of the workspace or inject into the previous bash -c
        # install strings. Strip to a basename and enforce a safe charset.
        filename = url.split("/")[-1].split("?")[0] or "download"
        if target_name.strip():
            cleaned_name = target_name.strip().replace("\\", "/").split("/")[-1]
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", cleaned_name):
                return f"BLOCKED: target_name must match [A-Za-z0-9._-]{{1,120}} (got {cleaned_name!r})."
            filename = cleaned_name

        attempt_dir, attempt_id = _attempt_dir(workspace)
        download_path = attempt_dir / filename

        # Download
        try:
            proc = subprocess.run(
                ["curl", "-fsSL", "-o", str(download_path), url],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                return f"DOWNLOAD_RESULT: failed\nURL: {url}\nERROR: curl failed: {proc.stderr[-1000:]}"
        except Exception as exc:
            return f"DOWNLOAD_RESULT: error - {exc}"

        # Install based on type
        if itype == "deb":
            # H6: argv lists (no shell) so download_path is a literal argument.
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
            except Exception as exc:
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
                # List extracted contents
                listing = ""
                try:
                    list_proc = subprocess.run(
                        ["ls", "-la", str(extract_dir)],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    listing = list_proc.stdout[:2000]
                except Exception:
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
            except Exception as exc:
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
            except Exception:
                # Fallback: keep in workspace and make executable
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
        except Exception as exc:
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
        except Exception as exc:
            return (
                f"UPDATE_RESULT: {update_status} (update) / error (upgrade)\n"
                f"UPDATE_OUTPUT:\n{update_output}\n"
                f"UPGRADE_ERROR: {exc}"
            )
