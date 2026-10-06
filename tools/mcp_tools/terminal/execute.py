"""Execution tools for terminal MCP (run_exploit_terminal, run_exploit_terminals, run_as_root, git_clone).

Family: interactive shell funnel + batched probes + privileged exec + repo fetch.

All agent-provided command execution in this family requires the disposable
sandbox worker. Target-bearing commands are preflighted and checked against
the full allowlist before the worker enforces its pinned network policy.
Secrets are never capped (RULE-NO-CAP-SECRETS): the only size bound on
commands is an MB-scale anti-fill cap; persisted logs AND live results
(COMMAND_*/OUTPUT) are secret-masked before return/emit. Git repository
fetches run in the worker; no URL preflight is made from the MCP host.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from tools.kernel.audit import _mask_secret_content
from tools.kernel.workspace import write_workspace_file
from tools.mcp_shared import _is_inside_workspace
from tools.mcp_tools.registry import ToolContext, _attempt_dir, _positive_int
from tools.mcp_tools.sandbox_exec import (
    loopback_hint,
    run_argv_in_sandbox,
    run_command_in_sandbox,
    sandbox_error_block,
)
from tools.mcp_tools.terminal.allowlist import _extract_lock_targets, _opsec_advisory_block, _target_lock_block
from tools.sandbox.exceptions import SandboxError, SandboxUnsupportedError
from tools.validation_utils import TargetCorrection, preflight_command_check

__all__ = ["_register_execute_tools"]

# MB-scale anti-fill ONLY (per RULE-NO-CAP-SECRETS): commands carrying
# code/passwords/PEM/base64 are never capped small; this just stops a runaway
# write from filling the operator disk or blowing past ARG_MAX.
_MAX_COMMAND_CHARS = 10 * 1024 * 1024
# Batch cap for run_exploit_terminals: one docker-exec round-trip carries every
# probe, so the cap bounds worker output/memory rather than round-trips.
_MAX_BATCH_COMMANDS = 20
# Display OUTPUT tails (live result) + persisted-log bound (terminal.log).
_OUTPUT_CHARS = 4000
_GIT_OUTPUT_CHARS = 3000
_MAX_LOG_FILE_CHARS = 200_000


def _tail(text: Any, limit: int) -> str:
    """Last ``limit`` chars of ``text`` with a ``[truncated]`` marker when cut.

    Args:
        text: Raw output (None-safe, stringified).
        limit: Max chars to show (tail).

    Returns:
        Full text when short, else a ``[truncated ...]`` header + last
        ``limit`` chars. Gates always saw the FULL text; only display is cut.

    Gates:
        None (pure display helper).

    Side-effects:
        None.
    """
    body = str(text or "")
    if len(body) <= limit:
        return body
    return f"[truncated - showing last {limit} of {len(body)} chars]\n{body[-limit:]}"


def _config_timeout(config: Any, default: int = 300) -> int:
    """Contained-command timeout from ``exploit.command_timeout_seconds``.

    Args:
        config: Full config dict (reads the ``exploit`` block).
        default: Fallback seconds when the key is missing/invalid.

    Returns:
        Positive-int seconds (validated via ``_positive_int``).

    Gates:
        None (reads config; validation falls back, never raises).

    Side-effects:
        None.
    """
    try:
        raw = (config or {}).get("exploit", {}).get("command_timeout_seconds", default)
    except (AttributeError, TypeError):
        return default
    return _positive_int(raw, default)


def _sandbox_required_result(ctx: ToolContext, tool_name: str) -> str | None:
    """Return a structured denial if an execution tool has no worker."""
    if getattr(ctx, "sandbox", None) is not None:
        return None
    exc = SandboxUnsupportedError(f"{tool_name} requires an active sandbox worker")
    return sandbox_error_block(exc, tool_name=tool_name)


def _sandbox_terminal_ok(result: Any) -> tuple[str, str, int | None, float]:
    """(status, output_tail, exit_code, duration) from a contained SandboxResult.

    Args:
        result: Sandbox result with ``stdout`` / ``stderr`` / ``status`` /
            ``exit_code`` / ``duration_seconds``.

    Returns:
        Tuple of status, raw OUTPUT tail (marked when trimmed -- callers
        mask with ``_mask_secret_content`` before return), exit code, and
        duration.

    Gates:
        None (renders the contained execution -- the sandbox already gated).

    Side-effects:
        None.
    """
    merged = result.stdout or ""
    if result.stderr:
        merged = f"{merged}\n{result.stderr}" if merged else result.stderr
    return result.status, _tail(merged, _OUTPUT_CHARS), result.exit_code, result.duration_seconds


def _valid_git_repo_url(value: str) -> bool:
    """Accept credential-free HTTPS repository paths on pinned Git hosts."""
    if not value or len(value) > 2048 or any(ord(char) <= 32 or ord(char) == 127 for char in value):
        return False
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or host not in {"github.com", "gitlab.com"}
        or parsed.netloc.lower() != host
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        return False
    segments = parsed.path.split("/")[1:]
    if len(segments) < 2 or any(segment in {"", ".", ".."} for segment in segments):
        return False
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", segment) for segment in segments):
        return False
    return bool(segments[-1].removesuffix(".git"))


def _sandbox_status_line(manager: Any) -> str:
    """One-line sandbox identity for the result block (advisory, never blocks).

    Args:
        manager: Session sandbox manager (``status()`` dict).

    Returns:
        ``SANDBOX:`` line, or a bare fallback when the probe fails.

    Gates:
        None (advisory only).

    Side-effects:
        None.
    """
    try:
        st = manager.status()
        return (
            f"SANDBOX: run_id={st.get('run_id', '')} container={st.get('container_id', '')[:12]} "
            f"network_locked={st.get('network_locked', False)} image={st.get('image', '')}\n"
        )
    except Exception:  # ponytail: bare except intentional -- status is advisory, never blocks the result
        return "SANDBOX: active\n"


def _register_execute_tools(mcp: Any, *, ctx: ToolContext) -> None:
    """Register the terminal execution family on ``mcp``.

    Args:
        mcp: The MCP server to register tools on.
        ctx: ToolContext (workspace + config + audit_tool used here; command
            execution requires an attached sandbox worker).

    Returns:
        None.

    Gates:
        Per-tool gates inside each body (see family docstring).

    Side-effects:
        Registers ``run_exploit_terminal`` / ``run_exploit_terminals`` /
        ``run_as_root`` / ``git_clone``.
    """
    workspace = ctx.workspace
    config = ctx.config
    audit_tool = ctx.audit_tool

    @mcp.tool()
    @audit_tool
    def run_exploit_terminals(commands: list[str]) -> str:
        """Run several short shell probes as ONE sandbox round-trip.

        Batching amortizes the ~0.3-1.0s ``docker exec`` fork + daemon cost per
        call that dominates hundreds of short probes. Prefer this over N serial
        ``run_exploit_terminal`` calls for independent read-only probes
        (``which`` checks, version banners, one-shot curls).

        Args:
            commands: 1-20 non-empty shell commands (total chars within the
                MB-scale anti-fill cap). Each is preflight-checked
                individually; the JOINED text is target-lock gated once
                (RULE-LOCK-FIRST -- a host past any join boundary blocks).

        Returns:
            BATCH_TERMINAL_RESULT block with per-command OUTPUT sections
            (delimited, truncated tails), or a preflight / target-lock
            BLOCKED BATCH_TERMINAL_RESULT.

        Gates:
            Per-command empty/MB-cap/``preflight_command_check`` pre-gates;
            MANUAL ``_target_lock_block`` on the FULL joined sanitized text.
            The host PATH is never consulted for command availability;
            correction warnings are retained.

        Side-effects:
            ONE contained execution in the sandbox worker; missing or failed
            containment blocks the command. Writes terminal.log
            (secret-masked, capped). Live
            COMMANDS/OUTPUT in the returned block are secret-masked.
        """
        if not isinstance(commands, list) or not commands:
            return "BLOCKED: commands must be a non-empty list of shell commands."
        if len(commands) > _MAX_BATCH_COMMANDS:
            return f"BLOCKED: batch exceeds the {_MAX_BATCH_COMMANDS}-command cap; split the batch."
        total_chars = sum(len(c) for c in commands if isinstance(c, str))
        if total_chars > _MAX_COMMAND_CHARS:
            return f"BLOCKED: batch exceeds the {_MAX_COMMAND_CHARS}-byte anti-fill cap; split the batch."
        sanitized_parts: list[str] = []
        shown_parts: list[str] = []
        corrections: list[TargetCorrection] = []
        for index, raw in enumerate(commands):
            if not isinstance(raw, str) or not raw.strip():
                return f"BLOCKED: batch command #{index} is empty."
            preflight = preflight_command_check(raw, check_tool_availability=False)
            if not preflight["valid"]:
                return (
                    "BATCH_TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                    f"FAILED_COMMAND: #{index} {_mask_secret_content(raw)}\n"
                    f"BLOCKED_REASON: {preflight['blocked_reason']}"
                )
            sanitized_parts.append(preflight["sanitized_command"])
            shown_parts.append(_mask_secret_content(raw))
            corrections.extend(preflight["corrections"])
        # RULE-LOCK-FIRST on the JOINED text: every destination across every
        # command (including hosts past a join boundary) must be allowlisted.
        joined = "\n".join(f"echo '--- probe #{i} ---'; {part}" for i, part in enumerate(sanitized_parts))
        _lock_targets = _extract_lock_targets(joined)
        _lock_reason = _target_lock_block(joined, config, targets=_lock_targets)
        if _lock_reason:
            return (
                "BATCH_TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                "ATTEMPT_ID: preflight\n"
                f"COMMANDS: {json.dumps(shown_parts)}\n"
                f"BLOCKED_REASON: {_lock_reason}"
            )
        if blocked := _sandbox_required_result(ctx, "run_exploit_terminals"):
            return blocked
        shown_sanitized = _mask_secret_content(joined)
        attempt_dir, attempt_id = _attempt_dir(workspace)
        timeout = _config_timeout(config)
        preflight_note = ""
        if corrections:
            preflight_note = f"PREFLIGHT_CORRECTIONS: {json.dumps(corrections)}\n"
        _opsec_advisory = _opsec_advisory_block(joined, config)
        try:
            _ran, result = run_command_in_sandbox(
                ctx,
                joined,
                timeout=timeout,
                cwd_host=attempt_dir,
                tool_name="run_exploit_terminals",
                targets=_lock_targets,
            )
        except SandboxError as exc:
            return (
                "BATCH_TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                f"ATTEMPT_ID: {attempt_id}\n"
                f"COMMANDS: {json.dumps(shown_parts)}\n"
                f"{preflight_note}"
                f"{sandbox_error_block(exc, tool_name='run_exploit_terminals')}"
            )
        if not _ran or result is None:
            return sandbox_error_block(
                SandboxUnsupportedError("run_exploit_terminals requires an active sandbox worker"),
                tool_name="run_exploit_terminals",
            )
        _sstatus, _output_tail, _exit_code, _elapsed = _sandbox_terminal_ok(result)
        _hint = ""
        try:
            # Reuses the single-parse lock targets (no re-parse).
            _primary = _lock_targets[0] if _lock_targets else ""
            if _primary:
                _hint = loopback_hint(_primary, config)
        except Exception:  # ponytail: bare except intentional -- hint is advisory only
            _hint = ""
        _logged = _mask_secret_content((result.stdout or "") + ("\n" + result.stderr if result.stderr else ""))
        log_content = (
            f"{'=' * 60}\nCOMMAND: {_mask_secret_content(joined)}\n{'=' * 60}\n"
            + _tail(_logged, _MAX_LOG_FILE_CHARS)
            + f"\nEXIT_CODE: {_exit_code if _exit_code is not None else 'timed_out'}\n"
        )
        try:
            write_workspace_file(workspace, f"{attempt_id}/terminal.log", log_content.encode("utf-8", errors="replace"))
        except (OSError, ValueError):
            pass  # Worker-controlled workspace entries are never followed by host writes.
        return (
            f"BATCH_TERMINAL_RESULT: {_sstatus} (exit_code={_exit_code}, duration={_elapsed:.1f}s)\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"COMMANDS: {json.dumps(shown_parts)}\n"
            f"COMMAND_SANITIZED: {shown_sanitized}\n"
            f"{preflight_note}"
            f"{_sandbox_status_line(ctx.sandbox)}"
            f"{_opsec_advisory}"
            f"{_hint}"
            f"WORKSPACE: {attempt_dir}\n"
            f"OUTPUT:\n{_mask_secret_content(_output_tail)}"
        )

    @mcp.tool()
    @audit_tool
    def run_exploit_terminal(command: str) -> str:
        """Run any shell command in a dedicated visible terminal window. The command executes synchronously; output is captured and RETURNED in the result under an OUTPUT: section. Use for running Kali tools, nmap, curl, netcat, searchsploit, etc. IMPORTANT: for long scans (nmap -sV), redirect output to a file with -oN scan.txt so you can read it later with read_workspace_file.

        Args:
            command: Full shell command text (never truncated before the gate;
                an MB-scale anti-fill cap is the only size bound, so
                code/passwords/PEM/base64 are never capped small).

        Returns:
            TERMINAL_RESULT block (status, exit code, duration, attempt id,
            original + sanitized command, OUTPUT tail) or a preflight /
            target-lock BLOCKED TERMINAL_RESULT.

        Gates:
            Empty/MB-cap pre-gates; ``preflight_command_check`` (sanitizes IP
            typos, never blocks except empty); MANUAL ``_target_lock_block``
            on the FULL sanitized command (RULE-LOCK-FIRST -- fail closed when
            ``require_explicit_allowlist`` is enforced).

        Side-effects:
            Executes the sanitized command only in the sandbox worker; missing
            or failed containment blocks the command. Writes terminal.log
            (secret-masked, capped). Live COMMAND_*/OUTPUT in the returned
            block are secret-masked before return/emit.
        """
        if not command or not command.strip():
            return "BLOCKED: empty command."
        if len(command) > _MAX_COMMAND_CHARS:
            return f"BLOCKED: command exceeds the {_MAX_COMMAND_CHARS}-byte anti-fill cap; split the command."

        original_command = command
        preflight = preflight_command_check(command, check_tool_availability=False)
        if not preflight["valid"]:
            return (
                "TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                "ATTEMPT_ID: preflight\n"
                f"COMMAND_ORIGINAL: {_mask_secret_content(original_command)}\n"
                f"COMMAND_SANITIZED: {_mask_secret_content(preflight['sanitized_command'])}\n"
                f"BLOCKED_REASON: {preflight['blocked_reason']}"
            )

        sanitized_command = preflight["sanitized_command"]
        corrections = preflight["corrections"]
        # Live-result display values: secrets are masked BEFORE return/emit
        # (the raw commands above still drive execution + the lock gate).
        shown_original = _mask_secret_content(original_command)
        shown_sanitized = _mask_secret_content(sanitized_command)

        # RULE-LOCK-FIRST: the gate sees the FULL sanitized command -- never a
        # truncated prefix (an off-target host past any display cap must block).
        # Single parse: extract once, gate on the same list, reuse downstream
        # (sandbox scope gate + loopback hint) instead of re-parsing per site.
        _lock_targets = _extract_lock_targets(sanitized_command)
        _lock_reason = _target_lock_block(sanitized_command, config, targets=_lock_targets)
        if _lock_reason:
            return (
                "TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                "ATTEMPT_ID: preflight\n"
                f"COMMAND_ORIGINAL: {shown_original}\n"
                f"COMMAND_SANITIZED: {shown_sanitized}\n"
                f"BLOCKED_REASON: {_lock_reason}"
            )
        if blocked := _sandbox_required_result(ctx, "run_exploit_terminal"):
            return blocked

        preflight_note = ""
        if corrections:
            preflight_note += f"PREFLIGHT_CORRECTIONS: {json.dumps(corrections)}\n"

        attempt_dir, attempt_id = _attempt_dir(workspace)
        timeout = _config_timeout(config)

        # ---- sandbox path (fail closed): when the disposable execution
        # sandbox is enabled, the command runs inside the hardened worker
        # container -- NEVER on the host. Any sandbox failure returns a
        # SANDBOX_* block instead of falling back to host execution.
        _opsec_advisory = _opsec_advisory_block(sanitized_command, config)
        try:
            _ran, result = run_command_in_sandbox(
                ctx,
                sanitized_command,
                timeout=timeout,
                cwd_host=attempt_dir,
                tool_name="run_exploit_terminal",
                targets=_lock_targets,
            )
        except SandboxError as exc:
            return (
                "TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                f"ATTEMPT_ID: {attempt_id}\n"
                f"COMMAND_ORIGINAL: {shown_original}\n"
                f"COMMAND_SANITIZED: {shown_sanitized}\n"
                f"{preflight_note}"
                f"{sandbox_error_block(exc, tool_name='run_exploit_terminal')}"
            )
        if not _ran or result is None:
            return sandbox_error_block(
                SandboxUnsupportedError("run_exploit_terminal requires an active sandbox worker"),
                tool_name="run_exploit_terminal",
            )
        _sstatus, _output_tail, _exit_code, _elapsed = _sandbox_terminal_ok(result)
        _hint = ""
        try:
            # ponytail: unconditional for loopback targets -- gating on output
            # substrings ("connection refused") misses curl/python/timeout
            # variants and exit-0-masked probes (cmd1; curl | head).
            # Reuses the single-parse lock targets above (no re-parse).
            _primary = _lock_targets[0] if _lock_targets else ""
            if _primary:
                _hint = loopback_hint(_primary, config)
        except Exception:  # ponytail: bare except intentional -- hint is advisory only
            _hint = ""
        # Persisted AND live outputs are masked: raw stdout may carry
        # dumped hashes, tokens, or key material that must neither sit on
        # disk nor echo verbatim in results/events in the clear.
        _logged = _mask_secret_content((result.stdout or "") + ("\n" + result.stderr if result.stderr else ""))
        log_content = (
            f"{'=' * 60}\nCOMMAND: {_mask_secret_content(sanitized_command)}\n{'=' * 60}\n"
            + _tail(_logged, _MAX_LOG_FILE_CHARS)
            + f"\nEXIT_CODE: {_exit_code if _exit_code is not None else 'timed_out'}\n"
        )
        try:
            write_workspace_file(workspace, f"{attempt_id}/terminal.log", log_content.encode("utf-8", errors="replace"))
        except (OSError, ValueError):
            pass  # Worker-controlled workspace entries are never followed by host writes.
        return (
            f"TERMINAL_RESULT: {_sstatus} (exit_code={_exit_code}, duration={_elapsed:.1f}s)\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"COMMAND_ORIGINAL: {shown_original}\n"
            f"COMMAND_SANITIZED: {shown_sanitized}\n"
            f"{preflight_note}"
            f"{_sandbox_status_line(ctx.sandbox)}"
            f"{_opsec_advisory}"
            f"{_hint}"
            f"WORKSPACE: {attempt_dir}\n"
            f"OUTPUT:\n{_mask_secret_content(_output_tail)}"
        )

    @mcp.tool()
    @audit_tool
    def run_as_root(command: str) -> str:
        """Run a command as root inside the sandbox worker and capture its output.

        Args:
            command: Full shell command text (never truncated before the gate;
                an MB-scale anti-fill cap is the only size bound).

        Returns:
            ROOT_CMD_RESULT block (status, exit code, command, OUTPUT tail),
            or a preflight / target-lock / sandbox-denial block.

        Gates:
            Empty/MB-cap pre-gates; ``preflight_command_check`` (sanitizes IP
            typos); MANUAL ``_target_lock_block`` on the FULL sanitized
            command (RULE-LOCK-FIRST); active sandbox worker required.

        Side-effects:
            Executes the sanitized command as container root. No host command
            runs if the worker is unavailable. Live COMMAND/OUTPUT are
            secret-masked before return/emit.
        """
        if not command or not command.strip():
            return "BLOCKED: empty command."
        if len(command) > _MAX_COMMAND_CHARS:
            return f"BLOCKED: command exceeds the {_MAX_COMMAND_CHARS}-byte anti-fill cap; split the command."
        original_command = command
        preflight = preflight_command_check(command, check_tool_availability=False)
        if not preflight["valid"]:
            return (
                f"ROOT_CMD_RESULT: blocked (preflight: {preflight['blocked_reason']})\n"
                f"COMMAND: {_mask_secret_content(original_command)}"
            )
        sanitized_command = preflight["sanitized_command"]
        # Live-result display value: masked before return (raw drives execution).
        shown_command = _mask_secret_content(original_command)
        # RULE-LOCK-FIRST: lock on the FULL sanitized command, before the sudo
        # pivot, so an off-target command reports the lock (not the pivot).
        # Single parse: gate on the extracted list and reuse it downstream.
        _lock_targets = _extract_lock_targets(sanitized_command)
        _lock_reason = _target_lock_block(sanitized_command, config, targets=_lock_targets)
        if _lock_reason:
            return f"ROOT_CMD_RESULT: blocked (target lock: {_lock_reason})"
        if blocked := _sandbox_required_result(ctx, "run_as_root"):
            return blocked
        timeout = _config_timeout(config)
        # ---- sandbox path: root INSIDE the disposable worker (confined by
        # --cap-drop ALL / no devices / netns firewall / workspace-only bind);
        # host root is never involved.
        try:
            _ran, result = run_command_in_sandbox(
                ctx,
                sanitized_command,
                timeout=timeout,
                tool_name="run_as_root",
                user="root",
                targets=_lock_targets,
            )
        except SandboxError as exc:
            return f"ROOT_CMD_RESULT: blocked\n{sandbox_error_block(exc, tool_name='run_as_root')}"
        if not _ran or result is None:
            return f"ROOT_CMD_RESULT: blocked\n{sandbox_error_block(SandboxUnsupportedError('run_as_root requires an active sandbox worker'), tool_name='run_as_root')}"
        merged = result.stdout or ""
        if result.stderr:
            merged = f"{merged}\n{result.stderr}" if merged else result.stderr
        return (
            f"ROOT_CMD_RESULT: {result.status} (exit_code={result.exit_code}, sandbox)\n"
            f"COMMAND: {shown_command}\nSUDO: not required (executed as container root)\n"
            f"OUTPUT:\n{_mask_secret_content(_tail(merged, _OUTPUT_CHARS))}"
        )

    @mcp.tool()
    @audit_tool
    def git_clone(repo_url: str, target_dir: str = "") -> str:
        """Clone a Git repository (GitHub exploit/PoC/tool) into the workspace. Provide the full repo URL (e.g., 'https://github.com/user/repo.git'). Optional target_dir for a custom folder name.

        Args:
            repo_url: Full HTTPS repo URL (format-gated to https Git URLs).
            target_dir: Optional custom folder name ([A-Za-z0-9._-]{1,80}).

        Returns:
            GIT_CLONE_RESULT block (status, exit code, repo, path, OUTPUT
            tail), or BLOCKED on validation or sandbox failure.

        Gates:
            Local-only ``@audit_tool`` (never an allowlist -- no target
            touch). URL format regex; ``target_dir`` charset/length;
            workspace containment (fail closed on escape).

        Side-effects:
            Clones via argv-list ``git clone`` inside the sandbox worker;
            missing or failed containment blocks the request.
        """
        if not repo_url or not repo_url.strip():
            return "BLOCKED: repo_url is required."
        url = repo_url.strip()
        if not _valid_git_repo_url(url):
            return "BLOCKED: invalid repo URL. Must be a GitHub/GitLab HTTPS URL."
        repo_name = urlsplit(url).path.rsplit("/", 1)[-1].removesuffix(".git")
        dir_name = target_dir.strip() if target_dir.strip() else repo_name
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", dir_name):
            return f"BLOCKED: target_dir must match [A-Za-z0-9._-]{{1,80}} (got {dir_name!r})."
        clone_dir = workspace / dir_name
        if not _is_inside_workspace(workspace, clone_dir.resolve()):
            return f"BLOCKED: clone target {clone_dir} escapes the exploit workspace."
        timeout = _config_timeout(config, 120)
        if blocked := _sandbox_required_result(ctx, "git_clone"):
            return blocked

        # Do not preflight this URL from the MCP host. The actual clone runs
        # inside the worker, where the pinned egress policy governs DNS and
        # redirects without opening an SSRF path from the operator machine.
        preflight_note = ""

        # ---- sandbox path: clone inside the worker (egress is governed by
        # the pinned RESEARCH_HOSTS set + the netns firewall, not by the host).
        try:
            _ran, result = run_argv_in_sandbox(
                ctx,
                ["git", "clone", "--", url, dir_name],
                timeout=timeout,
                cwd_host=workspace,
                tool_name="git_clone",
            )
        except SandboxError as exc:
            return f"{preflight_note}GIT_CLONE_RESULT: blocked\n{sandbox_error_block(exc, tool_name='git_clone')}"
        if not _ran or result is None:
            return f"GIT_CLONE_RESULT: blocked\n{sandbox_error_block(SandboxUnsupportedError('git_clone requires an active sandbox worker'), tool_name='git_clone')}"
        merged = result.stdout or ""
        if result.stderr:
            merged = f"{merged}\n{result.stderr}" if merged else result.stderr
        return (
            f"{preflight_note}GIT_CLONE_RESULT: {result.status} (exit_code={result.exit_code}, sandbox)\n"
            f"REPO: {_mask_secret_content(url)}\nPATH: {clone_dir} (container: /workspace/{dir_name})\n"
            f"OUTPUT:\n{_mask_secret_content(_tail(merged, _GIT_OUTPUT_CHARS))}"
        )
