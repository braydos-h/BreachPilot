"""Hash-cracking MCP tool registration.

First-class execution wrapper for hashcat / john. ``hash_crack_identify`` only
identifies hashes and suggests commands; this tool actually runs the cracker
locally on the operator box and returns the recovered plaintext. Local-only --
no target touch -- so it is ``@audit_tool`` only (no allowlist gate).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tools.mcp_shared import _attempt_dir
from tools.mcp_tools.modules.hash import _identify_hash_modes
from tools.mcp_tools.registry import ToolContext
from tools.mcp_tools.sandbox_exec import run_argv_in_sandbox, sandbox_error_block
from tools.sandbox.exceptions import SandboxError, SandboxUnsupportedError, SandboxWorkspaceError


def register_cracking_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    audit_tool = ctx.audit_tool

    _TOOLS = {"hashcat", "john"}
    _DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
    # MB-scale anti-fill only (RULE-NO-CAP-SECRETS): hashes are secrets, never
    # capped small; this rejects only absurd multi-MB fills.
    _MAX_HASH_CHARS = 1_000_000
    _MIN_TIMEOUT = 1
    _MAX_TIMEOUT = 3600
    _DEFAULT_TIMEOUT = 600
    # Hashcat -m mode -> john --format map (best-effort). Unmapped modes warn
    # and fall back to john auto-detect instead of failing.
    _JOHN_FORMAT_BY_MODE = {
        "0": "Raw-MD5",
        "100": "Raw-SHA1",
        "1000": "NT",
        "1400": "Raw-SHA256",
        "1700": "Raw-SHA512",
        "1800": "sha512crypt",
        "500": "md5crypt",
        "3200": "bcrypt",
        "5600": "netntlmv2",
        "13100": "krb5tgs",
        "18200": "krb5asrep",
    }

    def _resolve_wordlist(wordlist: str) -> str:
        wl = (wordlist or "").strip()
        if wl:
            return wl
        cfg_wl = ((config or {}).get("exploit") or {}).get("wordlist")
        return str(cfg_wl) if cfg_wl else _DEFAULT_WORDLIST

    def _worker_path(raw_path: str) -> str | None:
        """Map workspace paths into the worker; never inspect a host path."""
        path = Path(raw_path)
        candidate = path if path.is_absolute() else workspace / path
        sandbox = ctx.sandbox
        if sandbox is None:
            return None
        try:
            return str(sandbox.container_path(candidate))
        except SandboxWorkspaceError:
            # Absolute paths outside the shared workspace refer to the worker
            # image only; relative paths may not escape the workspace.
            return str(path) if path.is_absolute() else None
        except SandboxError:
            return None

    def _clamp_timeout(value: Any) -> int:
        try:
            ivalue = int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return _DEFAULT_TIMEOUT
        return max(_MIN_TIMEOUT, min(_MAX_TIMEOUT, ivalue))

    def _tail(text: str, limit: int) -> str:
        body = str(text or "")
        if len(body) <= limit:
            return body
        return "[truncated]\n" + body[-limit:]

    @mcp.tool()
    @audit_tool
    def run_hash_crack(
        hash_value: str,
        tool: str = "hashcat",
        hash_mode: str = "",
        wordlist: str = "",
        rules: str = "",
        timeout: int = 600,
    ) -> str:
        """Crack a hash inside the disposable worker with hashcat or john.

        Args:
            hash_value: Single hash string to crack (full input is gated;
                MB-scale anti-fill only, never capped small).
            tool: ``hashcat`` or ``john`` (case-insensitive).
            hash_mode: Optional explicit hashcat ``-m`` mode (digits only).
                Omitted means auto-identify from the hash string.
            wordlist: Optional wordlist path (explicit, config, or default).
                Workspace-relative paths are mapped into the worker; absolute
                paths outside the workspace refer to the worker image.
            rules: Optional hashcat rule file path in the same path namespace.
            timeout: Crack-command timeout in seconds, clamped to 1..3600.

        Returns:
            ``CRACK_RESULT`` envelope with ``--show`` plaintext recovery, or a
            ``BLOCKED`` / ``WORDLIST_NOT_FOUND`` / ``RULES_NOT_FOUND`` /
            ``CRACKER_NOT_INSTALLED`` fail-closed string.

        Gates:
            ``@audit_tool`` only. No target is touched, so no allowlist gate is
            added. All cracker processes run inside the sandbox worker.

        Side-effects:
            Writes the hash to ``<workspace>/hash.txt`` for the attempt and
            executes the cracker via argv inside the disposable worker.
        """
        sandbox = ctx.sandbox
        if sandbox is None:
            return sandbox_error_block(
                SandboxUnsupportedError("hash cracking requires an active sandbox worker"),
                tool_name="run_hash_crack",
            )
        # RULE-LOCK-FIRST: gate sees the FULL input; truncation applies only to
        # display OUTPUT tails below (with [truncated] markers).
        if not hash_value or not hash_value.strip():
            return "BLOCKED: hash_value is required."
        h = hash_value.strip()
        if len(h) > _MAX_HASH_CHARS:
            return f"BLOCKED: hash_value exceeds {_MAX_HASH_CHARS} chars."
        t = (tool or "").strip().lower()
        if t not in _TOOLS:
            return f"BLOCKED: unsupported tool '{t}'. Allowed: {', '.join(sorted(_TOOLS))}."
        clamped_timeout = _clamp_timeout(timeout)

        # Resolve the hashcat -m mode: explicit override, else auto-identify.
        mode = (hash_mode or "").strip()
        hash_name = ""
        if not mode:
            all_ids = _identify_hash_modes(h)
            # Drop non-hashcat modes (e.g. Argon2 "N/A" -- john-only) before exec.
            ids = [(name, m, cmd) for name, m, cmd in all_ids if m != "N/A" and m.isdigit()]
            if not ids:
                if any(m == "N/A" for _, m, _ in all_ids):
                    return (
                        "BLOCKED: identified hash type is not supported by hashcat "
                        "(e.g. Argon2); retry with tool='john'."
                    )
                return (
                    "BLOCKED: could not identify hash type; pass hash_mode=<hashcat mode> "
                    "explicitly (e.g. 1000 for NTLM, 3200 for bcrypt)."
                )
            hash_name, mode, _ = ids[0]
        else:
            if not mode.isdigit():
                return f"BLOCKED: hash_mode must be a numeric hashcat mode (got '{mode}')."
            # Try to label the mode for the result block (best-effort, non-authoritative).
            ids = _identify_hash_modes(h)
            for name, m, _ in ids:
                if m == mode:
                    hash_name = name
                    break
            if not hash_name:
                hash_name = f"mode {mode}"

        # Map-or-warn john modes: numeric hash_mode is hashcat-specific. Map the
        # common modes to a john --format; otherwise warn and let john
        # auto-detect instead of failing.
        john_format = ""
        john_warn = ""
        if t == "john" and mode:
            john_format = _JOHN_FORMAT_BY_MODE.get(mode, "")
            if not john_format:
                john_warn = (
                    f"WARN: hash_mode {mode} is hashcat-specific and has no john mapping; "
                    "proceeding with john auto-detect."
                )

        wl = _resolve_wordlist(wordlist)
        worker_wl = _worker_path(wl)
        if worker_wl is None:
            return "BLOCKED: relative wordlist must remain inside the shared run workspace."
        rules_path = (rules or "").strip()
        worker_rules = _worker_path(rules_path) if rules_path else ""
        if rules_path and worker_rules is None:
            return "BLOCKED: relative rule file must remain inside the shared run workspace."

        attempt_dir, attempt_id = _attempt_dir(workspace)
        hashfile = attempt_dir / "hash.txt"
        hashfile.write_text(h + "\n", encoding="utf-8")
        try:
            worker_hashfile = str(sandbox.container_path(hashfile))
        except SandboxError as exc:
            return sandbox_error_block(exc, tool_name="run_hash_crack")

        cracked: list[tuple[str, str]] = []
        crack_argv: list[str]
        show_argv: list[str]
        if t == "hashcat":
            crack_argv = ["hashcat", "-m", mode, "-a", "0", worker_hashfile, worker_wl]
            if worker_rules:
                crack_argv.extend(["-r", worker_rules])
            show_argv = ["hashcat", "-m", mode, worker_hashfile, "--show"]
        else:  # john
            crack_argv = ["john", f"--wordlist={worker_wl}", worker_hashfile]
            if john_format:
                crack_argv.extend([f"--format={john_format}"])
            show_argv = ["john", "--show", worker_hashfile]
            if john_format:
                show_argv.extend([f"--format={john_format}"])

        cmd = " ".join(crack_argv)
        try:
            ran, crack_result = run_argv_in_sandbox(
                ctx,
                crack_argv,
                timeout=clamped_timeout,
                cwd_host=attempt_dir,
                tool_name="run_hash_crack",
            )
            if not ran or crack_result is None:
                return sandbox_error_block(
                    SandboxUnsupportedError("hash cracking requires an active sandbox worker"),
                    tool_name="run_hash_crack",
                )
        except SandboxError as exc:
            return sandbox_error_block(exc, tool_name="run_hash_crack")
        crack_status = crack_result.status
        returncode = crack_result.exit_code
        crack_out = _tail(
            (crack_result.stdout or "") + ("\n" + crack_result.stderr if crack_result.stderr else ""), 3000
        )
        elapsed = crack_result.duration_seconds
        if returncode == 127:
            return (
                f"CRACKER_NOT_INSTALLED: {t} is not installed in the sandbox worker image. "
                "Use a derived worker image that includes the cracker; host installation is not used."
            )

        # Retrieve recovered plaintext via the cracker's --show view.
        show_out = ""
        if crack_status not in {"error", "blocked", "timed_out"}:
            try:
                ran, show_result = run_argv_in_sandbox(
                    ctx,
                    show_argv,
                    timeout=60,
                    cwd_host=attempt_dir,
                    tool_name="run_hash_crack",
                )
                if ran and show_result is not None:
                    show_out = _tail(
                        (show_result.stdout or "") + ("\n" + show_result.stderr if show_result.stderr else ""), 2000
                    )
            except SandboxError as exc:
                return sandbox_error_block(exc, tool_name="run_hash_crack")

        # Parse --show output. hashcat: "hash:plain" (or "hash:salt:plain");
        # john: "username:password" lines plus a "Ng 0:00:..." summary line.
        for line in show_out.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            # Skip john's summary line ("2g 0:00:00:00 DONE ...").
            if t == "john" and re.match(r"^\d+g\s+\d+:\d", line):
                continue
            if t == "hashcat":
                left, plain = line.rsplit(":", 1)
            else:
                left, plain = line.split(":", 1)
            if plain:
                cracked.append((left, plain))

        cracked_lines = "\n".join(f"  {left} : {plain}" for left, plain in cracked[:50])
        warn_block = f"{john_warn}\n" if john_warn else ""

        return (
            f"CRACK_RESULT: {crack_status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"TOOL: {t}\n"
            f"HASH_TYPE: {hash_name} (mode {mode})\n"
            f"COMMAND: {cmd}\n"
            f"EXIT_CODE: {returncode}\n"
            f"DURATION: {elapsed:.1f}s\n"
            f"CRACKED: {len(cracked)}\n"
            f"{warn_block}"
            f"{cracked_lines}\n"
            f"SHOW_OUTPUT:\n{_tail(show_out, 1500)}\n"
            f"OUTPUT:\n{_tail(crack_out, 3000)}"
        )
