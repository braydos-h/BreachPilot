"""Hash cracking MCP tools (split from god file)."""

from __future__ import annotations

from tools.mcp_tools.registry import *


def _identify_hash_modes(h: str) -> list[tuple[str, str, str]]:
    """Return ``[(name, hashcat_mode, sample_cmd), ...]`` for a hash string.

    Single source of truth for the hash-type -> hashcat-mode mapping, shared by
    ``hash_crack_identify`` (advisory command suggestions) and the standalone
    ``run_hash_crack`` MCP tool (execution). Order matters: a 32-hex hash is
    reported as BOTH NTLM and MD5 (they are format-indistinguishable; the
    operator/LLM picks based on context -- NTLM from SMB, MD5 from a web app).
    """
    identifications: list[tuple[str, str, str]] = []

    # NTLM: 32 hex chars
    if re.fullmatch(r"[0-9a-fA-F]{32}", h):
        identifications.append(("NTLM", "1000", f"hashcat -m 1000 -a 3 '{h}' ?l?l?l?l?l?l?l?l"))

    # NetNTLMv2: user::domain:challenge:HMAC-MD5:blob
    if "::" in h and ":" in h:
        parts = h.split(":")
        if len(parts) >= 5:
            identifications.append(("NetNTLMv2", "5600", f"hashcat -m 5600 -a 0 '{h}' rockyou.txt"))

    # Kerberos TGS: $krb5tgs$23$*... (etype 23 RC4) / $krb5tgs$18$*... (etype 18 AES)
    if h.startswith("$krb5tgs$18$"):
        identifications.append(
            ("Kerberos 5 TGS-REP etype 18 (AES256)", "19900", f"hashcat -m 19900 -a 0 '{h}' rockyou.txt")
        )
    elif h.startswith("$krb5tgs$"):
        identifications.append(("Kerberos 5 TGS-REP", "13100", f"hashcat -m 13100 -a 0 '{h}' rockyou.txt"))

    # Kerberos AS-REP: $krb5asrep$23$*... (etype 23) / $krb5asrep$18$*... (etype 18)
    if h.startswith("$krb5asrep$18$"):
        identifications.append(
            ("Kerberos 5 AS-REP etype 18 (AES256)", "19900", f"hashcat -m 19900 -a 0 '{h}' rockyou.txt")
        )
    elif h.startswith("$krb5asrep$"):
        identifications.append(("Kerberos 5 AS-REP", "18200", f"hashcat -m 18200 -a 0 '{h}' rockyou.txt"))

    # MD5: 32 hex chars (always reported alongside NTLM -- format-ambiguous)
    if re.fullmatch(r"[0-9a-fA-F]{32}", h):
        identifications.append(("MD5 (also possible)", "0", f"hashcat -m 0 -a 0 '{h}' rockyou.txt"))

    # SHA1: 40 hex chars
    if re.fullmatch(r"[0-9a-fA-F]{40}", h):
        identifications.append(("SHA1", "100", f"hashcat -m 100 -a 0 '{h}' rockyou.txt"))

    # SHA256: 64 hex chars
    if re.fullmatch(r"[0-9a-fA-F]{64}", h):
        identifications.append(("SHA2-256", "1400", f"hashcat -m 1400 -a 0 '{h}' rockyou.txt"))

    # SHA512: 128 hex chars
    if re.fullmatch(r"[0-9a-fA-F]{128}", h):
        identifications.append(("SHA2-512", "1700", f"hashcat -m 1700 -a 0 '{h}' rockyou.txt"))

    # bcrypt: $2a$ / $2b$ / $2y$ / $2$ / $2x$
    if any(h.startswith(p) for p in ("$2a$", "$2b$", "$2y$", "$2$", "$2x$")):
        identifications.append(("bcrypt", "3200", f"hashcat -m 3200 -a 0 '{h}' rockyou.txt"))

    # sha512crypt: $6$...$...
    if h.startswith("$6$") and h.count("$") >= 3:
        identifications.append(("sha512crypt", "1800", f"hashcat -m 1800 -a 0 '{h}' rockyou.txt"))

    # md5crypt: $1$...$... (also catches Cisco type 5)
    if h.startswith("$1$") and h.count("$") >= 3:
        identifications.append(("md5crypt / Cisco type 5", "500", f"hashcat -m 500 -a 0 '{h}' rockyou.txt"))

    # Cisco type 9 (scrypt): $9$...
    if h.startswith("$9$"):
        identifications.append(("Cisco type 9 (scrypt)", "22321", f"hashcat -m 22321 -a 0 '{h}' rockyou.txt"))

    # Cisco type 4 (PBKDF2-SHA256): $4$...
    if h.startswith("$4$"):
        identifications.append(("Cisco type 4 (PBKDF2-SHA256)", "2400", f"hashcat -m 2400 -a 0 '{h}' rockyou.txt"))

    # MSSQL 2005: 0x0100...
    if h.lower().startswith("0x0100") and len(h) >= 54:
        identifications.append(("MSSQL 2005", "132", f"hashcat -m 132 -a 0 '{h}' rockyou.txt"))

    # MSSQL 2012/2014: 0x0200...
    if h.lower().startswith("0x0200") and len(h) >= 70:
        identifications.append(("MSSQL 2012/2014", "1731", f"hashcat -m 1731 -a 0 '{h}' rockyou.txt"))

    # Argon2: $argon2i$ / $argon2id$ (not in hashcat -- john only)
    if h.startswith("$argon2"):
        identifications.append(("Argon2", "N/A", f"john --format=argon2 '{h}'"))

    # scrypt: $scrypt$... or SCRYPT:...
    if h.startswith("$scrypt$") or h.startswith("SCRYPT:"):
        identifications.append(("scrypt", "8900", f"hashcat -m 8900 -a 0 '{h}' rockyou.txt"))

    # Django PBKDF2: pbkdf2_sha256$...
    if h.startswith("pbkdf2_sha256$") or h.startswith("pbkdf2_sha1$"):
        identifications.append(("Django PBKDF2", "12100", f"hashcat -m 12100 -a 0 '{h}' rockyou.txt"))

    # PDF: $pdf$...
    if h.startswith("$pdf$"):
        identifications.append(
            ("PDF", "10400", f"hashcat -m 10400 -a 0 '{h}' rockyou.txt  # 10600/10700 for newer revisions")
        )

    # MS Office: $office$...
    if h.startswith("$office$"):
        identifications.append(
            ("MS Office", "9400", f"hashcat -m 9400 -a 0 '{h}' rockyou.txt  # 9500/9600 for 2010/2013")
        )

    # WPA-PBKDF2 (possible): 64-hex:SSID
    if ":" in h and len(h.split(":")[0]) == 64 and len(h.split(":")[1]) <= 32:
        identifications.append(("WPA-PBKDF2 (possible)", "22000", f"hashcat -m 22000 -a 0 '{h}' rockyou.txt"))

    # LM: 16 bytes hex -- only when nothing else matched (a 16-hex fragment
    # of a longer hash must not false-positive as LM)
    if re.fullmatch(r"[0-9a-fA-F]{16}", h) and not identifications:
        identifications.append(("LM", "3000", f"hashcat -m 3000 -a 3 '{h}' ?u?u?u?u?u?u?u"))

    return identifications


def register_hash_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @audit_tool
    def hash_crack_identify(hash_value: str) -> str:
        """Identify hash type and suggest cracking commands. Provide an NTLM, NetNTLMv2, Kerberos TGS, MD5, SHA, or bcrypt hash. Returns hashcat mode and cracking command."""
        if not hash_value or not hash_value.strip():
            return "BLOCKED: hash_value is required."

        h = hash_value.strip()
        result_lines = ["HASH_CRACK_IDENTIFY:", ""]

        identifications = _identify_hash_modes(h)

        if identifications:
            for name, mode, cmd in identifications:
                result_lines.append(f"  Type: {name} (hashcat mode {mode})")
                result_lines.append(f"  Command: {cmd}")
                result_lines.append("")
        else:
            result_lines.append("  Unknown hash format. Try: hashid or hash-identifier tools.")
            result_lines.append(f"  Hash preview: {h[:80]}...")

        result_lines.append("")
        result_lines.append("Rule-based attack (more effective):")
        result_lines.append("  hashcat -m <mode> -a 0 hash.txt rockyou.txt -r best64.rule")
        result_lines.append("  hashcat -m <mode> -a 0 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule")

        return "\n".join(result_lines)

    # ── Post-Exploitation & Lateral Movement (see tools/attack_modules for full impl) ──
