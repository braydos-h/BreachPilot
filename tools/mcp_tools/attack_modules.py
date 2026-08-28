"""Attack Modules MCP tool registration — registry+ranking only (split from god file)."""

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


def register_attack_module_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @audit_tool
    def list_attack_modules() -> str:
        """List all registered pre-packaged attack modules.

        Returns a formatted list of every AttackModule with its name, description,
        target services, target ports, and required CVEs. Use this to discover
        available exploit recipes before running them with run_attack_module.

        Returns:
            Formatted list of all registered attack modules.

        Example:
            list_attack_modules()
        """
        try:
            modules = list_modules()
            if not modules:
                return "NO_MODULES: No attack modules registered."

            lines = [f"ATTACK_MODULES: {len(modules)} available", ""]
            for mod in modules:
                lines.append(f"  [{mod.name}]")
                lines.append(f"    Description: {mod.description}")
                lines.append(f"    Target Services: {', '.join(mod.target_services) if mod.target_services else 'any'}")
                lines.append(f"    Target Ports: {mod.target_ports if mod.target_ports else 'any'}")
                lines.append(f"    Required CVEs: {', '.join(mod.required_cves) if mod.required_cves else 'none'}")
                lines.append("")
            return "\n".join(lines)
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            return f"ERROR: Module listing failed — {exc}"

    @mcp.tool()
    @require_allowlist()
    def run_attack_module(module_name: str, target_ip: str, options: str = "") -> str:
        """Execute a pre-packaged attack module against a target IP.

        Looks up the module by name, checks applicability against the target context
        (loading recon results if available), and executes the module. If the module
        generates a Python script, it is saved to the workspace.

        Args:
            module_name: Name of the attack module (e.g., 'SSHBruteForce', 'Log4jRCE').
                         Use list_attack_modules to see all available modules.
            target_ip: IPv4 address of the target host.
            options: Optional key=value pairs separated by spaces for module parameters.

        Returns:
            Structured result: applicability score, success/failure, output summary,
            and script path if a Python exploit was generated.

        Example:
            run_attack_module("SSHBruteForce", "192.168.1.100", "timeout=30 threads=4")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."

        try:
            module = get_module(module_name)
            if module is None:
                return f"ERROR: Module '{module_name}' not found. Use list_attack_modules to see available modules."

            # Build context — try to load recon results for richer context
            services: list[dict[str, str]] = []
            target_os: str | None = None
            cves: list[str] = []

            # Search for the most recent recon_result.json for this target
            for attempt_dir in sorted(
                workspace.glob("*"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True
            ):
                recon_file = attempt_dir / "recon_result.json"
                if recon_file.exists():
                    try:
                        recon_data = json.loads(recon_file.read_text(encoding="utf-8"))
                        if recon_data.get("target_ip") == target_ip:
                            target_os = recon_data.get("os_family")
                            for svc in recon_data.get("services", []):
                                services.append(
                                    {
                                        "service": svc.get("service", ""),
                                        "port": f"{svc.get('port', '')}/{svc.get('protocol', 'tcp')}",
                                        "version": svc.get("version", ""),
                                    }
                                )
                            # Extract CVEs from script results
                            for svc in recon_data.get("services", []):
                                for script_id, output in svc.get("scripts", {}).items():
                                    cve_matches = re.findall(r"CVE-\d{4}-\d{4,}", output)
                                    cves.extend(cve_matches)
                            break
                    except (json.JSONDecodeError, KeyError):
                        pass

            ctx = ModuleContext(
                target_ip=target_ip,
                target_os=target_os,
                services=services,
                cves=cves,
                workspace=workspace,
            )

            # Check applicability
            score = module.applicability(ctx)
            if score == 0:
                return (
                    f"MODULE_RESULT: not_applicable\n"
                    f"MODULE: {module_name}\n"
                    f"TARGET: {target_ip}\n"
                    f"APPLICABILITY_SCORE: 0\n"
                    f"REASON: Module does not match any known services or CVEs on this target."
                )

            # Execute module
            result = module.run(ctx)

            # Save generated script if present
            script_path = ""
            script_text = result.get("script", "")
            if script_text:
                modules_dir = workspace / "modules"
                modules_dir.mkdir(parents=True, exist_ok=True)
                safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{module_name}_{target_ip}.py")
                script_path = str(modules_dir / safe_name)
                Path(script_path).write_text(script_text, encoding="utf-8")

            # Also try generate_python_script if run didn't produce one
            if not script_text:
                try:
                    script_text = module.generate_python_script(ctx)
                    if script_text:
                        modules_dir = workspace / "modules"
                        modules_dir.mkdir(parents=True, exist_ok=True)
                        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{module_name}_{target_ip}.py")
                        script_path = str(modules_dir / safe_name)
                        Path(script_path).write_text(script_text, encoding="utf-8")
                except Exception:
                    pass

            lines = [
                f"MODULE_RESULT: {result.get('status', 'executed')}",
                f"MODULE: {module_name}",
                f"TARGET: {target_ip}",
                f"APPLICABILITY_SCORE: {score}",
            ]
            if result.get("note"):
                lines.append(f"NOTE: {result['note']}")
            if result.get("suggested_command"):
                lines.append(f"SUGGESTED_COMMAND: {result['suggested_command']}")
            if result.get("suggested_msf"):
                lines.append(f"SUGGESTED_MSF: {result['suggested_msf']}")
            # Phase 2.1: render the compromise / credential signals a typed
            # ModuleResult (or an enriched dict from the autonomous executor)
            # carries. These keys are what ``AttackState.record_success`` reads
            # to flip ``access_achieved`` -- surfacing them here lets the MCP
            # caller see whether a module verified a real foothold.
            if result.get("shell_type"):
                lines.append(f"SHELL_TYPE: {result['shell_type']}")
            if result.get("privilege_level"):
                lines.append(f"PRIVILEGE_LEVEL: {result['privilege_level']}")
            creds = result.get("credentials_found") or result.get("credentials") or []
            if creds:
                creds_str = "; ".join(
                    c if isinstance(c, str) else " ".join(f"{k}={v}" for k, v in c.items()) for c in creds
                )
                lines.append(f"CREDENTIALS_FOUND: {creds_str}")
            if result.get("evidence"):
                lines.append(f"EVIDENCE: {'; '.join(str(e) for e in result['evidence'])}")
            if result.get("references"):
                lines.append(f"REFERENCES: {'; '.join(str(r) for r in result['references'])}")
            if script_path:
                lines.append(f"SCRIPT_SAVED: {script_path}")
            if result.get("script"):
                lines.append(f"SCRIPT_PREVIEW:\n{result['script'][:500]}")

            return "\n".join(lines)
        except Exception as exc:
            return f"ERROR: Module execution failed — {exc}"