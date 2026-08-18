"""Attack modules: supply-chain / CI-CD reconnaissance (detection-only)."""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


class ExposedVCS(AttackModule):
    """Detect exposed version-control metadata on an authorized target web root.

    Read-only detection: GETs well-known VCS paths (`.git/HEAD`, `.svn/entries`,
    `.hg/store`, `.bzr/README`) on ctx.target_ip and reports which are exposed.
    If a live `.git/HEAD` is found, it downloads `.git/config` (read-only) to
    surface remote URLs / paths. No write operations, no pivot.
    """

    name = "ExposedVCS"
    description = "Detect exposed VCS metadata (.git/.svn/.hg/.bzr) on the target web root and leak .git/config (read-only)"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Read-only detection of exposed VCS metadata on the target. If a live "
                ".git/HEAD is found, .git/config is downloaded to leak remote URLs / paths. "
                "No write operations; targets only ctx.target_ip. Remote URLs / tokens in "
                ".git/config feed CredentialSpray against the upstream VCS host."
            ),
            "evidence": [f"exposed-VCS detection queued against {ctx.target_ip}"],
            "references": [
                "https://attack.mitre.org/techniques/T1592/",
                "https://attack.mitre.org/techniques/T1552/",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''import json, sys, urllib.request, urllib.error
# Read-only / non-disruptive VCS metadata detection.
# Target: {ctx.target_ip}  (authorized pentest target)
# Connects ONLY to {ctx.target_ip}. No writes, no pivot, no DoS.
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
base = f"http://{{host}}"
paths = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.svn/entries",
    "/.hg/store",
    "/.bzr/README",
]
findings = {{"target": host, "exposed_vcs": [], "git_config_leak": None}}
for p in paths:
    url = base + p
    try:
        req = urllib.request.Request(url, headers={{"User-Agent": "supplychain-recon/1.0"}})
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read(4096)
            status = resp.status
            text = body.decode(errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        text = ""
    except Exception:
        status = None
        text = ""
    if status == 200 and text:
        findings["exposed_vcs"].append({{"path": p, "status": status, "bytes": len(text)}})
        if p == "/.git/HEAD" and "ref:" in text:
            findings["exposed_git_repo"] = True
        if p == "/.git/config":
            findings["git_config_leak"] = text
print(json.dumps(findings, indent=2))
'''


class CICDMisconfig(AttackModule):
    """Detect exposed CI/CD configuration and fingerprint CI servers on the target.

    Read-only detection: GETs common CI config files (`.github/workflows/`,
    `Jenkinsfile`, `.gitlab-ci.yml`, `.travis.yml`, `.circleci/config.yml`,
    `azure-pipelines.yml`) and fingerprints exposed CI/CD servers (Jenkins,
    GitLab, Gitea, Artifactory, Drone, GoCD, TeamCity). Reports what is exposed
    and whether CI config appears to leak secrets / injected env. No writes.
    """

    name = "CICDMisconfig"
    description = "Detect exposed CI/CD config files and fingerprint CI servers (Jenkins/GitLab/Gitea/Artifactory/Drone/GoCD/TeamCity) on the target"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 8081, 9090, 3000]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Read-only detection of exposed CI/CD config + server fingerprints on the "
                "target. Reports leaked secrets/injected env indicators. No writes; targets "
                "only ctx.target_ip. CI injection points chain to WebShellUpload; leaked "
                "secrets chain to HashCrack / CredentialSpray."
            ),
            "evidence": [f"CI/CD misconfig detection queued against {ctx.target_ip}"],
            "references": [
                "https://attack.mitre.org/techniques/T1190/",
                "https://attack.mitre.org/techniques/T1552/",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''import json, sys, urllib.request, urllib.error
# Read-only / non-disruptive CI/CD reconnaissance.
# Target: {ctx.target_ip}  (authorized pentest target)
# Connects ONLY to {ctx.target_ip}. No writes, no pivot, no DoS.
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
base = f"http://{{host}}"
config_paths = [
    "/.github/workflows/",
    "/Jenkinsfile",
    "/.gitlab-ci.yml",
    "/.travis.yml",
    "/.circleci/config.yml",
    "/azure-pipelines.yml",
]
ci_fingerprints = [
    ("/jenkins/", "Jenkins"),
    ("/login", "Jenkins-login"),
    ("/users/sign_in", "GitLab"),
    ("/user/login", "Gitea"),
    ("/artifactory/api/repositories", "Artifactory"),
    ("/login/form", "Drone"),
    ("/go/auth/login", "GoCD"),
    ("/login.html", "TeamCity"),
    ("/httpAuth/app/rest", "TeamCity-API"),
]
secret_indicators = ["secrets.", "env:", "TOKEN", "PASSWORD", "API_KEY", "credentials(", "withCredentials", "{{{{ secrets"]

findings = {{"target": host, "exposed_ci_config": [], "ci_servers": [], "secret_indicators_in_config": []}}
for p in config_paths:
    url = base + p
    try:
        req = urllib.request.Request(url, headers={{"User-Agent": "supplychain-recon/1.0"}})
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read(8192)
            status = resp.status
            text = body.decode(errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        text = ""
    except Exception:
        status = None
        text = ""
    if status == 200 and text:
        entry = {{"path": p, "status": status, "bytes": len(text)}}
        leaked = [s for s in secret_indicators if s.lower() in text.lower()]
        if leaked:
            entry["secret_indicators"] = leaked
            findings["secret_indicators_in_config"].append({{"path": p, "indicators": leaked}})
        findings["exposed_ci_config"].append(entry)

for p, label in ci_fingerprints:
    url = base + p
    try:
        req = urllib.request.Request(url, headers={{"User-Agent": "supplychain-recon/1.0"}})
        with urllib.request.urlopen(req, timeout=8) as resp:
            status = resp.status
            body = resp.read(2048).decode(errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        body = ""
    except Exception:
        status = None
        body = ""
    if status in (200, 401, 403) and status is not None:
        findings["ci_servers"].append({{"label": label, "path": p, "status": status}})

print(json.dumps(findings, indent=2))
'''


class DependencyConfusion(AttackModule):
    """Detection-only dependency-confusion risk assessment.

    Info/workflow module. Orchestrates existing MCP tools to: fetch the target's
    exposed dependency manifests, classify each name as likely INTERNAL vs
    PUBLIC, and cross-check internal-only names that are UNCLAIMED in the public
    registry -- that is the dependency-confusion risk. This module REPORTS the
    risk only. It explicitly does NOT register any package in a public registry
    (that would attack third-party infrastructure the operator does not own).
    """

    name = "DependencyConfusion"
    description = "Detection-only dependency-confusion risk assessment: identify internal package names unclaimed in public registries (report only, never register)"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        workflow = [
            "1. Fetch exposed dependency manifests from the target via fetch_webpage or ExposedVCS output: requirements.txt, package.json, Pipfile, pyproject.toml, go.mod, Gemfile (read-only GET against ctx.target_ip).",
            "2. For each dependency, note whether the name is a likely INTERNAL package (e.g. prefixed with the company name, or sourced from a private index referenced in pip.conf / .npmrc) versus a PUBLIC one already published in PyPI / npm / RubyGems.",
            "3. Cross-check: an internal-only name that is ALSO UNCLAIMED in the public registry is a dependency-confusion risk. A name already available in public PyPI / npm is NOT confusion-vulnerable.",
            "4. Build the risk list (package name, manifest, internal indicator, public-registry claim status) and report it back to the operator.",
            "5. Detection only. Do NOT register, publish, or squat any package in a public registry -- doing so would attack third-party infrastructure outside the operator's authorization. This module reports risk; it never performs the registration step.",
        ]
        return self._info_result(
            ctx,
            note=(
                "Detection-only dependency-confusion risk assessment against ctx.target_ip. "
                "Reports internal package names that are unclaimed in public registries. "
                "Explicitly forbids registering a malicious package in a public registry "
                "(that attacks third-party infrastructure the operator does not own). "
                "The generated script checks unclaimed status via read-only GETs to "
                "pypi.org / registry.npmjs.org JSON APIs (404 = unclaimed)."
            ),
            evidence=[f"dependency-confusion risk assessment queued against {ctx.target_ip}"],
            references=[
                "https://blog.sonatype.com/dependency-confusion",
                "https://nvd.nist.gov/vuln/detail/CVE-2021-24105 (dependency-confusion concept)",
            ],
            workflow=workflow,
        )

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return ""


class ArtifactExposure(AttackModule):
    """Detect exposed sensitive artifacts / secrets on the target web root.

    Read-only detection: GETs common exposed-artifact paths (`.env`,
    `.env.production`, `config/secrets`, `credentials.json`, `id_rsa`,
    `backup/`, `artifacts/`, `releases/`, `dist/`, `.npmrc`, `.pypirc`,
    `docker-compose.yml`, `Dockerfile`) and reports which are exposed (200 vs
    403/404). No downloads of secret material beyond a small banner; no writes.
    """

    name = "ArtifactExposure"
    description = "Detect exposed sensitive files / build artifacts on the target web root (.env, credentials, .npmrc, .pypirc, docker-compose, id_rsa, backup/, artifacts/, releases/)"
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443, 3000, 8081]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Read-only detection of exposed sensitive artifacts on the target. Reports "
                "200/403/404 status for each path; does not exfiltrate secret contents beyond "
                "a small banner peek. No writes; targets only ctx.target_ip. Leaked AWS keys / "
                "VCS tokens / private keys chain to CredentialSpray / HashCrack."
            ),
            "evidence": [f"artifact-exposure detection queued against {ctx.target_ip}"],
            "references": [
                "https://attack.mitre.org/techniques/T1552/",
                "https://attack.mitre.org/techniques/T1213/",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''import json, sys, urllib.request, urllib.error
# Read-only / non-disruptive sensitive-artifact detection.
# Target: {ctx.target_ip}  (authorized pentest target)
# Connects ONLY to {ctx.target_ip}. No writes, no pivot, no DoS.
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
base = f"http://{{host}}"
paths = [
    "/.env",
    "/.env.production",
    "/config/secrets",
    "/credentials.json",
    "/id_rsa",
    "/backup/",
    "/artifacts/",
    "/releases/",
    "/dist/",
    "/.npmrc",
    "/.pypirc",
    "/docker-compose.yml",
    "/Dockerfile",
]
findings = {{"target": host, "exposed_artifacts": []}}
for p in paths:
    url = base + p
    try:
        req = urllib.request.Request(url, headers={{"User-Agent": "supplychain-recon/1.0"}})
        with urllib.request.urlopen(req, timeout=8) as resp:
            status = resp.status
            # Read only a tiny peek to confirm a real file vs directory listing marker.
            body = resp.read(64)
    except urllib.error.HTTPError as e:
        status = e.code
        body = b""
    except Exception:
        status = None
        body = b""
    findings["exposed_artifacts"].append({{"path": p, "status": status, "exposed": status == 200}})
print(json.dumps(findings, indent=2))
'''


class SupplyChainRecon(AttackModule):
    """Orchestrator: combine exposed repo + manifests into a supply-chain CVE report.

    Info/workflow module. Routes the operator through existing MCP tools:
    use ExposedVCS / ArtifactExposure output to find the repo + dependency
    manifests on the target, extract dependency names + versions, then call
    search_cve_intel / search_web_exploit for each dependency and fetch_webpage
    on advisory references to produce a supply-chain CVE report. No script
    generation; no third-party package download or execution.
    """

    name = "SupplyChainRecon"
    description = "Orchestrate ExposedVCS + ArtifactExposure output into a per-dependency supply-chain CVE report using search_cve_intel / search_web_exploit / fetch_webpage"
    target_services = ["http", "https", "ssh", "smb", "microsoft-ds"]
    target_ports = [80, 443, 22, 445, 8080]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        workflow = [
            "1. Use ExposedVCS / ArtifactExposure output to locate the exposed source repo and dependency manifests on ctx.target_ip (read-only).",
            "2. Extract dependency names + versions from requirements.txt, package.json, Pipfile, pyproject.toml, go.mod, Gemfile.",
            "3. For each dependency, call search_cve_intel(dependency_name, version) to find known CVEs from NVD.",
            "4. For each dependency, call search_web_exploit(dependency_name) to find public advisories, PoCs, and exploit code.",
            "5. Call fetch_webpage on any security advisory / GHSA / vendor bulletin URLs returned by steps 3-4 to enrich the report.",
            "6. Produce a supply-chain CVE report: dependency, version, CVE list, advisory references, exploit availability. Do NOT download or execute untrusted third-party packages.",
        ]
        return self._info_result(
            ctx,
            note=(
                "Orchestrator module. Combines exposed-repo and manifest findings into a "
                "per-dependency supply-chain CVE report by routing through search_cve_intel, "
                "search_web_exploit, and fetch_webpage. Detection / reporting only -- does not "
                "download or execute untrusted third-party packages. Targets only ctx.target_ip."
            ),
            evidence=[f"supply-chain CVE report queued against {ctx.target_ip}"],
            references=[
                "https://nvd.nist.gov/",
                "https://github.com/advisories",
                "https://osv.dev/",
            ],
            workflow=workflow,
        )

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return ""