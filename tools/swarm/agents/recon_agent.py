"""Recon Agent — specialist swarm agent for reconnaissance tasks.

Deep recon specialist with:
- Multi-stage scanning (quick → deep → service-specific)
- Technology stack fingerprinting (Wappalyzer-style banner analysis)
- Attack surface scoring per discovered service
- Automatic task generation for downstream agents
- Shared blackboard updates for inter-agent state
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from tools.swarm.base import Agent, AgentResult, AgentStatus
from tools.swarm.bb_compat import bb_set
from tools.recon_pipeline import ReconPipeline, ReconConfig


def _run_coro(coro: "Any") -> Any:
    """Drive an async coroutine to completion from a sync ``Agent.run``.

    The swarm dispatches agents two ways: ``route_parallel`` runs
    ``agent.run`` in a ``run_in_executor`` worker thread (no running loop, so
    ``asyncio.run`` suffices), while the sync ``route()`` path may execute
    inside the campaign's already-running loop. Handle both: if no loop is
    running in *this* thread, ``asyncio.run``; otherwise run the coroutine in
    a fresh thread with its own loop (cannot ``run_until_complete`` on a
    loop that is already running).
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()


# ── Technology fingerprint database ───────────────────────────────────────

_TECH_SIGNATURES: dict[str, list[str]] = {
    "Apache": ["Apache/", "apache"],
    "Nginx": ["nginx/", "nginx"],
    "IIS": ["Microsoft-IIS/", "IIS/", "Microsoft-HTTPAPI"],
    "Tomcat": ["Apache-Coyote/", "Tomcat/", "Apache Tomcat"],
    "Node.js": ["Express/", "Koa/", "node.js", "Node.js"],
    "Django": ["django", "wsgiref", "Django/"],
    "Flask": ["Werkzeug/", "Flask/"],
    "PHP": ["PHP/", "X-Powered-By: PHP"],
    "ASP.NET": ["ASP.NET", "X-AspNet-Version", "X-AspNetMvc-Version"],
    "WordPress": ["WordPress/", "wp-content", "wp-json"],
    "Drupal": ["Drupal/", "drupal"],
    "Joomla": ["Joomla/", "joomla"],
    "Laravel": ["laravel_session", "X-Laravel"],
    "Spring": ["X-Application-Context", "spring", "Spring Boot"],
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
    "AWS": ["AWSLB", "AWSALB", "X-Amzn-", "AmazonS3"],
    "GCP": ["GCP", "Google Frontend", "X-Cloud-Trace-Context"],
    "Azure": ["Azure", "X-Azure-", "ARRAffinity"],
}

_SERVICE_RISK_SCORES: dict[str, int] = {
    "ssh": 70, "smb": 90, "microsoft-ds": 90, "rdp": 85, "ms-wbt-server": 85,
    "http": 60, "https": 60, "ftp": 65, "telnet": 95, "redis": 80,
    "elasticsearch": 75, "mongodb": 80, "mysql": 70, "postgresql": 70,
    "ldap": 75, "ldaps": 75, "docker": 85, "kubernetes": 85,
    "winrm": 80, "vnc": 70, "smtp": 50, "dns": 40, "snmp": 65,
    "unknown": 50,
}

_RECON_SYSTEM_PROMPT = """You are a RECONNAISSANCE SPECIALIST agent in an autonomous penetration testing swarm.

YOUR MISSION: Map the target's complete attack surface. Be thorough and methodical.

CAPABILITIES:
- Multi-port TCP/UDP scanning with banner grabbing
- HTTP/HTTPS technology stack fingerprinting (server, framework, CMS, CDN, cloud)
- Service version detection and CPE mapping
- OS detection via TTL analysis, banner heuristics, and port signatures
- Attack surface risk scoring (0-100) per discovered service

DEEP RECON METHODOLOGY:
1. INITIAL PROBE: Start with quick_scan on common ports (21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,9000,27017)
2. SERVICE FINGERPRINTING: For each open port, determine exact service and version:
   - HTTP/HTTPS: Grab full response headers (Server, X-Powered-By, Set-Cookie, WWW-Authenticate, X-AspNet-Version, X-Drupal-*, X-Generator)
   - SSH: Parse banner for OpenSSH/Dropbear version and OS hints
   - SMB: Check dialect, signing status, null session access
   - FTP: Check anonymous login, banner for vsftpd/ProFTPD/Pure-FTPd version
   - RDP: Check NLA status, TLS version, certificate info
   - Database ports (3306, 5432, 27017, 6379, 9200): Check for auth requirements, version exposure
3. OS FINGERPRINTING:
   - TTL analysis: 64=Linux, 128=Windows, 255=network devices
   - TCP window size patterns
   - Banner cross-referencing (e.g., "Ubuntu" in SSH + "Apache/2.4.41 (Ubuntu)" in HTTP = Ubuntu Linux)
   - SMB dialect negotiation reveals Windows version
4. WEB DEEP DIVE (for HTTP/HTTPS services):
   - Check robots.txt, sitemap.xml, .well-known/ endpoints
   - Identify CMS: WordPress (wp-content, wp-json, wp-login), Drupal (sites/default, user/login), Joomla (administrator, components)
   - Identify frameworks: Laravel (X-Laravel header, debug routes), Django (admin/, csrf tokens), Rails (X-Runtime, assets/)
   - Check for exposed .git/, .env, config.php.bak, backup files
   - Identify CDN/WAF: Cloudflare (cf-ray, __cfduid), AWS CloudFront (X-Cache: Hit from cloudfront), Akamai (X-Akamai-*)
5. ATTACK SURFACE SCORING:
   - Score each service 0-100 based on exploitability:
     95: telnet (cleartext creds), 90: SMB/RPC (EternalBlue, relay), 85: RDP (BlueKeep, brute), 80: Redis/MongoDB (no-auth default),
     75: LDAP (anonymous bind), 70: SSH/FTP (brute force), 65: WinRM (Pass-the-Hash),
     60: HTTP/HTTPS (web vulns), 50: SMTP/DNS, 40: NTP/SNMP
   - Overall attack surface score = weighted average, boosted by:
     +10 if multiple high-risk services found
     +15 if default/weak credentials detected
     +10 if unpatched OS detected
     +5 per additional open high-risk port beyond 3

OUTPUT FORMAT: Always produce structured JSON with:
- services: [{port, protocol, service, version, banner, risk_score, cpe, auth_required, exploit_hints}]
- technologies: [{name, category, version, confidence, evidence}]
- os_guess: {name, family, version, confidence, indicators, ttl_value}
- attack_surface_score: overall 0-100 risk score with breakdown
- web_endpoints: [{url, method, status, content_type, interesting_findings}]
- recommended_next_phases: ordered list of phases to pursue next with rationale

RULES:
- Start with quick_scan on common ports, then deep scan on discovered ports
- For HTTP services, always grab full response headers for tech fingerprinting
- Score each service by exploitability (RDP=85, SMB=90, SSH=70, HTTP=60, etc.)
- Generate specific follow-up tasks for the VulnAgent and ExploitAgent
- Update the shared blackboard with ALL discovered services immediately
- If a service returns a banner with version, record it precisely for CVE matching
- Never skip a service because it seems "boring" — low-risk services can chain into high-impact attacks
"""


class ReconAgent(Agent):
    """Agent specialized in reconnaissance and target mapping.

    Deep recon with multi-stage scanning, technology fingerprinting,
    attack surface scoring, and automatic downstream task generation.
    """

    # Specialist system prompt for LLM-driven recon
    SYSTEM_PROMPT = _RECON_SYSTEM_PROMPT

    def run(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        self._set_status(AgentStatus.RUNNING)
        start = time.monotonic()

        mission = context.get("mission", {})
        target = task.get("target", "")
        task_id = task.get("task_id", task.get("id", ""))
        blackboard = context.get("blackboard", {})

        output: dict[str, Any] = {
            "target": target,
            "services": [],
            "technologies": [],
            "endpoints": [],
            "os_guess": {},
            "attack_surface_score": 0,
            "recommended_next_phases": [],
        }
        evidence_refs: list[str] = []
        new_tasks: list[dict[str, Any]] = []
        memory_updates: list[dict[str, Any]] = []
        graph_updates: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        error = ""

        try:
            # ── Stage 1: Full recon via the shared ReconPipeline ──
            # Mirror the MCP run_full_recon path: ReconConfig.from_config +
            # ReconPipeline(recon_cfg) + await pipeline.recon_host(target).
            # The previous code raised TypeError/AttributeError: it passed
            # non-existent ``target=``/``ports=`` kwargs to ReconConfig, a
            # second positional (tool_router) to ReconPipeline.__init__(config),
            # and called a non-existent pipeline.run() -- so the swarm recon
            # path never actually ran.
            recon_cfg = ReconConfig.from_config(
                context.get("config"),
                aggression_level="stealth" if context.get("stealth", False) else "normal",
            )
            pipeline = ReconPipeline(recon_cfg)
            host_result = _run_coro(pipeline.recon_host(target))
            result = host_result.to_dict()

            raw_services = result.get("services", [])
            # HostReconResult has no top-level technologies/endpoints/os_guess:
            # technologies are per-service (built up in Stage 2 from banners),
            # endpoints come from spider_results, and the OS guess is assembled
            # from os_name/os_family/os_accuracy.
            output["technologies"] = []
            output["endpoints"] = result.get("spider_results", [])
            output["os_guess"] = {
                "name": result.get("os_name", ""),
                "family": result.get("os_family", ""),
                "accuracy": result.get("os_accuracy", 0),
            }
            evidence_refs = result.get("evidence_refs", [])

            # ── Stage 2: Enrich services with risk scores and tech fingerprinting ──
            enriched_services = []
            for svc in raw_services:
                svc_name = (svc.get("name") or svc.get("service") or "unknown").lower()
                port = svc.get("port", 0)
                banner = svc.get("banner", "")
                version = svc.get("version", "")

                # Risk score
                risk = _SERVICE_RISK_SCORES.get(svc_name, _SERVICE_RISK_SCORES["unknown"])

                # Technology fingerprinting from banners
                detected_tech = self._fingerprint_tech(banner)

                enriched = {
                    "port": port,
                    "protocol": svc.get("protocol", "tcp"),
                    "service": svc_name,
                    "version": version,
                    "banner": banner[:300] if banner else "",
                    "risk_score": risk,
                    "cpe": svc.get("cpe", []),
                    "technologies": detected_tech,
                    "ssl_info": svc.get("ssl_info", {}),
                }
                enriched_services.append(enriched)

                # Add technologies to global list
                for tech in detected_tech:
                    if tech not in output["technologies"]:
                        output["technologies"].append(tech)

            output["services"] = enriched_services

            # ── Stage 3: Attack surface scoring ──
            if enriched_services:
                output["attack_surface_score"] = sum(s["risk_score"] for s in enriched_services) // len(enriched_services)
            else:
                output["attack_surface_score"] = 0

            # ── Stage 4: Generate downstream tasks ──
            high_risk_services = [s for s in enriched_services if s["risk_score"] >= 70]
            web_services = [s for s in enriched_services if s["service"] in ("http", "https")]

            # Vuln research tasks for high-risk services
            for svc in high_risk_services:
                new_tasks.append({
                    "phase": "analysis",
                    "target": target,
                    "asset_type": "service",
                    "objective": f"Research CVEs and exploits for {svc['service']} {svc['version']} on port {svc['port']}",
                    "hypothesis": f"{svc['service']} {svc['version']} on port {svc['port']} may have known vulnerabilities (risk={svc['risk_score']}).",
                    "allowed_tools": ["cve_lookup", "searchsploit", "search_web_exploit"],
                    "risk_level": "low",
                    "priority": svc["risk_score"],
                    "service_context": json.dumps(svc),
                })

            # Web-specific tasks
            for svc in web_services:
                new_tasks.append({
                    "phase": "analysis",
                    "target": target,
                    "asset_type": "web",
                    "objective": f"Deep web enumeration on {target}:{svc['port']} — discover endpoints, APIs, auth mechanisms",
                    "hypothesis": f"Web service on port {svc['port']} may expose admin panels, APIs, or vulnerable endpoints.",
                    "allowed_tools": ["curl", "python", "nuclei"],
                    "risk_level": "low",
                    "priority": 75,
                    "service_context": json.dumps(svc),
                })

            # ── Stage 5: Determine recommended next phases ──
            phases = []
            if high_risk_services:
                phases.append("vulnerability_research")
            if web_services:
                phases.append("web_enumeration")
            if any(s["service"] in ("ssh", "smb", "rdp", "redis") for s in enriched_services):
                phases.append("credential_testing")
            if not enriched_services:
                phases.append("expanded_scanning")
            phases.append("exploitation")
            output["recommended_next_phases"] = phases

            # ── Stage 6: Update shared blackboard ──
            # Atomic writes via the Blackboard API (tools/swarm/blackboard.py),
            # bridged by bb_compat so a plain-dict blackboard (test/legacy path)
            # keeps working. recon replaces these keys rather than appending,
            # so bb_set is the right call (the legacy ``bb[k] = v`` did the
            # same). The lock inside Blackboard.set_scalar makes the overwrite
            # safe if a concurrent reader (e.g. a vuln agent that started early)
            # is reading the same key.
            bb_set(blackboard, "recon_complete", True)
            bb_set(blackboard, "discovered_services", enriched_services)
            bb_set(blackboard, "target_os", output["os_guess"])
            bb_set(blackboard, "attack_surface_score", output["attack_surface_score"])
            bb_set(blackboard, "technologies", output["technologies"])

            # Memory updates
            memory_updates.append({
                "target": target,
                "memory_type": "recon",
                "content": json.dumps({
                    "services_count": len(enriched_services),
                    "high_risk_count": len(high_risk_services),
                    "attack_surface_score": output["attack_surface_score"],
                    "os": output["os_guess"],
                    "technologies": [t.get("name") for t in output["technologies"]],
                }),
                "tags": ["recon", "services", "os", "tech"],
            })

            # Graph updates
            graph_updates.append({
                "node_type": "host",
                "value": target,
                "metadata": {
                    "os": output["os_guess"],
                    "attack_surface_score": output["attack_surface_score"],
                },
                "edges": [
                    {"relation": "exposes", "to": f"{target}:{s['port']}/{s['service']}", "risk": s["risk_score"]}
                    for s in enriched_services
                ],
            })

            self._set_status(AgentStatus.COMPLETE)
        except Exception as exc:
            error = str(exc)
            self._set_status(AgentStatus.FAILED)

        return AgentResult(
            agent_type=self.agent_type,
            status=self.status,
            task_id=task_id,
            output=output,
            error=error,
            execution_time=time.monotonic() - start,
            evidence_refs=evidence_refs,
            new_tasks=new_tasks,
            memory_updates=memory_updates,
            graph_updates=graph_updates,
            findings=findings,
        )

    # ── Technology fingerprinting ──────────────────────────────────────

    @staticmethod
    def _fingerprint_tech(banner: str) -> list[dict[str, Any]]:
        """Analyze banner text for technology signatures."""
        if not banner:
            return []
        low = banner.lower()
        detected: list[dict[str, Any]] = []
        for tech_name, signatures in _TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in low:
                    detected.append({
                        "name": tech_name,
                        "category": ReconAgent._categorize_tech(tech_name),
                        "confidence": 0.8 if sig in banner else 0.6,
                    })
                    break
        return detected

    @staticmethod
    def _categorize_tech(name: str) -> str:
        cats = {
            "Apache": "web_server", "Nginx": "web_server", "IIS": "web_server",
            "Tomcat": "app_server", "Node.js": "runtime", "Django": "framework",
            "Flask": "framework", "PHP": "language", "ASP.NET": "framework",
            "WordPress": "cms", "Drupal": "cms", "Joomla": "cms",
            "Laravel": "framework", "Spring": "framework",
            "Cloudflare": "cdn", "AWS": "cloud", "GCP": "cloud", "Azure": "cloud",
        }
        return cats.get(name, "unknown")
