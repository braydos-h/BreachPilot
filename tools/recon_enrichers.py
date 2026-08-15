"""Recon enrichers: pure parsing helpers + a bounded stdlib web spider.

This module is a standalone helper layer for the recon pipeline's
SecondaryEnumerator. The parsing functions are pure (take strings/dicts,
return structured dicts, never raise). The :func:`http_spider` is a bounded
BFS spider that connects ONLY to the single authorized ``target_ip:port``
passed in; all network I/O goes through an injectable ``fetch_fn`` so tests
can run without touching the network.

Security posture (lab build, authorized pentest):
- Recon is READ-ONLY / non-destructive. Nothing here writes coils/registers
  or performs any destructive action.
- The spider never connects to any host other than the single ``target_ip``
  argument. Off-site absolute URLs are recorded as links but NOT fetched.
- No third-party submissions; passive OSINT-style parsing only.

This module deliberately does NOT import ``tools.recon_pipeline`` and does NOT
re-implement any allowlist gating — callers (the pipeline / MCP layer) are
responsible for routing through ``require_allowlist``. These are pure helpers.
"""

from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from collections import deque
from html.parser import HTMLParser
from typing import Callable, Optional

from tools.opsec import process_user_agent


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_EMPTY_TLS = {
    "issuer": "",
    "subject": "",
    "san": [],
    "valid_from": "",
    "valid_to": "",
    "protocol": "",
    "cipher": "",
}


def _to_text(raw) -> str:
    """Best-effort coercion of *raw* to a string. Never raises."""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    try:
        return json.dumps(raw)
    except Exception:
        try:
            return str(raw)
        except Exception:
            return ""


# ---------------------------------------------------------------------------
# parse_tls_info
# ---------------------------------------------------------------------------

_DNS_SAN_RE = re.compile(r"DNS:([^,\s]+)", re.IGNORECASE)
_ISSUER_RE = re.compile(r"Issuer:\s*(.+)", re.IGNORECASE)
_SUBJECT_RE = re.compile(r"Subject:\s*(.+)", re.IGNORECASE)
_NOT_BEFORE_RE = re.compile(r"Not valid before:?\s*(.+)", re.IGNORECASE)
_NOT_AFTER_RE = re.compile(r"Not valid after:?\s*(.+)", re.IGNORECASE)
_SAN_LINE_RE = re.compile(r"Subject Alternative Name:\s*(.+)", re.IGNORECASE)
_PROTOCOL_RE = re.compile(r"Protocol:\s*(.+)", re.IGNORECASE)
_PROTOCOL_HDR_RE = re.compile(
    r"^\s*(TLSv?[-\d.]+|SSLv?[-\d.]+)\s*:?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_CIPHER_RE = re.compile(r"Cipher:\s*(.+)", re.IGNORECASE)


def _first_match(pattern: re.Pattern, text: str) -> str:
    m = pattern.search(text)
    if not m:
        return ""
    return m.group(1).strip().strip("\n\r")


def parse_tls_info(raw: str) -> dict:
    """Parse nmap ssl-cert script output (text) OR a JSON cert dict.

    Returns ``{"issuer", "subject", "san", "valid_from", "valid_to",
    "protocol", "cipher"}``. Tolerant: missing fields -> "" / [], never
    raises.
    """
    try:
        if raw is None:
            return dict(_EMPTY_TLS)

        # If given a dict (or a JSON string that decodes to one), normalize it.
        obj = None
        if isinstance(raw, dict):
            obj = raw
        elif isinstance(raw, str):
            stripped = raw.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    decoded = json.loads(stripped)
                    if isinstance(decoded, dict):
                        obj = decoded
                except Exception:
                    obj = None

        if obj is not None:
            issuer = obj.get("issuer") or obj.get("issuerName") or ""
            subject = obj.get("subject") or obj.get("subjectName") or ""
            if isinstance(issuer, dict):
                issuer = issuer.get("commonName") or issuer.get("CN") or json.dumps(issuer)
            if isinstance(subject, dict):
                subject = subject.get("commonName") or subject.get("CN") or json.dumps(subject)
            san_raw = obj.get("san") or obj.get("subjectAltName") or []
            if isinstance(san_raw, str):
                san = [s.strip() for s in san_raw.split(",") if s.strip()]
            elif isinstance(san_raw, list):
                san = []
                for s in san_raw:
                    if isinstance(s, dict):
                        val = s.get("value") or s.get("DNS") or s.get("name") or ""
                        if val:
                            san.append(str(val).strip())
                    elif s is not None:
                        san.append(str(s).strip())
            else:
                san = []
            return {
                "issuer": str(issuer).strip() if issuer else "",
                "subject": str(subject).strip() if subject else "",
                "san": san,
                "valid_from": str(obj.get("valid_from") or obj.get("notBefore") or obj.get("not_valid_before") or "").strip(),
                "valid_to": str(obj.get("valid_to") or obj.get("notAfter") or obj.get("not_valid_after") or "").strip(),
                "protocol": str(obj.get("protocol") or "").strip(),
                "cipher": str(obj.get("cipher") or "").strip(),
            }

        text = _to_text(raw)
        if not text:
            return dict(_EMPTY_TLS)

        issuer = _first_match(_ISSUER_RE, text)
        subject = _first_match(_SUBJECT_RE, text)
        valid_from = _first_match(_NOT_BEFORE_RE, text)
        valid_to = _first_match(_NOT_AFTER_RE, text)
        protocol = _first_match(_PROTOCOL_RE, text)
        if not protocol:
            hm = _PROTOCOL_HDR_RE.search(text)
            if hm:
                protocol = hm.group(1).strip()
        cipher = _first_match(_CIPHER_RE, text)

        san: list[str] = []
        san_line = _first_match(_SAN_LINE_RE, text)
        if san_line:
            san.extend([m.strip() for m in re.split(r"[,\s]+", san_line) if m.strip()])
        # Also pick up DNS:foo entries anywhere in the text.
        for m in _DNS_SAN_RE.finditer(text):
            val = m.group(1).strip().rstrip(",")
            if val and val not in san:
                san.append(val)
        # Strip a leading "DNS:" prefix if the SAN-line split captured it.
        san = [s[4:].strip() if s.lower().startswith("dns:") else s for s in san]
        # Drop empties / duplicates while preserving order.
        seen = set()
        san_clean = []
        for s in san:
            if s and s not in seen:
                seen.add(s)
                san_clean.append(s)

        return {
            "issuer": issuer,
            "subject": subject,
            "san": san_clean,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "protocol": protocol,
            "cipher": cipher,
        }
    except Exception:
        return dict(_EMPTY_TLS)


# ---------------------------------------------------------------------------
# parse_smtp_banner
# ---------------------------------------------------------------------------

_STARTTLS_RE = re.compile(r"\bSTARTTLS\b", re.IGNORECASE)
_AUTH_RE = re.compile(r"^\s*\d+[ -]?AUTH\s+(.+)$", re.IGNORECASE | re.MULTILINE)
_SERVER_RE = re.compile(
    r"(Postfix|Exim|Sendmail|Microsoft ESMTP|Microsoft SMTP|Courier|Dovecot|hMailServer|MailEnable)",
    re.IGNORECASE,
)
_SERVER_GENERIC_RE = re.compile(r"\b(ESMTP|SMTP)\b", re.IGNORECASE)


def parse_smtp_banner(banner: str) -> dict:
    """Parse an SMTP EHLO/220 banner into structured fields. Tolerant."""
    try:
        text = _to_text(banner)
        if not text:
            return {
                "server_software": "",
                "supports_starttls": False,
                "auth_methods": [],
                "banner": "",
            }

        supports_starttls = bool(_STARTTLS_RE.search(text))

        auth_methods: list[str] = []
        for m in _AUTH_RE.finditer(text):
            for method in re.split(r"\s+", m.group(1).strip()):
                method = method.strip()
                if method and method.upper() not in auth_methods:
                    auth_methods.append(method.upper())
        # Dedup, preserve order, filter common noise tokens.
        auth_methods = [a for a in auth_methods if re.fullmatch(r"[A-Z0-9-]+", a)]

        server_software = ""
        sm = _SERVER_RE.search(text)
        if sm:
            server_software = sm.group(1)
        elif _SERVER_GENERIC_RE.search(text):
            gm = _SERVER_GENERIC_RE.search(text)
            server_software = gm.group(1)

        return {
            "server_software": server_software,
            "supports_starttls": supports_starttls,
            "auth_methods": auth_methods,
            "banner": text,
        }
    except Exception:
        return {
            "server_software": "",
            "supports_starttls": False,
            "auth_methods": [],
            "banner": _to_text(banner),
        }


# ---------------------------------------------------------------------------
# parse_db_banner
# ---------------------------------------------------------------------------

_MYSQL_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+[-\w]*)")
_MYSQL_MARKER_RE = re.compile(r"mariadb|mysql", re.IGNORECASE)
_POSTGRES_RE = re.compile(r"PostgreSQL|FATAL|Catalina", re.IGNORECASE)
_POSTGRES_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")
_MSSQL_RE = re.compile(r"Microsoft SQL Server|SQL Server|TDS", re.IGNORECASE)
_MSSQL_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")
_MONGO_RE = re.compile(r"MongoDB", re.IGNORECASE)
_MONGO_VERSION_RE = re.compile(r"version[\":= ]+([0-9.]+)", re.IGNORECASE)
_REDIS_RE = re.compile(r"^\s*(\+PONG|-NOAUTH|-ERR.*)", re.IGNORECASE | re.MULTILINE)
_REDIS_AUTH_RE = re.compile(r"NOAUTH", re.IGNORECASE)


def parse_db_banner(banner: str, service: str = "") -> dict:
    """Parse a database handshake/banner. Tolerant; never raises."""
    try:
        text = _to_text(banner)
        svc = _to_text(service).lower()
        auth_required = False
        db_type = "unknown"
        version = ""

        if not text and not svc:
            return {"db_type": "unknown", "version": "", "auth_required": False, "banner": ""}

        # Redis: very distinct textual protocol.
        if "redis" in svc or _REDIS_RE.search(text):
            db_type = "redis"
            auth_required = bool(_REDIS_AUTH_RE.search(text))
            vm = re.search(r"redis_version:?\s*([0-9.]+)", text, re.IGNORECASE)
            if vm:
                version = vm.group(1)
            return {"db_type": db_type, "version": version, "auth_required": auth_required, "banner": text}

        # MongoDB: JSON-ish / "MongoDB" string.
        if "mongo" in svc or _MONGO_RE.search(text):
            db_type = "mongodb"
            vm = _MONGO_VERSION_RE.search(text)
            if vm:
                version = vm.group(1)
            if "auth" in text.lower() or "unauthorized" in text.lower():
                auth_required = True
            return {"db_type": db_type, "version": version, "auth_required": auth_required, "banner": text}

        # MSSQL: TDS header 0x04 0x01 or textual marker.
        if "mssql" in svc or "sqlserver" in svc or _MSSQL_RE.search(text) or text.startswith("\x04\x01"):
            db_type = "mssql"
            vm = _MSSQL_VERSION_RE.search(text)
            if vm:
                version = vm.group(1)
            return {"db_type": db_type, "version": version, "auth_required": auth_required, "banner": text}

        # Postgres.
        if "postgres" in svc or "postgresql" in svc or _POSTGRES_RE.search(text):
            db_type = "postgres"
            vm = _POSTGRES_VERSION_RE.search(text)
            if vm:
                version = vm.group(1)
            if "password" in text.lower() or "authentication" in text.lower() or "FATAL" in text:
                auth_required = True
            return {"db_type": db_type, "version": version, "auth_required": auth_required, "banner": text}

        # MySQL: protocol marker or version string; also raw packet bytes
        # starting with a length prefix then 0x0a (command byte for greeting).
        if "mysql" in svc or _MYSQL_MARKER_RE.search(text):
            db_type = "mysql"
            vm = _MYSQL_VERSION_RE.search(text)
            if vm:
                version = vm.group(1)
            return {"db_type": db_type, "version": version, "auth_required": auth_required, "banner": text}

        # Heuristic: a leading byte 0x0a after a 3-byte length prefix is the
        # MySQL greeting protocol byte. Detect only when raw bytes present.
        if text and text[0:1] in ("\x00", "\x0a"):
            # Look for an embedded version-like token.
            vm = re.search(r"([0-9]+\.[0-9]+\.[0-9]+[-\w]*)", text)
            if vm:
                db_type = "mysql"
                version = vm.group(1)
                return {"db_type": db_type, "version": version, "auth_required": auth_required, "banner": text}

        # Fall back: try to detect a version string alone.
        vm = re.search(r"([0-9]+\.[0-9]+\.[0-9]+[-\w]*)", text)
        if vm:
            version = vm.group(1)

        return {"db_type": db_type, "version": version, "auth_required": auth_required, "banner": text}
    except Exception:
        return {"db_type": "unknown", "version": "", "auth_required": False, "banner": _to_text(banner)}


# ---------------------------------------------------------------------------
# parse_udp_nmap_output
# ---------------------------------------------------------------------------

# grepable line: "Host: 10.0.0.5 (host)  Ports: 68/open/udp//tcpwrapped///, ..."
_GREPABLE_HOST_RE = re.compile(r"Host:\s+\S+\s+\([^)]*\)\s+Ports:\s+(.+)$", re.IGNORECASE)
_GREPABLE_PORT_RE = re.compile(
    r"(\d+)/(open|open|closed|filtered|open|open\|filtered)/(\w+)//(\w*)",  # tolerant
    re.IGNORECASE,
)


def _parse_grepable_ports(ports_str: str) -> list[dict]:
    results: list[dict] = []
    for token in ports_str.split(","):
        token = token.strip()
        if not token:
            continue
        # format: port/state/protocol//service//
        parts = token.split("/")
        if len(parts) < 3:
            continue
        try:
            port = int(parts[0])
        except (ValueError, IndexError):
            continue
        state = parts[1].strip().lower() or "unknown"
        protocol = parts[2].strip().lower() or "udp"
        service = parts[4].strip() if len(parts) > 4 else ""
        banner = parts[6].strip() if len(parts) > 6 else ""
        # Skip closed / filtered-uninteresting per spec.
        if state in ("closed", "filtered"):
            continue
        # open|filtered is the common UDP "interesting" state — keep it.
        if protocol != "udp":
            continue
        results.append({
            "port": port,
            "protocol": "udp",
            "service": service,
            "state": state,
            "banner": banner,
        })
    return results


def _parse_xml_udp(raw: str) -> list[dict]:
    import xml.etree.ElementTree as ET

    results: list[dict] = []
    try:
        root = ET.fromstring(raw.encode("utf-8", errors="replace"))
    except ET.ParseError:
        return results
    for port in root.iter("port"):
        if (port.get("protocol") or "").lower() != "udp":
            continue
        try:
            port_id = int(port.get("portid", "0"))
        except ValueError:
            continue
        state_elem = port.find("state")
        state = "unknown"
        if state_elem is not None and state_elem.get("state"):
            state = state_elem.get("state").strip().lower()
        service_elem = port.find("service")
        service = ""
        banner = ""
        if service_elem is not None:
            service = (service_elem.get("name") or "").strip()
            banner = (service_elem.get("product") or "").strip()
        # Skip closed / filtered-uninteresting.
        if state in ("closed", "filtered"):
            continue
        results.append({
            "port": port_id,
            "protocol": "udp",
            "service": service,
            "state": state,
            "banner": banner,
        })
    return results


def parse_udp_nmap_output(raw: str) -> list[dict]:
    """Parse nmap UDP output (grepable or XML) into a list of port dicts.

    Tolerant; skip closed/filtered-uninteresting; never raises. Returns ``[]``
    on empty/None input.
    """
    try:
        text = _to_text(raw)
        if not text:
            return []

        results: list[dict] = []

        # XML path.
        if "<port" in text and 'protocol="udp"' in text.lower():
            results.extend(_parse_xml_udp(text))

        # grepable path: look for "Status: Up" lines and Host: lines.
        if "Host:" in text:
            for line in text.splitlines():
                hm = _GREPABLE_HOST_RE.search(line)
                if hm:
                    results.extend(_parse_grepable_ports(hm.group(1)))
                else:
                    # tolerant: try a looser "udp" token line
                    if "/udp/" in line.lower():
                        results.extend(_parse_grepable_ports(line))

        return results
    except Exception:
        return []


# ---------------------------------------------------------------------------
# http_spider
# ---------------------------------------------------------------------------

# Simple, conservative link extraction: href="..." and href='...'.
_HREF_RE = re.compile(r'href\s*=\s*"([^"]*)"', re.IGNORECASE)
_HREF_SINGLE_RE = re.compile(r"href\s*=\s*'([^']*)'", re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b", re.IGNORECASE)
_META_GEN_RE = re.compile(
    r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']*)["\']',
    re.IGNORECASE,
)


class _LinkCollector(HTMLParser):
    """Collect hrefs and form flags from HTML using the stdlib parser."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms = 0

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t == "a":
            for k, v in attrs:
                if k.lower() == "href" and v:
                    self.links.append(v)
        elif t == "form":
            self.forms += 1


def _extract_links(body: str) -> tuple[list[str], int]:
    """Return (links, form_count). Never raises."""
    links: list[str] = []
    forms = 0
    try:
        collector = _LinkCollector()
        try:
            collector.feed(body)
        except Exception:
            pass
        try:
            collector.close()
        except Exception:
            pass
        links = collector.links
        forms = collector.forms
    except Exception:
        links = []
        forms = 0
    # Fallback regex extraction if the parser found nothing.
    if not links:
        for m in _HREF_RE.finditer(body):
            links.append(m.group(1))
        for m in _HREF_SINGLE_RE.finditer(body):
            links.append(m.group(1))
    if forms == 0 and _FORM_RE.search(body):
        forms = len(_FORM_RE.findall(body))
    return links, forms


def _resolve_link(base_path: str, link: str) -> Optional[str]:
    """Resolve *link* relative to the base path on the target.

    Returns an absolute path string (starting with "/") for same-target
    links, or None for off-site / unusable links (mailto:, javascript:, etc.)
    """
    if not link:
        return None
    link = link.strip()
    if not link:
        return None
    lower = link.lower()
    if lower.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return None
    if link.startswith("//") or link.startswith("http://") or link.startswith("https://"):
        # Absolute URL — off-site for our single-target spider. Skip fetching.
        return None
    if link.startswith("/"):
        return link
    # Relative: join against base_path directory.
    if base_path and not base_path.endswith("/"):
        base_dir = base_path.rsplit("/", 1)[0] + "/"
    else:
        base_dir = base_path or "/"
    # Strip any query/fragment for the path component but keep it crawlable.
    resolved = base_dir + link
    if not resolved.startswith("/"):
        resolved = "/" + resolved
    return resolved


def _detect_technologies(body: str, status: int) -> list[str]:
    """Simple heuristic tech detection from body + status. Never raises."""
    techs: list[str] = []
    try:
        m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if m:
            gen = m.group(1).strip()
            if gen:
                techs.append(gen)
        for m in re.finditer(r"X-Powered-By:\s*([^\r\n]+)", body, re.IGNORECASE):
            val = m.group(1).strip()
            if val and val not in techs:
                techs.append(val)
        for m in re.finditer(r"Server:\s*([^\r\n]+)", body, re.IGNORECASE):
            val = m.group(1).strip()
            if val and val not in techs:
                techs.append(val)
    except Exception:
        pass
    return techs


def _default_fetch(url: str) -> tuple[int, str]:
    """Real-network fetch via urllib. Only invoked when fetch_fn is None."""
    req = urllib.request.Request(url, headers={"User-Agent": process_user_agent("NetAttackAi-recon-spider/1.0")})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = getattr(resp, "status", resp.getcode())
            body = resp.read().decode("utf-8", errors="replace")
            return int(status), body
    except urllib.error.HTTPError as e:
        return int(e.code), ""
    except Exception:
        return 0, ""


def http_spider(
    target_ip: str,
    port: int,
    *,
    scheme: str = "http",
    max_pages: int = 20,
    fetch_fn: Optional[Callable[[str], tuple[int, str]]] = None,
) -> dict:
    """Bounded stdlib web spider against the SINGLE target only.

    Starts at ``{scheme}://{target_ip}:{port}/`` and BFS-bounded by
    ``max_pages`` (default 20). ``fetch_fn(url) -> (status, body)`` is
    injectable; if None, uses :func:`urllib.request` (real network).

    Returns:
        ``{"target_ip", "port", "urls_visited", "links", "forms",
        "status_codes", "technologies"}``.

    Tolerant: per-URL errors skip that URL. NEVER raises. Connects ONLY to
    ``target_ip:port``; off-site absolute links are recorded but never
    fetched.
    """
    base_url = f"{scheme}://{target_ip}:{port}"
    result = {
        "target_ip": target_ip,
        "port": port,
        "urls_visited": [],
        "links": [],
        "forms": 0,
        "status_codes": {},
        "technologies": [],
    }
    try:
        if not target_ip or not port:
            return result
        try:
            port_int = int(port)
        except (TypeError, ValueError):
            return result

        if max_pages is None or max_pages <= 0:
            max_pages = 20

        fetch = fetch_fn if fetch_fn is not None else _default_fetch

        start_path = "/"
        visited: set[str] = set()
        seen_links: set[str] = set()
        queue: deque[str] = deque([start_path])

        while queue and len(visited) < max_pages:
            path = queue.popleft()
            if path in visited:
                continue
            visited.add(path)
            url = base_url + path
            try:
                status, body = fetch(url)
            except Exception:
                status, body = 0, ""
            result["urls_visited"].append(path)
            result["status_codes"][path] = int(status) if status is not None else 0

            if body:
                links, forms = _extract_links(body)
                result["forms"] += forms
                for link in links:
                    raw = link.strip()
                    if raw and raw not in seen_links:
                        seen_links.add(raw)
                        result["links"].append(raw)
                    resolved = _resolve_link(path, raw)
                    if resolved is None:
                        continue
                    # Strip fragment for crawl uniqueness.
                    crawl_path = resolved.split("#", 1)[0]
                    if not crawl_path:
                        continue
                    if crawl_path not in visited and crawl_path not in queue:
                        queue.append(crawl_path)

                for tech in _detect_technologies(body, status):
                    if tech not in result["technologies"]:
                        result["technologies"].append(tech)
    except Exception:
        # NEVER raise — return whatever we have so far.
        pass
    return result


__all__ = [
    "parse_tls_info",
    "parse_smtp_banner",
    "parse_db_banner",
    "parse_udp_nmap_output",
    "http_spider",
]