"""CVSS 3.1 scoring for the finding report (split out of ``tools.enhanced_reporting``).

Pure helpers: no I/O, no lifecycle state. Re-exported through
:mod:`tools.enhanced_reporting` so existing imports keep working.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "CVSSScore",
    "calculate_cvss",
    "estimate_cvss",
    "_bump_cia",
    "_cvss_profile_from_services",
    "_service_field",
    "_service_indicates_vulnerable_version",
]


@dataclass
class CVSSScore:
    """CVSS 3.1 score components."""

    base_score: float = 0.0
    temporal_score: float | None = None
    environmental_score: float | None = None
    vector_string: str = ""
    severity: str = "None"

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_score": self.base_score,
            "temporal_score": self.temporal_score,
            "environmental_score": self.environmental_score,
            "vector_string": self.vector_string,
            "severity": self.severity,
        }


def calculate_cvss(
    attack_vector: str = "N",  # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = "L",  # L=Low, H=High
    privileges_required: str = "N",  # N=None, L=Low, H=High
    user_interaction: str = "N",  # N=None, R=Required
    scope: str = "U",  # U=Unchanged, C=Changed
    confidentiality: str = "N",  # N=None, L=Low, H=High
    integrity: str = "N",
    availability: str = "N",
) -> CVSSScore:
    """Calculate CVSS 3.1 base score from metric values.

    Args:
        attack_vector: N/A/L/P
        attack_complexity: L/H
        privileges_required: N/L/H
        user_interaction: N/R
        scope: U/C
        confidentiality: N/L/H
        integrity: N/L/H
        availability: N/L/H

    Returns:
        CVSSScore with base score and severity
    """
    # Metric weights
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_weights = {"L": 0.77, "H": 0.44}
    pr_weights = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_weights_scope_changed = {"N": 0.85, "L": 0.68, "H": 0.5}
    ui_weights = {"N": 0.85, "R": 0.62}
    cia_weights = {"N": 0.0, "L": 0.22, "H": 0.56}

    # Calculate ISS (Impact Sub-Score)
    iss = 1 - (
        (1 - cia_weights.get(confidentiality, 0))
        * (1 - cia_weights.get(integrity, 0))
        * (1 - cia_weights.get(availability, 0))
    )

    # Calculate Impact
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    # Calculate Exploitability
    pr_weight = (
        pr_weights_scope_changed.get(privileges_required, 0.85)
        if scope == "C"
        else pr_weights.get(privileges_required, 0.85)
    )
    exploitability = (
        8.22
        * av_weights.get(attack_vector, 0.85)
        * ac_weights.get(attack_complexity, 0.77)
        * pr_weight
        * ui_weights.get(user_interaction, 0.85)
    )

    # Calculate Base Score
    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = min((impact + exploitability), 10)
    else:
        base_score = min(1.08 * (impact + exploitability), 10)

    # Round to one decimal place
    base_score = round(base_score, 1)

    # Determine severity
    if base_score == 0.0:
        severity = "None"
    elif base_score < 4.0:
        severity = "Low"
    elif base_score < 7.0:
        severity = "Medium"
    elif base_score < 9.0:
        severity = "High"
    else:
        severity = "Critical"

    vector = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"

    return CVSSScore(
        base_score=base_score,
        vector_string=vector,
        severity=severity,
    )


def estimate_cvss(exploit_name: str, services: list[dict]) -> CVSSScore:
    """Estimate CVSS score based on exploit type and exposed services.

    The exploit-name branches below take precedence (they encode known
    exploit mechanics). When none of them fire, the ``services`` list is
    consulted to pick a sane profile from the exposed surface (SMB / SSH /
    Redis / LDAP / SQL / HTTP). A recognized vulnerable-version banner can
    also bump Confidentiality/Integrity/Availability to High.
    """
    # Default: Network, Low complexity, None privileges, None interaction
    av, ac, pr, ui = "N", "L", "N", "N"
    c, i, a = "H", "H", "H"
    scope = "U"

    exploit_lower = exploit_name.lower()
    matched = True

    if "brute" in exploit_lower or "spray" in exploit_lower:
        ac = "H"  # High complexity (time-based)
        pr = "N"
        c, i, a = "H", "L", "N"
    elif "cve-2024-6387" in exploit_lower or "regresshion" in exploit_lower:
        av, ac, pr = "N", "L", "N"
        c, i, a = "H", "H", "H"
        scope = "C"
    elif "eternalblue" in exploit_lower or "smbghost" in exploit_lower:
        av, ac, pr = "N", "L", "N"
        c, i, a = "H", "H", "H"
        scope = "C"
    elif "bluekeep" in exploit_lower:
        av, ac, pr = "N", "L", "N"
        c, i, a = "H", "H", "H"
    elif "webshell" in exploit_lower or "upload" in exploit_lower:
        av, ac, pr = "N", "L", "L"
        c, i, a = "H", "H", "L"
    elif "sql" in exploit_lower:
        av, ac, pr = "N", "L", "N"
        c, i, a = "H", "L", "L"
    elif "xss" in exploit_lower:
        av, ac, pr, ui = "N", "L", "N", "R"
        c, i, a = "L", "L", "N"
    elif "privesc" in exploit_lower or "suid" in exploit_lower:
        av = "L"
        pr = "L"
        c, i, a = "H", "H", "H"
    elif "container" in exploit_lower or "docker" in exploit_lower:
        av = "L"
        pr = "L"
        c, i, a = "H", "H", "H"
        scope = "C"
    elif "ldap" in exploit_lower or "anonymous" in exploit_lower:
        av, ac, pr = "N", "L", "N"
        c, i, a = "H", "L", "N"
    elif "redis" in exploit_lower:
        av, ac, pr = "N", "L", "N"
        c, i, a = "H", "H", "L"
    else:
        matched = False

    # Service-aware fallback / refinement using the (previously unused)
    # ``services`` arg. Only applies when no exploit-name branch fired.
    if not matched:
        profile = _cvss_profile_from_services(services)
        av, ac, pr, ui, c, i, a, scope = profile

    # A vulnerable-version banner in any exposed service bumps impact to High.
    if _service_indicates_vulnerable_version(services):
        c = "H"
        i = _bump_cia(i)
        a = _bump_cia(a)

    return calculate_cvss(av, ac, pr, ui, scope, c, i, a)


def _service_field(service: Any, *names: str) -> str:
    """Read the first present field from a service dict (case-insensitive)."""
    if not isinstance(service, dict):
        return ""
    lower = {k.lower(): v for k, v in service.items()}
    for name in names:
        if name.lower() in lower:
            return str(lower[name.lower()] or "")
    return ""


def _bump_cia(value: str) -> str:
    """Raise a CIA metric toward High (N -> L -> H). Used when a vulnerable
    service version is detected."""
    rank = {"N": 0, "L": 1, "H": 2}
    current = rank.get(str(value).upper(), 0)
    if current >= 2:
        return "H"
    if current == 1:
        return "H"
    return "L"


def _service_indicates_vulnerable_version(services: list[dict]) -> bool:
    """Heuristic: does any exposed service banner hint at a known-vulnerable version?

    Looks for version substrings associated with high-profile CVEs (OpenSSH < 9.8,
    SMBv1, Redis unauthenticated, vsftpd 2.3.4, ProFTPD 1.3.3c, old Apache/IIS).
    Intentionally conservative — a true match only bumps C/I/A, never the score
    on its own.
    """
    for svc in services or []:
        product = _service_field(svc, "product", "service", "name").lower()
        version = _service_field(svc, "version", "banner").lower()
        blob = f"{product} {version}"
        if "openssh" in blob and any(v in blob for v in ("7.", "8.", "6.")):
            return True
        if "smbv1" in blob or ("microsoft-ds" in blob and "v1" in version):
            return True
        if "redis" in blob and "unauthorized" in blob:
            return True
        if "vsftpd" in blob and "2.3.4" in version:
            return True
        if "proftpd" in blob and "1.3.3c" in version:
            return True
        if "apache" in blob and any(v in version for v in ("2.2.", "2.4.49", "2.4.50")):
            return True
    return False


def _cvss_profile_from_services(services: list[dict]) -> tuple[str, str, str, str, str, str, str, str]:
    """Pick a (av, ac, pr, ui, c, i, a, scope) profile from exposed services.

    Used only as a fallback when the exploit name does not match a known
    branch. Recognizes SMB, SSH, Redis, LDAP, SQL, and HTTP/HTTPS surfaces;
    defaults to Network/Low/None/None with High C/I/A otherwise.
    """
    ports = set()
    products: list[str] = []
    for svc in services or []:
        port = _service_field(svc, "port", "id")
        if port:
            try:
                ports.add(int(str(port)))
            except (TypeError, ValueError):
                pass
        product = _service_field(svc, "product", "service", "name").lower()
        if product:
            products.append(product)
    blob = " ".join(products)

    if 445 in ports or "microsoft-ds" in blob or "smb" in blob:
        # SMB exposure -> remote code execution surface, scope changed.
        return ("N", "L", "N", "N", "H", "H", "H", "C")
    if 22 in ports or "ssh" in blob or "openssh" in blob:
        return ("N", "L", "N", "N", "H", "H", "H", "U")
    if 6379 in ports or "redis" in blob:
        return ("N", "L", "N", "N", "H", "H", "L", "U")
    if 389 in ports or 636 in ports or "ldap" in blob:
        return ("N", "L", "N", "N", "H", "L", "N", "U")
    if any(p in ports for p in (3306, 5432, 1433, 1521)) or any(
        k in blob for k in ("mysql", "postgres", "mssql", "oracle")
    ):
        return ("N", "L", "N", "N", "H", "L", "L", "U")
    if any(p in ports for p in (80, 443, 8080, 8443)) or "http" in blob:
        return ("N", "L", "N", "N", "L", "L", "N", "U")
    # Nothing recognized — keep the conservative default.
    return ("N", "L", "N", "N", "H", "H", "H", "U")
