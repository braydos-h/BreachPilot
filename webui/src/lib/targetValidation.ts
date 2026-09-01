/**
 * Browser-side target validation. Mirrors the backend's strict syntax checks
 * in ``tools/validation_utils.py`` (``_STRICT_IPV4_RE`` / ``_FQDN_RE`` /
 * ``ipaddress.ip_address``) so the UI rejects the same invalid forms the API
 * does, without adding a dependency.
 *
 * Kept dependency-free and framework-agnostic so it can be unit-tested in
 * isolation (see ``targetValidation.test.ts``).
 */

// Strict IPv4: four octets 0-255 separated by dots, anchored.
const STRICT_IPV4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

// FQDN: dot-separated labels (RFC1035 length bounds), TLD >= 2 alphabetic chars.
const FQDN = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;

const HEX_GRP = /^[0-9a-fA-F]{1,4}$/;

/**
 * Strict IPv6 validator matching Python's ``ipaddress.ip_address`` for the
 * forms that matter to BreachPilot (normal, compressed ``::``, and
 * IPv4-embedded). Rejects malformed values that the previous loose
 * ``/^[0-9a-fA-F:]+$/`` regex accepted (``:``, ``:::``, too many groups,
 * double ``::``, non-hex).
 *
 * Zone IDs (``%eth0``) are stripped before validation to mirror Python's
 * ``ip_address`` which accepts them; the remainder is validated normally.
 */
function isValidIPv6(s: string): boolean {
  if (!s.includes(":")) return false;

  // Strip zone id like "%eth0" / "%lo0" (Python accepts it).
  let base = s;
  const pct = s.indexOf("%");
  if (pct !== -1) {
    if (s.indexOf("%", pct + 1) !== -1) return false;
    base = s.slice(0, pct);
    if (!base || !base.includes(":")) return false;
    const zone = s.slice(pct + 1);
    if (!zone) return false;
  }

  // Only hex, colon, and dot (dot only allowed in embedded IPv4 suffix)
  if (!/^[0-9a-fA-F:.]+$/.test(base)) return false;
  if (base.includes(":::")) return false;
  if (base.indexOf("::") !== base.lastIndexOf("::")) return false;

  // Handle IPv4-embedded suffix (e.g. ::ffff:192.0.2.1)
  let temp = base;
  if (base.includes(".")) {
    const lastColon = base.lastIndexOf(":");
    if (lastColon === -1) return false;
    const ipv4 = base.slice(lastColon + 1);
    if (!STRICT_IPV4.test(ipv4)) return false;
    if (base.slice(0, lastColon).includes(".")) return false;
    temp = base.slice(0, lastColon + 1) + "0:0";
    if (temp.includes(":::")) return false;
    if (temp.indexOf("::") !== temp.lastIndexOf("::")) return false;
  }

  if (temp.includes("::")) {
    const [leftStr, rightStr] = temp.split("::");
    const left = leftStr ? leftStr.split(":") : [];
    const right = rightStr ? rightStr.split(":") : [];
    for (const g of left) if (!HEX_GRP.test(g)) return false;
    for (const g of right) if (!HEX_GRP.test(g)) return false;
    // :: must compress at least one group (8 total)
    if (left.length + right.length > 7) return false;
    return true;
  }

  // No compression
  if (temp.startsWith(":") || temp.endsWith(":")) return false;
  const groups = temp.split(":");
  if (groups.length !== 8) return false;
  for (const g of groups) if (!HEX_GRP.test(g)) return false;
  return true;
}

export function isValidTarget(v: string): boolean {
  const s = (v ?? "").trim();
  if (!s) return false;
  if (STRICT_IPV4.test(s)) return true;
  if (isValidIPv6(s)) return true;
  return FQDN.test(s);
}
