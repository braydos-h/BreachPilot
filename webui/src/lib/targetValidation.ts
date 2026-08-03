/**
 * Browser-side target validation. Mirrors the backend's strict syntax checks
 * in ``tools/validation_utils.py`` (``_STRICT_IPV4_RE`` / ``_FQDN_RE``) so the
 * UI rejects the same invalid forms the API does, without adding a dependency.
 *
 * Kept dependency-free and framework-agnostic so it can be unit-checked in
 * isolation (see ``targetValidation.selfcheck.ts``).
 */

// Strict IPv4: four octets 0-255 separated by dots, anchored.
const STRICT_IPV4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

// FQDN: dot-separated labels (RFC1035 length bounds), TLD >= 2 alphabetic chars.
const FQDN = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;

// IPv6: hex groups with at least one colon (loose structural check — the
// backend uses ipaddress.ip_address for the authoritative parse).
const IPV6 = /^[0-9a-fA-F:]+$/;

export function isValidTarget(v: string): boolean {
  const s = (v ?? "").trim();
  if (!s) return false;
  if (STRICT_IPV4.test(s)) return true;
  if (IPV6.test(s) && s.includes(":")) return true;
  return FQDN.test(s);
}