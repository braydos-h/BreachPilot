/**
 * Self-check for browser-side target validation. Run with: ``node webui/src/lib/targetValidation.selfcheck.mjs``
 *
 * Keeps the regexes in ``targetValidation.ts`` honest by re-asserting the
 * same behavior here. If you change the regex in the .ts file, mirror it here.
 * Mirrors the backend's strict IPv4/FQDN behavior (tools/validation_utils.py).
 *
 * ponytail: one small self-check, no framework, no deps.
 */

// Keep these in sync with webui/src/lib/targetValidation.ts
const STRICT_IPV4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const FQDN = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;
const IPV6 = /^[0-9a-fA-F:]+$/;

function isValidTarget(v) {
  const s = (v ?? "").trim();
  if (!s) return false;
  if (STRICT_IPV4.test(s)) return true;
  if (IPV6.test(s) && s.includes(":")) return true;
  return FQDN.test(s);
}

const CASES = [
  ["127.0.0.1", true], ["10.0.0.50", true], ["192.168.1.1", true],
  ["0.0.0.0", true], ["255.255.255.255", true],
  ["999.999.999.999", false], ["256.1.1.1", false], ["1.2.3", false],
  ["1.2.3.4.5", false], ["1.2.3.999", false],
  ["::1", true], ["2001:db8::1", true],
  ["example.com", true], ["sub.example.com", true], ["lab.example.com", true],
  ["no-tld", false], ["", false], ["   ", false], ["not a target", false],
];

let failed = 0;
for (const [input, expected] of CASES) {
  const got = isValidTarget(input);
  if (got !== expected) {
    failed++;
    console.error(`FAIL isValidTarget(${JSON.stringify(input)}) => ${got}, expected ${expected}`);
  }
}
if (failed > 0) {
  console.error(`${failed} check(s) failed.`);
  process.exit(1);
}
console.log(`OK — ${CASES.length} target validation checks passed.`);