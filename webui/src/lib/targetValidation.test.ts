import { describe, expect, it } from "vitest";
import { isValidTarget } from "./targetValidation";

describe("isValidTarget", () => {
  // Valid IPv4 — mirrors backend _STRICT_IPV4_RE
  it.each(["127.0.0.1", "10.0.0.50", "192.168.1.1", "0.0.0.0", "255.255.255.255"])(
    "accepts IPv4 %s",
    (v) => {
      expect(isValidTarget(v)).toBe(true);
    },
  );

  it.each([
    "999.999.999.999",
    "256.1.1.1",
    "1.2.3",
    "1.2.3.4.5",
    "1.2.3.999",
    "01.02.03.04.05",
    "1.2.3.",
  ])("rejects invalid IPv4 %s", (v) => {
    expect(isValidTarget(v)).toBe(false);
  });

  // Required valid IPv6 (compressed and uncompressed)
  it.each(["::1", "2001:db8::1", "fe80::1", "2001:db8:0:0:0:0:2:1"])(
    "accepts valid IPv6 %s",
    (v) => {
      expect(isValidTarget(v)).toBe(true);
    },
  );

  // Additional valid IPv6 that should still pass (backend parity)
  it.each([
    "::",
    "2001:db8::",
    "::ffff:192.0.2.1",
    "1:2:3:4:5:6:7:8",
    "0:0:0:0:0:0:0:1",
    "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
    "2001:db8:85a3::8a2e:370:7334",
    // trimmed input should also be valid
    "  ::1  ",
  ])("accepts additional valid IPv6 %s", (v) => {
    expect(isValidTarget(v)).toBe(true);
  });

  // Required invalid IPv6 (regression cases)
  it.each([":", ":::", "1:2:3:4:5:6:7:8:9", "gggg::1", "2001::db8::1"])(
    "rejects invalid IPv6 %s",
    (v) => {
      expect(isValidTarget(v)).toBe(false);
    },
  );

  // Additional invalid IPv6 regressions
  it.each([
    "",
    "   ",
    ":::",
    "2001:db8:::1",
    "1::2::3",
    "1:2:3:4:5:6:7:8:9",
    "::ffff:999.0.0.1",
    "12345::1",
    "1:2:3:4:5:6::8:9", // would expand to more than 8 groups
    "2001:db8:1:2:3:4:5:6:7:8", // 9 groups without ::
  ])("rejects additional invalid IPv6 %s", (v) => {
    expect(isValidTarget(v)).toBe(false);
  });

  // Empty / whitespace
  it.each(["", "   ", "\t\n"])("rejects empty/whitespace %s", (v) => {
    expect(isValidTarget(v)).toBe(false);
  });

  // Valid FQDN — mirrors backend _FQDN_RE (TLD >=2 alpha, labels)
  it.each(["example.com", "sub.example.com", "lab.example.com", "a-b.example.co.uk"])(
    "accepts FQDN %s",
    (v) => {
      expect(isValidTarget(v)).toBe(true);
    },
  );

  // Invalid FQDN / hostname
  it.each([
    "no-tld",
    "kali",
    "example",
    "not a target",
    "example.c",
    "-bad.example.com",
  ])("rejects invalid domain %s", (v) => {
    expect(isValidTarget(v)).toBe(false);
  });

  // Null / undefined safety (function accepts string, but guard handles)
  it("rejects nullish input", () => {
    expect(isValidTarget(null as unknown as string)).toBe(false);
    expect(isValidTarget(undefined as unknown as string)).toBe(false);
  });

  // Ensure the four required accepts and six required rejects in one sweep
  it("matches backend for the 10 mandated cases", () => {
    const accepts = ["::1", "2001:db8::1", "fe80::1", "2001:db8:0:0:0:0:2:1"];
    const rejects = [":", ":::", "1:2:3:4:5:6:7:8:9", "gggg::1", "2001::db8::1", ""];
    for (const v of accepts) expect(isValidTarget(v)).toBe(true);
    for (const v of rejects) expect(isValidTarget(v)).toBe(false);
    expect(isValidTarget("   ")).toBe(false);
  });
});
