// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { isDemoRun, DEMO_RUN_ID } from "@/api/types";

describe("isDemoRun", () => {
  it("identifies demo via is_demo flag", () => {
    expect(isDemoRun({ id: "other", is_demo: true })).toBe(true);
  });

  it("identifies demo via id fallback", () => {
    expect(isDemoRun({ id: DEMO_RUN_ID })).toBe(true);
  });

  it("rejects non-demo", () => {
    expect(isDemoRun({ id: "real-123", is_demo: false })).toBe(false);
    expect(isDemoRun({ id: "real-123" })).toBe(false);
    expect(isDemoRun(null)).toBe(false);
  });
});
