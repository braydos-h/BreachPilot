import { describe, expect, it } from "vitest";
import {
  AGGRESSION_LEVELS,
  CAMPAIGN_PHASES,
  aggressionIndex,
  aggressionVariant,
  isKnownPhase,
  phaseIndex,
} from "@/lib/campaignPhases";

describe("campaignPhases", () => {
  it("lists the 8 backend AttackPhase values in execution order", () => {
    expect(CAMPAIGN_PHASES).toEqual([
      "recon",
      "enumeration",
      "exploit",
      "privesc",
      "lateral",
      "persistence",
      "validation",
      "report",
    ]);
    expect(AGGRESSION_LEVELS).toEqual(["stealth", "normal", "aggressive", "maximum"]);
  });

  it("indexes known phases and returns -1 for unknown values", () => {
    expect(phaseIndex("recon")).toBe(0);
    expect(phaseIndex("report")).toBe(7);
    // run_campaign_step writes "done" when the campaign finishes — the UI must
    // degrade, not crash.
    expect(phaseIndex("done")).toBe(-1);
    expect(phaseIndex("definitely-not-a-phase")).toBe(-1);
    expect(phaseIndex("")).toBe(-1);
  });

  it("isKnownPhase mirrors phaseIndex", () => {
    expect(isKnownPhase("exploit")).toBe(true);
    expect(isKnownPhase("done")).toBe(false);
  });

  it("aggressionIndex ranks tiers and rejects unknown levels", () => {
    expect(aggressionIndex("stealth")).toBe(0);
    expect(aggressionIndex("maximum")).toBe(3);
    expect(aggressionIndex("apocalyptic")).toBe(-1);
  });

  it("aggressionVariant maps every tier plus a junk fallback", () => {
    expect(aggressionVariant("stealth")).toBe("muted");
    expect(aggressionVariant("normal")).toBe("info");
    expect(aggressionVariant("aggressive")).toBe("warn");
    expect(aggressionVariant("maximum")).toBe("danger");
    expect(aggressionVariant("bogus")).toBe("outline");
  });
});