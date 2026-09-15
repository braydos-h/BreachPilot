// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { PRODUCT_ROUTES, RUN_SATELLITE_ROUTES } from "@/lib/productRoutes";
import { autoAnswerFor } from "@/lib/permissionMode";
import type { DecisionListRow } from "@/api/types";

// Consistency gates (todo 21): fail CI on nav/help/docs drift.
describe("product registry consistency", () => {
  it("every top-level route has a help entry", () => {
    for (const r of PRODUCT_ROUTES) {
      expect(r.helpId, `route ${r.path} missing helpId`).toBeTruthy();
      expect(r.helpTitle, `route ${r.path} missing helpTitle`).toBeTruthy();
    }
  });

  it("wizard steps are reachable: target -> intent -> review", async () => {
    const { STEPS } = await import("@/components/run-create/RunStepper");
    expect([...STEPS]).toEqual(["target", "intent", "review"]);
  });

  it("permission copy matches autoAnswerFor behavior (todo 07)", async () => {
    const { APPROVAL_POLICY_DESCRIPTIONS } = await import("@/lib/terminology");
    const goalSelect = { kind: "goal_select", status: "pending" } as DecisionListRow;
    const campaign = { kind: "campaign_next_step", status: "pending" } as DecisionListRow;
    const destructive = { kind: "tool_approval", status: "pending", required_text: "YES" } as DecisionListRow;
    // Goals + campaign checkpoints never auto-answer, even in full_access.
    expect(autoAnswerFor(goalSelect, "full_access")).toBeNull();
    expect(autoAnswerFor(campaign, "full_access")).toBeNull();
    // Destructive waits in approve, auto-submits in full_access.
    expect(autoAnswerFor(destructive, "approve")).toBeNull();
    expect(autoAnswerFor(destructive, "full_access")).toBe("YES");
    // Copy must state goals/campaign still wait.
    expect(APPROVAL_POLICY_DESCRIPTIONS.full_access).toMatch(/Goals and campaign checkpoints still wait/i);
  });

  it("satellite run routes preserve back-to-run context", () => {
    expect(RUN_SATELLITE_ROUTES.length).toBeGreaterThan(0);
    for (const r of RUN_SATELLITE_ROUTES) {
      expect(r.helpId).toBeTruthy();
    }
  });

  it("no user-visible Session(s) in sidebar labels", () => {
    for (const r of PRODUCT_ROUTES) {
      expect(r.label).not.toMatch(/session/i);
    }
  });
});
