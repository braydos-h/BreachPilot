import { describe, expect, it } from "vitest";
import {
  checkpointVisual,
  detectCheckpointKind,
  parseCheckpointOptions,
  encodeCheckpointAnswer,
  toSuggestedGoal,
} from "@/lib/campaignCheckpoint";

describe("checkpointVisual", () => {
  it("renders access as green ('Verified access obtained')", () => {
    const v = checkpointVisual("access");
    expect(v.title).toBe("Verified access obtained");
    expect(v.borderClass).toContain("emerald");
    expect(v.badgeClass).toContain("emerald");
  });

  it("renders no_path as amber ('No verified access yet')", () => {
    const v = checkpointVisual("no_path");
    expect(v.title).toBe("No verified access yet");
    expect(v.borderClass).toContain("amber");
    expect(v.badgeClass).toContain("amber");
  });
});

describe("detectCheckpointKind", () => {
  it("detects 'access' from the VERIFIED ACCESS OBTAINED marker", () => {
    expect(detectCheckpointKind("VERIFIED ACCESS OBTAINED\nTarget: 10.0.0.50")).toBe("access");
  });

  it("detects 'no_path' from the NO VERIFIED ACCESS YET marker", () => {
    expect(detectCheckpointKind("NO VERIFIED ACCESS YET\nTarget: 10.0.0.50")).toBe("no_path");
  });

  it("defaults to no_path (the safer default) on unknown/empty markers", () => {
    expect(detectCheckpointKind("")).toBe("no_path");
    expect(detectCheckpointKind(undefined)).toBe("no_path");
    expect(detectCheckpointKind("something else entirely")).toBe("no_path");
  });
});

describe("parseCheckpointOptions", () => {
  it("parses typed options from raw JSON", () => {
    const opts = parseCheckpointOptions([
      { action: "privesc", label: "Escalate privileges" },
      { action: "another_goal", label: "Continue with another goal", goals: [{ name: "backdoor", description: "d1" }, { name: "custom", description: "Type your own goal" }] },
      { action: "finish", label: "Finish" },
      { action: "cancel", label: "Cancel" },
    ]);
    expect(opts).toHaveLength(4);
    expect(opts[0]).toEqual({ action: "privesc", label: "Escalate privileges", goals: undefined });
    expect(opts[1].goals).toEqual([{ name: "backdoor", description: "d1" }, { name: "custom", description: "Type your own goal" }]);
  });

  it("drops malformed/empty rows", () => {
    const opts = parseCheckpointOptions([
      { label: "no action" },
      { action: "", label: "empty action" },
      { action: "finish", label: "Finish" },
      null,
      "not-an-object",
    ]);
    expect(opts).toHaveLength(1);
    expect(opts[0].action).toBe("finish");
  });

  it("filters nested goals without a name", () => {
    const opts = parseCheckpointOptions([
      { action: "change_goal", label: "x", goals: [{ name: "ok", description: "d" }, { description: "no name" }] },
    ]);
    expect(opts[0].goals).toEqual([{ name: "ok", description: "d" }]);
  });

  it("returns [] on non-array input", () => {
    expect(parseCheckpointOptions(undefined)).toEqual([]);
    expect(parseCheckpointOptions(null)).toEqual([]);
    expect(parseCheckpointOptions({})).toEqual([]);
  });
});

describe("encodeCheckpointAnswer", () => {
  it("encodes a plain action as '<action>'", () => {
    expect(encodeCheckpointAnswer({ action: "finish", label: "Finish" })).toBe("finish");
    expect(encodeCheckpointAnswer({ action: "cancel", label: "Cancel" })).toBe("cancel");
  });

  it("encodes an action + goal pick as '<action>:<goalName>'", () => {
    const opt = { action: "change_goal", label: "x", goals: [{ name: "backdoor", description: "d" }] };
    expect(encodeCheckpointAnswer(opt, "backdoor")).toBe("change_goal:backdoor");
  });

  it("encodes an action + custom goal as '<action>:custom:<text>'", () => {
    const opt = { action: "another_goal", label: "x", goals: [{ name: "custom", description: "Type your own" }] };
    expect(encodeCheckpointAnswer(opt, "custom", "dump hashes")).toBe("another_goal:custom:dump hashes");
  });

  it("returns '' when a goal-bearing option has no goal selected", () => {
    const opt = { action: "change_goal", label: "x", goals: [{ name: "backdoor", description: "d" }] };
    expect(encodeCheckpointAnswer(opt)).toBe("");
  });

  it("returns '' for an empty action", () => {
    expect(encodeCheckpointAnswer({ action: "", label: "x" })).toBe("");
  });
});

describe("toSuggestedGoal", () => {
  it("coerces a minimal {name, description} into the SuggestedGoal shape", () => {
    const g = toSuggestedGoal({ name: "backdoor", description: "plant a backdoor" });
    expect(g.name).toBe("backdoor");
    expect(g.description).toBe("plant a backdoor");
    expect(g.compatible).toBe(true);
    expect(g.is_ai_generated).toBe(false);
    expect(g.success_rating).toBe(0);
  });
});