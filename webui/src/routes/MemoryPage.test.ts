import { describe, expect, it } from "vitest";
import {
  deriveMemoryOverview,
  filterAndSortAttackMemory,
  filterAndSortConfidence,
  filterAndSortLessons,
} from "@/routes/MemoryPage";
import type { AttackMemoryItem, MemoryConfidence, MemoryLesson } from "@/api/types";

function confidence(overrides: Partial<MemoryConfidence> = {}): MemoryConfidence {
  return {
    action_type: "recon_scan",
    observations: 10,
    successes: 7,
    failures: 2,
    partials: 1,
    confidence: 0.7,
    last_seen: "2026-08-20T12:00:00Z",
    ...overrides,
  };
}

function lesson(overrides: Partial<MemoryLesson> = {}): MemoryLesson {
  return {
    id: "l1",
    target_signature: "10.0.0.1:80",
    action_type: "exploit_http",
    outcome: "success",
    confidence: 0.9,
    created_at: "2026-08-20T12:00:00Z",
    metadata: {},
    ...overrides,
  };
}

function attackItem(overrides: Partial<AttackMemoryItem> = {}): AttackMemoryItem {
  return {
    id: "a1",
    session_id: "sess1",
    target_ip: "10.10.10.5",
    category: "credential",
    item_key: "username",
    item_value: "admin",
    source_tool: "nxc",
    success: true,
    metadata: {},
    first_seen_at: "2026-08-20T10:00:00Z",
    last_seen_at: "2026-08-20T12:00:00Z",
    seen_count: 1,
    ...overrides,
  };
}

describe("deriveMemoryOverview", () => {
  it("aggregates counts and unique targets", () => {
    const conf = [confidence({ observations: 5, confidence: 0.8 }), confidence({ action_type: "brute", observations: 10, confidence: 0.6 })];
    const lessons = [lesson(), lesson({ id: "l2" })];
    const attack = [
      attackItem({ id: "a1", target_ip: "10.0.0.1" }),
      attackItem({ id: "a2", target_ip: "10.0.0.1" }),
      attackItem({ id: "a3", target_ip: "10.0.0.2", category: "loot" }),
      attackItem({ id: "a4", target_ip: "" }),
    ];
    const ov = deriveMemoryOverview(conf, lessons, attack);
    expect(ov.learnedActions).toBe(2);
    expect(ov.observations).toBe(15);
    expect(ov.recordedLessons).toBe(2);
    expect(ov.attackFacts).toBe(4);
    expect(ov.knownTargets).toBe(2);
    expect(ov.avgConfidence).toBeCloseTo(70);
    // successes 7 +7 =14, obs 15 => 93.33
    expect(ov.weightedSuccessRate).toBeCloseTo(93.333, 1);
  });

  it("handles empty datasets with null averages", () => {
    const ov = deriveMemoryOverview([], [], []);
    expect(ov.learnedActions).toBe(0);
    expect(ov.observations).toBe(0);
    expect(ov.knownTargets).toBe(0);
    expect(ov.avgConfidence).toBeNull();
    expect(ov.weightedSuccessRate).toBeNull();
  });

  it("does not display misleading percentages when denominator zero", () => {
    const conf = [confidence({ observations: 0, successes: 0, confidence: 0 })];
    const ov = deriveMemoryOverview(conf, [], []);
    expect(ov.weightedSuccessRate).toBeNull();
    expect(ov.avgConfidence).toBe(0);
  });
});

describe("filterAndSortConfidence", () => {
  const items: MemoryConfidence[] = [
    confidence({ action_type: "recon_scan", observations: 12, confidence: 0.9, last_seen: "2026-08-22T12:00:00Z" }),
    confidence({ action_type: "brute_force", observations: 3, confidence: 0.2, last_seen: "2026-08-19T12:00:00Z" }),
    confidence({ action_type: "exploit_smb", observations: 8, confidence: 0.5, last_seen: "2026-08-21T12:00:00Z" }),
  ];

  it("filters by action_type case-insensitively", () => {
    expect(filterAndSortConfidence(items, "RECON", "confidence_desc", 0).map((c) => c.action_type)).toEqual([
      "recon_scan",
    ]);
    expect(filterAndSortConfidence(items, "force", "confidence_desc", 0).map((c) => c.action_type)).toEqual([
      "brute_force",
    ]);
  });

  it("filters by minimum observations", () => {
    const out = filterAndSortConfidence(items, "", "confidence_desc", 5);
    expect(out.map((c) => c.action_type)).toEqual(["recon_scan", "exploit_smb"]);
  });

  it("sorts confidence high to low", () => {
    const out = filterAndSortConfidence(items, "", "confidence_desc", 0);
    expect(out.map((c) => c.action_type)).toEqual(["recon_scan", "exploit_smb", "brute_force"]);
  });

  it("sorts confidence low to high", () => {
    const out = filterAndSortConfidence(items, "", "confidence_asc", 0);
    expect(out.map((c) => c.action_type)).toEqual(["brute_force", "exploit_smb", "recon_scan"]);
  });

  it("sorts by most observations", () => {
    const out = filterAndSortConfidence(items, "", "observations_desc", 0);
    expect(out.map((c) => c.action_type)).toEqual(["recon_scan", "exploit_smb", "brute_force"]);
  });

  it("sorts by most recent", () => {
    const out = filterAndSortConfidence(items, "", "recent", 0);
    expect(out.map((c) => c.action_type)).toEqual(["recon_scan", "exploit_smb", "brute_force"]);
  });

  it("sorts by name", () => {
    const out = filterAndSortConfidence(items, "", "name_asc", 0);
    expect(out.map((c) => c.action_type)).toEqual(["brute_force", "exploit_smb", "recon_scan"]);
  });

  it("does not mutate source array", () => {
    const original = [...items];
    filterAndSortConfidence(items, "", "confidence_desc", 0);
    expect(items.map((c) => c.action_type)).toEqual(original.map((c) => c.action_type));
  });

  it("clearing filters returns all items sorted", () => {
    const filtered = filterAndSortConfidence(items, "smb", "confidence_desc", 10);
    expect(filtered.length).toBe(0);
    const cleared = filterAndSortConfidence(items, "", "confidence_desc", 0);
    expect(cleared.length).toBe(3);
  });
});

describe("filterAndSortLessons", () => {
  const items: MemoryLesson[] = [
    lesson({ id: "1", action_type: "recon_scan", target_signature: "10.0.0.1", outcome: "success", created_at: "2026-08-22T12:00:00Z" }),
    lesson({ id: "2", action_type: "exploit_http", target_signature: "10.0.0.2", outcome: "failure", created_at: "2026-08-20T12:00:00Z" }),
    lesson({ id: "3", action_type: "brute_smb", target_signature: "corp.local", outcome: "partial", created_at: "2026-08-21T12:00:00Z" }),
    lesson({ id: "4", action_type: "recon_scan", target_signature: "10.0.0.3", outcome: "blocked", created_at: "2026-08-19T12:00:00Z" }),
  ];

  it("searches by action type", () => {
    const out = filterAndSortLessons(items, "recon", "all", "newest");
    expect(out.map((l) => l.id)).toEqual(["1", "4"]);
  });

  it("searches by target signature case-insensitively", () => {
    const out = filterAndSortLessons(items, "CORP.LOCAL", "all", "newest");
    expect(out.map((l) => l.id)).toEqual(["3"]);
  });

  it("filters outcome success", () => {
    expect(filterAndSortLessons(items, "", "success", "newest").map((l) => l.id)).toEqual(["1"]);
  });

  it("filters outcome failure", () => {
    expect(filterAndSortLessons(items, "", "failure", "newest").map((l) => l.id)).toEqual(["2"]);
  });

  it("filters partial/other includes non-success non-failure", () => {
    const out = filterAndSortLessons(items, "", "partial", "newest");
    expect(out.map((l) => l.id).sort()).toEqual(["3", "4"].sort());
  });

  it("sorts newest first", () => {
    expect(filterAndSortLessons(items, "", "all", "newest").map((l) => l.id)).toEqual(["1", "3", "2", "4"]);
  });

  it("sorts oldest first", () => {
    expect(filterAndSortLessons(items, "", "all", "oldest").map((l) => l.id)).toEqual(["4", "2", "3", "1"]);
  });

  it("sorts by action name", () => {
    const out = filterAndSortLessons(items, "", "all", "action");
    expect(out.map((l) => l.action_type)).toEqual(["brute_smb", "exploit_http", "recon_scan", "recon_scan"]);
  });

  it("does not mutate source array", () => {
    const original = [...items];
    filterAndSortLessons(items, "", "all", "newest");
    expect(items).toEqual(original);
  });
});

describe("filterAndSortAttackMemory", () => {
  const items: AttackMemoryItem[] = [
    attackItem({ id: "1", target_ip: "10.10.10.5", category: "credential", source_tool: "nxc", item_key: "username", item_value: "admin", success: true, last_seen_at: "2026-08-22T12:00:00Z", seen_count: 2 }),
    attackItem({ id: "2", target_ip: "10.10.10.6", category: "loot", source_tool: "mimikatz", item_key: "hash", item_value: "aad3b435", success: false, last_seen_at: "2026-08-20T12:00:00Z", seen_count: 5 }),
    attackItem({ id: "3", target_ip: "10.10.10.5", category: "credential", source_tool: "impacket", item_key: "password", item_value: "Secret123!", success: true, last_seen_at: "2026-08-21T12:00:00Z", seen_count: 1 }),
    attackItem({ id: "4", target_ip: "192.168.1.1", category: "service", source_tool: "nmap", item_key: "port", item_value: "445 open", success: false, last_seen_at: "2026-08-19T12:00:00Z", seen_count: 1 }),
  ];

  it("text search across target, category, source_tool, item_key, item_value case-insensitively", () => {
    expect(filterAndSortAttackMemory(items, "10.10.10.5", "", "", "all", "recent").map((m) => m.id)).toEqual(["1", "3"]);
    expect(filterAndSortAttackMemory(items, "CREDENTIAL", "", "", "all", "recent").map((m) => m.id).sort()).toEqual(["1", "3"]);
    expect(filterAndSortAttackMemory(items, "mimikatz", "", "", "all", "recent").map((m) => m.id)).toEqual(["2"]);
    expect(filterAndSortAttackMemory(items, "password", "", "", "all", "recent").map((m) => m.id)).toEqual(["3"]);
    expect(filterAndSortAttackMemory(items, "aad3b435", "", "", "all", "recent").map((m) => m.id)).toEqual(["2"]);
    expect(filterAndSortAttackMemory(items, "ADMIN", "", "", "all", "recent").map((m) => m.id)).toEqual(["1"]);
    expect(filterAndSortAttackMemory(items, "open", "", "", "all", "recent").map((m) => m.id)).toEqual(["4"]);
  });

  it("filters by target", () => {
    expect(filterAndSortAttackMemory(items, "", "10.10.10.5", "", "all", "recent").map((m) => m.id).sort()).toEqual(["1", "3"]);
  });

  it("filters by category", () => {
    expect(filterAndSortAttackMemory(items, "", "", "loot", "all", "recent").map((m) => m.id)).toEqual(["2"]);
  });

  it("filters by success and failure", () => {
    expect(filterAndSortAttackMemory(items, "", "", "", "success", "recent").map((m) => m.id).sort()).toEqual(["1", "3"]);
    expect(filterAndSortAttackMemory(items, "", "", "", "failure", "recent").map((m) => m.id).sort()).toEqual(["2", "4"]);
  });

  it("combines filters: target + result + search", () => {
    const out = filterAndSortAttackMemory(items, "admin", "10.10.10.5", "credential", "success", "recent");
    expect(out.map((m) => m.id)).toEqual(["1"]);
  });

  it("sorts most recently seen first", () => {
    expect(filterAndSortAttackMemory(items, "", "", "", "all", "recent").map((m) => m.id)).toEqual(["1", "3", "2", "4"]);
  });

  it("sorts most frequently seen first", () => {
    expect(filterAndSortAttackMemory(items, "", "", "", "all", "frequent").map((m) => m.id)).toEqual(["2", "1", "3", "4"]);
  });

  it("sorts by target", () => {
    expect(filterAndSortAttackMemory(items, "", "", "", "all", "target").map((m) => m.id)).toEqual(["1", "3", "2", "4"]);
  });

  it("sorts by category", () => {
    const out = filterAndSortAttackMemory(items, "", "", "", "all", "category");
    // categories alphabetical: credential, credential, loot, service => ids 1,3,2,4 (stable within same category sorted by target)
    expect(out.map((m) => m.category)).toEqual(["credential", "credential", "loot", "service"]);
  });

  it("does not mutate source array", () => {
    const original = [...items];
    filterAndSortAttackMemory(items, "", "", "", "all", "recent");
    expect(items).toEqual(original);
  });

  it("clearing filters returns all entries", () => {
    const filtered = filterAndSortAttackMemory(items, "nope", "10.10.10.99", "missing", "success", "recent");
    expect(filtered.length).toBe(0);
    const cleared = filterAndSortAttackMemory(items, "", "", "", "all", "recent");
    expect(cleared.length).toBe(4);
  });
});
