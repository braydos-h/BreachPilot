import { ApiError } from "@/api/client";
import type { AttackMemoryItem, MemoryConfidence, MemoryLesson } from "@/api/types";

export type ConfidenceSort =
  | "confidence_desc"
  | "confidence_asc"
  | "observations_desc"
  | "recent"
  | "name_asc";
export type LessonOutcomeFilter = "all" | "success" | "failure" | "partial";
export type LessonSort = "newest" | "oldest" | "action";
export type AttackResultFilter = "all" | "success" | "failure";
export type AttackSort = "recent" | "frequent" | "target" | "category";

export interface MemoryOverview {
  learnedActions: number;
  observations: number;
  recordedLessons: number;
  attackFacts: number;
  knownTargets: number;
  avgConfidence: number | null;
  weightedSuccessRate: number | null;
}

function timestampMs(value?: string): number {
  if (!value) return Number.NEGATIVE_INFINITY;
  const t = Date.parse(value);
  return Number.isNaN(t) ? Number.NEGATIVE_INFINITY : t;
}

export function formatMemoryPercent(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) return "—";
  return `${Math.round(value)}%`;
}

export function deriveMemoryOverview(
  confidence: MemoryConfidence[],
  lessons: MemoryLesson[],
  attackMemory: AttackMemoryItem[],
): MemoryOverview {
  const learnedActions = confidence.length;
  const observations = confidence.reduce((acc, c) => acc + (Number.isFinite(c.observations) ? c.observations : 0), 0);
  const recordedLessons = lessons.length;
  const attackFacts = attackMemory.length;
  const knownTargets = new Set(attackMemory.map((m) => m.target_ip).filter(Boolean)).size;
  const avgConfidence =
    confidence.length > 0
      ? confidence.reduce((acc, c) => acc + (Number.isFinite(c.confidence) ? c.confidence : 0), 0) / confidence.length
      : null;
  const totalSuccesses = confidence.reduce((acc, c) => acc + (Number.isFinite(c.successes) ? c.successes : 0), 0);
  const weightedSuccessRate = observations > 0 ? (totalSuccesses / observations) * 100 : null;
  return {
    learnedActions,
    observations,
    recordedLessons,
    attackFacts,
    knownTargets,
    avgConfidence: avgConfidence != null && Number.isFinite(avgConfidence) ? avgConfidence * 100 : null,
    weightedSuccessRate,
  };
}

export function filterAndSortConfidence(
  items: MemoryConfidence[],
  query: string,
  sortKey: ConfidenceSort,
  minObservations: number,
): MemoryConfidence[] {
  const q = query.trim().toLowerCase();
  let out = items;
  if (q) out = out.filter((c) => c.action_type.toLowerCase().includes(q));
  if (minObservations > 0) out = out.filter((c) => c.observations >= minObservations);
  const cloned = [...out];
  switch (sortKey) {
    case "confidence_desc":
      cloned.sort((a, b) => b.confidence - a.confidence || b.observations - a.observations);
      break;
    case "confidence_asc":
      cloned.sort((a, b) => a.confidence - b.confidence || a.observations - b.observations);
      break;
    case "observations_desc":
      cloned.sort((a, b) => b.observations - a.observations || b.confidence - a.confidence);
      break;
    case "recent":
      cloned.sort((a, b) => timestampMs(b.last_seen) - timestampMs(a.last_seen));
      break;
    case "name_asc":
      cloned.sort((a, b) => a.action_type.localeCompare(b.action_type));
      break;
  }
  return cloned;
}

export function filterAndSortLessons(
  items: MemoryLesson[],
  query: string,
  outcome: LessonOutcomeFilter,
  sortKey: LessonSort,
): MemoryLesson[] {
  const q = query.trim().toLowerCase();
  let out = items;
  if (q) {
    out = out.filter(
      (l) =>
        l.action_type.toLowerCase().includes(q) ||
        (l.target_signature ?? "").toLowerCase().includes(q),
    );
  }
  if (outcome !== "all") {
    out = out.filter((l) => {
      const o = (l.outcome ?? "").toLowerCase();
      if (outcome === "success") return o === "success";
      if (outcome === "failure") return o === "failure";
      // partial/other = everything not success/failure
      return o !== "success" && o !== "failure";
    });
  }
  const cloned = [...out];
  switch (sortKey) {
    case "newest":
      cloned.sort((a, b) => timestampMs(b.created_at) - timestampMs(a.created_at));
      break;
    case "oldest":
      cloned.sort((a, b) => timestampMs(a.created_at) - timestampMs(b.created_at));
      break;
    case "action":
      cloned.sort((a, b) => a.action_type.localeCompare(b.action_type));
      break;
  }
  return cloned;
}

export function filterAndSortAttackMemory(
  items: AttackMemoryItem[],
  query: string,
  targetFilter: string,
  categoryFilter: string,
  resultFilter: AttackResultFilter,
  sortKey: AttackSort,
): AttackMemoryItem[] {
  const q = query.trim().toLowerCase();
  let out = items;
  if (targetFilter) out = out.filter((m) => m.target_ip === targetFilter);
  if (categoryFilter) out = out.filter((m) => m.category === categoryFilter);
  if (resultFilter !== "all") {
    out = out.filter((m) => (resultFilter === "success" ? m.success : !m.success));
  }
  if (q) {
    out = out.filter((m) => {
      const hay = [m.target_ip, m.category, m.source_tool, m.item_key, m.item_value]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }
  const cloned = [...out];
  switch (sortKey) {
    case "recent":
      cloned.sort((a, b) => timestampMs(b.last_seen_at) - timestampMs(a.last_seen_at));
      break;
    case "frequent":
      cloned.sort((a, b) => b.seen_count - a.seen_count || timestampMs(b.last_seen_at) - timestampMs(a.last_seen_at));
      break;
    case "target":
      cloned.sort((a, b) => (a.target_ip ?? "").localeCompare(b.target_ip ?? "") || (a.category ?? "").localeCompare(b.category ?? ""));
      break;
    case "category":
      cloned.sort((a, b) => (a.category ?? "").localeCompare(b.category ?? "") || (a.target_ip ?? "").localeCompare(b.target_ip ?? ""));
      break;
  }
  return cloned;
}

export function formatMemoryError(error: unknown, fallback: string): string {
  if (error instanceof ApiError && error.message) return error.message;
  if (error instanceof Error && error.message) return error.message;
  return fallback;
}
