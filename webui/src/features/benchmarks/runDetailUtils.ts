import { isActiveState } from "@/features/benchmarks/format";
import type { BenchmarkEvent, Trial } from "@/features/benchmarks/types";

export const REFRESH_MS = 2000;

/** Cap on cached timeline events per run page (rendering caps far lower —
 * without this a multi-hour run accumulates unbounded arrays in query cache). */
export const MAX_CACHED_EVENTS = 2000;

export function isRunActive(status: string): boolean {
  return isActiveState(status);
}

/** Fill live-trial payload gaps so tabs can dereference Trial fields safely.
 * The scenarios endpoint returns full trial dicts today, but a slimmer shape
 * (or a missing field) must degrade to blanks, never throw mid-render. */
export function normalizeTrial(t: Trial): Trial {
  return {
    ...t,
    ended_at: t.ended_at ?? "",
    failure_category: (t.failure_category ?? "UNKNOWN") as Trial["failure_category"],
    failure_detail: t.failure_detail ?? "",
    claimed_summary: t.claimed_summary ?? "",
    flags: Array.isArray(t.flags) ? t.flags : [],
    evidence_refs: Array.isArray(t.evidence_refs) ? t.evidence_refs : [],
    audit_path: t.audit_path ?? "",
    workspace: t.workspace ?? "",
    errors: Array.isArray(t.errors) ? t.errors : [],
    tool_calls: t.tool_calls ?? 0,
    total_tokens: t.total_tokens ?? 0,
    duration_seconds: t.duration_seconds ?? 0,
    flags_captured: t.flags_captured ?? 0,
    flags_total: t.flags_total ?? 0,
    sandbox: t.sandbox ?? {
      enabled: false,
      required: false,
      image: "unknown",
      image_digest: "unknown",
      container_id: "",
      network_policy_fingerprint: "",
      authorized_destinations: [],
      blocked_events: 0,
      failures: 0,
      last_error: "",
    },
    target: t.target ?? {
      host: "",
      ports: [],
      image: "unknown",
      image_digest: "unknown",
      container_id: "",
      snapshot_id: "",
      reset_strategy: "recreate",
    },
    telemetry: t.telemetry ?? {
      model_calls: 0,
      total_tokens: 0,
      prompt_tokens: 0,
      completion_tokens: 0,
      estimated_cost: null,
      tool_calls: 0,
      tool_errors: 0,
      sandbox_blocked_actions: 0,
    },
  };
}

/** Merge event pages: dedup by sequence, sort ascending, cap the cache.
 * Server pages can overlap or arrive out of order — render order and elapsed
 * time must never depend on fetch order. */
export function mergeEvents(existing: BenchmarkEvent[], incoming: BenchmarkEvent[]): BenchmarkEvent[] {
  const seen = new Set<number>();
  const merged: BenchmarkEvent[] = [];
  for (const e of [...existing, ...incoming]) {
    if (e == null || typeof e.sequence !== "number" || seen.has(e.sequence)) continue;
    seen.add(e.sequence);
    merged.push(e);
  }
  merged.sort((a, b) => a.sequence - b.sequence);
  if (merged.length > MAX_CACHED_EVENTS) return merged.slice(merged.length - MAX_CACHED_EVENTS);
  return merged;
}

export interface BenchmarkPhase {
  label: string;
  state: "done" | "running" | "pending";
}

export function derivePhases(trial: Trial | undefined, runningHint = false): BenchmarkPhase[] {
  if (!trial) {
    // A live run with no finished trial row yet is mid-exploit, not idle.
    if (runningHint) {
      return [
        { label: "Provision", state: "done" },
        { label: "Exploit", state: "running" },
        { label: "Verify", state: "pending" },
      ];
    }
    return [
      { label: "Provision", state: "pending" },
      { label: "Exploit", state: "pending" },
      { label: "Verify", state: "pending" },
    ];
  }
  // One falsy check everywhere (matches the active-trial finder): a live or
  // field-missing trial is never "done".
  const done = !!trial.ended_at;
  return [
    { label: "Provision", state: "done" },
    { label: "Exploit", state: done ? "done" : "running" },
    { label: "Verify", state: done ? "done" : "pending" },
  ];
}
