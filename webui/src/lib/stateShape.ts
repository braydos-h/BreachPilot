// Defensive accessors for untrusted JSON state (swarm/campaign state files).
// The backend writes these files, but they can be missing fields, malformed,
// or hold unexpected types — these helpers coerce to safe shapes so the
// orchestration views never throw on a bad value.

export type Json = Record<string, unknown>;

export function asRecord(v: unknown): Json {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Json) : {};
}

export function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

export function str(v: unknown): string {
  return v == null ? "" : String(v);
}

export function num(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

export function bool(v: unknown): boolean {
  return v === true || v === "true" || v === 1;
}

export function json(v: unknown): string {
  try {
    return typeof v === "string" ? v : JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}
