// Unified status vocabulary (todo 44) + transport separation (todo 36).
// One status system shared by runs, connections, benchmarks, transport.

export const RUN_STATUS_LABELS = {
  running: "Running",
  waiting: "Waiting for you",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
  preparing: "Preparing",
  queued: "Queued",
  inconclusive: "Inconclusive",
} as const;

export const TRANSPORT_LABELS = {
  live: "Live updates connected",
  connecting: "Connecting live updates…",
  reconnecting: "Reconnecting live updates…",
  offline: "Live updates disconnected",
  stale: "Live updates stale",
  error: "Live updates error",
} as const;

export type StatusTone = "success" | "warn" | "danger" | "info" | "muted";

export function runStateTone(state: string | undefined): StatusTone {
  switch (state) {
    case "running":
    case "queued":
    case "preparing":
      return "info";
    case "completed":
      return "success";
    case "failed":
      return "danger";
    case "cancelled":
    case "interrupted":
      return "muted";
    default:
      return "muted";
  }
}

export function waitingTone(): StatusTone {
  return "warn";
}

/** Humanize a raw run/connection state for primary UI (todo 44). */
export function humanizeStatus(state: string | undefined | null): string {
  if (!state) return "Unknown";
  const s = String(state).toLowerCase();
  if (s in RUN_STATUS_LABELS) return RUN_STATUS_LABELS[s as keyof typeof RUN_STATUS_LABELS];
  if (s === "active") return "Running";
  if (s === "stale") return "Stale";
  if (s === "disconnected" || s === "offline" || s === "closed") return "Disconnected";
  if (s === "error") return "Failed";
  // Fallback: Title Case snake_case instead of leaking raw enums.
  return s
    .split("_")
    .map((w) => (w ? `${w[0]?.toUpperCase()}${w.slice(1)}` : w))
    .join(" ");
}
