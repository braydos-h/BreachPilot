import type { RunEvent } from "@/api/types";

/** Shared cap for every live-event collection (UI state + eventStore). */
export const MAX_EVENTS_PER_RUN = 1000;

export interface AppendResult {
  /** New chronological array (ascending sequence), trimmed to MAX_EVENTS_PER_RUN. */
  events: RunEvent[];
  /** How many events fell off the front of the window this append. */
  dropped: number;
}

/**
 * Append a batch to a bounded chronological window. Never mutates the input;
 * avoids copying the front of the window when only the head needs trimming.
 * ``dropped`` counts events that aged out of THIS window (they still exist
 * server-side — the UI must not claim they were deleted).
 */
export function appendBounded(prev: RunEvent[], batch: RunEvent[]): AppendResult {
  if (batch.length === 0) return { events: prev, dropped: 0 };
  const over = prev.length + batch.length - MAX_EVENTS_PER_RUN;
  if (over <= 0) return { events: [...prev, ...batch], dropped: 0 };
  const events =
    batch.length >= MAX_EVENTS_PER_RUN
      ? batch.slice(-MAX_EVENTS_PER_RUN)
      : prev.slice(over).concat(batch);
  return { events, dropped: over };
}
