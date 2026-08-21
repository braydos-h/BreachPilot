import type { RunEvent } from "@/api/types";
import { appendBounded } from "@/api/eventBuffer";

const MAX_RUNS = 10;

interface Entry {
  events: RunEvent[];
  cursor: number;
  /** Events omitted from this window this session (older than the cap). */
  dropped: number;
}

/**
 * Session-only LRU cache of per-run events. Pure in-memory (no React, no
 * localStorage/IndexedDB) so revisiting a run can resume its live stream from
 * the last seen cursor instead of replaying from zero. Shares the same
 * MAX_EVENTS_PER_RUN bound as the live UI state via appendBounded.
 */
class EventStore {
  private runs = new Map<string, Entry>();

  get(runId: string): Entry | undefined {
    const entry = this.runs.get(runId);
    if (!entry) return undefined;
    // Re-insert to mark as most-recently-used (LRU order).
    this.runs.delete(runId);
    this.runs.set(runId, entry);
    return entry;
  }

  set(runId: string, events: RunEvent[], cursor: number, dropped = 0): void {
    const trimmed = appendBounded([], events);
    this.runs.delete(runId);
    this.runs.set(runId, { events: trimmed.events, cursor, dropped });
    this.evict();
  }

  append(runId: string, event: RunEvent): void {
    const entry = this.runs.get(runId);
    if (!entry) {
      this.runs.set(runId, { events: [event], cursor: event.sequence, dropped: 0 });
      this.evict();
      return;
    }
    if (event.sequence <= entry.cursor) return;
    entry.cursor = event.sequence;
    // Immutable append so a caller holding the previous array (e.g. React
    // state) is never mutated in place.
    const result = appendBounded(entry.events, [event]);
    entry.events = result.events;
    entry.dropped += result.dropped;
    this.runs.delete(runId);
    this.runs.set(runId, entry);
  }

  cursor(runId: string): number {
    return this.runs.get(runId)?.cursor ?? 0;
  }

  clear(runId: string): void {
    this.runs.delete(runId);
  }

  private evict(): void {
    while (this.runs.size > MAX_RUNS) {
      const oldest = this.runs.keys().next().value;
      if (oldest === undefined) break;
      this.runs.delete(oldest);
    }
  }
}

export const eventStore = new EventStore();
