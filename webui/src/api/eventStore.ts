import type { RunEvent } from "@/api/types";

const MAX_EVENTS = 1000;
const MAX_RUNS = 10;

interface Entry {
  events: RunEvent[];
  cursor: number;
}

/**
 * Session-only LRU cache of per-run events. Pure in-memory (no React, no
 * localStorage/IndexedDB) so revisiting a run can resume its live stream from
 * the last seen cursor instead of replaying from zero.
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

  set(runId: string, events: RunEvent[], cursor: number): void {
    const trimmed =
      events.length > MAX_EVENTS ? events.slice(events.length - MAX_EVENTS) : events;
    this.runs.delete(runId);
    this.runs.set(runId, { events: trimmed, cursor });
    this.evict();
  }

  append(runId: string, event: RunEvent): void {
    const entry = this.runs.get(runId);
    if (!entry) {
      this.runs.set(runId, { events: [event], cursor: event.sequence });
      this.evict();
      return;
    }
    if (event.sequence <= entry.cursor) return;
    entry.cursor = event.sequence;
    // Immutable append so a caller holding the previous array (e.g. React
    // state) is never mutated in place.
    entry.events =
      entry.events.length >= MAX_EVENTS
        ? [...entry.events.slice(entry.events.length - MAX_EVENTS + 1), event]
        : [...entry.events, event];
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
