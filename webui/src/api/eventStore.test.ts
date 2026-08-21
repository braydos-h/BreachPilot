import { beforeEach, describe, expect, it } from "vitest";
import { eventStore } from "@/api/eventStore";
import type { RunEvent } from "@/api/types";

// The store is a module singleton with no clearAll(), so each test uses unique
// run ids and clears them in beforeEach to keep tests isolated.
const created: string[] = [];

function rid(prefix = "run"): string {
  const id = `${prefix}-${created.length}-${Math.random().toString(36).slice(2, 8)}`;
  created.push(id);
  return id;
}

function ev(sequence: number, runId: string, type: RunEvent["type"] = "state"): RunEvent {
  return {
    sequence,
    timestamp: new Date(sequence * 1000).toISOString(),
    run_id: runId,
    type,
    payload: {},
  };
}

beforeEach(() => {
  for (const id of created) eventStore.clear(id);
  created.length = 0;
});

describe("eventStore", () => {
  it("preserves event ordering across set and append", () => {
    const id = rid();
    eventStore.set(id, [ev(1, id), ev(2, id), ev(3, id)], 3);
    eventStore.append(id, ev(4, id));
    const entry = eventStore.get(id);
    expect(entry?.events.map((e) => e.sequence)).toEqual([1, 2, 3, 4]);
  });

  it("suppresses duplicates with sequence <= cursor", () => {
    const id = rid();
    eventStore.set(id, [ev(1, id), ev(2, id)], 2);
    eventStore.append(id, ev(2, id)); // duplicate
    eventStore.append(id, ev(1, id)); // stale
    eventStore.append(id, ev(3, id)); // new
    const entry = eventStore.get(id);
    expect(entry?.events.map((e) => e.sequence)).toEqual([1, 2, 3]);
    expect(entry?.cursor).toBe(3);
  });

  it("replays cursor for resume", () => {
    const id = rid();
    expect(eventStore.cursor(id)).toBe(0);
    eventStore.set(id, [ev(1, id), ev(2, id)], 2);
    expect(eventStore.cursor(id)).toBe(2);
    eventStore.append(id, ev(3, id));
    expect(eventStore.cursor(id)).toBe(3);
  });

  it("bounds history to 1000 events on set", () => {
    const id = rid();
    const events = Array.from({ length: 1500 }, (_, i) => ev(i + 1, id));
    eventStore.set(id, events, 1500);
    const entry = eventStore.get(id);
    expect(entry?.events.length).toBe(1000);
    expect(entry?.events[0].sequence).toBe(501);
    expect(entry?.events[999].sequence).toBe(1500);
  });

  it("bounds history to 1000 events on append", () => {
    const id = rid();
    eventStore.set(id, Array.from({ length: 1000 }, (_, i) => ev(i + 1, id)), 1000);
    eventStore.append(id, ev(1001, id));
    const entry = eventStore.get(id);
    expect(entry?.events.length).toBe(1000);
    expect(entry?.events[0].sequence).toBe(2);
    expect(entry?.events[999].sequence).toBe(1001);
  });

  it("evicts the oldest run when an 11th run is added", () => {
    const ids = Array.from({ length: 11 }, () => rid("lru"));
    ids.forEach((id) => eventStore.set(id, [ev(1, id)], 1));
    expect(eventStore.get(ids[0])).toBeUndefined();
    expect(eventStore.get(ids[10])).toBeDefined();
  });

  it("transitions from a seeded tail to live appends without gaps or dupes", () => {
    const id = rid();
    // Seed the tail (most recent page) with cursor 5.
    eventStore.set(id, [ev(3, id), ev(4, id), ev(5, id)], 5);
    // Live events stream in.
    eventStore.append(id, ev(6, id));
    eventStore.append(id, ev(5, id)); // duplicate of tail cursor, ignored
    eventStore.append(id, ev(7, id));
    const entry = eventStore.get(id);
    expect(entry?.events.map((e) => e.sequence)).toEqual([3, 4, 5, 6, 7]);
    expect(entry?.cursor).toBe(7);
  });

  it("returns undefined for unknown runs and clears on demand", () => {
    const id = rid();
    expect(eventStore.get(id)).toBeUndefined();
    eventStore.set(id, [ev(1, id)], 1);
    expect(eventStore.get(id)).toBeDefined();
    eventStore.clear(id);
    expect(eventStore.get(id)).toBeUndefined();
  });

  it("tracks dropped count seeded from server-side omitted history", () => {
    const id = rid();
    // 3,427 older events exist server-side; tail seeded events start at seq 3428.
    eventStore.set(id, Array.from({ length: 1000 }, (_, i) => ev(i + 3428, id)), 4427, 3427);
    const entry = eventStore.get(id);
    expect(entry?.dropped).toBe(3427);
    expect(entry?.events[0].sequence).toBe(3428);
  });

  it("increments dropped as live appends overflow the window", () => {
    const id = rid();
    eventStore.set(id, Array.from({ length: 1000 }, (_, i) => ev(i + 1, id)), 1000, 0);
    expect(eventStore.get(id)?.dropped).toBe(0);
    // Overflow by 2 events: both the new ones keep the newest window.
    eventStore.append(id, ev(1001, id));
    eventStore.append(id, ev(1002, id));
    const entry = eventStore.get(id);
    expect(entry?.events.length).toBe(1000);
    expect(entry?.events[0].sequence).toBe(3);
    expect(entry?.events[999].sequence).toBe(1002);
    expect(entry?.dropped).toBe(2);
  });

  it("reset clears dropped alongside events", () => {
    const id = rid();
    eventStore.set(id, [ev(1, id)], 1, 99);
    eventStore.clear(id);
    expect(eventStore.get(id)).toBeUndefined();
  });
});
