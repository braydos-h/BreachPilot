import { describe, expect, it } from "vitest";
import { MAX_EVENTS_PER_RUN, appendBounded } from "@/api/eventBuffer";
import type { RunEvent } from "@/api/types";

function ev(sequence: number, runId = "r1"): RunEvent {
  return {
    sequence,
    timestamp: new Date(sequence * 1000).toISOString(),
    run_id: runId,
    type: "state",
    payload: {},
  };
}

describe("appendBounded", () => {
  it("never exceeds MAX_EVENTS_PER_RUN", () => {
    const filled = Array.from({ length: MAX_EVENTS_PER_RUN }, (_, i) => ev(i + 1));
    const result = appendBounded(filled, [ev(MAX_EVENTS_PER_RUN + 1), ev(MAX_EVENTS_PER_RUN + 2)]);
    expect(result.events.length).toBe(MAX_EVENTS_PER_RUN);
  });

  it("preserves chronological order and keeps the newest events", () => {
    const base = Array.from({ length: MAX_EVENTS_PER_RUN }, (_, i) => ev(i + 1));
    const result = appendBounded(base, [ev(1001), ev(1002)]);
    expect(result.events[0]!.sequence).toBe(3);
    expect(result.events[result.events.length - 1]!.sequence).toBe(1002);
    // Fully ascending.
    for (let i = 1; i < result.events.length; i++) {
      expect(result.events[i]!.sequence).toBe(result.events[i - 1]!.sequence + 1);
    }
  });

  it("reports the number of events discarded from the window", () => {
    const base = Array.from({ length: MAX_EVENTS_PER_RUN }, (_, i) => ev(i + 1));
    const result = appendBounded(base, [ev(1001), ev(1002), ev(1003)]);
    expect(result.dropped).toBe(3);
    expect(result.events[0]!.sequence).toBe(4);
  });

  it("reports zero dropped when the window has headroom", () => {
    const result = appendBounded([ev(1)], [ev(2), ev(3)]);
    expect(result.dropped).toBe(0);
    expect(result.events.map((e) => e.sequence)).toEqual([1, 2, 3]);
  });

  it("handles a batch larger than the window", () => {
    const batch = Array.from({ length: MAX_EVENTS_PER_RUN + 50 }, (_, i) => ev(i + 1));
    const result = appendBounded([ev(9999)], batch);
    expect(result.events.length).toBe(MAX_EVENTS_PER_RUN);
    expect(result.events[0]!.sequence).toBe(51);
    expect(result.events[result.events.length - 1]!.sequence).toBe(MAX_EVENTS_PER_RUN + 50);
    expect(result.dropped).toBe(51); // 1 (headroom consumer) + 50 batch overflow
  });

  it("does not mutate the input arrays", () => {
    const prev = [ev(1)];
    const batch = [ev(2)];
    const beforePrev = [...prev];
    const beforeBatch = [...batch];
    appendBounded(prev, batch);
    expect(prev).toEqual(beforePrev);
    expect(batch).toEqual(beforeBatch);
  });
});
