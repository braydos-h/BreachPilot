import { describe, expect, it } from "vitest";
import { asRecord, asArray, str, num, bool, json } from "@/lib/stateShape";

describe("stateShape accessors", () => {
  it("asRecord returns {} for non-objects and passes through plain objects", () => {
    expect(asRecord(null)).toEqual({});
    expect(asRecord(undefined)).toEqual({});
    expect(asRecord("x")).toEqual({});
    expect(asRecord([1, 2])).toEqual({});
    expect(asRecord({ a: 1 })).toEqual({ a: 1 });
  });

  it("asArray returns [] for non-arrays and passes through arrays", () => {
    expect(asArray(null)).toEqual([]);
    expect(asArray({ a: 1 })).toEqual([]);
    expect(asArray("x")).toEqual([]);
    expect(asArray([1, 2])).toEqual([1, 2]);
  });

  it("str coerces null/undefined to empty string", () => {
    expect(str(null)).toBe("");
    expect(str(undefined)).toBe("");
    expect(str(0)).toBe("0");
    expect(str(false)).toBe("false");
    expect(str("ok")).toBe("ok");
  });

  it("num coerces numeric strings and rejects non-finite", () => {
    expect(num(5)).toBe(5);
    expect(num("5")).toBe(5);
    expect(num("5.5")).toBe(5.5);
    expect(num("abc")).toBe(0);
    expect(num(null)).toBe(0);
    expect(num(undefined)).toBe(0);
  });

  it("bool accepts true, 'true', and 1", () => {
    expect(bool(true)).toBe(true);
    expect(bool("true")).toBe(true);
    expect(bool(1)).toBe(true);
    expect(bool(false)).toBe(false);
    expect(bool("false")).toBe(false);
    expect(bool(0)).toBe(false);
    expect(bool(null)).toBe(false);
  });

  it("json stringifies objects and passes through strings", () => {
    expect(json("already a string")).toBe("already a string");
    expect(json({ a: 1 })).toBe('{\n  "a": 1\n}');
    expect(json(null)).toBe("null");
  });
});
