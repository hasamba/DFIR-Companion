import { describe, it, expect } from "vitest";
import { isRealUtcTime, parseBsdTime } from "../../src/analysis/bsdTime.js";

// #2061 — Date.parse rolls an impossible day (Feb 30/31, Apr 31, a non-leap Feb 29) and hour 24
// forward into a real, wrong time. The parser must return "" instead of a shifted timestamp.
describe("parseBsdTime — impossible dates (#2061)", () => {
  it.each([
    ["Feb 31 10:00:00", 2026],
    ["Feb 30 10:00:00", 2026],
    ["Apr 31 10:00:00", 2026],
    ["Jan  1 24:00:00", 2026],
    ["Feb 29 00:00:00", 2026],
    ["Feb 29 00:00:00", 1900],
  ])("%s in %i is unparseable", (ts, year) => {
    expect(parseBsdTime(ts, year)).toBe("");
  });

  it("still rejects values Date.parse already refused", () => {
    expect(parseBsdTime("Jan 32 10:00:00", 2026)).toBe("");
    expect(parseBsdTime("Jan 00 10:00:00", 2026)).toBe("");
    expect(parseBsdTime("Jan  1 25:00:00", 2026)).toBe("");
    expect(parseBsdTime("Jan  1 10:60:00", 2026)).toBe("");
    expect(parseBsdTime("Jan  1 10:00:60", 2026)).toBe("");
  });
});

describe("parseBsdTime — real dates are unchanged", () => {
  it.each([
    ["Feb 29 00:00:00", 2024, "2024-02-29T00:00:00.000Z"],
    ["Feb 29 00:00:00", 2000, "2000-02-29T00:00:00.000Z"],
    ["May 16 13:40:26", 2026, "2026-05-16T13:40:26.000Z"],
    ["Jan  1 00:00:00", 2026, "2026-01-01T00:00:00.000Z"],
    ["Dec 31 23:59:59", 2026, "2026-12-31T23:59:59.000Z"],
    ["Apr 30 12:00:00", 2026, "2026-04-30T12:00:00.000Z"],
  ])("%s in %i → %s", (ts, year, iso) => {
    expect(parseBsdTime(ts, year)).toBe(iso);
  });

  it("returns '' for malformed input", () => {
    expect(parseBsdTime("Foo 1 10:00:00", 2026)).toBe("");
    expect(parseBsdTime("not a time", 2026)).toBe("");
  });
});

describe("isRealUtcTime", () => {
  it("accepts a real calendar time", () => {
    expect(isRealUtcTime(2024, 2, 29, 23, 59, 59)).toBe(true);
  });

  it("rejects parts that would roll over", () => {
    expect(isRealUtcTime(2026, 2, 29, 0, 0, 0)).toBe(false);
    expect(isRealUtcTime(2026, 4, 31, 0, 0, 0)).toBe(false);
    expect(isRealUtcTime(2026, 1, 1, 24, 0, 0)).toBe(false);
    expect(isRealUtcTime(2026, 13, 1, 0, 0, 0)).toBe(false);
  });
});
