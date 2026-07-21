import { describe, it, expect } from "vitest";
import { resolveTimeScope } from "../../src/analysis/veloTimeScope.js";

const NOW = new Date("2026-07-21T12:00:00.000Z");

describe("resolveTimeScope", () => {
  it("returns undefined for no scope, an empty object, and the explicit 'all' preset", () => {
    expect(resolveTimeScope(undefined, NOW)).toBeUndefined();
    expect(resolveTimeScope({}, NOW)).toBeUndefined();
    expect(resolveTimeScope({ preset: "all" }, NOW)).toBeUndefined();
  });

  it("resolves each relative preset to an absolute start with NO end bound", () => {
    // No upper bound on purpose: a hunt keeps scheduling on clients that check in later, so pinning
    // end=launch time would silently drop activity between launch and check-in.
    expect(resolveTimeScope({ preset: "24h" }, NOW)).toEqual({ start: "2026-07-20T12:00:00.000Z" });
    expect(resolveTimeScope({ preset: "7d" }, NOW)).toEqual({ start: "2026-07-14T12:00:00.000Z" });
    expect(resolveTimeScope({ preset: "30d" }, NOW)).toEqual({ start: "2026-06-21T12:00:00.000Z" });
    expect(resolveTimeScope({ preset: "90d" }, NOW)).toEqual({ start: "2026-04-22T12:00:00.000Z" });
  });

  it("resolves a custom range to both bounds, normalized to UTC ISO", () => {
    expect(resolveTimeScope({ start: "2026-06-01T00:00:00Z", end: "2026-06-30T23:59:59Z" }, NOW))
      .toEqual({ start: "2026-06-01T00:00:00.000Z", end: "2026-06-30T23:59:59.000Z" });
  });

  it("accepts a custom range with only a start", () => {
    expect(resolveTimeScope({ start: "2026-06-01T00:00:00Z" }, NOW)).toEqual({ start: "2026-06-01T00:00:00.000Z" });
  });

  it("rejects an unparseable bound and an end before its start", () => {
    expect(() => resolveTimeScope({ start: "not-a-date" }, NOW)).toThrow(/start must be a valid date/);
    expect(() => resolveTimeScope({ start: "2026-06-01T00:00:00Z", end: "nope" }, NOW)).toThrow(/end must be a valid date/);
    expect(() => resolveTimeScope({ start: "2026-06-30T00:00:00Z", end: "2026-06-01T00:00:00Z" }, NOW))
      .toThrow(/end must be at or after start/);
    expect(() => resolveTimeScope({ end: "2026-06-01T00:00:00Z" }, NOW)).toThrow(/start is required/);
  });

  it("rejects an unknown preset rather than silently collecting everything", () => {
    expect(() => resolveTimeScope({ preset: "5y" }, NOW)).toThrow(/unknown time-scope preset/);
  });

  it("rejects preset='custom' with no start (prevents silent unbounded collection)", () => {
    expect(() => resolveTimeScope({ preset: "custom" }, NOW)).toThrow(/start is required/);
    expect(() => resolveTimeScope({ preset: "custom", end: "2026-06-30T00:00:00Z" }, NOW)).toThrow(/start is required/);
  });

  it("preset takes precedence over start/end dates when both are supplied", () => {
    // If both preset and custom dates supplied, preset wins, dates ignored
    expect(resolveTimeScope({ preset: "24h", start: "2026-01-01T00:00:00Z", end: "2026-12-31T23:59:59Z" }, NOW))
      .toEqual({ start: "2026-07-20T12:00:00.000Z" });
  });

  it("whitespace-only preset treated as no preset", () => {
    expect(resolveTimeScope({ preset: "   " }, NOW)).toBeUndefined();
    expect(resolveTimeScope({ preset: "\t\n" }, NOW)).toBeUndefined();
  });

  it("accepts end equal to start as a zero-width window", () => {
    expect(resolveTimeScope({ start: "2026-06-15T12:00:00Z", end: "2026-06-15T12:00:00Z" }, NOW))
      .toEqual({ start: "2026-06-15T12:00:00.000Z", end: "2026-06-15T12:00:00.000Z" });
  });
});
