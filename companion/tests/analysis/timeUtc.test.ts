import { describe, it, expect } from "vitest";
import { toUtcIso } from "../../src/analysis/timeUtc.js";

describe("toUtcIso", () => {
  it("converts a positive timezone offset to UTC", () => {
    expect(toUtcIso("2026-05-28T10:00:00+02:00")).toBe("2026-05-28T08:00:00.000Z");
  });

  it("converts a negative offset (and the compact ±HHMM form) to UTC", () => {
    expect(toUtcIso("2026-05-28T05:00:00-05:00")).toBe("2026-05-28T10:00:00.000Z");
    expect(toUtcIso("2026-05-28T05:00:00-0500")).toBe("2026-05-28T10:00:00.000Z");
  });

  it("leaves an already-UTC timestamp untouched (no spurious milliseconds)", () => {
    expect(toUtcIso("2026-05-28T10:00:00Z")).toBe("2026-05-28T10:00:00Z");
    expect(toUtcIso("2026-05-28T10:00:00.123Z")).toBe("2026-05-28T10:00:00.123Z");
  });

  it("leaves a naive (timezone-less) timestamp untouched — never reinterprets it as local", () => {
    expect(toUtcIso("2026-05-28T10:00:00")).toBe("2026-05-28T10:00:00");
    expect(toUtcIso("2026-05-28 10:00:00")).toBe("2026-05-28 10:00:00");
    expect(toUtcIso("May 28 09:00:01")).toBe("May 28 09:00:01");
    expect(toUtcIso("2026-05-28")).toBe("2026-05-28");
  });

  it("returns empty/unparseable input unchanged", () => {
    expect(toUtcIso("")).toBe("");
    expect(toUtcIso("  ")).toBe("");
    expect(toUtcIso(undefined)).toBe("");
    expect(toUtcIso("not-a-date+99:99")).toBe("not-a-date+99:99");
  });

  it("is idempotent", () => {
    const once = toUtcIso("2026-05-28T10:00:00+02:00");
    expect(toUtcIso(once)).toBe(once);
  });
});
