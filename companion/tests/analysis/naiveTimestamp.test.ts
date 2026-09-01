import { describe, it, expect } from "vitest";
import { tagNaiveAsUtc } from "../../src/analysis/naiveTimestamp.js";

describe("tagNaiveAsUtc (#757)", () => {
  it("tags a naive ISO date-time as UTC without shifting it", () => {
    expect(tagNaiveAsUtc("2026-01-01T00:30:00")).toBe("2026-01-01T00:30:00Z");
    expect(tagNaiveAsUtc("2026-05-28T10:00:00.123")).toBe("2026-05-28T10:00:00.123Z");
    expect(tagNaiveAsUtc("2026-01-01T00:30")).toBe("2026-01-01T00:30Z"); // seconds are optional
  });

  it("normalizes a space separator to T — V8 reads that form as local time too", () => {
    expect(tagNaiveAsUtc("2026-05-28 10:00:00")).toBe("2026-05-28T10:00:00Z");
  });

  it("leaves an already-zoned timestamp alone", () => {
    expect(tagNaiveAsUtc("2026-05-28T10:00:00Z")).toBe("2026-05-28T10:00:00Z");
    expect(tagNaiveAsUtc("2026-05-28T10:00:00+02:00")).toBe("2026-05-28T10:00:00+02:00");
    expect(tagNaiveAsUtc("2026-05-28T10:00:00-0500")).toBe("2026-05-28T10:00:00-0500");
  });

  it("leaves a date with no time alone — ECMAScript already reads that form as UTC", () => {
    expect(tagNaiveAsUtc("2026-05-28")).toBe("2026-05-28");
  });

  it("leaves a non-ISO or unparseable value alone, and empty stays empty", () => {
    expect(tagNaiveAsUtc("May 28 09:00:01")).toBe("May 28 09:00:01");
    expect(tagNaiveAsUtc("not-a-date")).toBe("not-a-date");
    expect(tagNaiveAsUtc("")).toBe("");
    expect(tagNaiveAsUtc("  ")).toBe("");
    expect(tagNaiveAsUtc(undefined)).toBe("");
  });

  it("is idempotent", () => {
    const once = tagNaiveAsUtc("2026-01-01T00:30:00");
    expect(tagNaiveAsUtc(once)).toBe(once);
  });
});
