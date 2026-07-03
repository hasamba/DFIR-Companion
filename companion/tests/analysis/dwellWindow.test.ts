import { describe, it, expect } from "vitest";
import { sanitizeDwellWindowInput } from "../../src/analysis/dwellWindow.js";

describe("sanitizeDwellWindowInput", () => {
  it("normalizes a valid label/start/end", () => {
    const out = sanitizeDwellWindowInput({ label: "  Attacker session 1  ", start: "2026-06-01T00:00:00Z", end: "2026-06-02T00:00:00Z" });
    expect(out).toEqual({ label: "Attacker session 1", start: "2026-06-01T00:00:00.000Z", end: "2026-06-02T00:00:00.000Z" });
  });

  it("throws when label is empty", () => {
    expect(() => sanitizeDwellWindowInput({ label: "  ", start: "2026-06-01T00:00:00Z", end: "2026-06-02T00:00:00Z" })).toThrow(/label/);
  });

  it("throws when start is not a parseable date", () => {
    expect(() => sanitizeDwellWindowInput({ label: "x", start: "not-a-date", end: "2026-06-02T00:00:00Z" })).toThrow(/start/);
  });

  it("throws when end is not a parseable date", () => {
    expect(() => sanitizeDwellWindowInput({ label: "x", start: "2026-06-01T00:00:00Z", end: "nope" })).toThrow(/end/);
  });

  it("throws when end is before start", () => {
    expect(() => sanitizeDwellWindowInput({ label: "x", start: "2026-06-02T00:00:00Z", end: "2026-06-01T00:00:00Z" })).toThrow(/end.*after|before/i);
  });
});
