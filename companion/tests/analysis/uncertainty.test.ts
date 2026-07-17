import { describe, it, expect } from "vitest";
import { sanitizeUncertainties, UNCERTAINTY_MAX_DEFAULT } from "../../src/analysis/uncertainty.js";

describe("sanitizeUncertainties", () => {
  it("keeps valid entries and preserves field values", () => {
    const out = sanitizeUncertainties([
      { topic: "initial access", status: "inferred", basis: "finding f1", gap: "collect mail logs" },
    ]);
    expect(out).toEqual([
      { topic: "initial access", status: "inferred", basis: "finding f1", gap: "collect mail logs" },
    ]);
  });

  it("drops entries with a blank/missing topic", () => {
    const out = sanitizeUncertainties([
      { topic: "   ", status: "confirmed", basis: "b", gap: "g" },
      { status: "confirmed", basis: "b", gap: "g" },
      { topic: "real", status: "confirmed", basis: "", gap: "" },
    ]);
    expect(out.map((u) => u.topic)).toEqual(["real"]);
  });

  it("coerces an unknown/invalid status to 'unknown' (never over-claims)", () => {
    const out = sanitizeUncertainties([
      { topic: "a", status: "definitely", basis: "", gap: "" },
      { topic: "b", basis: "", gap: "" },
      { topic: "c", status: "CONFIRMED", basis: "", gap: "" },
    ]);
    expect(out.map((u) => u.status)).toEqual(["unknown", "unknown", "confirmed"]);
  });

  it("dedupes by normalized topic, first wins", () => {
    const out = sanitizeUncertainties([
      { topic: "Data Exfiltrated", status: "inferred", basis: "first", gap: "" },
      { topic: "  data   exfiltrated ", status: "confirmed", basis: "second", gap: "" },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].basis).toBe("first");
    expect(out[0].status).toBe("inferred");
  });

  it("trims strings and caps prose length", () => {
    const out = sanitizeUncertainties([
      { topic: "  spaced  ", status: "unknown", basis: "x".repeat(5000), gap: "y".repeat(5000) },
    ]);
    expect(out[0].topic).toBe("spaced");
    expect(out[0].basis.length).toBe(1000);
    expect(out[0].gap.length).toBe(1000);
  });

  it("caps the number of entries", () => {
    const many = Array.from({ length: UNCERTAINTY_MAX_DEFAULT + 10 }, (_, i) => ({
      topic: `t${i}`, status: "unknown", basis: "", gap: "",
    }));
    expect(sanitizeUncertainties(many)).toHaveLength(UNCERTAINTY_MAX_DEFAULT);
    expect(sanitizeUncertainties(many, 3)).toHaveLength(3);
  });

  it("returns [] for undefined / non-array / junk input", () => {
    expect(sanitizeUncertainties(undefined)).toEqual([]);
    expect(sanitizeUncertainties([null, 42, "nope", {}] as unknown[])).toEqual([]);
  });
});
