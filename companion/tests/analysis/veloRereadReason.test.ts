// #1992 — why a cut-short Velociraptor read was NOT re-read. The reason can carry a server error
// string, so it is capped and stripped of control characters before it is stored or shown.
import { describe, expect, it } from "vitest";
import { MAX_REREAD_REASON_LENGTH, cleanRereadReason } from "../../src/analysis/veloRereadReason.js";
import { truncatedRecord } from "../../src/analysis/veloKeptSpan.js";

describe("cleanRereadReason", () => {
  it("returns an empty string for a non-string or blank value", () => {
    expect(cleanRereadReason(undefined)).toBe("");
    expect(cleanRereadReason(42)).toBe("");
    expect(cleanRereadReason("  \n\t ")).toBe("");
  });

  it("folds newlines and strips control characters to a single line", () => {
    expect(cleanRereadReason("bad\r\nVQL\u0000 error\u001b[31m\u007f")).toBe("bad VQL error [31m");
  });

  it("caps the length", () => {
    const out = cleanRereadReason("x".repeat(5000));
    expect(out.length).toBeLessThanOrEqual(MAX_REREAD_REASON_LENGTH);
    expect(out.endsWith("…")).toBe(true);
  });
});

describe("truncatedRecord — rereadDeclined", () => {
  it("carries a cleaned reason onto the record", () => {
    const rec = truncatedRecord("Windows.Forensics.Usn", [], 3, {
      truncated: true,
      rereadDeclined: "boom\nsecond line",
    });
    expect(rec.rereadDeclined).toBe("boom second line");
  });

  it("omits the field when there is no reason", () => {
    expect(truncatedRecord("A", [], 3, { truncated: true })).not.toHaveProperty("rereadDeclined");
  });
});
