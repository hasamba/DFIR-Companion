// #1950 — a capped Velociraptor read keeps the FIRST rows the artifact returns, not the incident
// window. The kept span says which time range those rows cover, so the model and the analyst can
// tell which days are missing.
import { describe, expect, it } from "vitest";
import { keptSpan, truncatedRecord } from "../../src/analysis/veloKeptSpan.js";

describe("keptSpan", () => {
  it("returns the earliest and latest row time across the kept rows, in any order", () => {
    const rows = [
      { Timestamp: "2026-09-29T19:00:00Z" },
      { Timestamp: "2026-09-28T00:00:00Z" },
      { Timestamp: "2026-09-29T05:30:00Z" },
    ];
    expect(keptSpan(rows)).toEqual({ earliest: "2026-09-28T00:00:00Z", latest: "2026-09-29T19:00:00Z" });
  });

  it("is undefined when no row has a readable artifact time", () => {
    expect(keptSpan([{ Name: "a" }, { x: 1 }, null, "text"])).toBeUndefined();
    expect(keptSpan([])).toBeUndefined();
  });

  it("never dates a row by its collection time (_ts) — that is when it was read, not when it happened", () => {
    expect(keptSpan([{ Name: "a", _ts: 1790000000 }])).toBeUndefined();
  });

  it("skips undated rows and keeps the span of the dated ones", () => {
    const rows = [{ Name: "a" }, { EventTime: "2026-09-29T10:00:00Z" }];
    expect(keptSpan(rows)).toEqual({ earliest: "2026-09-29T10:00:00Z", latest: "2026-09-29T10:00:00Z" });
  });
});

describe("truncatedRecord", () => {
  it("carries the kept count, the read total and the kept span", () => {
    const rows = [{ Timestamp: "2026-09-29T00:00:00Z" }, { Timestamp: "2026-09-29T19:00:00Z" }];
    expect(truncatedRecord("Windows.Forensics.Usn", rows, 3)).toEqual({
      name: "Windows.Forensics.Usn",
      kept: 2,
      total: 3,
      earliest: "2026-09-29T00:00:00Z",
      latest: "2026-09-29T19:00:00Z",
    });
  });

  it("omits the span fields when no kept row is dated", () => {
    expect(truncatedRecord("Custom.X", [{ x: 1 }], 2)).toEqual({ name: "Custom.X", kept: 1, total: 2 });
  });
});
