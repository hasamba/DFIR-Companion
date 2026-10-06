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

  // #1969 — a cut-short read re-read inside the incident window records which window it kept.
  it("records the incident window a re-read kept, and whether every window row fit", () => {
    const rows = [{ Timestamp: "2026-09-20T05:00:00Z" }];
    const win = { start: "2026-09-20T00:00:00.000Z", end: "2026-09-21T00:00:00.000Z" };
    expect(truncatedRecord("U", rows, 1, { window: win, truncated: false })).toMatchObject({
      windowStart: win.start,
      windowEnd: win.end,
      windowFull: true,
    });
    expect(truncatedRecord("U", rows, 2, { window: { start: win.start }, truncated: true })).toMatchObject({
      windowStart: win.start,
      windowFull: false,
    });
    expect(truncatedRecord("U", rows, 2, { truncated: true })).not.toHaveProperty("windowStart");
  });
});
