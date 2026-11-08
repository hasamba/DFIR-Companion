import { describe, expect, it } from "vitest";
import { progressLine } from "../../src/routes/cloudCollectJob.js";
import { sourceProgress, type CollectProgress } from "../../src/integrations/cloudCollect/collectEngine.js";
import type { SubWindowStatus } from "../../src/integrations/cloudCollect/collectTypes.js";

// #2384 — while a collection downloads, the job line said "436 page(s) pending … 436/437 · ETA one
// page away" forever: the total was "saved + 1". It now estimates from the S3 walk's folder
// position, and shows no ETA at all when a source cannot tell how much is left.

const net = (sources: CollectProgress["sources"]): CollectProgress => ({
  stage: "network",
  pages: sources.reduce((n, s) => n + s.pages, 0),
  records: 0,
  imported: 0,
  sources,
});

const WINDOW = { start: "2026-10-01T00:00:00Z", end: "2026-10-08T00:00:00Z" };
const sw = (over: Partial<SubWindowStatus>): SubWindowStatus => ({
  id: "x",
  source: "s3-trail",
  window: WINDOW,
  state: "pending",
  pages: 0,
  records: 0,
  restarts: 0,
  ...over,
});

describe("cloud collect progress line (#2384)", () => {
  it("scales the saved pages by the folder position into an estimated total", () => {
    const line = progressLine(
      net([
        { source: "s3-trail", pages: 400, records: 0, state: "pending", walk: { at: 10, of: 100 } },
        { source: "guardduty-findings", pages: 3, records: 0, state: "done" },
      ]),
    );
    expect(line.done).toBe(403);
    expect(line.total).toBe(4003);
    expect(line.detail).toContain("s3-trail 400 page(s) saved, folder 11 of 100");
    expect(line.detail).toContain("guardduty-findings 3 page(s) saved done");
    expect(line.detail).not.toContain("pending");
  });

  it("reports no total (so no bar and no ETA) while any source cannot tell how much is left", () => {
    for (const s3 of [
      { source: "s3-trail", pages: 50, records: 0, state: "pending", walk: { at: 0, of: 100 } },
      { source: "cloudtrail-lookup", pages: 50, records: 0, state: "pending" },
    ]) {
      const line = progressLine(net([s3]));
      expect(line.total).toBe(0);
      expect(line.done).toBe(0);
      expect(line.detail).toContain("50 page(s) saved");
    }
  });

  it("never estimates fewer pages than one more than saved while a source runs", () => {
    const line = progressLine(
      net([{ source: "s3-trail", pages: 10, records: 0, state: "pending", walk: { at: 100, of: 100 } }]),
    );
    expect(line.total).toBe(11);
  });

  it("sums the walk over a source's sub-windows; a settled one counts as finished", () => {
    const [p] = sourceProgress([
      sw({ id: "a", state: "done", walk: { at: 3, of: 8 } }),
      sw({ id: "b", walk: { at: 2, of: 8 } }),
      sw({ id: "p", state: "split", walk: { at: 1, of: 16 } }),
    ]);
    expect(p.walk).toEqual({ at: 10, of: 16 });
  });

  it("a failed sub-window beside a downloading one is not settled: no exact total", () => {
    const sources = sourceProgress([
      sw({ id: "a", source: "cloudtrail-lookup", state: "failed", pages: 4 }),
      sw({ id: "b", source: "cloudtrail-lookup", pages: 6 }),
    ]);
    expect(sources[0]).toMatchObject({ state: "failed", running: true });
    expect(progressLine(net(sources)).total).toBe(0);
  });

  it("states no walk while an unsettled sub-window has not reported one yet", () => {
    const [p] = sourceProgress([sw({ id: "a", walk: { at: 3, of: 8 } }), sw({ id: "b" })]);
    expect(p.walk).toBeUndefined();
    const [q] = sourceProgress([sw({ id: "c", state: "failed" }), sw({ id: "d", walk: { at: 1, of: 4 } })]);
    expect(q.walk).toEqual({ at: 1, of: 4 });
  });
});
