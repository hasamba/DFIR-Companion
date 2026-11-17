import { describe, expect, it, vi } from "vitest";
import { ImportLock } from "../../src/analysis/importLock.js";
import { landSearchResult, importRows, type SiemSearchSpec } from "../../src/routes/crowdstrikeSiemImport.js";
import type { RouteContext } from "../../src/routes/context.js";
import type { NgsiemRunResult } from "../../src/integrations/crowdstrike/ngsiemSearch.js";
import { siemSearchText } from "../../src/analysis/siemSearch.js";

// #2666: the failure paths of landing a search result — a zero-row timeout is not "found nothing",
// a cancel that landed stops it before the first write, and a failed snapshot imports nothing.

const spec: SiemSearchSpec = {
  caseId: "c1",
  title: "t",
  query: "#event_simpleName=ProcessRollup2 | table([ComputerName])",
  startMs: 1,
  endMs: 2,
  repository: "search-all",
  maxRows: 100,
  timeoutMs: 300_000,
  actor: "analyst",
};
const result = (over: Partial<NgsiemRunResult> = {}): NgsiemRunResult => ({
  rows: [],
  truncated: false,
  timedOut: false,
  aggregate: false,
  finished: true,
  pages: 1,
  warnings: [],
  ...over,
});
const row = { "@id": "a", "@timestamp": 1731399999000, ComputerName: "WS-01" };

function fakeCtx(opts: { snapshotFails?: boolean } = {}) {
  const saveImport = vi.fn(async () => "/p");
  const importCrowdstrike = vi.fn(async () => ({}));
  const ctx = {
    store: { nextImportSeq: async () => 1, saveImport, appendImport: async () => ({}) },
    importLock: new ImportLock(),
    options: {
      pipeline: { importCrowdstrike },
      stateStore: {
        loadOverviewWithoutIocs: async () => {
          if (opts.snapshotFails) throw new Error("disk");
          return {};
        },
        loadOverview: async () => {
          if (opts.snapshotFails) throw new Error("disk");
          return {};
        },
      },
      superTimelineStore: {},
    },
    runStateExclusive: <T>(_c: string, fn: () => Promise<T>) => fn(),
    demoteForensic: async () => [],
    resynthesizeInBackground: () => undefined,
    pushImportCheckpoint: async () => undefined,
  } as unknown as RouteContext;
  return { ctx, saveImport, importCrowdstrike };
}

describe("landSearchResult failure paths (#2666)", () => {
  it("a search that timed out before any row failed — it never reads as found nothing", async () => {
    const { ctx, saveImport } = fakeCtx();
    const o = await landSearchResult(ctx, spec, result({ timedOut: true, truncated: true }));
    expect(o.failed).toContain("timed out after 5 minutes before Falcon returned any rows");
    expect(siemSearchText(o)).not.toContain("found nothing");
    expect(saveImport).not.toHaveBeenCalled();
  });

  it("a cancel that already landed stops the search before the evidence write", async () => {
    const { ctx, saveImport, importCrowdstrike } = fakeCtx();
    await expect(landSearchResult(ctx, spec, result({ rows: [row] }), () => true)).rejects.toMatchObject({
      name: "AbortError",
    });
    expect(saveImport).not.toHaveBeenCalled();
    expect(importCrowdstrike).not.toHaveBeenCalled();
  });

  it("a failed case snapshot imports nothing into the timeline (the evidence file is kept)", async () => {
    const { ctx, saveImport, importCrowdstrike } = fakeCtx({ snapshotFails: true });
    await expect(landSearchResult(ctx, spec, result({ rows: [row] }))).rejects.toThrow(
      /could not be snapshotted/,
    );
    expect(saveImport).toHaveBeenCalled();
    expect(importCrowdstrike).not.toHaveBeenCalled();
  });
});

describe("importRows (#2666)", () => {
  it("stamps the inferred event name only in the import text and keeps evidence indexes", () => {
    const r = importRows([row, { ComputerName: "no time" }], spec.query, { aggregate: true, finished: true });
    expect(r.events).toBe(1);
    expect(r.indexes).toEqual([0]);
    expect(JSON.parse(r.text)["#event_simpleName"]).toBe("ProcessRollup2");
  });

  it("imports nothing from an unfinished aggregate snapshot", () => {
    expect(importRows([row], spec.query, { aggregate: true, finished: false }).events).toBe(0);
  });

  it("never stamps an aggregate query's rows", () => {
    const r = importRows([row], "#event_simpleName=ProcessRollup2 | groupBy([ComputerName])", {
      aggregate: true,
      finished: true,
    });
    expect(r.events).toBe(0);
  });
});
