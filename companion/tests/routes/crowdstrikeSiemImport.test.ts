import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { buildRuntimePipeline } from "../../src/composition/aiProviders.js";
import { createImportDemote } from "../../src/composition/importDemote.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import { failSettleAfterStamp } from "../helpers/settleFailure.js";
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

// #2891 (gap 3): a search whose settle fails still fails, but the rows the importer merged are
// stamped, dual-written and demoted first — the next import's demote cannot move them untagged.
describe("landSearchResult when the settle fails (#2891)", () => {
  let root: string | undefined;
  afterEach(async () => {
    vi.restoreAllMocks();
    if (root) await rm(root, { recursive: true, force: true });
    root = undefined;
  });

  async function realCtx() {
    root = await mkdtemp(join(tmpdir(), "dfir-ngsiem-settle-"));
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(store);
    const lock = new StateLock();
    const runStateExclusive = <T>(c: string, fn: () => Promise<T>) => lock.runExclusive(c, fn);
    const superTimelineStore = new SuperTimelineStore(store);
    const pipeline = buildRuntimePipeline({
      stateStore,
      store,
      stateLock: lock,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const options = {
      pipeline,
      stateStore,
      superTimelineStore,
      forensicGateControlStore: new ForensicGateControlStore(store),
    } as unknown as AppOptions;
    const demote = createImportDemote({ options, runStateExclusive });
    const ctx = {
      store,
      options,
      importLock: new ImportLock(),
      runStateExclusive,
      demoteForensic: demote.demoteForensic,
      serverLogger: { info: () => {}, warn: () => {}, debug: () => {}, error: () => {} },
      resynthesizeInBackground: () => undefined,
      pushImportCheckpoint: async () => undefined,
    } as unknown as RouteContext;
    return { ctx, stateStore, superTimelineStore };
  }

  it("fails the search, after its rows are stamped, dual-written and demoted", async () => {
    const { ctx, stateStore, superTimelineStore } = await realCtx();
    const fired = failSettleAfterStamp(stateStore);
    const rows = [
      { ...row, "@id": "a", aid: "aid-1", ImageFileName: "\\Device\\x\\a.exe" },
      { ...row, "@id": "b", ComputerName: "WS-02", aid: "aid-2", ImageFileName: "\\Device\\x\\b.exe" },
    ];
    await expect(landSearchResult(ctx, spec, result({ rows }))).rejects.toThrow("out of memory");
    expect(fired()).toBe(true);
    const mine = (e: { sourceScreenshots: string[] }) =>
      e.sourceScreenshots.some((s) => s.includes("crowdstrike-ngsiem"));
    const superRows: { id: string; sourceScreenshots: string[] }[] = [];
    for await (const b of superTimelineStore.eventBatches("c1")) superRows.push(...b.filter(mine));
    expect(superRows.length).toBeGreaterThan(0); // dual-written: nothing lost to a demote
    const kept = (await stateStore.load("c1")).forensicTimeline.filter(mine);
    expect(kept.every((e) => e.importBatchId && e.severity !== "Info")).toBe(true);
  });
});
