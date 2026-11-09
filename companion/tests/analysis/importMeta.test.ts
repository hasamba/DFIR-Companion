import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  aiExtractionFromDebug,
  describeImportSource,
  importMetaSchema,
  ImportMetaStore,
} from "../../src/analysis/importMeta.js";
import { createImportDebugRecorder } from "../../src/analysis/importDebug.js";
import type { TimelineDiff } from "../../src/analysis/timelineDiff.js";
import type { IocsDiff } from "../../src/analysis/iocsDiff.js";

const DIFF: TimelineDiff = {
  added: [
    { timestamp: "2026-01-01T01:00:00Z", description: "ransomware note dropped", severity: "Critical" },
    { timestamp: "2026-01-01T02:00:00Z", description: "lateral movement to DC01", severity: "High" },
  ],
  removed: [{ timestamp: "2026-01-01T00:00:00Z", description: "file written: a.exe", severity: "Medium" }],
};

const IOCS: IocsDiff = {
  added: [
    { value: "evil.com", type: "domain" },
    { value: "1.2.3.4", type: "ip" },
  ],
  removed: [],
};
const NO_IOCS: IocsDiff = { added: [], removed: [] };

describe("describeImportSource", () => {
  it("names the bundle, the hunt and how many artifacts came back", () => {
    expect(
      describeImportSource({ bundleName: "Super-Timeline Triage", huntId: "H.ABC", artifactCount: 21 }),
    ).toBe("Super-Timeline Triage · hunt H.ABC · 21 artifacts");
  });

  it("says 'artifact' for exactly one", () => {
    expect(describeImportSource({ huntId: "H.ABC", artifactCount: 1 })).toBe("hunt H.ABC · 1 artifact");
  });

  it("drops the parts it does not have — a fleet hunt has no bundle", () => {
    expect(describeImportSource({ huntId: "H.ABC", artifactCount: 0 })).toBe("hunt H.ABC");
  });

  it("returns empty when nothing identifies the import better than its filename", () => {
    // Callers pass this straight through; every consumer falls back to lastImportFile.
    expect(describeImportSource({})).toBe("");
  });
});

describe("ImportMetaStore", () => {
  let store: ImportMetaStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-importmeta-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new ImportMetaStore(cases);
  });

  it("returns an empty meta when none exists", async () => {
    expect(await store.load("c1")).toEqual({
      lastImportedAt: "",
      lastImportKind: "",
      lastImportFile: "",
      lastImportSource: "",
      addedCount: 0,
      superTimelineAddedCount: 0,
      superTimelineEvicted: null,
      removedCount: 0,
      lastDiff: null,
      iocsAddedCount: 0,
      iocsRemovedCount: 0,
      iocsDiff: null,
      linesIn: 0,
      path: "",
      fpPropagation: [],
      truncation: null,
    });
  });

  // #1535 — an Info row lives only in the super-timeline, so what its cap dropped is part of what
  // the import did to the record, not a log detail.
  it("records what the super-timeline cap dropped, and nothing when it dropped nothing", async () => {
    await store.record("c1", {
      kind: "velociraptor",
      file: "f.json",
      diff: { added: [], removed: [] },
      iocsDiff: { added: [], removed: [] },
      superTimelineAddedCount: 10,
      superTimelineEvicted: {
        count: 4,
        setAside: 1,
        from: "2026-05-01T00:00:00Z",
        to: "2026-05-02T00:00:00Z",
      },
    });
    expect((await store.load("c1")).superTimelineEvicted).toEqual({
      count: 4,
      setAside: 1,
      from: "2026-05-01T00:00:00Z",
      to: "2026-05-02T00:00:00Z",
    });

    await store.record("c1", {
      kind: "velociraptor",
      file: "f.json",
      diff: { added: [], removed: [] },
      iocsDiff: { added: [], removed: [] },
      superTimelineEvicted: { count: 0, setAside: 0, from: "", to: "" },
    });
    expect((await store.load("c1")).superTimelineEvicted).toBeNull();
  });

  it("loads legacy metadata that predates the eviction record as 'not recorded'", () => {
    expect(
      importMetaSchema.parse({ lastImportedAt: "2026-06-01T00:00:00.000Z" }).superTimelineEvicted,
    ).toBeUndefined();
  });

  it("keeps the super-timeline count unknown when loading legacy metadata", () => {
    expect(
      importMetaSchema.parse({ lastImportedAt: "2026-06-01T00:00:00.000Z" }).superTimelineAddedCount,
    ).toBeUndefined();
  });

  it("records the SOURCE that produced an import, for imports that span many files", async () => {
    // A Velociraptor hunt writes one evidence file per artifact, so `file` alone names whichever
    // artifact the import loop finished on — useless for telling one hunt from another. `source`
    // carries the thing the analyst actually launched.
    await store.record("c1", {
      kind: "velociraptor",
      file: "0042_velo-hunt_H.DA2M66KBG5OHC_Windows.EventLogs.Evtx.json",
      source: "Super-Timeline Triage — hunt H.DA2M66KBG5OHC · 21 artifacts",
      diff: { added: [], removed: [] },
      iocsDiff: NO_IOCS,
      superTimelineAddedCount: 5559,
    });

    const meta = await store.load("c1");
    expect(meta.lastImportSource).toBe("Super-Timeline Triage — hunt H.DA2M66KBG5OHC · 21 artifacts");
    expect(meta.lastImportFile).toBe("0042_velo-hunt_H.DA2M66KBG5OHC_Windows.EventLogs.Evtx.json");
  });

  it("leaves the source empty for a single-file import that has none", async () => {
    await store.record("c1", {
      kind: "thor",
      file: "0003_thor.json",
      diff: DIFF,
      iocsDiff: NO_IOCS,
    });
    expect((await store.load("c1")).lastImportSource).toBe("");
  });

  it("records an import (time + kind/file + timeline & IOC diff) and loads it back", async () => {
    const at = "2026-06-06T12:00:00.000Z";
    await store.record(
      "c1",
      {
        kind: "thor",
        file: "0003_thor.json",
        diff: DIFF,
        iocsDiff: IOCS,
        superTimelineAddedCount: 7,
      },
      at,
    );
    const meta = await store.load("c1");
    expect(meta.lastImportedAt).toBe(at);
    expect(meta.lastImportKind).toBe("thor");
    expect(meta.lastImportFile).toBe("0003_thor.json");
    expect(meta.addedCount).toBe(2);
    expect(meta.superTimelineAddedCount).toBe(7);
    expect(meta.removedCount).toBe(1);
    expect(meta.lastDiff).toEqual(DIFF);
    expect(meta.iocsAddedCount).toBe(2);
    expect(meta.iocsRemovedCount).toBe(0);
    expect(meta.iocsDiff).toEqual(IOCS);
  });

  it("overwrites the previous record on the next import", async () => {
    await store.record(
      "c1",
      { kind: "thor", file: "a", diff: DIFF, iocsDiff: IOCS },
      "2026-06-06T12:00:00.000Z",
    );
    const empty: TimelineDiff = { added: [], removed: [] };
    await store.record(
      "c1",
      { kind: "siem", file: "b", diff: empty, iocsDiff: NO_IOCS },
      "2026-06-06T13:00:00.000Z",
    );
    const meta = await store.load("c1");
    expect(meta.lastImportedAt).toBe("2026-06-06T13:00:00.000Z");
    expect(meta.lastImportKind).toBe("siem");
    expect(meta.addedCount).toBe(0);
    expect(meta.lastDiff).toEqual(empty);
    expect(meta.iocsAddedCount).toBe(0);
    expect(meta.iocsDiff).toEqual(NO_IOCS);
  });

  it("clear() resets the record to empty (used when an import is undone, #76)", async () => {
    await store.record(
      "c1",
      { kind: "thor", file: "a", diff: DIFF, iocsDiff: IOCS },
      "2026-06-06T12:00:00.000Z",
    );
    await store.clear("c1");
    expect(await store.load("c1")).toEqual({
      lastImportedAt: "",
      lastImportKind: "",
      lastImportFile: "",
      lastImportSource: "",
      addedCount: 0,
      superTimelineAddedCount: 0,
      superTimelineEvicted: null,
      removedCount: 0,
      lastDiff: null,
      iocsAddedCount: 0,
      iocsRemovedCount: 0,
      iocsDiff: null,
      linesIn: 0,
      path: "",
      fpPropagation: [],
      truncation: null,
    });
  });

  it("caps the stored detail lists but keeps the true totals in the counts", async () => {
    const many: TimelineDiff = {
      added: Array.from({ length: 800 }, (_, i) => ({
        timestamp: `2026-01-01T00:00:${String(i % 60).padStart(2, "0")}Z`,
        description: `evt ${i}`,
        severity: "Info" as const,
      })),
      removed: [],
    };
    const manyIocs: IocsDiff = {
      added: Array.from({ length: 700 }, (_, i) => ({ value: `10.0.0.${i}`, type: "ip" })),
      removed: [],
    };
    await store.record("c1", { kind: "plaso", file: "big.csv", diff: many, iocsDiff: manyIocs });
    const meta = await store.load("c1");
    expect(meta.addedCount).toBe(800); // true total preserved
    expect(meta.lastDiff?.added.length).toBe(500); // list capped
    expect(meta.iocsAddedCount).toBe(700); // true total preserved
    expect(meta.iocsDiff?.added.length).toBe(500); // list capped
  });
});

// #2460: an AI-triage import that kept 0 of N rows must be told apart from a re-import whose events
// were all already in the timeline — both show addedCount 0. The extraction's own kept count is the
// discriminator, so it is stored on import-meta.
describe("aiExtraction (#2460)", () => {
  let store: ImportMetaStore;
  beforeEach(async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-2460-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new ImportMetaStore(cases);
  });

  it("round-trips the rows the AI read and the events it kept", async () => {
    await store.record("c1", {
      kind: "csv",
      file: "0001_sysmon.csv",
      diff: { added: [], removed: [] },
      iocsDiff: NO_IOCS,
      path: "ai",
      aiExtraction: { rowsIn: 14, kept: 0 },
    });
    expect((await store.load("c1")).aiExtraction).toEqual({ rowsIn: 14, kept: 0 });
  });

  it("an older import-meta file without the field loads cleanly as not recorded", () => {
    const meta = importMetaSchema.parse({ lastImportedAt: "2026-01-01T00:00:00Z", path: "ai" });
    expect(meta.aiExtraction).toBeUndefined();
  });

  it("a malformed value loads as not recorded instead of failing the whole file", () => {
    const meta = importMetaSchema.parse({ path: "ai", aiExtraction: { rowsIn: "x" } });
    expect(meta.aiExtraction).toBeUndefined();
  });
});

describe("aiExtractionFromDebug (#2460)", () => {
  it("reads rows in and events kept from an AI import's debug recorder", () => {
    const debug = createImportDebugRecorder();
    debug.counts({ total: 14, kept: 0 });
    expect(aiExtractionFromDebug("ai", debug)).toEqual({ rowsIn: 14, kept: 0 });
    debug.counts({ kept: 3 });
    expect(aiExtractionFromDebug("ai", debug)).toEqual({ rowsIn: 14, kept: 3 });
  });

  it("is absent for a deterministic import, even when its importer counted rows", () => {
    const debug = createImportDebugRecorder();
    debug.counts({ total: 14, kept: 0 });
    expect(aiExtractionFromDebug("deterministic", debug)).toBeUndefined();
  });

  it("is absent when the model DID return events and the analyst's severity floor removed them", () => {
    const debug = createImportDebugRecorder();
    debug.counts({ total: 14, kept: 0 });
    debug.omitted("below_severity_floor", 5);
    expect(aiExtractionFromDebug("ai", debug)).toBeUndefined();
  });

  it("is absent when the import was cancelled between batches (kept 0 is not a result)", () => {
    const debug = createImportDebugRecorder();
    debug.counts({ total: 14, kept: 0 });
    debug.observed("cancelled_between_batches");
    expect(aiExtractionFromDebug("ai", debug)).toBeUndefined();
  });

  it("is absent when the AI extraction never counted (no recorder, or it never ran)", () => {
    expect(aiExtractionFromDebug("ai", undefined)).toBeUndefined();
    expect(aiExtractionFromDebug("ai", createImportDebugRecorder())).toBeUndefined();
  });
});
