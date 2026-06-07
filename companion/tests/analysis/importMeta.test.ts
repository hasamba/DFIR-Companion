import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
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
  added: [{ value: "evil.com", type: "domain" }, { value: "1.2.3.4", type: "ip" }],
  removed: [],
};
const NO_IOCS: IocsDiff = { added: [], removed: [] };

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
      lastImportedAt: "", lastImportKind: "", lastImportFile: "",
      addedCount: 0, removedCount: 0, lastDiff: null,
      iocsAddedCount: 0, iocsRemovedCount: 0, iocsDiff: null,
    });
  });

  it("records an import (time + kind/file + timeline & IOC diff) and loads it back", async () => {
    const at = "2026-06-06T12:00:00.000Z";
    await store.record("c1", { kind: "thor", file: "0003_thor.json", diff: DIFF, iocsDiff: IOCS }, at);
    const meta = await store.load("c1");
    expect(meta.lastImportedAt).toBe(at);
    expect(meta.lastImportKind).toBe("thor");
    expect(meta.lastImportFile).toBe("0003_thor.json");
    expect(meta.addedCount).toBe(2);
    expect(meta.removedCount).toBe(1);
    expect(meta.lastDiff).toEqual(DIFF);
    expect(meta.iocsAddedCount).toBe(2);
    expect(meta.iocsRemovedCount).toBe(0);
    expect(meta.iocsDiff).toEqual(IOCS);
  });

  it("overwrites the previous record on the next import", async () => {
    await store.record("c1", { kind: "thor", file: "a", diff: DIFF, iocsDiff: IOCS }, "2026-06-06T12:00:00.000Z");
    const empty: TimelineDiff = { added: [], removed: [] };
    await store.record("c1", { kind: "siem", file: "b", diff: empty, iocsDiff: NO_IOCS }, "2026-06-06T13:00:00.000Z");
    const meta = await store.load("c1");
    expect(meta.lastImportedAt).toBe("2026-06-06T13:00:00.000Z");
    expect(meta.lastImportKind).toBe("siem");
    expect(meta.addedCount).toBe(0);
    expect(meta.lastDiff).toEqual(empty);
    expect(meta.iocsAddedCount).toBe(0);
    expect(meta.iocsDiff).toEqual(NO_IOCS);
  });

  it("caps the stored detail lists but keeps the true totals in the counts", async () => {
    const many: TimelineDiff = {
      added: Array.from({ length: 800 }, (_, i) => ({ timestamp: `2026-01-01T00:00:${String(i % 60).padStart(2, "0")}Z`, description: `evt ${i}`, severity: "Info" as const })),
      removed: [],
    };
    const manyIocs: IocsDiff = {
      added: Array.from({ length: 700 }, (_, i) => ({ value: `10.0.0.${i}`, type: "ip" })),
      removed: [],
    };
    await store.record("c1", { kind: "plaso", file: "big.csv", diff: many, iocsDiff: manyIocs });
    const meta = await store.load("c1");
    expect(meta.addedCount).toBe(800);                 // true total preserved
    expect(meta.lastDiff?.added.length).toBe(500);     // list capped
    expect(meta.iocsAddedCount).toBe(700);             // true total preserved
    expect(meta.iocsDiff?.added.length).toBe(500);     // list capped
  });
});
