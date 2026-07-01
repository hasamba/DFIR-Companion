import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";

describe("DropStatusStore", () => {
  let store: DropStatusStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-dropstatus-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new DropStatusStore(cases);
  });

  it("returns an empty status when none exists", async () => {
    expect(await store.load("c1")).toEqual({
      lastSweepAt: "", dropPath: "", importedCount: 0, failedCount: 0, imported: [], failed: [], pendingRawInputs: [],
    });
  });

  it("records a sweep (imported + failed) and loads it back", async () => {
    const at = "2026-06-29T12:00:00.000Z";
    await store.record("c1", {
      dropPath: "/cases/c1/drop",
      imported: ["triage/prefetch.csv", "events.json"],
      failed: [{ relpath: "broken.bin", reason: "unrecognized file type" }],
    }, at);
    const s = await store.load("c1");
    expect(s.lastSweepAt).toBe(at);
    expect(s.dropPath).toBe("/cases/c1/drop");
    expect(s.importedCount).toBe(2);
    expect(s.failedCount).toBe(1);
    expect(s.imported).toEqual(["triage/prefetch.csv", "events.json"]);
    expect(s.failed).toEqual([{ relpath: "broken.bin", reason: "unrecognized file type" }]);
  });

  it("clears back to empty", async () => {
    await store.record("c1", { dropPath: "/x", imported: ["a"], failed: [] });
    await store.clear("c1");
    const s = await store.load("c1");
    expect(s.importedCount).toBe(0);
    expect(s.imported).toEqual([]);
    expect(s.lastSweepAt).toBe("");
  });
});
