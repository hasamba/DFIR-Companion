import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StarredReportStore } from "../../src/analysis/starredReportStore.js";

async function makeStore() {
  const root = await mkdtemp(join(tmpdir(), "dfir-starred-report-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return new StarredReportStore(cases);
}

describe("StarredReportStore", () => {
  it("returns null when nothing was saved", async () => {
    const store = await makeStore();
    expect(await store.load("c1")).toBeNull();
  });

  it("round-trips a saved report", async () => {
    const store = await makeStore();
    await store.save("c1", { markdown: "# Starred Events Report\n\nbody", savedAt: "2026-07-16T10:00:00Z", eventCount: 4 });
    const loaded = await store.load("c1");
    expect(loaded).toEqual({ markdown: "# Starred Events Report\n\nbody", savedAt: "2026-07-16T10:00:00Z", eventCount: 4 });
  });

  it("overwrites on re-save (single slot)", async () => {
    const store = await makeStore();
    await store.save("c1", { markdown: "first", savedAt: "2026-07-16T10:00:00Z", eventCount: 1 });
    await store.save("c1", { markdown: "second", savedAt: "2026-07-16T11:00:00Z", eventCount: 2 });
    expect((await store.load("c1"))!.markdown).toBe("second");
  });
});
