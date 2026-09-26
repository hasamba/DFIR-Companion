// #1599: after any action other than the four synthesis triggers, the case says its conclusions are
// out of date instead of starting a paid run. The marker lives in synth-meta and a real synthesis
// clears it — unless the change landed while that run was in flight, which the run could not see.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import type { FindingsDiff } from "../../src/analysis/findingsDiff.js";

const DIFF: FindingsDiff = { added: [], removed: [], severityChanged: [] };

describe("SynthMetaStore — conclusions out of date", () => {
  let cases: CaseStore;
  let store: SynthMetaStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-synthmeta-ood-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new SynthMetaStore(cases);
  });

  it("starts at revision 0 with no marker", async () => {
    expect(await store.revision("c1")).toBe(0);
    expect((await store.load("c1")).outOfDate ?? null).toBeNull();
  });

  it("marks the case out of date and bumps the revision on every mark", async () => {
    await store.markOutOfDate("c1", "false positive marked", "2026-09-25T10:00:00.000Z");
    await store.markOutOfDate("c1", "scope window changed", "2026-09-25T10:01:00.000Z");
    const meta = await store.load("c1");
    expect(meta.revision).toBe(2);
    expect(meta.outOfDate).toEqual({
      reason: "scope window changed",
      at: "2026-09-25T10:01:00.000Z",
      revision: 2,
    });
  });

  it("keeps the rest of the meta when marking", async () => {
    await store.record("c1", DIFF, "2026-09-25T09:00:00.000Z");
    await store.markOutOfDate("c1", "manual event added");
    expect((await store.load("c1")).lastSynthesizedAt).toBe("2026-09-25T09:00:00.000Z");
  });

  it("a real run that started after the mark clears it, and keeps the revision", async () => {
    await store.markOutOfDate("c1", "false positive marked");
    const start = await store.revision("c1");
    await store.record("c1", DIFF, undefined, {
      durationMs: 1,
      eventCount: 1,
      iocCount: 0,
      startRevision: start,
    });
    const meta = await store.load("c1");
    expect(meta.outOfDate ?? null).toBeNull();
    expect(meta.revision).toBe(1);
  });

  it("a mark that lands during the run survives the run's record", async () => {
    const start = await store.revision("c1");
    await store.markOutOfDate("c1", "row promoted"); // while the run is in flight
    await store.record("c1", DIFF, undefined, {
      durationMs: 1,
      eventCount: 1,
      iocCount: 0,
      startRevision: start,
    });
    expect((await store.load("c1")).outOfDate?.reason).toBe("row promoted");
  });

  it("never persists the start revision", async () => {
    await store.record("c1", DIFF, undefined, {
      durationMs: 1,
      eventCount: 1,
      iocCount: 0,
      startRevision: 0,
    });
    expect(await store.load("c1")).not.toHaveProperty("startRevision");
  });

  it("record() without a start revision clears the marker (old callers)", async () => {
    await store.markOutOfDate("c1", "x");
    await store.record("c1", DIFF);
    expect((await store.load("c1")).outOfDate ?? null).toBeNull();
  });

  it("clearOutOfDate() drops a mark the caller saw, and keeps the rest of the card (#1676)", async () => {
    await store.record("c1", DIFF, "2026-09-25T09:00:00.000Z");
    await store.markOutOfDate("c1", "anonymization changed");
    const start = await store.revision("c1");
    await store.clearOutOfDate("c1", start);
    const meta = await store.load("c1");
    expect(meta.outOfDate ?? null).toBeNull();
    expect(meta.revision).toBe(1);
    expect(meta.lastSynthesizedAt).toBe("2026-09-25T09:00:00.000Z");
  });

  it("clearOutOfDate() keeps a mark that landed after the caller read the revision (#1676)", async () => {
    const start = await store.revision("c1");
    await store.markOutOfDate("c1", "row promoted");
    await store.clearOutOfDate("c1", start);
    expect((await store.load("c1")).outOfDate?.reason).toBe("row promoted");
  });

  it("record() still writes over an unreadable synth-meta file", async () => {
    await writeFile(join(cases.stateDir("c1"), "synth-meta.json"), "{not json", "utf8");
    await store.record("c1", DIFF, "2026-09-25T09:00:00.000Z");
    expect((await store.load("c1")).lastSynthesizedAt).toBe("2026-09-25T09:00:00.000Z");
  });
});
