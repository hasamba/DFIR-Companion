import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { forgetCaseKeyedState } from "../../src/storage/caseKeyedState.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1881: the super-timeline's content version names one state of its rows, so a result computed
// from a full scan can be reused until a row really changes — and never across a restore branch.

const DatabaseSync = loadDatabaseSync();

function ev(id: string, asset = "WS-1", ts = "2026-06-01T00:00:00Z"): ForensicEvent {
  return {
    id,
    timestamp: ts,
    description: `event ${id}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
  };
}

async function countRows(batches: AsyncIterable<ForensicEvent[]>): Promise<number> {
  let n = 0;
  for await (const batch of batches) n += batch.length;
  return n;
}

describe("super-timeline content version (#1881)", () => {
  let root: string;
  let cases: CaseStore;
  let store: SuperTimelineStore;
  const dbPath = () => join(cases.stateDir("c1"), INVESTIGATION_DB_FILENAME);

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-super-version-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new SuperTimelineStore(cases, 100000);
  });

  it("stamps a version on first open, before any row exists", async () => {
    const meta = await store.meta("c1");
    expect(meta.version).toMatch(/^[0-9a-f-]{36}$/);
    expect((await store.meta("c1")).version).toBe(meta.version);
  });

  it("rotates the version when rows are added, not on a duplicate-only append", async () => {
    await store.append("c1", [ev("e1")]);
    const v1 = (await store.meta("c1")).version;
    await store.append("c1", [ev("e2", "WS-1", "2026-06-02T00:00:00Z")]);
    const v2 = (await store.meta("c1")).version;
    expect(v2).not.toBe(v1);

    const genBefore = (await store.meta("c1")).generation;
    await store.append("c1", [ev("e2", "WS-1", "2026-06-02T00:00:00Z")]);
    const after = await store.meta("c1");
    expect(after.version).toBe(v2);
    // `generation` keeps its old contract: every append bumps it.
    expect(after.generation).toBeGreaterThan(genBefore);
  });

  it("rotates on a rehome that rewrites a row, not on one that matches nothing", async () => {
    await store.append("c1", [ev("e1")]);
    const v1 = (await store.meta("c1")).version;
    await store.rehome("c1", [ev("missing", "WS-9")]);
    expect((await store.meta("c1")).version).toBe(v1);
    await store.rehome("c1", [ev("e1", "WS-9")]);
    expect((await store.meta("c1")).version).not.toBe(v1);
  });

  it("rotates when the cap evicts rows", async () => {
    const small = new SuperTimelineStore(cases, 2);
    await small.append("c1", [ev("e1"), ev("e2", "WS-1", "2026-06-02T00:00:00Z")]);
    const v1 = (await small.meta("c1")).version;
    await small.append("c1", [ev("e3", "WS-1", "2026-06-03T00:00:00Z")]);
    const meta = await small.meta("c1");
    expect(meta.rows).toBe(2);
    expect(meta.version).not.toBe(v1);
  });

  it("backfills a stamp on a database written before #1881", async () => {
    await store.append("c1", [ev("e1")]);
    const db = new DatabaseSync(dbPath());
    db.prepare("DELETE FROM storage_meta WHERE key='super_version'").run();
    db.close();
    expect((await store.meta("c1")).version).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("refuses super-timeline rows through the generic append", async () => {
    await store.meta("c1");
    await expect(
      caseSqliteWorker.request({
        op: "appendEntities",
        dbPath: dbPath(),
        kind: "superTimeline",
        entities: [ev("x")],
      }),
    ).rejects.toThrow(/superTimeline/);
  });

  it("rotates when the generic prune deletes super rows, not when it deletes none", async () => {
    await store.append("c1", [
      ev("old", "WS-1", "2020-01-01T00:00:00Z"),
      ev("new", "WS-1", "2026-01-01T00:00:00Z"),
    ]);
    const v1 = (await store.meta("c1")).version;
    const prune = (iso: string) =>
      caseSqliteWorker.request({
        op: "pruneEntitiesBefore",
        dbPath: dbPath(),
        kind: "superTimeline",
        beforeMs: Date.parse(iso),
      });
    await prune("2019-01-01T00:00:00Z");
    expect((await store.meta("c1")).version).toBe(v1);
    await prune("2025-01-01T00:00:00Z");
    expect((await store.meta("c1")).version).not.toBe(v1);
  });
});

describe("SuperTimelineStore.memoizeScan (#1881)", () => {
  let root: string;
  let cases: CaseStore;
  let store: SuperTimelineStore;
  let calls: number;
  const reduce = async (batches: AsyncIterable<ForensicEvent[]>) => {
    calls += 1;
    return countRows(batches);
  };
  const dbPath = () => join(cases.stateDir("c1"), INVESTIGATION_DB_FILENAME);

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-super-memo-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new SuperTimelineStore(cases, 100000);
    calls = 0;
  });

  it("scans once while the rows are unchanged", async () => {
    await store.append("c1", [ev("e1"), ev("e2", "WS-2")]);
    expect(await store.memoizeScan("c1", "count", reduce)).toBe(2);
    expect(await store.memoizeScan("c1", "count", reduce)).toBe(2);
    expect(calls).toBe(1);
  });

  it("rescans after new rows, but not after a duplicate-only append", async () => {
    await store.append("c1", [ev("e1")]);
    await store.memoizeScan("c1", "count", reduce);
    await store.append("c1", [ev("e1")]);
    expect(await store.memoizeScan("c1", "count", reduce)).toBe(1);
    expect(calls).toBe(1);
    await store.append("c1", [ev("e2", "WS-2")]);
    expect(await store.memoizeScan("c1", "count", reduce)).toBe(2);
    expect(calls).toBe(2);
  });

  it("keeps results under different names apart", async () => {
    await store.append("c1", [ev("e1")]);
    await store.memoizeScan("c1", "a", reduce);
    await store.memoizeScan("c1", "b", reduce);
    expect(calls).toBe(2);
  });

  it("never serves a result across a restore branch", async () => {
    await store.append("c1", [ev("e1")]);
    const backup = join(root, "snap.sqlite");
    await caseSqliteWorker.request({ op: "backupDatabase", dbPath: dbPath(), targetPath: backup });
    await store.append("c1", [ev("e2", "WS-2"), ev("e3", "WS-3")]);
    expect(await store.memoizeScan("c1", "count", reduce)).toBe(3);

    await caseSqliteWorker.request({ op: "restoreDatabase", sourcePath: backup, targetPath: dbPath() });
    expect(await store.memoizeScan("c1", "count", reduce)).toBe(1);
    // A different branch from the restored state: same number of appends, different rows.
    await store.append("c1", [ev("e4", "WS-4"), ev("e5", "WS-5"), ev("e6", "WS-6")]);
    expect(await store.memoizeScan("c1", "count", reduce)).toBe(4);
  });

  it("does not cache a scan that raced an append", async () => {
    await store.append("c1", [ev("e1")]);
    let first = true;
    const racing = async (batches: AsyncIterable<ForensicEvent[]>) => {
      const n = await reduce(batches);
      if (first) {
        first = false;
        await store.append("c1", [ev("e2", "WS-2")]);
      }
      return n;
    };
    expect(await store.memoizeScan("c1", "count", racing)).toBe(1);
    expect(await store.memoizeScan("c1", "count", racing)).toBe(2);
    expect(calls).toBe(2);
  });

  it("does not reuse a deleted case's result for a new case with the same id", async () => {
    await store.append("c1", [ev("e1")]);
    await store.memoizeScan("c1", "count", reduce);
    await cases.deleteCaseFolder("c1");
    forgetCaseKeyedState(root, "c1");
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await store.append("c1", [ev("e9", "WS-9"), ev("e8", "WS-8")]);
    expect(await store.memoizeScan("c1", "count", reduce)).toBe(2);
    expect(calls).toBe(2);
  });
});
