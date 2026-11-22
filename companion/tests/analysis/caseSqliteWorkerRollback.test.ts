// The bulk import's rollback ops (#1480): `entityRowIdMark` fences a run (one watermark for the
// whole entities table), `rollbackImportBatch` removes exactly the rows one run appended after
// that fence — by the run's own `importBatchId`, never by id or position alone — for every kind
// named in ONE transaction, and takes the super side tables and the FTS terms row with them.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { INVESTIGATION_DB_FILENAME, StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

interface Rollback {
  deleted: number;
  ids: string[];
}
type Kind = "forensicTimeline" | "superTimeline";
type Rollbacks = Partial<Record<Kind, Rollback>>;
const NONE: Rollback = { deleted: 0, ids: [] };

function event(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-01-01T00:00:00Z",
    description: `row ${p.id}`,
    severity: "Info",
    sources: ["test"],
    ...p,
  } as ForensicEvent;
}

function withDb<T>(dbPath: string, fn: (db: InstanceType<ReturnType<typeof loadDatabaseSync>>) => T): T {
  const DatabaseSync = loadDatabaseSync();
  const db = new DatabaseSync(dbPath);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

function idsOf(dbPath: string, kind: string): string[] {
  return withDb(dbPath, (db) =>
    db
      .prepare("SELECT entity_id AS id FROM entities WHERE kind=? ORDER BY row_id")
      .all(kind)
      .map((row) => String((row as { id: string }).id)),
  );
}

function count(dbPath: string, sql: string, ...args: unknown[]): number {
  return withDb(dbPath, (db) => Number((db.prepare(sql).get(...(args as never[])) as { n: number }).n));
}

const mark = (dbPath: string) => caseSqliteWorker.request<number>({ op: "entityRowIdMark", dbPath });
const rollback = (dbPath: string, kinds: Kind[], afterRowId: number, importBatchId: string) =>
  caseSqliteWorker.request<Rollbacks>({
    op: "rollbackImportBatch",
    dbPath,
    kinds,
    afterRowId,
    importBatchId,
  });
const appendForensic = (dbPath: string, entities: ForensicEvent[]) =>
  caseSqliteWorker.request<number>({ op: "appendEntities", dbPath, kind: "forensicTimeline", entities });
const appendSuper = (dbPath: string, events: ForensicEvent[]) =>
  caseSqliteWorker.request<number>({ op: "appendSuper", dbPath, events, max: 100000 });

describe("case SQLite worker: import-batch rollback", () => {
  let root: string;
  let dbPath: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-rollback-"));
    dbPath = join(root, "case.sqlite");
    await caseSqliteWorker.request({
      op: "saveState",
      dbPath,
      state: { caseId: "c1", forensicTimeline: [] },
    });
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("a missing database marks at 0 and rolls back nothing", async () => {
    const absent = join(root, "absent.sqlite");
    expect(await mark(absent)).toBe(0);
    expect(await rollback(absent, ["forensicTimeline", "superTimeline"], 0, "run-a")).toEqual({
      forensicTimeline: NONE,
      superTimeline: NONE,
    });
  });

  it("removes only the rows one run appended after its mark, and keeps the count honest", async () => {
    await appendForensic(dbPath, [event({ id: "old1", importBatchId: "run-old" })]);
    const fence = await mark(dbPath);
    await appendForensic(dbPath, [
      event({ id: "a1", importBatchId: "run-a" }),
      event({ id: "a2", importBatchId: "run-a" }),
    ]);
    const out = await rollback(dbPath, ["forensicTimeline"], fence, "run-a");
    expect(out).toEqual({ forensicTimeline: { deleted: 2, ids: ["a1", "a2"] } });
    expect(idsOf(dbPath, "forensicTimeline")).toEqual(["old1"]);
    expect(count(dbPath, "SELECT count AS n FROM entity_counts WHERE kind='forensicTimeline'")).toBe(1);
    // The FTS terms row follows the entity (entities_terms_delete trigger).
    expect(count(dbPath, "SELECT count(*) AS n FROM event_terms WHERE event_terms MATCH '\"row a1\"'")).toBe(
      0,
    );
  });

  it("two runs after the same mark: rolling back one leaves the other's rows alone", async () => {
    const fence = await mark(dbPath);
    await appendSuper(dbPath, [event({ id: "hunt-e1", importBatchId: "run-b" })]);
    // Run A wanted the same stable id; the append deduped it, so run A never inserted that row.
    await appendSuper(dbPath, [
      event({ id: "hunt-e1", importBatchId: "run-a" }),
      event({ id: "hunt-e2", importBatchId: "run-a" }),
    ]);
    const out = await rollback(dbPath, ["superTimeline"], fence, "run-a");
    expect(out).toEqual({ superTimeline: { deleted: 1, ids: ["hunt-e2"] } });
    expect(idsOf(dbPath, "superTimeline")).toEqual(["hunt-e1"]);
  });

  it("a row from an earlier run of the same batch id, before the mark, is not touched", async () => {
    await appendForensic(dbPath, [event({ id: "p1", importBatchId: "run-a" })]);
    const fence = await mark(dbPath);
    await appendForensic(dbPath, [event({ id: "p2", importBatchId: "run-a" })]);
    expect(await rollback(dbPath, ["forensicTimeline"], fence, "run-a")).toEqual({
      forensicTimeline: { deleted: 1, ids: ["p2"] },
    });
    expect(idsOf(dbPath, "forensicTimeline")).toEqual(["p1"]);
  });

  it("a super rollback drops the rows' labels and protection and bumps the generation", async () => {
    const fence = await mark(dbPath);
    await appendSuper(dbPath, [
      event({ id: "s1", importBatchId: "run-a" }),
      event({ id: "s2", importBatchId: "run-other" }),
    ]);
    await caseSqliteWorker.request({ op: "setSuperLabels", dbPath, eventId: "s1", labels: ["x"] });
    await caseSqliteWorker.request({ op: "setSuperLabels", dbPath, eventId: "s2", labels: ["y"] });
    await caseSqliteWorker.request({ op: "protectSuper", dbPath, eventId: "s1" });
    await caseSqliteWorker.request({ op: "protectSuper", dbPath, eventId: "s2" });
    const before = await caseSqliteWorker.request<{ generation: number; rows: number }>({
      op: "superMeta",
      dbPath,
    });
    const out = await rollback(dbPath, ["superTimeline"], fence, "run-a");
    expect(out).toEqual({ superTimeline: { deleted: 1, ids: ["s1"] } });
    const after = await caseSqliteWorker.request<{ generation: number; rows: number }>({
      op: "superMeta",
      dbPath,
    });
    expect(after.generation).toBeGreaterThan(before.generation);
    expect(after.rows).toBe(1);
    expect(count(dbPath, "SELECT count(*) AS n FROM super_labels WHERE event_id='s1'")).toBe(0);
    expect(count(dbPath, "SELECT count(*) AS n FROM super_labels WHERE event_id='s2'")).toBe(1);
    expect(count(dbPath, "SELECT count(*) AS n FROM super_protected WHERE event_id='s1'")).toBe(0);
    expect(count(dbPath, "SELECT count(*) AS n FROM super_protected WHERE event_id='s2'")).toBe(1);
  });

  it("both kinds go in one call, under one fence", async () => {
    const fence = await mark(dbPath);
    await appendForensic(dbPath, [event({ id: "18e1", importBatchId: "run-a" })]);
    await appendSuper(dbPath, [
      event({ id: "18e1", importBatchId: "run-a" }),
      event({ id: "18e2", importBatchId: "run-a" }),
    ]);
    const out = await rollback(dbPath, ["forensicTimeline", "superTimeline"], fence, "run-a");
    expect(out).toEqual({
      forensicTimeline: { deleted: 1, ids: ["18e1"] },
      superTimeline: { deleted: 2, ids: ["18e1", "18e2"] },
    });
    expect(idsOf(dbPath, "forensicTimeline")).toEqual([]);
    expect(idsOf(dbPath, "superTimeline")).toEqual([]);
  });

  it("a forensic rollback does not move the super generation", async () => {
    const fence = await mark(dbPath);
    await appendForensic(dbPath, [event({ id: "f1", importBatchId: "run-a" })]);
    const before = await caseSqliteWorker.request<{ generation: number }>({ op: "superMeta", dbPath });
    await rollback(dbPath, ["forensicTimeline"], fence, "run-a");
    const after = await caseSqliteWorker.request<{ generation: number }>({ op: "superMeta", dbPath });
    expect(after.generation).toBe(before.generation);
  });
});

// #2816: while a batched run is open, the cap may evict only that run's own rows. The rows the
// case held before the run stay until the run commits, so a rollback hands back exactly the store
// the run found. Scaled down from the issue's example by 1000: a cap of 100 and 99 rows.
describe("case SQLite worker: a batched run holds the cap's evictions until it commits (#2816)", () => {
  interface Eviction {
    count: number;
    setAside: number;
    from: string;
    to: string;
  }
  interface Appended {
    retained: number;
    evicted: Eviction;
  }
  const CAP = 100;
  let root: string;
  let dbPath: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-rollback-hold-"));
    dbPath = join(root, "case.sqlite");
    await caseSqliteWorker.request({
      op: "saveState",
      dbPath,
      state: { caseId: "c1", forensicTimeline: [] },
    });
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  const rows = (prefix: string, from: number, n: number, importBatchId: string): ForensicEvent[] =>
    Array.from({ length: n }, (_, i) => event({ id: `${prefix}${from + i}`, importBatchId }));
  const idList = (events: ForensicEvent[]) => events.map((e) => e.id);
  const appendPlain = (events: ForensicEvent[], max: number) =>
    caseSqliteWorker.request<Appended>({ op: "appendSuper", dbPath, events, max });
  const appendHeld = (events: ForensicEvent[], max: number, holdRowId: number) =>
    caseSqliteWorker.request<Appended>({ op: "appendSuper", dbPath, events, max, holdRowId });
  const capPass = (max: number) => caseSqliteWorker.request<Eviction>({ op: "capSuper", dbPath, max });
  const evictedTotal = async () =>
    (await caseSqliteWorker.request<{ evictedTotal: number }>({ op: "superMeta", dbPath })).evictedTotal;

  async function nearlyFullThenThreeBatches(): Promise<{ before: string[]; fence: number }> {
    await appendPlain(rows("old", 1, 99, "run-old"), CAP);
    const before = idsOf(dbPath, "superTimeline");
    const fence = await mark(dbPath);
    for (let b = 0; b < 3; b++) {
      const out = await appendHeld(rows("new", b * 5 + 1, 5, "run-a"), CAP, fence);
      expect(out).toEqual({ retained: 5, evicted: { count: 0, setAside: 0, from: "", to: "" } });
    }
    return { before, fence };
  }

  it("a rollback after several batches leaves the rows the case held before the run", async () => {
    const { before, fence } = await nearlyFullThenThreeBatches();
    expect(before).toHaveLength(99);
    const out = await rollback(dbPath, ["superTimeline"], fence, "run-a");
    expect(out.superTimeline?.deleted).toBe(15);
    expect(idsOf(dbPath, "superTimeline")).toEqual(before);
    expect(count(dbPath, "SELECT count AS n FROM entity_counts WHERE kind='superTimeline'")).toBe(99);
    expect(await evictedTotal()).toBe(0); // nothing was lost, so the case's record says nothing was
  });

  it("the commit pass evicts what was held, and reports it", async () => {
    const { before } = await nearlyFullThenThreeBatches();
    expect(idsOf(dbPath, "superTimeline")).toHaveLength(114); // above the cap until the run commits
    const evicted = await capPass(CAP);
    expect(evicted.count).toBe(14);
    const after = idsOf(dbPath, "superTimeline");
    expect(after).toHaveLength(CAP);
    expect(after.slice(0, 85)).toEqual(before.slice(14)); // the 14 oldest are the ones that went
    expect(after.slice(85)).toEqual(idList(rows("new", 1, 15, "run-a")));
    expect(await evictedTotal()).toBe(14);
  });

  it("a run larger than the cap still evicts its own head while held", async () => {
    await appendPlain(rows("old", 1, 4, "run-old"), 10);
    const before = idsOf(dbPath, "superTimeline");
    const fence = await mark(dbPath);
    const counts: number[] = [];
    for (let b = 0; b < 3; b++) {
      counts.push((await appendHeld(rows("new", b * 5 + 1, 5, "run-a"), 10, fence)).evicted.count);
    }
    expect(counts).toEqual([0, 0, 5]); // the four old rows are spared; the run's first five are not
    expect(idsOf(dbPath, "superTimeline")).toEqual([...before, ...idList(rows("new", 6, 10, "run-a"))]);
    await rollback(dbPath, ["superTimeline"], fence, "run-a");
    expect(idsOf(dbPath, "superTimeline")).toEqual(before);
  });

  it("the store's own append and commit carry the hold", async () => {
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: "mock" });
    const state = new StateStore(cases);
    await state.save(await state.load("c2")); // a case with no saved state marks its fence at 0
    const store = new SuperTimelineStore(cases, CAP);
    const caseDb = join(cases.stateDir("c2"), INVESTIGATION_DB_FILENAME);
    await store.appendReporting("c2", rows("old", 1, 99, "run-old"));
    const before = idsOf(caseDb, "superTimeline");
    const fence = await state.importRowIdMark("c2");
    for (let b = 0; b < 3; b++) {
      const out = await store.appendReporting("c2", rows("new", b * 5 + 1, 5, "run-a"), {
        holdRowId: fence,
      });
      expect(out.evicted.count).toBe(0);
    }
    expect((await store.meta("c2")).rows).toBe(114);
    await state.rollbackImportBatch("c2", fence, "run-a", ["superTimeline"]);
    expect(idsOf(caseDb, "superTimeline")).toEqual(before);

    for (let b = 0; b < 3; b++) {
      await store.appendReporting("c2", rows("again", b * 5 + 1, 5, "run-b"), { holdRowId: fence });
    }
    expect((await store.enforceCap("c2")).count).toBe(14);
    expect((await store.meta("c2")).rows).toBe(CAP);
  });
});
