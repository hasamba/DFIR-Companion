// The bulk import's rollback ops (#1480): `entityRowIdMark` fences a run (one watermark for the
// whole entities table), `rollbackImportBatch` removes exactly the rows one run appended after
// that fence — by the run's own `importBatchId`, never by id or position alone — for every kind
// named in ONE transaction, and takes the super side tables and the FTS terms row with them.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
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
